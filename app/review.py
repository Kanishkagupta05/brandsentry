"""Grounded review pipeline.

Order of work:
 1. segment the draft into sentences
 2. deterministic checks (terms, absolute claims, numeric facts, tone, readability)
 3. optional LLM check for nuance, fed only retrieved clauses/facts
 4. citation validator: any finding whose source ID does not exist, or whose quote is not
    literally present in that source, is dropped (and counted)
 5. suggestions are re-checked so a fix cannot introduce a new high-severity problem
"""
import datetime
import json
import os
import re
import time
import urllib.request

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

SENT_RE = re.compile(r".+?(?:[.!?]+(?=\s|$)|$)", re.S)
NUM_RE = re.compile(r"(?<![\w.])\d[\d,]*(?:\.\d+)?%?")
HYPE = ["revolutionary", "game-changing", "game changer", "synergy", "disrupt", "leverage",
        "cutting-edge", "world-class", "next-level", "unleash"]
ALLOWED_CAPS = {"WCAG", "AA", "UK", "USA", "FAQ", "PDF", "CEO", "RS", "INR", "AI"}
SOURCE_WORDS = ["most popular", "leading", "award-winning", "trusted by", "loved by", "millions of",
                "thousands of", "top-rated", "fastest", "largest"]
STOP = set("the a an and or of to in on for with is are was were be been it this that you your our we "
           "at by from as will can all any every new".split())

ABSOLUTE_RE = re.compile(
    r"(?:\bthe\s+)?(?:\bbest\b|\bguaranteed?\b|(?<!\w)#1(?!\d)|\bnumber one\b|\bunbeatable\b|"
    r"\bunmatched\b|\brisk[- ]free\b|\bperfect\b|(?<!\w)100\s?%)", re.I)

SOFTEN = [
    (re.compile(r"^(?:the\s+)?best$", re.I), "a great"),
    (re.compile(r"^(?:the\s+)?(?:#1|number one)$", re.I), "a popular"),
    (re.compile(r"^guaranteed?$", re.I), "designed"),
    (re.compile(r"^(?:the\s+)?unbeatable$", re.I), "great"),
    (re.compile(r"^(?:the\s+)?unmatched$", re.I), "distinctive"),
    (re.compile(r"^(?:the\s+)?risk[- ]free$", re.I), "low-risk"),
    (re.compile(r"^(?:the\s+)?perfect$", re.I), "lovely"),
]


# ---------------- helpers ----------------
def segment(text):
    out = []
    for m in SENT_RE.finditer(text):
        s = m.group(0)
        if s.strip():
            lead = len(s) - len(s.lstrip())
            out.append((m.start() + lead, m.end(), s.strip()))
    return out


def tokens(s):
    return [w for w in re.findall(r"[a-z0-9']+", s.lower()) if len(w) > 2 and w not in STOP]


def numbers(s):
    res = []
    for m in NUM_RE.finditer(s):
        raw = m.group(0)
        norm = raw.replace(",", "")
        digits = norm.rstrip("%")
        if "." not in digits and not norm.endswith("%") and 1900 <= int(float(digits)) <= 2100:
            continue  # looks like a year
        res.append((m.start(), m.end(), norm))
    return res


def norm_space(s):
    return re.sub(r"\s+", " ", s).strip().lower()


def clause_quote(text, max_words=14):
    first = re.split(r"(?<=[.!?])\s", text.strip())[0]
    return " ".join(first.split()[:max_words]).rstrip(",;:")


def retrieve(items, text, key, k=4):
    """Keyword-overlap retrieval. Returns the k items most relevant to the text."""
    t = set(tokens(text))
    scored = []
    for it in items:
        score = len(t & set(tokens(key(it))))
        scored.append((score, it))
    scored.sort(key=lambda x: -x[0])
    return [it for sc, it in scored[:k]]


class KB:
    def __init__(self, clauses, terms, facts, today=None):
        self.clauses = {c["code"]: c for c in clauses}
        self.terms = terms
        self.facts = facts
        self.today = today or datetime.date.today().isoformat()

    def sources(self):
        s = {}
        for c in self.clauses.values():
            s[c["code"]] = c["text"]
        for t in self.terms:
            s[t["code"]] = t["rule_text"]
        for f in self.facts:
            s[f["code"]] = f["claim"]
        return s

    def clause(self, code):
        return self.clauses.get(code)


def mk(start, end, original, rule_code, rule_type, quote, category, severity, confidence,
       explanation, replacement=None, claim_status=None, route=False, source="rules"):
    return {
        "start": start, "end": end, "original": original,
        "rule": {"code": rule_code, "type": rule_type, "quote": quote},
        "category": category, "severity": severity, "confidence": confidence,
        "explanation": explanation, "replacement": replacement,
        "claim_status": claim_status, "route_to_reviewer": route, "source": source,
    }


# ---------------- deterministic checks ----------------
def deterministic(text, kb):
    found = []
    for s_start, s_end, sent in segment(text):
        found += check_terms(text, sent, s_start, kb)
        found += check_claims(text, sent, s_start, kb)
        found += check_tone(text, sent, s_start, kb)
        found += check_readability(text, sent, s_start, kb)
    return found


def check_terms(text, sent, off, kb):
    out = []
    for t in kb.terms:
        flags = 0 if t["case_sensitive"] else re.I
        for m in re.finditer(r"(?<![\w])" + re.escape(t["banned"]) + r"(?![\w])", sent, flags):
            orig = m.group(0)
            rep = t["preferred"]
            if orig[:1].isupper() and not t["case_sensitive"]:
                rep = rep[:1].upper() + rep[1:]
            out.append(mk(off + m.start(), off + m.end(), orig, t["code"], "term", t["rule_text"],
                          "terminology", "medium", 0.95,
                          f"'{orig}' is not approved wording. The terminology list prefers '{t['preferred']}'.",
                          replacement=rep))
    return out


def fact_matches(sent, kb):
    low = sent.lower()
    res = []
    for f in kb.facts:
        kws = [k.strip().lower() for k in f["keywords"].split(",") if k.strip()]
        if any(k in low for k in kws):
            res.append(f)
    return res


def check_claims(text, sent, off, kb):
    out = []
    matched = fact_matches(sent, kb)
    snums = numbers(sent)
    supported_tokens = set()
    handled_numbers = False

    for f in matched:
        fnums = [n for _, _, n in numbers(f["value"] + " ") ] or [f["value"].replace(",", "")]
        if not snums:
            continue
        snorms = [n for _, _, n in snums]
        expired = bool(f["valid_until"]) and f["valid_until"] < kb.today
        if all(fn in snorms for fn in fnums):
            handled_numbers = True
            supported_tokens.update(fnums)
            if expired:
                s0, e0, n0 = next(x for x in snums if x[2] in fnums)
                out.append(mk(off + s0, off + e0, sent[s0:e0], f["code"], "fact", f["claim"],
                              "factual accuracy", "medium", 0.9,
                              f"This figure matches an approved fact, but the fact expired on {f['valid_until']}. "
                              "Ask the admin to confirm or renew it before publishing.",
                              claim_status="expired", route=True))
        else:
            handled_numbers = True
            bad = next((x for x in snums if x[2] not in fnums), None)
            if bad:
                s0, e0, n0 = bad
                good = fnums[0]
                rep = good
                out.append(mk(off + s0, off + e0, sent[s0:e0], f["code"], "fact", f["claim"],
                              "factual accuracy", "high", 0.9,
                              f"The draft says {sent[s0:e0]}, but the approved fact says {f['value']} "
                              f"(source: {f['source']}).",
                              replacement=rep, claim_status="contradicted", route=True))

    # absolute claims
    g2 = kb.clause("G-2")
    if g2:
        for m in ABSOLUTE_RE.finditer(sent):
            tok = m.group(0)
            tok_core = re.sub(r"^the\s+", "", tok, flags=re.I).replace(" ", "")
            if tok_core in supported_tokens or tok_core.lower() in {s.lower() for s in supported_tokens}:
                continue
            rep = None
            for pat, r in SOFTEN:
                if pat.match(tok):
                    rep = r
            if rep and re.match(r"\s+(?:\w+\s+){0,6}?(?:you(?:'ll| will)?\s+)?ever\b", sent[m.end():], re.I):
                rep = None  # "the best X you will ever Y" cannot be softened mechanically; leave it to a human
            out.append(mk(off + m.start(), off + m.end(), tok, "G-2", "clause", clause_quote(g2["text"]),
                          "unsupported claim", "high", 0.8,
                          f"'{tok}' is an absolute or superlative claim, and no approved fact supports it.",
                          replacement=rep, claim_status="unsupported_absolute", route=True))

    # numbers / comparisons with no approved fact behind them
    g3 = kb.clause("G-3")
    if g3 and not handled_numbers:
        has_abs = any(f["claim_status"] == "unsupported_absolute" for f in out)
        flagged = False
        if snums and not has_abs:
            s0, e0, n0 = snums[0]
            out.append(mk(off + s0, off + e0, sent[s0:e0], "G-3", "clause", clause_quote(g3["text"]),
                          "unsupported claim", "medium", 0.6,
                          "This figure has no matching approved fact. Marked 'Needs a source' rather than guessed.",
                          claim_status="needs_source", route=True))
            flagged = True
        if not flagged and not has_abs:
            low = sent.lower()
            for w in SOURCE_WORDS:
                i = low.find(w)
                if i >= 0:
                    out.append(mk(off + i, off + i + len(w), sent[i:i + len(w)], "G-3", "clause",
                                  clause_quote(g3["text"]), "unsupported claim", "medium", 0.55,
                                  f"'{sent[i:i + len(w)]}' is a comparison with no approved fact behind it. "
                                  "Marked 'Needs a source'.", claim_status="needs_source", route=True))
                    break
    return out


def check_tone(text, sent, off, kb):
    g1 = kb.clause("G-1")
    if not g1:
        return []
    out = []
    q = clause_quote(g1["text"])
    for m in re.finditer(r"!+", sent):
        out.append(mk(off + m.start(), off + m.end(), m.group(0), "G-1", "clause", q, "tone", "low", 0.7,
                      "The voice guideline asks us to avoid exclamation marks.", replacement="."))
    for m in re.finditer(r"\b[A-Z]{3,}\b", sent):
        if m.group(0) in ALLOWED_CAPS:
            continue
        out.append(mk(off + m.start(), off + m.end(), m.group(0), "G-1", "clause", q, "tone", "low", 0.7,
                      "Shouting in capitals reads as hype. Use normal case.", replacement=m.group(0).lower()))
    low = sent.lower()
    for w in HYPE:
        i = low.find(w)
        if i >= 0:
            out.append(mk(off + i, off + i + len(w), sent[i:i + len(w)], "G-1", "clause", q, "tone", "low", 0.7,
                          f"'{sent[i:i + len(w)]}' is a hype word. Prefer plain, concrete wording."))
    return out


def check_readability(text, sent, off, kb):
    g5 = kb.clause("G-5")
    if not g5:
        return []
    n = len(sent.split())
    if n > 25:
        return [mk(off, off + len(sent), sent, "G-5", "clause", clause_quote(g5["text"]), "readability", "low", 0.9,
                   f"This sentence has {n} words. Consider splitting it.")]
    return []


# ---------------- optional AI check ----------------
def redact(s):
    s = re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "[EMAIL]", s)
    s = re.sub(r"(?<!\w)(?:\+?\d[\d\s-]{8,}\d)(?!\w)", "[PHONE]", s)
    return s


def ai_enabled():
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def ai_check(sentences, purpose, kb, already, con=None):
    """Ask the model only about nuance (tone, implied claims) using retrieved context.
    Returns (raw_findings, note). Never raises."""
    if not ai_enabled():
        return [], "AI check off: no ANTHROPIC_API_KEY set, running rules only"
    joined = " ".join(s for _, _, s in sentences)
    clauses = retrieve(list(kb.clauses.values()), joined, lambda c: c["text"], k=4)
    facts = retrieve(kb.facts, joined, lambda f: f["claim"] + " " + f["keywords"], k=4)
    sent_block = "\n".join(f"[{i}] {redact(s)}" for i, (_, _, s) in enumerate(sentences))
    ctx = "\n".join([f"{c['code']}: {c['text']}" for c in clauses] +
                    [f"{f['code']}: {f['claim']}" for f in facts])
    prompt = (
        "You review marketing text against ONLY the guideline clauses and approved facts below.\n"
        "Report just issues of tone or implied claims that the rule engine did not already flag.\n"
        "Every finding MUST cite a rule_code from the list and a quote copied exactly from that rule's text, "
        "and a span copied exactly from the sentence. If you are unsure, report nothing.\n"
        "Keep the author's purpose: " + redact(purpose or "(not stated)") + "\n\n"
        "RULES:\n" + ctx + "\n\nALREADY FLAGGED SPANS: " + json.dumps([a["original"] for a in already]) +
        "\n\nSENTENCES:\n" + sent_block + "\n\n"
        'Reply with only a JSON array of {"sentence_id":int,"span":str,"rule_code":str,"quote":str,'
        '"issue":str,"replacement":str|null,"severity":"low|medium|high"}. Use [] when nothing to report.'
    )
    t0 = time.time()
    try:
        body = json.dumps({
            "model": os.environ.get("BRANDSENTRY_MODEL", "claude-sonnet-5-5"),
            "max_tokens": 1500,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=body,
            headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01",
                     "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        text = "".join(b.get("text", "") for b in data.get("content", []))
        a, b = text.find("["), text.rfind("]")
        raw = json.loads(text[a:b + 1]) if a >= 0 and b > a else []
        _log_ai(con, len(prompt), 1, "ok")
        return raw, "AI-assisted check ran"
    except Exception as e:  # network, auth, parse: degrade to rules only
        _log_ai(con, len(prompt), 0, str(e)[:200])
        return [], f"AI check failed ({type(e).__name__}); showing rule-based findings only"


def _log_ai(con, chars, ok, note):
    if con is not None:
        con.execute("INSERT INTO ai_log(ts,service,purpose,chars_sent,ok,note) VALUES(?,?,?,?,?,?)",
                    (time.time(), "Anthropic Messages API", "tone / implied-claim review", chars, ok, note))


# ---------------- citation validator ----------------
def validate(f, sources, text=None):
    """True only if the cited source exists and the quote is literally inside it."""
    code = f["rule"]["code"]
    q = f["rule"]["quote"]
    if code not in sources or not q:
        return False
    if norm_space(q) not in norm_space(sources[code]):
        return False
    if text is not None and text[f["start"]:f["end"]] != f["original"]:
        return False
    return True


def to_findings_from_ai(raw, sentences, kb, text):
    out = []
    sources = kb.sources()
    for r in raw if isinstance(raw, list) else []:
        try:
            sid = int(r["sentence_id"])
            s_start, s_end, sent = sentences[sid]
            span = r["span"]
            i = sent.find(span)
            if i < 0 or not span:
                continue
            code = r["rule_code"]
            typ = "clause" if code in kb.clauses else ("fact" if code.startswith("F") else "term")
            sev = r.get("severity", "low")
            if sev not in SEVERITY_ORDER:
                sev = "low"
            rep = r.get("replacement")
            out.append(mk(s_start + i, s_start + i + len(span), span, code, typ, r["quote"], "tone / implied claim",
                          sev, 0.6, str(r.get("issue", ""))[:300], replacement=rep if isinstance(rep, str) else None,
                          source="ai"))
        except Exception:
            continue
    return out


# ---------------- intent check on suggestions ----------------
def check_suggestions(findings, text, kb):
    """Re-run the checks on the rewritten sentence; drop a suggestion that adds a new high-severity issue
    or throws away most of the original wording."""
    for f in findings:
        rep = f.get("replacement")
        if rep is None:
            continue
        sents = [s for s in segment(text) if s[0] <= f["start"] < s[1]]
        if not sents:
            continue
        s_start, s_end, sent = sents[0]
        lo, hi = f["start"] - s_start, f["end"] - s_start
        new_sent = sent[:lo] + rep + sent[hi:]
        before = {(x["rule"]["code"], x["original"].lower()) for x in deterministic(sent, kb)
                  if x["severity"] == "high"}
        after = {(x["rule"]["code"], x["original"].lower()) for x in deterministic(new_sent, kb)
                 if x["severity"] == "high"}
        old_words, new_words = set(tokens(sent)), set(tokens(new_sent))
        kept = len(old_words & new_words) / max(1, len(old_words))
        if (after - before) or kept < 0.6:
            f["replacement"] = None
            f["suggestion_note"] = "A mechanical fix would introduce a new problem or change the meaning, so no auto-fix is offered."
        else:
            f["suggestion_note"] = "Fix re-checked: introduces no new high-severity issue and keeps the original wording."
    return findings


# ---------------- main entry ----------------
def run_review(text, purpose, kb, con=None):
    sentences = segment(text)
    sources = kb.sources()
    findings = deterministic(text, kb)

    raw, ai_note = ai_check(sentences, purpose, kb, findings, con)
    ai_findings = to_findings_from_ai(raw, sentences, kb, text)

    dropped = 0
    valid = []
    for f in findings + ai_findings:
        if validate(f, sources, text):
            valid.append(f)
        else:
            dropped += 1

    # drop AI findings that overlap a rule finding
    final = []
    for f in valid:
        if f["source"] == "ai" and any(o["source"] == "rules" and f["start"] < o["end"] and o["start"] < f["end"]
                                        for o in valid):
            dropped += 1
            continue
        final.append(f)

    # a low-severity tone flag sitting inside a bigger finding's span is redundant (e.g. "BEST" in "the BEST")
    final = [f for f in final
             if not (f["category"] == "tone" and any(
                 o is not f and o["category"] != "tone" and o["start"] <= f["start"] and f["end"] <= o["end"]
                 for o in final))]

    final = check_suggestions(final, text, kb)
    final.sort(key=lambda f: (f["start"], SEVERITY_ORDER[f["severity"]]))
    for i, f in enumerate(final):
        f["id"] = f"f{i + 1}"
        f["key"] = f"{f['rule']['code']}|{f['original'].lower()}"

    # claim-level summary: every numeric/claim sentence ends up supported, contradicted, or needs a source
    meta = {
        "mode": "rules+ai" if raw is not None and ai_enabled() else "rules-only",
        "ai_note": ai_note,
        "dropped_invalid": dropped,
        "sentences": len(sentences),
        "counts": {s: sum(1 for f in final if f["severity"] == s) for s in SEVERITY_ORDER},
        "external_services": ["Anthropic Messages API"] if ai_enabled() else [],
    }
    return final, meta


def apply_edits(text, edits):
    """edits: list of (start, end, replacement). Overlapping edits are skipped, returns (new_text, skipped)."""
    edits = sorted(edits, key=lambda e: (e[0], e[1]))
    kept, skipped, last_end = [], [], -1
    for e in edits:
        if e[0] >= last_end:
            kept.append(e)
            last_end = e[1]
        else:
            skipped.append(e)
    for s, e, r in reversed(kept):
        text = text[:s] + r + text[e:]
    return text, skipped
