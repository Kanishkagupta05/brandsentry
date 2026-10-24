"""BrandSentry HTTP server (standard library only; no web framework needed)."""
import json
import mimetypes
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import db, extract, review

STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "static")
ROLES = ("creator", "manager", "reviewer", "admin")


class ApiError(Exception):
    def __init__(self, status, msg):
        self.status, self.msg = status, msg


def need(cond, status, msg):
    if not cond:
        raise ApiError(status, msg)


def load_kb(con):
    return review.KB(db.rows(con.execute("SELECT * FROM clauses ORDER BY code")),
                     db.rows(con.execute("SELECT * FROM terms ORDER BY code")),
                     db.rows(con.execute("SELECT * FROM facts ORDER BY code")))


def can_see(user, draft):
    return user["role"] != "creator" or draft["owner_id"] == user["id"]


def get_draft(con, did, user):
    d = con.execute("SELECT * FROM drafts WHERE id=?", (did,)).fetchone()
    need(d, 404, "Draft not found")
    d = dict(d)
    need(can_see(user, d), 403, "You cannot view this draft")
    return d


def version_view(con, v):
    v = dict(v)
    v["findings"] = json.loads(v["findings"] or "[]")
    v["review_meta"] = json.loads(v["review_meta"] or "{}")
    v["decisions"] = db.rows(con.execute(
        "SELECT d.*, u.name AS user_name FROM decisions d LEFT JOIN users u ON u.id=d.user_id WHERE version_id=?",
        (v["id"],)))
    v["comments"] = db.rows(con.execute(
        "SELECT c.*, u.name AS user_name, u.role AS user_role FROM comments c "
        "LEFT JOIN users u ON u.id=c.user_id WHERE version_id=? ORDER BY c.ts", (v["id"],)))
    return v


def draft_state(con, did, user):
    d = get_draft(con, did, user)
    owner = con.execute("SELECT name FROM users WHERE id=?", (d["owner_id"],)).fetchone()
    d["owner_name"] = owner["name"] if owner else ""
    versions = db.rows(con.execute(
        "SELECT id,n,note,created_at FROM versions WHERE draft_id=? ORDER BY n", (did,)))
    latest = con.execute("SELECT * FROM versions WHERE draft_id=? ORDER BY n DESC LIMIT 1", (did,)).fetchone()
    lv = version_view(con, latest)
    decided = {x["finding_id"] for x in lv["decisions"]}
    routed = [f for f in lv["findings"] if f["route_to_reviewer"]]
    d["unresolved_routed"] = sum(1 for f in routed if f["id"] not in decided)
    d["pending_apply"] = sum(1 for x in lv["decisions"] if x["action"] in ("accept", "edit"))
    d["needs_reviewer"] = bool(routed)
    d["approvals"] = db.rows(con.execute(
        "SELECT a.*, u.name AS user_name FROM approvals a LEFT JOIN users u ON u.id=a.user_id "
        "WHERE draft_id=? ORDER BY ts", (did,)))
    d["reviewer_signed"] = any(a["stage"] == "reviewer" and a["outcome"] == "approve"
                               and a["version_id"] == lv["id"] for a in d["approvals"])
    return {"draft": d, "versions": versions, "latest": lv}


def new_version(con, draft_id, content, author_id, note, purpose, carry_from=None):
    kb = load_kb(con)
    findings, meta = review.run_review(content, purpose, kb, con)
    n = (con.execute("SELECT COALESCE(MAX(n),0) FROM versions WHERE draft_id=?", (draft_id,)).fetchone()[0]) + 1
    cur = con.execute(
        "INSERT INTO versions(draft_id,n,content,findings,review_meta,author_id,created_at,note) VALUES(?,?,?,?,?,?,?,?)",
        (draft_id, n, content, json.dumps(findings), json.dumps(meta), author_id, time.time(), note))
    vid = cur.lastrowid
    carried = 0
    if carry_from:  # a dismissal (with its reason) survives re-review if the same finding comes back
        old = db.rows(con.execute("SELECT * FROM decisions WHERE version_id=? AND action='dismiss'", (carry_from,)))
        by_key = {o["finding_key"]: o for o in old}
        for f in findings:
            o = by_key.get(f["key"])
            if o:
                con.execute("INSERT INTO decisions(version_id,finding_id,finding_key,action,reason,final_text,user_id,ts) "
                            "VALUES(?,?,?,?,?,?,?,?)",
                            (vid, f["id"], f["key"], "dismiss", o["reason"], None, o["user_id"], time.time()))
                carried += 1
    return vid, n, findings, meta, carried


# ------------------------------------------------------------------ route handlers
def h_login(con, user, body, m):
    u = con.execute("SELECT * FROM users WHERE username=?", ((body.get("username") or "").strip().lower(),)).fetchone()
    need(u and db.hash_pw(body.get("password") or "", u["salt"]) == u["pw_hash"], 401, "Wrong username or password")
    db.audit(con, u["id"], "login", "")
    return {"token": db.make_token(u["id"]), "user": {"id": u["id"], "name": u["name"], "role": u["role"],
                                                       "username": u["username"]}}


def h_me(con, user, body, m):
    return {"user": user}


def h_demo_accounts(con, user, body, m):
    return {"accounts": [{"username": r["username"], "role": r["role"], "name": r["name"]}
                         for r in con.execute("SELECT * FROM users ORDER BY id")], "password": db.DEMO_PASSWORD}


def h_kb(con, user, body, m):
    return {"clauses": db.rows(con.execute("SELECT * FROM clauses ORDER BY code")),
            "terms": db.rows(con.execute("SELECT * FROM terms ORDER BY code")),
            "facts": db.rows(con.execute("SELECT * FROM facts ORDER BY code")),
            "today": review.datetime.date.today().isoformat()}


def admin_only(user):
    need(user["role"] == "admin", 403, "Only the brand admin can change the knowledge base")


def h_kb_clause(con, user, body, m):
    admin_only(user)
    code, text = (body.get("code") or "").strip(), (body.get("text") or "").strip()
    need(code and text, 400, "Code and text are required")
    old = con.execute("SELECT version FROM clauses WHERE code=?", (code,)).fetchone()
    if old:
        con.execute("UPDATE clauses SET title=?, text=?, version=version+1 WHERE code=?",
                    (body.get("title", ""), text, code))
    else:
        con.execute("INSERT INTO clauses(code,title,text) VALUES(?,?,?)", (code, body.get("title", ""), text))
    db.audit(con, user["id"], "kb.clause", code)
    return {"ok": True}


def h_kb_term(con, user, body, m):
    admin_only(user)
    code, banned, pref = (body.get("code") or "").strip(), (body.get("banned") or "").strip(), (body.get("preferred") or "").strip()
    need(code and banned and pref, 400, "Code, banned term and preferred term are required")
    rule = (body.get("rule_text") or "").strip() or f"Always say '{pref}' instead of '{banned}'."
    old = con.execute("SELECT 1 FROM terms WHERE code=?", (code,)).fetchone()
    if old:
        con.execute("UPDATE terms SET banned=?,preferred=?,rule_text=?,case_sensitive=?,version=version+1 WHERE code=?",
                    (banned, pref, rule, int(bool(body.get("case_sensitive"))), code))
    else:
        con.execute("INSERT INTO terms(code,banned,preferred,rule_text,case_sensitive) VALUES(?,?,?,?,?)",
                    (code, banned, pref, rule, int(bool(body.get("case_sensitive")))))
    db.audit(con, user["id"], "kb.term", code)
    return {"ok": True}


def h_kb_fact(con, user, body, m):
    admin_only(user)
    code, claim, value = (body.get("code") or "").strip(), (body.get("claim") or "").strip(), (body.get("value") or "").strip()
    need(code and claim and value, 400, "Code, claim and value are required")
    until = (body.get("valid_until") or "").strip()
    need(not until or re.fullmatch(r"\d{4}-\d{2}-\d{2}", until), 400, "valid_until must look like 2027-06-30")
    args = (claim, value, body.get("source", ""), body.get("keywords", ""), until)
    if con.execute("SELECT 1 FROM facts WHERE code=?", (code,)).fetchone():
        con.execute("UPDATE facts SET claim=?,value=?,source=?,keywords=?,valid_until=?,version=version+1 WHERE code=?",
                    args + (code,))
    else:
        con.execute("INSERT INTO facts(claim,value,source,keywords,valid_until,code) VALUES(?,?,?,?,?,?)", args + (code,))
    db.audit(con, user["id"], "kb.fact", code)
    return {"ok": True}


def h_kb_delete(con, user, body, m):
    admin_only(user)
    table = {"clause": "clauses", "term": "terms", "fact": "facts"}[m.group(1)]
    con.execute(f"DELETE FROM {table} WHERE code=?", (m.group(2),))
    db.audit(con, user["id"], f"kb.delete.{m.group(1)}", m.group(2))
    return {"ok": True}


def h_kb_import(con, user, body, m):
    admin_only(user)
    try:
        text = extract.extract_text(body.get("filename"), body.get("data"))
    except Exception as e:
        raise ApiError(400, str(e))
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if len(p.strip()) > 20]
    need(paras, 400, "No readable text found in that file")
    start = con.execute("SELECT COUNT(*) FROM clauses WHERE code LIKE 'U-%'").fetchone()[0]
    added = []
    for i, p in enumerate(paras[:40]):
        code = f"U-{start + i + 1}"
        con.execute("INSERT OR IGNORE INTO clauses(code,title,text) VALUES(?,?,?)",
                    (code, f"Imported: {body.get('filename')}", p))
        added.append(code)
    db.audit(con, user["id"], "kb.import", f"{body.get('filename')} -> {len(added)} clauses")
    return {"added": added}


def h_extract(con, user, body, m):
    try:
        return {"text": extract.extract_text(body.get("filename"), body.get("data"))}
    except Exception as e:
        raise ApiError(400, str(e))


def h_sample(con, user, body, m):
    return db.SAMPLE_DRAFT


def h_drafts_list(con, user, body, m):
    q = "SELECT d.*, u.name AS owner_name FROM drafts d LEFT JOIN users u ON u.id=d.owner_id "
    args = ()
    if user["role"] == "creator":
        q += "WHERE d.owner_id=? "
        args = (user["id"],)
    q += "ORDER BY d.updated_at DESC"
    return {"drafts": db.rows(con.execute(q, args))}


def h_draft_create(con, user, body, m):
    need(user["role"] in ("creator", "manager", "admin"), 403, "Your role cannot submit drafts")
    content = (body.get("content") or "").strip()
    need(content, 400, "Paste or upload some text to review")
    need(len(content) <= 20000, 400, "Please keep drafts under 20,000 characters for this demo")
    purpose = (body.get("purpose") or "").strip()
    need(purpose, 400, "State the purpose of the piece in one line so fixes can preserve it")
    now = time.time()
    cur = con.execute("INSERT INTO drafts(title,channel,purpose,owner_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                      ((body.get("title") or "Untitled draft").strip(), body.get("channel", ""), purpose, user["id"],
                       "draft", now, now))
    did = cur.lastrowid
    new_version(con, did, content, user["id"], "Initial submission", purpose)
    db.audit(con, user["id"], "draft.create", f"#{did}")
    return draft_state(con, did, user)


def h_draft_get(con, user, body, m):
    return draft_state(con, int(m.group(1)), user)


def h_version_get(con, user, body, m):
    v = con.execute("SELECT * FROM versions WHERE id=?", (int(m.group(1)),)).fetchone()
    need(v, 404, "Version not found")
    get_draft(con, v["draft_id"], user)
    return {"version": version_view(con, v)}


def h_decision(con, user, body, m):
    v = con.execute("SELECT * FROM versions WHERE id=?", (int(m.group(1)),)).fetchone()
    need(v, 404, "Version not found")
    d = get_draft(con, v["draft_id"], user)
    need(d["owner_id"] == user["id"], 403, "Only the creator of this draft can accept or dismiss suggestions")
    latest = con.execute("SELECT MAX(n) FROM versions WHERE draft_id=?", (d["id"],)).fetchone()[0]
    need(v["n"] == latest, 409, "This version has been superseded; decide on the latest version")
    need(d["status"] in ("draft", "changes_requested"), 409, "This draft is locked while it is in approval")
    findings = json.loads(v["findings"])
    f = next((x for x in findings if x["id"] == body.get("finding_id")), None)
    need(f, 404, "Finding not found")
    action = body.get("action")
    need(action in ("accept", "edit", "dismiss", "undo"), 400, "action must be accept, edit, dismiss or undo")
    if action == "undo":
        con.execute("DELETE FROM decisions WHERE version_id=? AND finding_id=?", (v["id"], f["id"]))
        return draft_state(con, d["id"], user)
    final_text, reason = None, (body.get("reason") or "").strip()
    if action == "accept":
        need(f["replacement"] is not None, 400, "This finding has no suggested fix. Edit it yourself or dismiss it with a reason.")
        final_text = f["replacement"]
    elif action == "edit":
        final_text = body.get("final_text")
        need(isinstance(final_text, str), 400, "Provide your edited text")
    else:
        need(len(reason) >= 3, 400, "Dismissing a suggestion needs a short reason")
    con.execute(
        "INSERT INTO decisions(version_id,finding_id,finding_key,action,reason,final_text,user_id,ts) VALUES(?,?,?,?,?,?,?,?) "
        "ON CONFLICT(version_id,finding_id) DO UPDATE SET action=excluded.action, reason=excluded.reason, "
        "final_text=excluded.final_text, user_id=excluded.user_id, ts=excluded.ts",
        (v["id"], f["id"], f["key"], action, reason, final_text, user["id"], time.time()))
    db.audit(con, user["id"], f"decision.{action}", f"draft #{d['id']} v{v['n']} {f['id']} {f['rule']['code']}")
    return draft_state(con, d["id"], user)


def h_revise(con, user, body, m):
    d = get_draft(con, int(m.group(1)), user)
    need(d["owner_id"] == user["id"], 403, "Only the creator can revise this draft")
    need(d["status"] in ("draft", "changes_requested"), 409, "This draft is locked while it is in approval")
    latest = con.execute("SELECT * FROM versions WHERE draft_id=? ORDER BY n DESC LIMIT 1", (d["id"],)).fetchone()
    note, skipped = "", 0
    if body.get("content") is not None:  # creator edited the text directly
        content = body["content"].strip()
        need(content, 400, "Text cannot be empty")
        note = "Edited by creator"
    else:  # apply accepted / edited suggestions
        findings = {f["id"]: f for f in json.loads(latest["findings"])}
        decs = db.rows(con.execute("SELECT * FROM decisions WHERE version_id=? AND action IN ('accept','edit')",
                                   (latest["id"],)))
        need(decs, 400, "Accept or edit at least one suggestion first")
        edits = [(findings[x["finding_id"]]["start"], findings[x["finding_id"]]["end"], x["final_text"])
                 for x in decs if x["finding_id"] in findings]
        content, sk = review.apply_edits(latest["content"], edits)
        skipped = len(sk)
        note = f"Applied {len(edits) - skipped} accepted or edited suggestion(s)"
    vid, n, findings, meta, carried = new_version(con, d["id"], content, user["id"], note, d["purpose"],
                                                   carry_from=latest["id"])
    con.execute("UPDATE drafts SET status='draft', updated_at=? WHERE id=?", (time.time(), d["id"]))
    db.audit(con, user["id"], "draft.revise", f"#{d['id']} -> v{n}: {note}")
    out = draft_state(con, d["id"], user)
    out["revise_info"] = {"skipped_overlaps": skipped, "carried_dismissals": carried}
    return out


def h_comment(con, user, body, m):
    v = con.execute("SELECT * FROM versions WHERE id=?", (int(m.group(1)),)).fetchone()
    need(v, 404, "Version not found")
    d = get_draft(con, v["draft_id"], user)
    text = (body.get("text") or "").strip()
    need(text, 400, "Write a comment first")
    con.execute("INSERT INTO comments(version_id,user_id,text,anchor,ts) VALUES(?,?,?,?,?)",
                (v["id"], user["id"], text, body.get("anchor", ""), time.time()))
    db.audit(con, user["id"], "comment", f"draft #{d['id']} v{v['n']}")
    return draft_state(con, d["id"], user)


def h_submit(con, user, body, m):
    d = get_draft(con, int(m.group(1)), user)
    need(d["owner_id"] == user["id"], 403, "Only the creator can submit this draft")
    need(d["status"] in ("draft", "changes_requested"), 409, "This draft is already in approval")
    st = draft_state(con, d["id"], user)
    need(st["draft"]["pending_apply"] == 0, 409,
         "You have accepted suggestions that are not applied yet. Use 'Apply accepted fixes' first.")
    con.execute("UPDATE drafts SET status='pending_approval', updated_at=? WHERE id=?", (time.time(), d["id"]))
    db.audit(con, user["id"], "draft.submit", f"#{d['id']} v{st['latest']['n']}")
    return draft_state(con, d["id"], user)


def h_approve(con, user, body, m):
    need(user["role"] in ("manager", "reviewer"), 403, "Only managers and authorised reviewers can approve")
    d = get_draft(con, int(m.group(1)), user)
    need(d["status"] == "pending_approval", 409, "This draft is not waiting for approval")
    outcome = body.get("outcome")
    need(outcome in ("approve", "changes", "reject"), 400, "outcome must be approve, changes or reject")
    comment = (body.get("comment") or "").strip()
    need(outcome == "approve" or comment, 400, "Please explain why you are requesting changes or rejecting")
    st = draft_state(con, d["id"], user)
    lv = st["latest"]
    stage = "reviewer" if user["role"] == "reviewer" else "manager"
    if outcome == "approve" and stage == "manager":
        need(st["draft"]["unresolved_routed"] == 0, 409,
             f"{st['draft']['unresolved_routed']} flagged claim(s) still have no human decision from the creator.")
        need(not st["draft"]["needs_reviewer"] or st["draft"]["reviewer_signed"], 409,
             "This version has flagged claims that need an authorised reviewer's sign-off first.")
    if outcome == "approve" and stage == "reviewer":
        need(st["draft"]["unresolved_routed"] == 0, 409, "The creator has not yet decided on every flagged claim.")
    con.execute("INSERT INTO approvals(draft_id,version_id,user_id,stage,outcome,comment,ts) VALUES(?,?,?,?,?,?,?)",
                (d["id"], lv["id"], user["id"], stage, outcome, comment, time.time()))
    if outcome == "approve" and stage == "manager":
        new_status = "approved"
    elif outcome == "approve":
        new_status = "pending_approval"
    elif outcome == "changes":
        new_status = "changes_requested"
    else:
        new_status = "rejected"
    con.execute("UPDATE drafts SET status=?, updated_at=? WHERE id=?", (new_status, time.time(), d["id"]))
    db.audit(con, user["id"], f"approval.{stage}.{outcome}", f"draft #{d['id']} v{lv['n']}")
    return draft_state(con, d["id"], user)


def h_export(con, user, body, m):
    d = get_draft(con, int(m.group(1)), user)
    need(d["status"] == "approved", 409, "Only approved drafts can be exported")
    st = draft_state(con, d["id"], user)
    lv = st["latest"]
    lines = [f"# {d['title']}", "", f"Channel: {d['channel']}", f"Purpose: {d['purpose']}", "",
             "## Approved content", "", lv["content"], "", "## Approval record", ""]
    for a in st["draft"]["approvals"]:
        when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(a["ts"]))
        lines.append(f"- {when}: {a['user_name']} ({a['stage']}) -> {a['outcome']}" + (f" - {a['comment']}" if a["comment"] else ""))
    lines += ["", "## Human decisions on AI/rule findings", ""]
    fmap = {f["id"]: f for f in lv["findings"]}
    for x in lv["decisions"]:
        f = fmap.get(x["finding_id"], {})
        lines.append(f"- {f.get('rule', {}).get('code', '?')} '{f.get('original', '')}': {x['action']} by {x['user_name']}"
                     + (f" ({x['reason']})" if x["reason"] else ""))
    lines += ["", f"Review mode: {lv['review_meta'].get('mode')}. {lv['review_meta'].get('ai_note', '')}",
              f"Exported from version {lv['n']}."]
    return {"filename": f"approved-draft-{d['id']}.md", "text": "\n".join(lines)}


def h_audit(con, user, body, m):
    need(user["role"] in ("manager", "admin"), 403, "Managers and admins only")
    return {"audit": db.rows(con.execute(
        "SELECT a.*, u.name AS user_name FROM audit a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 150"))}


def h_disclosure(con, user, body, m):
    log = db.rows(con.execute("SELECT * FROM ai_log ORDER BY id DESC LIMIT 20"))
    return {"ai_enabled": review.ai_enabled(),
            "services": [{"name": "Anthropic Messages API", "used_for": "tone and implied-claim review",
                          "sends": "Only the sentences under review and the retrieved guideline clauses, with emails and phone numbers redacted",
                          "active": review.ai_enabled()}],
            "local_processing": "Document text extraction, term checks, numeric fact checks and the citation validator run on this server.",
            "log": log}


ROUTES = [
    ("POST", r"/api/login", h_login, False),
    ("GET", r"/api/demo-accounts", h_demo_accounts, False),
    ("GET", r"/api/me", h_me, True),
    ("GET", r"/api/kb", h_kb, True),
    ("POST", r"/api/kb/clause", h_kb_clause, True),
    ("POST", r"/api/kb/term", h_kb_term, True),
    ("POST", r"/api/kb/fact", h_kb_fact, True),
    ("POST", r"/api/kb/import", h_kb_import, True),
    ("DELETE", r"/api/kb/(clause|term|fact)/([\w-]+)", h_kb_delete, True),
    ("POST", r"/api/extract", h_extract, True),
    ("GET", r"/api/sample", h_sample, True),
    ("GET", r"/api/drafts", h_drafts_list, True),
    ("POST", r"/api/drafts", h_draft_create, True),
    ("GET", r"/api/drafts/(\d+)", h_draft_get, True),
    ("POST", r"/api/drafts/(\d+)/revise", h_revise, True),
    ("POST", r"/api/drafts/(\d+)/submit", h_submit, True),
    ("POST", r"/api/drafts/(\d+)/approve", h_approve, True),
    ("GET", r"/api/drafts/(\d+)/export", h_export, True),
    ("GET", r"/api/versions/(\d+)", h_version_get, True),
    ("POST", r"/api/versions/(\d+)/decisions", h_decision, True),
    ("POST", r"/api/versions/(\d+)/comments", h_comment, True),
    ("GET", r"/api/audit", h_audit, True),
    ("GET", r"/api/disclosure", h_disclosure, True),
]


class Handler(BaseHTTPRequestHandler):
    server_version = "BrandSentry/0.2"

    def log_message(self, fmt, *args):
        if os.environ.get("BS_VERBOSE"):
            super().log_message(fmt, *args)

    def _send(self, status, payload, ctype="application/json"):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _static(self, path):
        rel = "index.html" if path in ("", "/") else path.lstrip("/").replace("static/", "", 1)
        full = os.path.abspath(os.path.join(STATIC_DIR, rel))
        if not full.startswith(os.path.abspath(STATIC_DIR)) or not os.path.isfile(full):
            return self._send(404, {"error": "Not found"})
        with open(full, "rb") as fh:
            self._send(200, fh.read(), mimetypes.guess_type(full)[0] or "application/octet-stream")

    def _dispatch(self, method):
        path = urlparse(self.path).path.rstrip("/") or "/"
        if not path.startswith("/api/"):
            return self._static(path) if method == "GET" else self._send(405, {"error": "Method not allowed"})
        con = db.connect()
        try:
            for meth, pat, fn, auth in ROUTES:
                mm = re.fullmatch(pat, path)
                if meth == method and mm:
                    user = None
                    if auth:
                        tok = (self.headers.get("Authorization") or "").replace("Bearer ", "")
                        uid = db.read_token(tok)
                        row = con.execute("SELECT id,name,role,username FROM users WHERE id=?", (uid,)).fetchone() if uid else None
                        need(row, 401, "Please sign in")
                        user = dict(row)
                    body = {}
                    if method in ("POST", "PUT"):
                        n = int(self.headers.get("Content-Length") or 0)
                        need(n <= 12_000_000, 413, "Request too large")
                        try:
                            body = json.loads(self.rfile.read(n) or b"{}")
                        except ValueError:
                            raise ApiError(400, "Invalid JSON")
                    res = fn(con, user, body, mm)
                    con.commit()
                    return self._send(200, res)
            raise ApiError(404, "Unknown endpoint")
        except ApiError as e:
            con.rollback()
            self._send(e.status, {"error": e.msg})
        except Exception as e:  # last-resort guard so the demo never shows a stack trace
            con.rollback()
            self._send(500, {"error": f"Something went wrong ({type(e).__name__}). Please try again."})
            if os.environ.get("BS_VERBOSE"):
                raise
        finally:
            con.close()

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")


def main():
    db.init_db()
    port = int(os.environ.get("PORT", "8000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"BrandSentry running on http://0.0.0.0:{port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
