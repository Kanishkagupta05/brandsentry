"""SQLite storage, schema and demo seed data for BrandSentry."""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "..", "data", "brandsentry.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE, name TEXT, role TEXT, salt TEXT, pw_hash TEXT);
CREATE TABLE IF NOT EXISTS clauses(
  id INTEGER PRIMARY KEY, code TEXT UNIQUE, title TEXT, text TEXT, version INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS terms(
  id INTEGER PRIMARY KEY, code TEXT UNIQUE, banned TEXT, preferred TEXT, rule_text TEXT,
  case_sensitive INTEGER DEFAULT 0, version INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS facts(
  id INTEGER PRIMARY KEY, code TEXT UNIQUE, claim TEXT, value TEXT, source TEXT,
  keywords TEXT, valid_until TEXT, version INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS drafts(
  id INTEGER PRIMARY KEY, title TEXT, channel TEXT, purpose TEXT, owner_id INTEGER,
  status TEXT DEFAULT 'draft', created_at REAL, updated_at REAL);
CREATE TABLE IF NOT EXISTS versions(
  id INTEGER PRIMARY KEY, draft_id INTEGER, n INTEGER, content TEXT, findings TEXT,
  review_meta TEXT, author_id INTEGER, created_at REAL, note TEXT);
CREATE TABLE IF NOT EXISTS decisions(
  id INTEGER PRIMARY KEY, version_id INTEGER, finding_id TEXT, finding_key TEXT, action TEXT,
  reason TEXT, final_text TEXT, user_id INTEGER, ts REAL,
  UNIQUE(version_id, finding_id));
CREATE TABLE IF NOT EXISTS comments(
  id INTEGER PRIMARY KEY, version_id INTEGER, user_id INTEGER, text TEXT, anchor TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS approvals(
  id INTEGER PRIMARY KEY, draft_id INTEGER, version_id INTEGER, user_id INTEGER,
  stage TEXT, outcome TEXT, comment TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts REAL, user_id INTEGER, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS ai_log(
  id INTEGER PRIMARY KEY, ts REAL, service TEXT, purpose TEXT, chars_sent INTEGER, ok INTEGER, note TEXT);
"""


def connect():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def hash_pw(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()


def make_user(con, username, name, role, password):
    salt = secrets.token_hex(8)
    con.execute("INSERT OR IGNORE INTO users(username,name,role,salt,pw_hash) VALUES(?,?,?,?,?)",
                (username, name, role, salt, hash_pw(password, salt)))


def audit(con, user_id, action, detail=""):
    con.execute("INSERT INTO audit(ts,user_id,action,detail) VALUES(?,?,?,?)",
                (time.time(), user_id, action, detail))


def rows(cur):
    return [dict(r) for r in cur.fetchall()]


DEMO_PASSWORD = "demo1234"

SEED_CLAUSES = [
    ("G-1", "Voice and tone",
     "Write in a warm, plain and confident voice. Avoid hype words, jargon and exclamation marks."),
    ("G-2", "Claims",
     "Do not use unsupported superlatives or absolute claims such as 'best', 'guaranteed', '#1' or '100%' "
     "unless an approved fact supports them."),
    ("G-3", "Evidence",
     "Every number, statistic or comparison must match the approved facts registry or carry a named source."),
    ("G-4", "Terminology",
     "Use the approved terminology list in every channel, and spell the brand name Brightleaf."),
    ("G-5", "Plain language",
     "Keep sentences under 25 words where possible so readers can follow them easily."),
    ("G-6", "Accessibility",
     "Every image needs alt text, and text on images must meet WCAG AA contrast of 4.5:1."),
]

SEED_TERMS = [
    ("T-1", "users", "customers", "Always say 'customers' instead of 'users'.", 0),
    ("T-2", "cheap", "affordable", "Say 'affordable' instead of 'cheap'; we never describe our tea as cheap.", 0),
    ("T-3", "tea bags", "tea sachets", "Always say 'tea sachets' instead of 'tea bags'.", 0),
    ("T-4", "BrightLeaf", "Brightleaf", "Spell the brand name as Brightleaf, with a lowercase l.", 1),
    ("T-5", "Bright Leaf", "Brightleaf", "Spell the brand name as Brightleaf, as one word.", 1),
]

SEED_FACTS = [
    ("F-1", "Brightleaf sources its tea from 42 partner farms.", "42", "Sourcing report FY26",
     "partner farms,farms,sources its tea", "2027-06-30"),
    ("F-2", "Brightleaf packaging is 100% recyclable.", "100%", "Packaging audit Sep 2026",
     "recyclable,packaging", "2027-03-31"),
    ("F-3", "Free delivery on orders over 499 rupees.", "499", "Shipping policy v4",
     "free delivery,delivery", "2026-12-31"),
    ("F-4", "Brightleaf runs 18 cafes across India.", "18", "Retail overview H1 2026",
     "cafes,stores,outlets", "2026-06-30"),
]

SAMPLE_DRAFT = {
    "title": "Spring launch Instagram caption",
    "channel": "Instagram caption",
    "purpose": "Announce the spring tea range and free delivery to customers.",
    "content": (
        "Our new spring range is the BEST tea you will ever taste!! "
        "Brightleaf sources its tea from 60 partner farms, and every blend is guaranteed to delight our users. "
        "Grab your tea bags today because delivery is free on orders over 299 rupees. "
        "We are the #1 choice of tea lovers in India, and our packaging is 100% recyclable."
    ),
}


def init_db():
    con = connect()
    con.executescript(SCHEMA)
    if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        make_user(con, "admin", "Alex Admin", "admin", DEMO_PASSWORD)
        make_user(con, "manager", "Maya Manager", "manager", DEMO_PASSWORD)
        make_user(con, "reviewer", "Rohan Reviewer", "reviewer", DEMO_PASSWORD)
        make_user(con, "creator", "Chitra Creator", "creator", DEMO_PASSWORD)
        for code, title, text in SEED_CLAUSES:
            con.execute("INSERT INTO clauses(code,title,text) VALUES(?,?,?)", (code, title, text))
        for code, banned, pref, rule, cs in SEED_TERMS:
            con.execute("INSERT INTO terms(code,banned,preferred,rule_text,case_sensitive) VALUES(?,?,?,?,?)",
                        (code, banned, pref, rule, cs))
        for code, claim, value, source, kw, until in SEED_FACTS:
            con.execute("INSERT INTO facts(code,claim,value,source,keywords,valid_until) VALUES(?,?,?,?,?,?)",
                        (code, claim, value, source, kw, until))
        audit(con, None, "seed", "Demo brand 'Brightleaf Tea Co.' and demo accounts created")
    con.commit()
    con.close()


# ---- signed session tokens (HMAC, no external deps) ----
_SECRET = os.environ.get("SECRET_KEY") or secrets.token_hex(32)


def make_token(user_id, ttl=60 * 60 * 12):
    payload = f"{user_id}:{int(time.time()) + ttl}"
    sig = hmac.new(_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def read_token(token):
    try:
        uid, exp, sig = token.split(":")
        good = hmac.new(_SECRET.encode(), f"{uid}:{exp}".encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, good) and int(exp) > time.time():
            return int(uid)
    except Exception:
        pass
    return None
