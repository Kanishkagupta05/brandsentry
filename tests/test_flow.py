"""End-to-end tests: start the real server on a free port and walk the whole product journey."""
import base64
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ.pop("ANTHROPIC_API_KEY", None)

from http.server import ThreadingHTTPServer  # noqa: E402

from app import db, review, server  # noqa: E402


class Client:
    def __init__(self, base):
        self.base, self.token = base, None

    def call(self, method, path, body=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {self.token}" if self.token else "",
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def login(self, user):
        s, r = self.call("POST", "/api/login", {"username": user, "password": db.DEMO_PASSWORD})
        assert s == 200, r
        self.token = r["token"]
        return self


class Flow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def c(self, user):
        return Client(self.base).login(user)

    def test_01_auth(self):
        self.assertEqual(Client(self.base).call("GET", "/api/kb")[0], 401)
        s, _ = Client(self.base).call("POST", "/api/login", {"username": "creator", "password": "nope"})
        self.assertEqual(s, 401)

    def test_02_full_journey(self):
        cr, mg, rv = self.c("creator"), self.c("manager"), self.c("reviewer")
        s, sample = cr.call("GET", "/api/sample")
        s, st = cr.call("POST", "/api/drafts", sample)
        self.assertEqual(s, 200, st)
        did, v1 = st["draft"]["id"], st["latest"]
        cats = {f["category"] for f in v1["findings"]}
        self.assertTrue({"terminology", "factual accuracy", "unsupported claim", "tone"} <= cats, cats)
        for f in v1["findings"]:  # every finding is grounded
            self.assertTrue(f["rule"]["code"] and f["rule"]["quote"])

        # supported 100% claim must NOT be flagged
        self.assertFalse(any(f["original"].strip() == "100%" for f in v1["findings"]))

        # dismissal needs a reason
        fid = v1["findings"][0]["id"]
        s, r = cr.call("POST", f"/api/versions/{v1['id']}/decisions", {"finding_id": fid, "action": "dismiss"})
        self.assertEqual(s, 400)

        # cannot submit with unapplied accepted fixes; accept all fixable, dismiss the rest
        for f in v1["findings"]:
            if f["replacement"] is not None:
                s, r = cr.call("POST", f"/api/versions/{v1['id']}/decisions", {"finding_id": f["id"], "action": "accept"})
            else:
                s, r = cr.call("POST", f"/api/versions/{v1['id']}/decisions",
                               {"finding_id": f["id"], "action": "dismiss", "reason": "Intentional wording"})
            self.assertEqual(s, 200, r)
        s, r = cr.call("POST", f"/api/drafts/{did}/submit")
        self.assertEqual(s, 409)

        s, st2 = cr.call("POST", f"/api/drafts/{did}/revise", {})
        self.assertEqual(s, 200, st2)
        v2 = st2["latest"]
        self.assertEqual(v2["n"], 2)
        self.assertLess(len(v2["findings"]), len(v1["findings"]))
        self.assertIn("42 partner farms", v2["content"])
        self.assertIn("499 rupees", v2["content"])
        self.assertNotIn("users", v2["content"])

        # remaining routed findings need a decision; approval must be blocked until then
        s, r = cr.call("POST", f"/api/drafts/{did}/submit")
        self.assertEqual(s, 200, r)
        s, r = mg.call("POST", f"/api/drafts/{did}/approve", {"outcome": "approve"})
        if st2["draft"]["unresolved_routed"]:
            self.assertEqual(s, 409)
            s, r = mg.call("POST", f"/api/drafts/{did}/approve", {"outcome": "changes", "comment": "Decide on flagged claims"})
            self.assertEqual(s, 200)
            for f in v2["findings"]:
                if f["route_to_reviewer"]:
                    cr.call("POST", f"/api/versions/{v2['id']}/decisions",
                            {"finding_id": f["id"], "action": "dismiss", "reason": "Checked with the founder"})
            s, r = cr.call("POST", f"/api/drafts/{did}/submit")
            self.assertEqual(s, 200, r)
            s, r = mg.call("POST", f"/api/drafts/{did}/approve", {"outcome": "approve"})
        # reviewer sign-off gate
        if s == 409 and "reviewer" in r["error"]:
            s, r = rv.call("POST", f"/api/drafts/{did}/approve", {"outcome": "approve"})
            self.assertEqual(s, 200, r)
            s, r = mg.call("POST", f"/api/drafts/{did}/approve", {"outcome": "approve"})
        self.assertEqual(s, 200, r)
        self.assertEqual(r["draft"]["status"], "approved")

        s, ex = mg.call("GET", f"/api/drafts/{did}/export")
        self.assertEqual(s, 200)
        self.assertIn("Approval record", ex["text"])
        s, au = mg.call("GET", "/api/audit")
        self.assertTrue(any(a["action"].startswith("approval.manager") for a in au["audit"]))

    def test_03_roles(self):
        cr = self.c("creator")
        self.assertEqual(cr.call("POST", "/api/kb/term", {"code": "T-9", "banned": "x", "preferred": "y"})[0], 403)
        self.assertEqual(cr.call("GET", "/api/audit")[0], 403)
        ad = self.c("admin")
        self.assertEqual(ad.call("POST", "/api/kb/term", {"code": "T-9", "banned": "synergy", "preferred": "teamwork"})[0], 200)
        s, r = cr.call("POST", "/api/drafts", {"title": "t", "channel": "x", "purpose": "p", "content": "Great synergy here."})
        self.assertEqual(s, 200)
        self.assertTrue(any(f["rule"]["code"] == "T-9" for f in r["latest"]["findings"]))
        # creator cannot see another creator's draft; reviewer can
        other = Client(self.base)
        with db.connect() as con:
            db.make_user(con, "creator2", "Second Creator", "creator", db.DEMO_PASSWORD)
        other.login("creator2")
        self.assertEqual(other.call("GET", f"/api/drafts/{r['draft']['id']}")[0], 403)
        self.assertEqual(self.c("reviewer").call("GET", f"/api/drafts/{r['draft']['id']}")[0], 200)

    def test_04_validator_drops_invented_findings(self):
        with db.connect() as con:
            kb = server.load_kb(con)
        src = kb.sources()
        good = review.mk(0, 4, "text", "G-2", "clause", "Do not use unsupported superlatives", "x", "low", .5, "e")
        fake_quote = review.mk(0, 4, "text", "G-2", "clause", "Never mention competitors", "x", "low", .5, "e")
        fake_id = review.mk(0, 4, "text", "G-99", "clause", "anything", "x", "low", .5, "e")
        bad_span = review.mk(0, 5, "nope", "G-2", "clause", "Do not use unsupported superlatives", "x", "low", .5, "e")
        t = "text here"
        self.assertTrue(review.validate(good, src, t))
        self.assertFalse(review.validate(fake_quote, src, t))
        self.assertFalse(review.validate(fake_id, src, t))
        self.assertFalse(review.validate(bad_span, src, t))

    def test_05_needs_source_and_expired(self):
        with db.connect() as con:
            kb = server.load_kb(con)
        f, _ = review.run_review("We blend 31 tea varieties. Our founder started in 2014.", "p", kb)
        self.assertTrue(any(x["claim_status"] == "needs_source" for x in f))
        f, _ = review.run_review("Brightleaf runs 18 cafes across India.", "p", kb)
        self.assertTrue(any(x["claim_status"] == "expired" for x in f))
        f, _ = review.run_review("We source tea from 42 partner farms.", "p", kb)
        self.assertEqual(f, [])

    def test_06_document_upload(self):
        import docx
        d = docx.Document()
        d.add_paragraph("Our users love the cheap tea.")
        buf = io.BytesIO()
        d.save(buf)
        cr = self.c("creator")
        s, r = cr.call("POST", "/api/extract", {"filename": "x.docx", "data": base64.b64encode(buf.getvalue()).decode()})
        self.assertEqual(s, 200)
        self.assertIn("cheap tea", r["text"])
        self.assertEqual(cr.call("POST", "/api/extract", {"filename": "x.exe", "data": "AA=="})[0], 400)

    def test_07_apply_edits_overlap(self):
        new, skipped = review.apply_edits("abcdef", [(0, 3, "X"), (2, 4, "Y"), (4, 6, "Z")])
        self.assertEqual(new, "XdZ")  # (2,4) overlaps (0,3) and is skipped; (4,6) applies
        self.assertEqual(len(skipped), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
