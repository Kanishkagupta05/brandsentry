# BrandSentry (Round 2 prototype)

Evidence-grounded, pre-publication brand review. Team SoloStack, Inkloom AI problem statement.

## Run locally

```bash
pip install -r requirements.txt
python -m app.server          # http://localhost:8000
python -m unittest discover -s tests
```

Demo accounts (password `demo1234`): `creator`, `manager`, `reviewer`, `admin`. The login page has one-click buttons.

## Deploy (Render, free tier)

1. Push this folder to a GitHub repo.
2. In Render choose New > Blueprint (it reads `render.yaml`) or New > Web Service with
   build `pip install -r requirements.txt` and start `python -m app.server`.
3. Optional: set `ANTHROPIC_API_KEY` to turn on the AI tone / implied-claim pass.
   Without it the product runs in rules-only mode, and says so in the UI.

Note: free-tier disks are ephemeral, so the SQLite database and demo data reset on redeploy
(the demo brand re-seeds itself on every start).

## Environment variables

| Variable | Purpose |
|---|---|
| `PORT` | HTTP port (default 8000) |
| `DB_PATH` | SQLite file location |
| `SECRET_KEY` | Signs session tokens (set a fixed value so sessions survive restarts) |
| `ANTHROPIC_API_KEY` | Optional. Enables the AI review pass |
| `BRANDSENTRY_MODEL` | Optional. Model for the AI pass (default `claude-sonnet-5-5`) |

## How a finding is produced

1. Segment text into sentences.
2. Deterministic checks: banned/preferred terms, absolute claims, numbers against the approved-facts registry (with expiry), tone, readability.
3. Optional AI pass, given only retrieved clauses and facts, asked for tone and implied-claim issues the rules missed.
4. **Citation validator**: a finding is kept only if its source ID exists and its quote is literally inside that source. Others are dropped and counted.
5. Suggested fixes are re-checked so a fix cannot add a new high-severity issue.
6. Humans accept, edit or dismiss (dismissals need a reason). Claims with no approved source are marked "Needs a source", never guessed.

## Layout

- `app/review.py` pipeline and validator
- `app/server.py` HTTP API, roles, versions, approvals, audit, export
- `app/db.py` schema, demo brand, seed accounts
- `app/extract.py` DOCX / PDF / TXT text extraction
- `static/index.html` the whole UI
- `tests/test_flow.py` end-to-end tests
