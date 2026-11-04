# Macaroon File Share

Anonymous file sharing with capability-based access control.
Files are encrypted in the browser (AES-256-GCM) and the key never leaves the client.
Access is granted with **macaroons**: HMAC-chained bearer tokens that anyone can narrow (add caveats) but nobody can widen.

> Cryptography course midterm project. Report deadline: **15/11/2026**.

## Team

| Part | Scope | Members |
|---|---|---|
| Leader | Reviews every pull request, final check of each part | Nguyễn Trương Thịnh |
| 1. Build | Macaroon core (pymacaroons), Python backend | Trần Thị Thu Trang, Hoàng Ngân Anh |
| 2. Test + data | Acceptance tests, attack scripts, benchmarks | Đỗ Trần Tuấn Đạt, Trịnh Phương Nam |
| 3. Integrate + demo | Specs, frontend, diagrams, integration, demo, report | Lã Thị Bảo Trâm, Nguyễn Hải Phong |

## Repository layout

```
backend/    Macaroon core + HTTP API (Python)            Part 1
frontend/   HTML + JS, WebCrypto encryption              Part 3
tests/      Acceptance tests + benchmarks                Part 2
docs/
  spec/       design-spec.md, api-spec.md               Part 3
  diagrams/   StarUML source (.mdj) + exported PNGs     Part 3
  report/     report outline and drafts                 Part 3
```

## How we work

Read [CONTRIBUTING.md](CONTRIBUTING.md) before your first commit. Short version:

1. Never push to `main`. Create a branch: `p1/backend-share-endpoint`, `p2/attack-tests`, `p3/frontend-upload`.
2. Open a pull request. Thịnh must approve before it is merged.
3. Never commit secrets: root keys, `.env`, uploaded files.

## Running locally

_Filled in by Part 1 once the backend runs._

```bash
# backend
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# start command: TBD

# tests
pytest tests/
```

## Key dates

| Date | Milestone |
|---|---|
| 5/11 | Repo + skeleton; design spec |
| 6/11 | API spec reviewed by Part 1 |
| 8/11 | Macaroon core with unit tests |
| 10/11 | Backend API complete (leader check, Part 1) |
| 12/11 | Tests, benchmarks, charts (leader check, Part 2) |
| 13/11 | Demo + report draft |
| 14/11 | Final version (leader check, Part 3) |
| 15/11 | Submit |
