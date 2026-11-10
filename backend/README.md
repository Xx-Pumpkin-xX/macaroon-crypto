# Backend (Part 1: Trang, Anh)

Python HTTP API + macaroon core. Must follow `docs/spec/api-spec.md` exactly.

## Layout

- `macaroon_core/`: wrapper over pymacaroons (mint, add caveat, verify), the
  caveat grammar, file storage, and the service functions behind all six
  operations.
- `app.py`: Flask HTTP layer for the first three endpoints:
  - `POST /api/files` — upload, returns a `full` token
  - `GET /api/files/{file_id}` — download, returns `X-Permission`
  - `PUT /api/files/{file_id}` — replace the blob (needs `edit`)
- `storage/` (git-ignored): ciphertext, root key per file, issued/revoked
  share ids.
- `tests/`: core unit tests and HTTP tests for the three endpoints.

Share, revoke and delete are implemented in `macaroon_core`; their HTTP routes
are a later change.

## Running

From the repository root:

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
python -m pip install ./pymacaroons
flask --app app run --host 127.0.0.1 --port 8000
```

`python app.py` also starts the development server. Run it single-process
(threaded) for the demo: the share/revoke lock is in-process only (known issue
F01 in `tests/PENTEST_FINDINGS.md`), so multiple workers can lose revocations.

## Tests

```bash
# from the repository root
backend/.venv/bin/python -m pytest backend/tests -q
backend/.venv/bin/python -m pytest tests backend/tests -q
```

F02 and F03 are fixed in the core. Until Part 2 removes their five strict
`xfail` markers in `tests/test_pentest.py` (four for F02, one for F03), the
full suite reports those as `XPASS(strict)` failures. The remaining F01 marker
is expected to stay xfailed.

## API rules

- Permissions: Read (GET), Edit (GET + PUT new ciphertext), Full Control (all,
  plus revoke and delete).
- Blobs are at most 1 MiB; empty bodies and oversized bodies are rejected.
- Root keys: 32 bytes from `secrets.token_bytes(32)`, never logged, never
  returned to the client.
- Unknown caveat = reject (fail-closed).
- Invalid UTF-8 token identifiers are rejected by the core as `invalid_token`.
- Never log tokens, root keys or blobs. The app logs only method, path, status
  and error code.
- Every response gets `Referrer-Policy: no-referrer` and
  `Cache-Control: no-store`.

## Known limits

- If `shares.json` is missing or malformed for an existing file, authorization
  fails closed with `500 internal_error`. Restore the state from a consistent
  backup; it is never recreated as empty automatically.
- A stale but valid `shares.json` restored from an old backup can still
  resurrect a revocation. Back up and restore the blob, root key and share
  state as one unit. We are not doing any backup, don't concern yourself
  too much with this.
- `Content-Type` is not enforced on upload/edit; the raw body bytes are stored.
- An oversized `PUT` may be rejected with `413` before token verification.
