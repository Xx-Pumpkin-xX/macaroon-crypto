# Backend (Part 1: Trang, Anh)

Python HTTP API + macaroon core. Must follow `docs/spec/api-spec.md` exactly.

Planned modules (names can change):

- `macaroon_core.py`: wrapper over pymacaroons (mint, add caveat, verify) using the caveat grammar in the design spec
- `app.py`: endpoints `POST /files`, `POST /share`, `GET /files/{id}`, `POST /revoke`, `DELETE /files/{id}`
- `storage/` (git-ignored): ciphertext, root key per file, revoked share_ids

Rules from the design:

- Root keys: 32 bytes from `secrets.token_bytes(32)`, never logged, never returned to the client
- Unknown caveat = reject (fail-closed)
- Never log tokens
