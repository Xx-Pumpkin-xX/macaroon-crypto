# API spec

Owner: Part 3. Reviewed by Part 1. Due 6/11.
Status: **draft v1**. Change it only through a pull request that also updates the backend and frontend.

## 1. Overview

- The backend serves `frontend/` as static files at `/` and the API under `/api`. Same origin, so no CORS.
- All API responses are JSON, except file downloads (`application/octet-stream`).
- The server never sees the file key K, the filename or the file content. It stores one encrypted blob per file.
- Permissions, from weakest to strongest: `read` < `edit` < `full`.

| Method | Path | Permission needed | Purpose |
|---|---|---|---|
| POST | `/api/files` | none | Upload a new file, get a `full` token |
| GET | `/api/files/{file_id}` | `read` | Download the encrypted blob |
| PUT | `/api/files/{file_id}` | `edit` | Replace the encrypted blob |
| POST | `/api/share` | any valid token | Get a narrower token for someone else |
| POST | `/api/revoke` | `full` | Revoke one share (and everything derived from it) |
| DELETE | `/api/files/{file_id}` | `full` | Delete the file and its root key |

## 2. Formats

| Item | Format |
|---|---|
| `file_id` | 16 random bytes, base64url, no padding (22 chars) |
| `share_id` | 8 random bytes, lowercase hex (16 chars) |
| Root key | 32 bytes from `secrets.token_bytes(32)`, one per file, server only |
| File key K | 32 random bytes from `crypto.getRandomValues`, base64url (43 chars), client only |
| Token | pymacaroons `Macaroon.serialize()` (URL-safe base64), at most 4096 chars |
| Timestamps | Unix time in seconds (UTC), integer |

### 2.1 Encrypted blob (built by the browser)

```
plaintext = UTF-8 JSON: {"name": "notes.txt", "text": "file content ..."}
nonce     = 12 random bytes (new nonce on every upload and every edit)
blob      = nonce || AES-256-GCM(K, nonce, plaintext)    # ciphertext includes the 16-byte tag
```

- Maximum blob size: **1 MiB** (1,048,576 bytes).
- Only text files are accepted: the frontend reads the file as text and refuses anything else.

### 2.2 Share link (built by the browser, never sent to the server)

```
https://<host>/view.html#f=<file_id>&t=<token>&k=<K>
```

All three values are in the fragment (after `#`), so the browser does not send them in requests or in the `Referer` header.

## 3. Token (macaroon)

- `location` = `"macaroon-crypto"`
- `identifier` = `file_id`. The server uses it to find the root key.
- First-party caveats only. Every caveat must match exactly one of these forms (exactly one space around the operator):

| Caveat | Regex | Meaning | When several appear |
|---|---|---|---|
| `op = <level>` | `^op = (read\|edit\|full)$` | Highest allowed permission | The **lowest** one wins |
| `expires < <ts>` | `^expires < [0-9]{1,12}$` | Valid while now < ts | The **earliest** one wins |
| `share_id = <id>` | `^share_id = [0-9a-f]{16}$` | Revocation tag | Rejected if **any** of them is revoked |

- A token minted at upload has exactly one caveat: `op = full`. It has no expiry.
- Any other caveat text means the token is rejected (fail-closed).
- At most 20 caveats per token.

### 3.1 Verification order (every endpoint that takes a token)

1. Read `Authorization: Bearer <token>`. Missing → `401 missing_token`.
2. Deserialize. Fails, or longer than 4096 chars, or more than 20 caveats → `401 invalid_token`.
3. If the path has a `{file_id}`, it must equal the token identifier → otherwise `401 invalid_token`.
4. Look up the root key by identifier. None → `404 not_found`.
5. Verify the HMAC chain with pymacaroons. In this pass, accept any caveat that matches one of the 3 regexes (a `satisfy_general` callback that checks syntax only). Signature mismatch or unknown caveat → `401 invalid_token`.
6. Evaluate the caveats:
   - Effective `op` = the lowest `op`.
   - Earliest `expires` is in the past → `403 expired`.
   - Any `share_id` is in this file's revoked set → `403 revoked`.
7. Effective `op` is below what the endpoint needs → `403 forbidden`.

Steps 5 and 6 are separate on purpose. pymacaroons reports every failed caveat the same way, so checking syntax in step 5 and meaning in step 6 is what lets us answer 401 for "not authentic" and 403 for "authentic but not allowed".

## 4. Endpoints

### 4.1 `POST /api/files`: upload

Request

```
Content-Type: application/octet-stream
Body: blob (section 2.1)
```

Response `201`

```json
{ "file_id": "q3J8xY2mN0aPz7Lk1VbC4w", "token": "<full token>" }
```

Errors: `400 bad_request` (empty body), `413 too_large`.

Server: generate `file_id` and root key, store the blob, mint the token with caveat `op = full`.

### 4.2 `GET /api/files/{file_id}`: download

Request: `Authorization: Bearer <token>` (needs `read`).

Response `200`

```
Content-Type: application/octet-stream
Cache-Control: no-store
X-Permission: read | edit | full
Body: blob
```

`X-Permission` is the effective `op`, so the frontend knows whether to show the Edit / Revoke / Delete buttons.

Errors: section 3.1.

### 4.3 `PUT /api/files/{file_id}`: edit

Request

```
Authorization: Bearer <token>        (needs edit)
Content-Type: application/octet-stream
Body: new blob, encrypted with the same K and a new nonce
```

Response `204` (no body). Last write wins; there is no version check.

Errors: section 3.1, `400 bad_request`, `413 too_large`.

### 4.4 `POST /api/share`: create a narrower token

Request

```
Authorization: Bearer <token to narrow>
Content-Type: application/json
```

```json
{ "op": "read", "expires_in": 86400 }
```

- `op`: `read`, `edit` or `full`. Must not be higher than the caller's effective `op`, otherwise `400 bad_request`.
- `expires_in`: seconds, 60 to 2,592,000 (30 days).

Response `200`

```json
{
  "token": "<new token>",
  "share_id": "9f2c41d07ab35e18",
  "op": "read",
  "expires_at": 1763164800
}
```

Server: verify the token (section 3.1), then add 3 caveats: `op = <op>`, `expires < <now + expires_in>`, `share_id = <new random id>`. Record the `share_id` as issued for this file. Adding caveats does not need the root key.

Errors: section 3.1, `400 bad_request`.

### 4.5 `POST /api/revoke`: revoke a share

Request

```
Authorization: Bearer <token>        (needs full)
Content-Type: application/json
```

```json
{ "share_id": "9f2c41d07ab35e18" }
```

Response `204`. Every token that carries this `share_id`, including tokens later derived from it, now fails with `403 revoked`.

Errors: section 3.1, `400 bad_request`, `404 not_found` (share_id was never issued for this file).

### 4.6 `DELETE /api/files/{file_id}`: delete

Request: `Authorization: Bearer <token>` (needs `full`).

Response `204`. The server deletes the blob, the root key, and the issued and revoked share lists. Every token for this file then gets `404 not_found`.

Errors: section 3.1.

## 5. Errors

Every error response has this body:

```json
{ "error": "revoked", "message": "This share has been revoked." }
```

| Status | `error` | When |
|---|---|---|
| 400 | `bad_request` | Malformed JSON, invalid `op`, `expires_in` out of range, empty body |
| 401 | `missing_token` | No `Authorization` header |
| 401 | `invalid_token` | Cannot deserialize, too long, too many caveats, wrong file, bad signature, unknown caveat |
| 403 | `expired` | Earliest `expires` is in the past |
| 403 | `revoked` | A `share_id` in the token is revoked |
| 403 | `forbidden` | Effective `op` too low for this endpoint |
| 404 | `not_found` | Unknown or deleted `file_id`, or unknown `share_id` on revoke |
| 413 | `too_large` | Blob over 1 MiB |

The `expired` / `revoked` distinction helps the demo and the tests. A production system might return one generic 403.

## 6. Server-side rules

- Never log tokens, keys or blobs. Log only the method, path, status and `error` code.
- State per file: blob, root key, issued `share_id`s, revoked `share_id`s. All of it lives in `storage/` (git-ignored).
- Send `Referrer-Policy: no-referrer` and `Cache-Control: no-store` on every response.

## 7. Example flow

```
A: POST /api/files (blob)                         → 201 {file_id, token_A (op = full)}
A: POST /api/share  (token_A) {op: read, 1 day}   → 200 {token_B, share_id: s1}
A sends B:  view.html#f=<file_id>&t=<token_B>&k=<K>
B: GET  /api/files/<file_id>  (token_B)           → 200 blob, X-Permission: read
B: PUT  /api/files/<file_id>  (token_B)           → 403 forbidden
B: POST /api/share  (token_B) {op: read, 1 hour}  → 200 {token_C, share_id: s2}   (carries s1 and s2)
A: POST /api/revoke (token_A) {share_id: s1}      → 204
B or C: GET /api/files/<file_id>                  → 403 revoked
A: DELETE /api/files/<file_id> (token_A)          → 204
anyone: GET /api/files/<file_id>                  → 404 not_found
```
