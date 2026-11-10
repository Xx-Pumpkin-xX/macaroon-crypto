# Design spec

Owner: Part 3. Reviewed by Part 1 and Part 2.
Exact formats, regexes, endpoints and error codes are in [api-spec.md](api-spec.md). This file explains what the system promises and why.

## 1. Goals and non-goals

Goals:

- Share text files without accounts.
- The server never sees file content or filenames.
- Anyone holding a link can create a weaker link without asking the server for a new key.
- The owner can revoke a share, or delete the file to cut off every link.

Non-goals: network-level anonymity, abuse prevention, protection against a malicious server (section 5.3).

## 2. Permissions

| Action | Read | Edit | Full Control |
|---|:---:|:---:|:---:|
| Download (`GET /api/files/{id}`) | ✓ | ✓ | ✓ |
| Replace content (`PUT /api/files/{id}`) |  | ✓ | ✓ |
| Create a share, up to its own level (`POST /api/share`) | ✓ | ✓ | ✓ |
| Revoke a share (`POST /api/revoke`) |  |  | ✓ |
| Delete the file (`DELETE /api/files/{id}`) |  |  | ✓ |

Rules:

1. A share can never be higher than the token it is made from.
2. If a token carries several `op` caveats, the lowest one counts. Adding `op = full` to a Read token leaves it at Read.
3. Only text files are supported. Edit means replacing the whole content with a new blob encrypted under the same key K.

Give Full Control only to someone you would trust to delete the file: they can also revoke other shares.

## 3. Caveat grammar and limits

See API spec sections 2 and 3: three caveat forms (`op`, `expires`, `share_id`), at most 20 caveats, at most 4096 token characters, blobs up to 1 MiB, share lifetime 60 seconds to 30 days.

Any caveat that does not match one of the three forms is rejected (fail-closed). A verifier that skipped a caveat it did not understand would silently drop a restriction someone deliberately added.

## 4. Revocation

- Every share gets a fresh random `share_id` caveat. Tokens derived from a share keep that caveat, so revoking one `share_id` cuts off the whole branch below it.
- Revocation is per file and only accepts a `share_id` that was issued for that file.
- Deleting a file deletes its root key. Every token for that file then fails, because there is no key left to verify it.

Limits, stated openly:

- Revocation cannot take back content that was already downloaded: the recipient already has K and the plaintext.
- The owner's upload token has no `share_id`, so it cannot be revoked. If the owner link leaks, the only remedy is deleting the file.

## 5. Threat model

### 5.1 Assets and trust

Assets: file content, filename, file key K, root keys, tokens.

The server is trusted to enforce access control (it holds the root keys and runs the checks). It is not trusted with content: it only ever stores ciphertext.

### 5.2 Attackers

| Attacker | Has | Tries to | What stops them | Tests (tests/README.md) |
|---|---|---|---|---|
| Outsider | Nothing | Guess a `file_id`, forge a token | `file_id` is 128 random bits; a valid signature needs the root key (HMAC-SHA256) | 2, 3, 12 |
| Recipient | A Read or Edit link | Remove or edit a caveat, reorder caveats, add `op = full`, use an unknown caveat | HMAC chain is one-way; lowest `op` wins; unknown caveats rejected | 4, 5, 6, 7, 10, 13 |
| Holder of an old link | An expired or revoked token | Keep using it | `expires` caveat; revoked `share_id` list | 8, 9 |
| Network observer | Traffic between browser and server | Read K or the file | K stays after `#` and is never sent; content is encrypted. Needs HTTPS; the demo runs on localhost | Manual: browser Network tab |
| Curious server or storage leak | Blobs, logs, disk | Read files or filenames | AES-256-GCM with K that never reaches the server. Still visible: blob size, time, IP | Manual: inspect `storage/` and logs |

### 5.3 Out of scope

- **Malicious server.** It holds the root keys, so it can mint any token. It also serves the frontend JavaScript, so it could ship code that reads K from the URL. Every in-browser end-to-end encryption design has this limit.
- **Rollback.** The server could serve an older blob. AES-GCM detects modified data, not an old but genuine version.
- Malware on the user's device, denial of service, abuse of the service.
