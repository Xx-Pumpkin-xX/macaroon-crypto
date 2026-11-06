# Macaroon core: interface for share / revoke / delete

Part 1 owns the first three endpoints and the shared primitives below.
The last three endpoints (`POST /api/share`, `POST /api/revoke`,
`DELETE /api/files/{file_id}`) go in a **new sibling module**,
`backend/macaroon_core/sharing.py`, and import these primitives instead of
duplicating the caveat grammar or the storage layout. Everything here
follows `docs/spec/api-spec.md`.

## Modules

| Module | Purpose |
|---|---|
| `macaroon_core.errors` | `CoreError` subclasses with `.code` and `.status` from spec section 5 |
| `macaroon_core.caveats` | format/parse/validate the three caveat forms, effective op/expiry |
| `macaroon_core.tokens` | mint, decode, verify, permission checks |
| `macaroon_core.storage` | `FileStore`: blob, root key, issued/revoked share ids |
| `macaroon_core.service` | `create_file`, `read_file`, `replace_file` (first three endpoints) |
| `macaroon_core.sharing` | **to be added**: `create_share`, `revoke_share`, `delete_file` (last three endpoints) |

Errors: `BadRequest(400)`, `MissingToken(401)`, `InvalidToken(401)`,
`Expired(403)`, `Revoked(403)`, `Forbidden(403)`, `NotFound(404)`,
`TooLarge(413)`. `str(error)` is a ready-made message.

## Where the last three endpoints go

They belong to the **same service layer**, but not in `service.py`. Keep the
endpoint groups in separate files so two people can work in parallel without
touching the same module.

| Path | Action |
|---|---|
| `backend/macaroon_core/sharing.py` | **new** module with the three service functions |
| `backend/tests/test_sharing.py` | **new** unit tests for those functions |
| `backend/macaroon_core/__init__.py` | add re-exports for the new functions |
| `backend/CORE_INTERFACE.md` | update only if public names or flows change |

Do **not** edit `service.py`, `caveats.py`, `tokens.py` or `storage.py` for
this milestone. They already expose everything needed. In particular:

- `service.py` stays the facade for `create_file`, `read_file`,
  `replace_file`; adding share logic there causes merge conflicts and mixes
  the two milestones.
- `caveats.py` / `tokens.py` already implement the complete grammar and
  verification. Only extend them if the spec gains a new caveat form, which
  requires updating `docs/spec/api-spec.md` and coordinating with Parts 1
  and 2.
- `storage.py` already has the issued/revoked/delete accessors. Changing the
  `shares.json` shape requires coordinating with Part 1 and Part 2.

Public API in `sharing.py`:

```python
# POST /api/share
def create_share(
    token: str | None,
    op: str,
    expires_in: int,
    store: FileStore | None = None,
    now: int | None = None,
) -> ShareResult: ...          # token, share_id, op, expires_at

# POST /api/revoke
def revoke_share(
    token: str | None,
    share_id: str,
    store: FileStore | None = None,
    now: int | None = None,
) -> None: ...

# DELETE /api/files/{file_id}
def delete_file(
    file_id: str,
    token: str | None,
    store: FileStore | None = None,
    now: int | None = None,
) -> None: ...
```

Use a frozen dataclass `ShareResult` like `UploadResult` in `service.py`.
Raise `macaroon_core.errors` subclasses, not HTTP exceptions. Then re-export
from `macaroon_core/__init__.py`:

```python
from .sharing import ShareResult, create_share, delete_file, revoke_share
```

The Flask layer still imports everything from one place, while the files stay
split by milestone.

One exception is worth discussing with the team: `delete_file` operates on
`/api/files/{file_id}`, so it could live in `service.py` instead. Keeping it
in `sharing.py` is recommended for now because the last three endpoints then
land together with one owner and one test file. If the team prefers grouping
by resource instead of milestone, move only the `delete_file` wrapper to
`service.py` and agree on who reviews it; `storage.delete_file` already
exists either way.

## Storage contract

```
backend/storage/files/<file_id>/
  blob           encrypted blob, at most 1 MiB, mode 0600
  root_key       32 bytes, mode 0600, never logged or returned
  shares.json    {"issued": [...], "revoked": [...]}
```

```python
from macaroon_core import FileStore, ids

store = FileStore()                         # backend/storage by default
store.get_root_key(file_id)                 # NotFound if missing/deleted
store.get_revoked_share_ids(file_id)        # frozenset[str]
store.get_issued_share_ids(file_id)         # frozenset[str]
store.is_share_issued(file_id, share_id)    # bool
store.add_issued_share_id(file_id, share_id)
store.revoke_share_id(file_id, share_id)    # adds to revoked set
store.delete_file(file_id)                  # removes blob + key + shares
```

`add_issued_share_id` / `revoke_share_id` reject malformed ids with
`ValueError` and unknown files with `NotFound`. Revocation is a set, so it is
idempotent. Do not change `shares.json`'s shape without updating Part 1 and
Part 2's tests.

## Authenticating share/revoke requests (`sharing.py`)

Both helper and endpoint functions below live in `sharing.py`. Share and
revoke have no `{file_id}` in the path, so read the identifier from the token
first, then look up the key. This preserves the spec order: syntax errors are
401, an unknown/deleted file is 404, and an authentic but expired/revoked
token is 403.

```python
import time

from macaroon_core import FileStore, caveats, errors, tokens

def authenticate(
    token: str | None,
    store: FileStore,
    now: int,
) -> tuple[str, tokens.TokenInfo]:
    file_id = tokens.peek_identifier(token)          # 401 if malformed
    root_key = store.get_root_key(file_id)           # 404 if unknown
    info = tokens.verify_token(
        token,
        file_id,
        root_key,
        store.get_revoked_share_ids(file_id),
        now=now,
    )                                                # 401, 403 expired/revoked
    return file_id, info
```

`peek_identifier` does **not** check the HMAC; always follow it with
`verify_token`.

## POST /api/share: `create_share`

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class ShareResult:
    token: str
    share_id: str
    op: str
    expires_at: int

def create_share(
    token: str | None,
    op: str,
    expires_in: int,
    store: FileStore | None = None,
    now: int | None = None,
) -> ShareResult:
    file_store = store if store is not None else FileStore()
    current_time = int(time.time()) if now is None else int(now)
    file_id, info = authenticate(token, file_store, current_time)

    requested = caveats.validate_op(op)               # BadRequest -> 400
    if (
        info.op is None
        or caveats.PERMISSION_RANK[requested]
        > caveats.PERMISSION_RANK[info.op]
    ):
        raise errors.BadRequest(
            "op must not exceed the caller's permission."
        )

    lifetime = caveats.validate_expires_in(expires_in)  # 60..2592000
    expires_at = current_time + lifetime
    share_id = ids.new_share_id()                       # 8 bytes, lower hex

    # Adding caveats needs no root key and keeps the existing HMAC chain.
    macaroon = tokens.decode_token(token, file_id)
    macaroon.add_first_party_caveat(caveats.format_op(requested))
    macaroon.add_first_party_caveat(caveats.format_expires(expires_at))
    macaroon.add_first_party_caveat(caveats.format_share_id(share_id))

    new_token = macaroon.serialize()
    # Keep the token limits from spec section 3 before returning it.
    if (
        len(macaroon.caveats) > tokens.MAX_CAVEATS
        or len(new_token) > tokens.MAX_TOKEN_LENGTH
    ):
        raise errors.BadRequest("token would exceed the size limits.")

    file_store.add_issued_share_id(file_id, share_id)
    return ShareResult(
        token=new_token,
        share_id=share_id,
        op=requested,
        expires_at=expires_at,
    )
```

`mint_token(file_id, root_key, all_caveats)` produces an equivalent token if
you prefer to rebuild instead of mutate, but mutation is what real
attenuation does and needs no key.

## POST /api/revoke: `revoke_share`

```python
def revoke_share(
    token: str | None,
    share_id: str,
    store: FileStore | None = None,
    now: int | None = None,
) -> None:
    file_store = store if store is not None else FileStore()
    current_time = int(time.time()) if now is None else int(now)
    file_id, info = authenticate(token, file_store, current_time)
    tokens.require_permission(info, "full")           # Forbidden -> 403

    if not ids.is_valid_share_id(share_id):
        raise errors.BadRequest(
            "share_id must be 16 lowercase hex characters."
        )
    if not file_store.is_share_issued(file_id, share_id):
        raise errors.NotFound()                       # spec section 4.5
    file_store.revoke_share_id(file_id, share_id)
```

Any token carrying that `share_id` is rejected by `verify_token`, including
tokens derived from it, because derived tokens keep the caveat.

## DELETE /api/files/{file_id}: `delete_file`

```python
def delete_file(
    file_id: str,
    token: str | None,
    store: FileStore | None = None,
    now: int | None = None,
) -> None:
    file_store = store if store is not None else FileStore()
    current_time = int(time.time()) if now is None else int(now)
    info = tokens.verify_token(
        token,
        file_id,
        file_store.get_root_key(file_id),
        file_store.get_revoked_share_ids(file_id),
        now=current_time,
    )
    tokens.require_permission(info, "full")
    file_store.delete_file(file_id)
```

After deletion the root key is gone, so every later token for that file gets
`NotFound` from `get_root_key`.

## Invariants the web layer must not break

- Never log or return tokens, root keys or blobs.
- Use absolute expiry: `expires < now + expires_in`, integer seconds.
- A share may narrow or keep the caller's `op`; it must never raise it.
- A revoked id must have been issued for that file first.
- Limits: 1 MiB blob, 20 caveats, 4096 token characters. The verifier
  enforces the last two; the service enforces the blob size.
- Pass `now` explicitly in tests; otherwise it defaults to `time.time()`.

## Tests

```bash
# from the repository root
pytest backend/tests
```

Part 1's 195 tests cover the grammar, minting/verification, tampering,
expiry, revocation, storage and the permission matrix.

The last three endpoints get their own `backend/tests/test_sharing.py`
instead of being appended to the existing test files. Reuse the fixtures in
`backend/tests/conftest.py`: `store`, `uploaded`, `narrow`, `mint`, `sign`
and `now`. Cover at least:

- a read or edit token cannot create a share with a higher `op`
- invalid `op` / `expires_in` values raise `BadRequest`
- the returned token verifies and reports the expected effective permission
- the new `share_id` appears in `store.get_issued_share_ids`
- revoke requires `full` and rejects never-issued ids with `NotFound`
- revoking invalidates the share and tokens derived from it
- delete requires `full`, removes blob/root key/shares, and later tokens get
  `NotFound`
- an edit token cannot revoke or delete
