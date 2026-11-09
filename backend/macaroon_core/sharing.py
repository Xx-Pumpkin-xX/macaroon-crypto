"""Service functions for the last three endpoints: share, revoke, delete.

    POST   /api/share              -> create_share
    POST   /api/revoke             -> revoke_share
    DELETE /api/files/{file_id}    -> delete_file

These functions raise ``macaroon_core.errors`` subclasses, never HTTP
exceptions. The Flask layer maps ``.status`` / ``str(error)`` to a response.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

# Relative imports on purpose: this module is imported from
# macaroon_core/__init__.py, so importing names back from the package itself
# could hit a half-initialised package.
from . import caveats, errors, ids, tokens
from .storage import FileStore


@dataclass(frozen=True)
class ShareResult:
    token: str
    share_id: str
    op: str
    expires_at: int


def _now(now: int | None) -> int:
    return int(time.time()) if now is None else int(now)


def authenticate(
    token: str | None,
    store: FileStore,
    now: int,
) -> tuple[str, tokens.TokenInfo]:
    """Authenticate a request that has no ``{file_id}`` in its path.

    Order matters (spec): a malformed token is 401, an unknown or deleted file
    is 404, and an authentic but expired/revoked token is 403.
    """
    file_id = tokens.peek_identifier(token)  # 401 if malformed
    root_key = store.get_root_key(file_id)  # 404 if unknown/deleted
    info = tokens.verify_token(
        token,
        file_id,
        root_key,
        store.get_revoked_share_ids(file_id),
        now=now,
    )  # 401, or 403 expired/revoked
    return file_id, info


# POST /api/share
def create_share(
    token: str | None,
    op: str,
    expires_in: int,
    store: FileStore | None = None,
    now: int | None = None,
) -> ShareResult:
    file_store = store if store is not None else FileStore()
    current_time = _now(now)
    file_id, info = authenticate(token, file_store, current_time)

    requested = caveats.validate_op(op)  # BadRequest -> 400
    if (
        info.op is None
        or caveats.PERMISSION_RANK[requested] > caveats.PERMISSION_RANK[info.op]
    ):
        raise errors.BadRequest("op must not exceed the caller's permission.")

    lifetime = caveats.validate_expires_in(expires_in)  # 60..2592000
    expires_at = current_time + lifetime
    share_id = ids.new_share_id()  # 8 bytes, lower hex

    # Attenuation: adding caveats needs no root key and extends the HMAC chain.
    macaroon = tokens.decode_token(token, file_id)
    macaroon.add_first_party_caveat(caveats.format_op(requested))
    macaroon.add_first_party_caveat(caveats.format_expires(expires_at))
    macaroon.add_first_party_caveat(caveats.format_share_id(share_id))

    new_token = macaroon.serialize()
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


# POST /api/revoke
def revoke_share(
    token: str | None,
    share_id: str,
    store: FileStore | None = None,
    now: int | None = None,
) -> None:
    file_store = store if store is not None else FileStore()
    current_time = _now(now)
    file_id, info = authenticate(token, file_store, current_time)
    tokens.require_permission(info, "full")  # Forbidden -> 403

    if not ids.is_valid_share_id(share_id):
        raise errors.BadRequest("share_id must be 16 lowercase hex characters.")
    if not file_store.is_share_issued(file_id, share_id):
        raise errors.NotFound()  # spec section 4.5
    file_store.revoke_share_id(file_id, share_id)


# DELETE /api/files/{file_id}
def delete_file(
    file_id: str,
    token: str | None,
    store: FileStore | None = None,
    now: int | None = None,
) -> None:
    file_store = store if store is not None else FileStore()
    current_time = _now(now)
    # Spec 3.1 order: decode the token (401) before the key lookup (404).
    macaroon = tokens.decode_token(token, file_id)
    info = tokens.verify_decoded(
        macaroon,
        file_store.get_root_key(file_id),
        file_store.get_revoked_share_ids(file_id),
        now=current_time,
    )
    tokens.require_permission(info, "full")
    file_store.delete_file(file_id)
