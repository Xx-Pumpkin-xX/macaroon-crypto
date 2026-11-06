"""Service functions behind the first three API endpoints.

The Flask layer only has to translate these calls and their errors into HTTP:

* :func:`create_file`   -> ``POST /api/files``
* :func:`read_file`     -> ``GET /api/files/{file_id}``
* :func:`replace_file`  -> ``PUT /api/files/{file_id}``
"""

from __future__ import annotations

from dataclasses import dataclass

from . import tokens
from .errors import BadRequest, TooLarge
from .storage import FileStore

MAX_BLOB_SIZE = 1_048_576  # 1 MiB

READ = "read"
EDIT = "edit"
FULL = "full"


@dataclass(frozen=True)
class UploadResult:
    file_id: str
    token: str


@dataclass(frozen=True)
class DownloadResult:
    blob: bytes
    permission: str


def _store(store: FileStore | None) -> FileStore:
    return store if store is not None else FileStore()


def _validate_blob(blob: object) -> bytes:
    if isinstance(blob, (bytearray, memoryview)):
        blob = bytes(blob)
    if not isinstance(blob, bytes):
        raise BadRequest("The body must be bytes.")
    if not blob:
        raise BadRequest("The body must not be empty.")
    if len(blob) > MAX_BLOB_SIZE:
        raise TooLarge()
    return blob


def _authorize(
    file_id: str,
    token: object,
    needed: str,
    store: FileStore,
    now: int | None,
) -> tokens.TokenInfo:
    # Verification order from api-spec section 3.1: cheap token checks first,
    # then the root-key lookup, then the HMAC chain and the caveat meaning.
    macaroon = tokens.decode_token(token, file_id)
    root_key = store.get_root_key(file_id)
    info = tokens.verify_decoded(
        macaroon,
        root_key,
        store.get_revoked_share_ids(file_id),
        now,
    )
    tokens.require_permission(info, needed)
    return info


def create_file(blob: object, store: FileStore | None = None) -> UploadResult:
    """Store a new blob and return its ``file_id`` and ``full`` token."""
    data = _validate_blob(blob)
    file_store = _store(store)
    file_id, root_key = file_store.create(data)
    token = tokens.mint_full_token(file_id, root_key)
    return UploadResult(file_id=file_id, token=token)


def read_file(
    file_id: str,
    token: object,
    store: FileStore | None = None,
    now: int | None = None,
) -> DownloadResult:
    """Return the blob and the effective permission of ``token``."""
    file_store = _store(store)
    info = _authorize(file_id, token, READ, file_store, now)
    blob = file_store.get_blob(file_id)
    # require_permission guarantees an op of at least "read".
    assert info.op is not None
    return DownloadResult(blob=blob, permission=info.op)


def replace_file(
    file_id: str,
    token: object,
    blob: object,
    store: FileStore | None = None,
    now: int | None = None,
) -> None:
    """Replace the blob after checking the ``edit`` permission."""
    file_store = _store(store)
    _authorize(file_id, token, EDIT, file_store, now)
    data = _validate_blob(blob)
    file_store.replace_blob(file_id, data)


__all__ = [
    "MAX_BLOB_SIZE",
    "READ",
    "EDIT",
    "FULL",
    "UploadResult",
    "DownloadResult",
    "create_file",
    "read_file",
    "replace_file",
]
