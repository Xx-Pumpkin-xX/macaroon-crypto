"""Macaroon core for the anonymous file-sharing service.

Public surface used by the Flask layer::

    from macaroon_core import create_file, read_file, replace_file
    from macaroon_core import create_share, revoke_share, delete_file

    result = create_file(blob)                     # POST   /api/files
    download = read_file(file_id, token)           # GET    /api/files/{id}
    replace_file(file_id, token, blob)             # PUT    /api/files/{id}
    share = create_share(token, "read", 3600)      # POST   /api/share
    revoke_share(token, share_id)                  # POST   /api/revoke
    delete_file(file_id, token)                    # DELETE /api/files/{id}

Errors inherit from :class:`CoreError` and carry a spec ``code`` and HTTP
``status``. The share/revoke/delete work imports the same helpers
(:mod:`caveats`, :mod:`tokens`, :class:`FileStore`) to stay interoperable.
"""

from . import caveats, ids, tokens
from .errors import (
    BadRequest,
    CoreError,
    Expired,
    Forbidden,
    InvalidToken,
    MissingToken,
    NotFound,
    Revoked,
    TooLarge,
)
from .service import (
    EDIT,
    FULL,
    MAX_BLOB_SIZE,
    READ,
    DownloadResult,
    UploadResult,
    create_file,
    read_file,
    replace_file,
)
from .sharing import ShareResult, create_share, delete_file, revoke_share
from .storage import DEFAULT_STORAGE_DIR, FileStore
from .tokens import (
    MAX_CAVEATS,
    MAX_TOKEN_LENGTH,
    TOKEN_LOCATION,
    TokenInfo,
    decode_token,
    mint_full_token,
    mint_token,
    peek_identifier,
    require_permission,
    verify_decoded,
    verify_token,
)

__all__ = [
    # modules
    "caveats",
    "ids",
    "tokens",
    # errors
    "CoreError",
    "BadRequest",
    "MissingToken",
    "InvalidToken",
    "Expired",
    "Revoked",
    "Forbidden",
    "NotFound",
    "TooLarge",
    # storage
    "DEFAULT_STORAGE_DIR",
    "FileStore",
    # tokens
    "TOKEN_LOCATION",
    "MAX_TOKEN_LENGTH",
    "MAX_CAVEATS",
    "TokenInfo",
    "mint_token",
    "mint_full_token",
    "decode_token",
    "peek_identifier",
    "verify_decoded",
    "verify_token",
    "require_permission",
    # service
    "MAX_BLOB_SIZE",
    "READ",
    "EDIT",
    "FULL",
    "UploadResult",
    "DownloadResult",
    "create_file",
    "read_file",
    "replace_file",
    # sharing
    "ShareResult",
    "create_share",
    "revoke_share",
    "delete_file",
]
