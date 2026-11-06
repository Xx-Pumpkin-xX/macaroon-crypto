"""Generators and format checks for identifiers used by the service.

Formats come from ``docs/spec/api-spec.md`` section 2:

* ``file_id``: 16 random bytes, base64url without padding (22 characters)
* ``share_id``: 8 random bytes, lowercase hex (16 characters)
* root key: 32 random bytes, server side only
"""

from __future__ import annotations

import base64
import re
import secrets

FILE_ID_BYTES = 16
SHARE_ID_BYTES = 8
ROOT_KEY_BYTES = 32

FILE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{22}")
SHARE_ID_PATTERN = re.compile(r"[0-9a-f]{16}")


def new_file_id() -> str:
    """Return a fresh base64url ``file_id`` without padding."""
    raw = secrets.token_bytes(FILE_ID_BYTES)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def new_share_id() -> str:
    """Return a fresh lowercase-hex ``share_id``."""
    return secrets.token_hex(SHARE_ID_BYTES)


def new_root_key() -> bytes:
    """Return a fresh 32-byte root key for one file."""
    return secrets.token_bytes(ROOT_KEY_BYTES)


def is_valid_file_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and FILE_ID_PATTERN.fullmatch(value) is not None
    )


def is_valid_share_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and SHARE_ID_PATTERN.fullmatch(value) is not None
    )


__all__ = [
    "FILE_ID_BYTES",
    "SHARE_ID_BYTES",
    "ROOT_KEY_BYTES",
    "FILE_ID_PATTERN",
    "SHARE_ID_PATTERN",
    "new_file_id",
    "new_share_id",
    "new_root_key",
    "is_valid_file_id",
    "is_valid_share_id",
]
