"""The caveat grammar from ``docs/spec/api-spec.md`` section 3.

Only three first-party caveat forms are accepted, with exactly one space on
each side of the operator:

    op = read | edit | full
    expires < <unix timestamp>
    share_id = <16 lowercase hex characters>

Anything else is rejected. Parsing is shared by the verifier (syntax check
before the HMAC check on the web layer) and by the share/revoke endpoints
when they mint caveats.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Union

from .errors import BadRequest, InvalidToken
from .ids import is_valid_share_id

PERMISSIONS = ("read", "edit", "full")
PERMISSION_RANK = {"read": 0, "edit": 1, "full": 2}

MIN_EXPIRES_IN = 60
MAX_EXPIRES_IN = 2_592_000  # 30 days
MAX_TIMESTAMP = 10**12 - 1

_OP_PATTERN = re.compile(r"op = (read|edit|full)")
_EXPIRES_PATTERN = re.compile(r"expires < ([0-9]{1,12})")
_SHARE_ID_PATTERN = re.compile(r"share_id = ([0-9a-f]{16})")


@dataclass(frozen=True)
class OpCaveat:
    level: str


@dataclass(frozen=True)
class ExpiresCaveat:
    timestamp: int


@dataclass(frozen=True)
class ShareIdCaveat:
    share_id: str


Caveat = Union[OpCaveat, ExpiresCaveat, ShareIdCaveat]


@dataclass(frozen=True)
class CaveatSet:
    """Effective values after evaluating every caveat on a token."""

    op: str | None
    expires_at: int | None
    share_ids: tuple[str, ...]
    count: int


def parse_caveat(text: object) -> Caveat:
    """Parse one caveat, raising :class:`InvalidToken` for anything unknown."""
    if not isinstance(text, str):
        raise InvalidToken()

    match = _OP_PATTERN.fullmatch(text)
    if match is not None:
        return OpCaveat(level=match.group(1))

    match = _EXPIRES_PATTERN.fullmatch(text)
    if match is not None:
        timestamp = int(match.group(1))
        if timestamp > MAX_TIMESTAMP:
            raise InvalidToken()
        return ExpiresCaveat(timestamp=timestamp)

    match = _SHARE_ID_PATTERN.fullmatch(text)
    if match is not None:
        share_id = match.group(1)
        if not is_valid_share_id(share_id):
            raise InvalidToken()
        return ShareIdCaveat(share_id=share_id)

    raise InvalidToken()


def is_known_caveat(text: object) -> bool:
    """Return whether ``text`` matches one of the three accepted forms."""
    try:
        parse_caveat(text)
    except InvalidToken:
        return False
    return True


def parse_caveats(texts: Iterable[str]) -> CaveatSet:
    """Parse all caveats and apply the combination rules from the spec.

    * the lowest ``op`` wins,
    * the earliest ``expires`` wins,
    * every ``share_id`` is kept, because one revoked id is enough to reject.
    """
    op_rank: int | None = None
    op: str | None = None
    expires_at: int | None = None
    share_ids: list[str] = []
    count = 0

    for text in texts:
        caveat = parse_caveat(text)
        count += 1

        if isinstance(caveat, OpCaveat):
            rank = PERMISSION_RANK[caveat.level]
            if op_rank is None or rank < op_rank:
                op_rank = rank
                op = caveat.level
        elif isinstance(caveat, ExpiresCaveat):
            if expires_at is None or caveat.timestamp < expires_at:
                expires_at = caveat.timestamp
        else:
            share_ids.append(caveat.share_id)

    return CaveatSet(
        op=op,
        expires_at=expires_at,
        share_ids=tuple(share_ids),
        count=count,
    )


def format_op(level: str) -> str:
    if level not in PERMISSION_RANK:
        raise ValueError(f"unknown permission: {level!r}")
    return f"op = {level}"


def format_expires(timestamp: int) -> str:
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise TypeError("timestamp must be an int")
    if timestamp < 0 or timestamp > MAX_TIMESTAMP:
        raise ValueError("timestamp out of range")
    return f"expires < {timestamp}"


def format_share_id(share_id: str) -> str:
    if not is_valid_share_id(share_id):
        raise ValueError(f"invalid share_id: {share_id!r}")
    return f"share_id = {share_id}"


def validate_op(level: object) -> str:
    """Validate an ``op`` value from a request body."""
    if not isinstance(level, str) or level not in PERMISSION_RANK:
        raise BadRequest("op must be read, edit or full.")
    return level


def validate_expires_in(seconds: object) -> int:
    """Validate the ``expires_in`` value from a share request body."""
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        raise BadRequest("expires_in must be an integer.")
    if seconds < MIN_EXPIRES_IN or seconds > MAX_EXPIRES_IN:
        raise BadRequest("expires_in must be between 60 and 2592000 seconds.")
    return seconds


__all__ = [
    "PERMISSIONS",
    "PERMISSION_RANK",
    "MIN_EXPIRES_IN",
    "MAX_EXPIRES_IN",
    "MAX_TIMESTAMP",
    "OpCaveat",
    "ExpiresCaveat",
    "ShareIdCaveat",
    "Caveat",
    "CaveatSet",
    "parse_caveat",
    "parse_caveats",
    "is_known_caveat",
    "format_op",
    "format_expires",
    "format_share_id",
    "validate_op",
    "validate_expires_in",
]
