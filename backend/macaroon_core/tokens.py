"""Minting and verification of macaroon tokens.

The module is a thin, fail-closed wrapper over pymacaroons:

* :func:`mint_token` creates a token bound to a ``file_id`` and root key.
* :func:`decode_token` performs the cheap, root-key-free checks (syntax,
  identifier, limits) so the storage layer can be queried afterwards.
* :func:`verify_decoded` checks the HMAC chain and then evaluates the caveat
  meaning (expiry, revocation).
* :func:`verify_token` composes the last two for callers that already have
  the root key; the share/revoke endpoints use it, the file endpoints use
  the split form because they must look the key up between both steps.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Iterable

from pymacaroons import Macaroon, Verifier
from pymacaroons.exceptions import MacaroonException

from . import caveats, ids
from .errors import Expired, Forbidden, InvalidToken, MissingToken, Revoked

TOKEN_LOCATION = "macaroon-crypto"
MAX_TOKEN_LENGTH = 4096
MAX_CAVEATS = 20

# pymacaroons serializes to unpadded URL-safe base64; anything else is not a
# token we minted, so reject it before the deserializer sees it.
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]+")


@dataclass(frozen=True)
class TokenInfo:
    """What an authentic token says, after caveat evaluation."""

    identifier: str
    location: str
    op: str | None
    expires_at: int | None
    share_ids: tuple[str, ...]
    caveat_count: int


def mint_token(
    file_id: str,
    root_key: str | bytes,
    token_caveats: Iterable[str] = (),
) -> str:
    """Mint a token for ``file_id`` with the given first-party caveats.

    Raises :class:`ValueError` for programmer errors: an empty identifier,
    an unknown caveat, or too many caveats. Tokens over the size limit raise
    as well, although the grammar makes that unreachable in practice.
    """
    if not isinstance(file_id, str) or not file_id:
        raise ValueError("file_id must be a non-empty string")
    if not isinstance(root_key, (str, bytes, bytearray)) or not root_key:
        raise ValueError("root_key must be non-empty")
    if isinstance(root_key, bytearray):
        root_key = bytes(root_key)

    texts = tuple(token_caveats)
    if len(texts) > MAX_CAVEATS:
        raise ValueError(f"at most {MAX_CAVEATS} caveats are allowed")
    for text in texts:
        if not caveats.is_known_caveat(text):
            raise ValueError(f"unknown caveat: {text!r}")

    macaroon = Macaroon(
        location=TOKEN_LOCATION,
        identifier=file_id,
        key=root_key,
    )
    for text in texts:
        macaroon.add_first_party_caveat(text)

    token = macaroon.serialize()
    if len(token) > MAX_TOKEN_LENGTH:
        raise ValueError("token is too long")
    return token


def mint_full_token(file_id: str, root_key: str | bytes) -> str:
    """Mint the token returned by upload: exactly one caveat, ``op = full``."""
    return mint_token(file_id, root_key, [caveats.format_op("full")])


def decode_token(token: object, file_id: str) -> Macaroon:
    """Steps 1-3 of the verification order.

    Nothing here needs the root key: the token must be a string, short enough,
    deserializable, bound to ``file_id``, minted by us and carry at most
    ``MAX_CAVEATS`` first-party caveats.
    """
    macaroon = _prepare(token)
    if not isinstance(macaroon.identifier, str):
        raise InvalidToken()
    if macaroon.identifier != file_id:
        raise InvalidToken()
    return macaroon


def peek_identifier(token: object) -> str:
    """Return the identifier of a well-formed token, without checking HMACs.

    Endpoints without a ``{file_id}`` in the path (share/revoke) use this to
    find the root key. The caller must still call :func:`verify_token` with
    the returned identifier and the stored key before trusting the token.
    """
    macaroon = _prepare(token)
    identifier = macaroon.identifier
    if not isinstance(identifier, str) or not ids.is_valid_file_id(identifier):
        raise InvalidToken()
    return identifier


def _prepare(token: object) -> Macaroon:
    """Steps 1-2 plus the structural checks that need no key."""
    if token is None:
        raise MissingToken()
    if not isinstance(token, str) or not token:
        raise InvalidToken()
    if len(token) > MAX_TOKEN_LENGTH:
        raise InvalidToken()
    if _TOKEN_PATTERN.fullmatch(token) is None:
        raise InvalidToken()

    try:
        macaroon = Macaroon.deserialize(token)
    except Exception as exc:  # pymacaroons raises several unrelated types
        raise InvalidToken() from exc

    if len(macaroon.caveats) > MAX_CAVEATS:
        raise InvalidToken()
    if any(caveat.third_party() for caveat in macaroon.caveats):
        raise InvalidToken()

    try:
        location = macaroon.location
        caveat_texts = [caveat.caveat_id for caveat in macaroon.caveats]
    except Exception as exc:
        raise InvalidToken() from exc

    if location != TOKEN_LOCATION:
        raise InvalidToken()
    if any(not isinstance(text, str) for text in caveat_texts):
        raise InvalidToken()

    return macaroon


def verify_decoded(
    macaroon: Macaroon,
    root_key: str | bytes,
    revoked_share_ids: Iterable[str] = (),
    now: int | None = None,
) -> TokenInfo:
    """Steps 5-6 of the verification order for an already decoded token."""
    verifier = Verifier()
    # pymacaroons reports every unmet caveat as a signature mismatch, so this
    # callback checks syntax only. Meaning is evaluated below; that split is
    # what lets the web layer answer 401 for unauthentic and 403 for denied.
    verifier.satisfy_general(caveats.is_known_caveat)

    try:
        verifier.verify(macaroon, root_key)
    except MacaroonException as exc:
        raise InvalidToken() from exc

    try:
        texts = [caveat.caveat_id for caveat in macaroon.caveats]
    except Exception as exc:
        raise InvalidToken() from exc
    parsed = caveats.parse_caveats(texts)

    current_time = int(time.time()) if now is None else int(now)
    if parsed.expires_at is not None and current_time >= parsed.expires_at:
        raise Expired()

    revoked = frozenset(revoked_share_ids)
    if revoked.intersection(parsed.share_ids):
        raise Revoked()

    return TokenInfo(
        identifier=macaroon.identifier,
        location=macaroon.location,
        op=parsed.op,
        expires_at=parsed.expires_at,
        share_ids=parsed.share_ids,
        caveat_count=parsed.count,
    )


def verify_token(
    token: object,
    file_id: str,
    root_key: str | bytes,
    revoked_share_ids: Iterable[str] = (),
    now: int | None = None,
) -> TokenInfo:
    """Decode and fully verify a token when the root key is already known."""
    macaroon = decode_token(token, file_id)
    return verify_decoded(macaroon, root_key, revoked_share_ids, now)


def require_permission(info: TokenInfo, needed: str) -> None:
    """Raise :class:`Forbidden` unless ``info.op`` reaches ``needed``."""
    if needed not in caveats.PERMISSION_RANK:
        raise ValueError(f"unknown permission: {needed!r}")
    if info.op is None:
        raise Forbidden()
    if caveats.PERMISSION_RANK[info.op] < caveats.PERMISSION_RANK[needed]:
        raise Forbidden()


__all__ = [
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
]
