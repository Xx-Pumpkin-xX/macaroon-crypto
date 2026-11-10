"""Regression tests for F02: non-UTF-8 token identifiers.

The identifier is stored as bytes inside a macaroon. Accessing
``Macaroon.identifier`` decodes it as UTF-8, so a hostile token could raise
``UnicodeDecodeError`` before the HMAC check. The core must normalize that to
``InvalidToken`` at its common preparation step.
"""

from __future__ import annotations

import base64

import pytest
from pymacaroons import Macaroon

from macaroon_core import caveats, create_share, delete_file, read_file, tokens
from macaroon_core.errors import InvalidToken


def corrupt_identifier(token: str, file_id: str) -> str:
    raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    malformed = raw.replace(
        file_id.encode("ascii"),
        b"\xff" + file_id[1:].encode("ascii"),
        1,
    )
    assert malformed != raw
    return base64.urlsafe_b64encode(malformed).decode("ascii").rstrip("=")


def test_decode_token_rejects_non_utf8_identifier(uploaded):
    token = corrupt_identifier(uploaded.token, uploaded.file_id)

    with pytest.raises(InvalidToken):
        tokens.decode_token(token, uploaded.file_id)


def test_peek_identifier_rejects_non_utf8_identifier(uploaded):
    token = corrupt_identifier(uploaded.token, uploaded.file_id)

    with pytest.raises(InvalidToken):
        tokens.peek_identifier(token)


def test_read_file_rejects_non_utf8_identifier(store, uploaded):
    token = corrupt_identifier(uploaded.token, uploaded.file_id)

    with pytest.raises(InvalidToken):
        read_file(uploaded.file_id, token, store=store)


def test_create_share_rejects_non_utf8_identifier(store, uploaded):
    token = corrupt_identifier(uploaded.token, uploaded.file_id)

    with pytest.raises(InvalidToken):
        create_share(token, "read", 60, store=store)


def test_delete_file_rejects_non_utf8_identifier(store, uploaded):
    token = corrupt_identifier(uploaded.token, uploaded.file_id)

    with pytest.raises(InvalidToken):
        delete_file(uploaded.file_id, token, store=store)


def test_verify_decoded_rejects_non_utf8_identifier():
    key = b"z" * 32
    macaroon = Macaroon(
        location=tokens.TOKEN_LOCATION,
        identifier=b"\xff",
        key=key,
    )
    macaroon.add_first_party_caveat(caveats.format_op("full"))

    with pytest.raises(InvalidToken):
        tokens.verify_decoded(macaroon, key)
