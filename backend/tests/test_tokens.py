"""Tests for minting and verifying tokens (api-spec sections 3 and 5)."""

from __future__ import annotations

import binascii
import hashlib
import hmac

import pytest
from pymacaroons import Macaroon

from macaroon_core import caveats, tokens
from macaroon_core.errors import (
    Expired,
    Forbidden,
    InvalidToken,
    MissingToken,
    Revoked,
)


def verify(token, file_id, store, revoked=(), now=1_700_000_000):
    return tokens.verify_token(
        token,
        file_id,
        store.get_root_key(file_id),
        revoked,
        now,
    )


# -- minting -------------------------------------------------------------


def test_upload_token_has_exactly_op_full(uploaded, store):
    info = verify(uploaded.token, uploaded.file_id, store)
    assert info.identifier == uploaded.file_id
    assert info.location == tokens.TOKEN_LOCATION
    assert info.op == "full"
    assert info.expires_at is None
    assert info.share_ids == ()
    assert info.caveat_count == 1


def test_token_serialization_is_urlsafe_base64(uploaded):
    token = uploaded.token
    assert len(token) <= tokens.MAX_TOKEN_LENGTH
    assert "=" not in token
    assert all(c.isalnum() or c in "-_" for c in token)


def test_mint_token_accepts_twenty_caveats(store, uploaded):
    token = tokens.mint_token(
        uploaded.file_id,
        store.get_root_key(uploaded.file_id),
        ["op = full"] * tokens.MAX_CAVEATS,
    )
    assert verify(token, uploaded.file_id, store).caveat_count == 20


def test_mint_token_rejects_twenty_one_caveats(store, uploaded):
    with pytest.raises(ValueError):
        tokens.mint_token(
            uploaded.file_id,
            store.get_root_key(uploaded.file_id),
            ["op = full"] * (tokens.MAX_CAVEATS + 1),
        )


@pytest.mark.parametrize(
    "token_caveats",
    [
        ["role = admin"],
        ["op=read"],
        ["op = read", "admin = yes"],
        ["expires < nope"],
        ["share_id = NOTHEX"],
    ],
)
def test_mint_token_rejects_unknown_caveats(store, uploaded, token_caveats):
    with pytest.raises(ValueError):
        tokens.mint_token(
            uploaded.file_id,
            store.get_root_key(uploaded.file_id),
            token_caveats,
        )


@pytest.mark.parametrize("file_id", ["", None, 123])
def test_mint_token_rejects_bad_file_id(store, uploaded, file_id):
    with pytest.raises(ValueError):
        tokens.mint_token(file_id, store.get_root_key(uploaded.file_id), [])


@pytest.mark.parametrize("root_key", [b"", "", None, 123])
def test_mint_token_rejects_bad_root_key(store, uploaded, root_key):
    with pytest.raises(ValueError):
        tokens.mint_token(uploaded.file_id, root_key, ["op = full"])


def test_mint_token_accepts_bytearray_root_key(store, uploaded):
    token = tokens.mint_token(
        uploaded.file_id,
        bytearray(store.get_root_key(uploaded.file_id)),
        ["op = full"],
    )
    assert verify(token, uploaded.file_id, store).op == "full"


# -- decoding: steps 1-3 -------------------------------------------------


def test_none_token_is_missing(uploaded, store):
    with pytest.raises(MissingToken):
        verify(None, uploaded.file_id, store)


@pytest.mark.parametrize("token", ["", "not a token", "%%%%", "A" * 4096])
def test_empty_or_garbage_token_is_invalid(uploaded, store, token):
    with pytest.raises(InvalidToken):
        verify(token, uploaded.file_id, store)


def test_oversized_token_is_rejected_before_deserializing(uploaded, store):
    with pytest.raises(InvalidToken):
        verify("A" * (tokens.MAX_TOKEN_LENGTH + 1), uploaded.file_id, store)


@pytest.mark.parametrize("token", [123, b"abc", ["x"]])
def test_non_string_token_is_invalid(uploaded, store, token):
    with pytest.raises(InvalidToken):
        verify(token, uploaded.file_id, store)


def test_token_for_another_file_is_invalid(uploaded, store):
    with pytest.raises(InvalidToken):
        tokens.verify_token(
            uploaded.token,
            "A" * 22,
            store.get_root_key(uploaded.file_id),
        )


def test_token_with_wrong_location_is_invalid(uploaded, store, sign):
    token = sign(
        uploaded.file_id,
        ["op = full"],
        location="someone-elses-service",
    )
    with pytest.raises(InvalidToken):
        verify(token, uploaded.file_id, store)


def test_third_party_caveat_is_invalid(uploaded, store):
    macaroon = Macaroon(
        location=tokens.TOKEN_LOCATION,
        identifier=uploaded.file_id,
        key=store.get_root_key(uploaded.file_id),
    )
    macaroon.add_third_party_caveat("auth", b"k" * 32, "key-id")
    with pytest.raises(InvalidToken):
        verify(macaroon.serialize(), uploaded.file_id, store)


# -- identifier peeking (share/revoke endpoints) ------------------------


def test_peek_identifier_returns_the_file_id(uploaded):
    assert tokens.peek_identifier(uploaded.token) == uploaded.file_id


def test_peek_identifier_rechecks_token_syntax(uploaded, store, sign):
    with pytest.raises(MissingToken):
        tokens.peek_identifier(None)
    with pytest.raises(InvalidToken):
        tokens.peek_identifier("not-a-token")
    with pytest.raises(InvalidToken):
        tokens.peek_identifier("A" * (tokens.MAX_TOKEN_LENGTH + 1))

    foreign = sign(
        uploaded.file_id,
        ["op = full"],
        location="someone-elses-service",
    )
    with pytest.raises(InvalidToken):
        tokens.peek_identifier(foreign)


def test_peek_identifier_requires_a_valid_file_id(store, sign):
    token = sign("short", ["op = full"], root_key=b"z" * 32)
    with pytest.raises(InvalidToken):
        tokens.peek_identifier(token)


# -- verification: tampering --------------------------------------------


def test_wrong_root_key_is_invalid(uploaded, store):
    with pytest.raises(InvalidToken):
        tokens.verify_token(
            uploaded.token,
            uploaded.file_id,
            b"x" * 32,
            now=1_700_000_000,
        )


def test_tampered_signature_is_invalid(uploaded, store):
    macaroon = Macaroon.deserialize(uploaded.token)
    signature = macaroon.signature
    replacement = "0" if signature[0] != "0" else "1"
    macaroon.signature = replacement + signature[1:]
    with pytest.raises(InvalidToken):
        verify(macaroon.serialize(), uploaded.file_id, store)


def test_removed_caveat_is_invalid(uploaded, store, narrow):
    token = narrow(uploaded.file_id, "full", "expires < 1800000000")
    macaroon = Macaroon.deserialize(token)
    del macaroon.caveats[-1]
    with pytest.raises(InvalidToken):
        verify(macaroon.serialize(), uploaded.file_id, store)


def test_edited_caveat_is_invalid(uploaded, store, narrow):
    token = narrow(uploaded.file_id, "read")
    macaroon = Macaroon.deserialize(token)
    macaroon.caveats[0].caveat_id = caveats.format_op("full")
    with pytest.raises(InvalidToken):
        verify(macaroon.serialize(), uploaded.file_id, store)


def test_reordered_caveats_are_invalid(uploaded, store, narrow):
    token = narrow(uploaded.file_id, "read", "expires < 1800000000")
    macaroon = Macaroon.deserialize(token)
    macaroon.caveats.reverse()
    with pytest.raises(InvalidToken):
        verify(macaroon.serialize(), uploaded.file_id, store)


def test_appended_caveat_without_recomputed_signature_is_invalid(
    uploaded, store, narrow
):
    token = narrow(uploaded.file_id, "read")
    macaroon = Macaroon.deserialize(token)
    macaroon.caveats.append(macaroon.caveats[0])
    with pytest.raises(InvalidToken):
        verify(macaroon.serialize(), uploaded.file_id, store)


def test_authentic_but_unknown_caveat_is_invalid(uploaded, store, sign):
    # Signed with the real root key, but outside the grammar: 401, not 403.
    token = sign(uploaded.file_id, ["op = full", "role = admin"])
    with pytest.raises(InvalidToken):
        verify(token, uploaded.file_id, store)


def test_authentic_token_with_too_many_caveats_is_invalid(
    uploaded, store, sign
):
    token = sign(uploaded.file_id, ["op = full"] * (tokens.MAX_CAVEATS + 1))
    with pytest.raises(InvalidToken):
        verify(token, uploaded.file_id, store)


def test_signature_matches_independent_hmac_computation(uploaded, store, sign):
    texts = [
        caveats.format_op("read"),
        caveats.format_expires(1_800_000_000),
        caveats.format_share_id("9f2c41d07ab35e18"),
    ]
    token = sign(uploaded.file_id, texts)
    macaroon = Macaroon.deserialize(token)

    root_key = store.get_root_key(uploaded.file_id)
    derived = hmac.new(
        b"macaroons-key-generator", root_key, hashlib.sha256
    ).digest()
    signature = hmac.new(
        derived, uploaded.file_id.encode("utf-8"), hashlib.sha256
    ).digest()
    for text in texts:
        signature = hmac.new(
            signature, text.encode("utf-8"), hashlib.sha256
        ).digest()

    assert macaroon.signature_bytes == binascii.hexlify(signature)


# -- caveat evaluation: step 6 ------------------------------------------


def test_effective_op_is_the_lowest(uploaded, store, mint):
    token = mint(
        uploaded.file_id,
        caveats.format_op("full"),
        caveats.format_op("edit"),
        caveats.format_op("read"),
    )
    assert verify(token, uploaded.file_id, store).op == "read"


def test_require_permission():
    info = tokens.TokenInfo(
        identifier="x",
        location=tokens.TOKEN_LOCATION,
        op="read",
        expires_at=None,
        share_ids=(),
        caveat_count=1,
    )
    tokens.require_permission(info, "read")
    with pytest.raises(Forbidden):
        tokens.require_permission(info, "edit")
    with pytest.raises(Forbidden):
        tokens.require_permission(info, "full")


def test_token_without_op_is_forbidden(uploaded, store, sign):
    token = sign(
        uploaded.file_id,
        [caveats.format_share_id("9f2c41d07ab35e18")],
    )
    info = verify(token, uploaded.file_id, store)
    assert info.op is None
    with pytest.raises(Forbidden):
        tokens.require_permission(info, "read")


def test_valid_expiry_in_the_future(uploaded, store, narrow, now):
    token = narrow(
        uploaded.file_id, "read", caveats.format_expires(now + 1)
    )
    info = verify(token, uploaded.file_id, store, now=now)
    assert info.expires_at == now + 1


def test_expiry_at_the_current_second_is_expired(uploaded, store, narrow, now):
    token = narrow(uploaded.file_id, "read", caveats.format_expires(now))
    with pytest.raises(Expired):
        verify(token, uploaded.file_id, store, now=now)


def test_expiry_in_the_past_is_expired(uploaded, store, narrow, now):
    token = narrow(
        uploaded.file_id, "read", caveats.format_expires(now - 1)
    )
    with pytest.raises(Expired):
        verify(token, uploaded.file_id, store, now=now)


def test_earliest_expiry_wins(uploaded, store, narrow, now):
    token = narrow(
        uploaded.file_id,
        "read",
        caveats.format_expires(now + 1000),
        caveats.format_expires(now - 10),
    )
    with pytest.raises(Expired):
        verify(token, uploaded.file_id, store, now=now)


def test_revoked_share_id_is_rejected(uploaded, store, narrow, now):
    share_id = "9f2c41d07ab35e18"
    token = narrow(
        uploaded.file_id, "read", caveats.format_share_id(share_id)
    )
    with pytest.raises(Revoked):
        verify(
            token,
            uploaded.file_id,
            store,
            revoked={share_id},
            now=now,
        )


def test_derived_token_carrying_a_revoked_share_is_rejected(
    uploaded, store, mint, now
):
    first = "1" * 16
    second = "2" * 16
    token = mint(
        uploaded.file_id,
        caveats.format_op("read"),
        caveats.format_share_id(first),
        caveats.format_share_id(second),
    )
    with pytest.raises(Revoked):
        verify(
            token,
            uploaded.file_id,
            store,
            revoked={first},
            now=now,
        )


def test_unrelated_revoked_share_does_not_affect_token(
    uploaded, store, narrow, now
):
    token = narrow(
        uploaded.file_id, "read", caveats.format_share_id("3" * 16)
    )
    info = verify(
        token,
        uploaded.file_id,
        store,
        revoked={"4" * 16},
        now=now,
    )
    assert info.op == "read"


def test_expired_is_reported_before_revoked(uploaded, store, narrow, now):
    share_id = "5" * 16
    token = narrow(
        uploaded.file_id,
        "read",
        caveats.format_expires(now - 1),
        caveats.format_share_id(share_id),
    )
    with pytest.raises(Expired):
        verify(
            token,
            uploaded.file_id,
            store,
            revoked={share_id},
            now=now,
        )
