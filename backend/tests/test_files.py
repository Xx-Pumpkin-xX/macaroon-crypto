"""Tests for the service functions behind the first three endpoints."""

from __future__ import annotations

import pytest
from pymacaroons import Macaroon

from macaroon_core import (
    MAX_BLOB_SIZE,
    caveats,
    create_file,
    read_file,
    replace_file,
    tokens,
)
from macaroon_core.errors import (
    BadRequest,
    Expired,
    Forbidden,
    InvalidToken,
    MissingToken,
    NotFound,
    Revoked,
    TooLarge,
)


# -- POST /api/files -----------------------------------------------------


def test_upload_returns_id_and_full_token(store, uploaded):
    result = read_file(uploaded.file_id, uploaded.token, store=store)
    assert result.blob == b"nonce-and-ciphertext"
    assert result.permission == "full"


@pytest.mark.parametrize("blob", [b"", None, "text", 42, ["x"]])
def test_upload_rejects_missing_or_non_bytes_body(store, blob):
    with pytest.raises(BadRequest):
        create_file(blob, store=store)


def test_upload_accepts_exactly_one_mib(store):
    result = create_file(b"a" * MAX_BLOB_SIZE, store=store)
    assert len(store.get_blob(result.file_id)) == MAX_BLOB_SIZE


def test_upload_rejects_over_one_mib(store):
    with pytest.raises(TooLarge):
        create_file(b"a" * (MAX_BLOB_SIZE + 1), store=store)


def test_upload_accepts_bytearray(store):
    result = create_file(bytearray(b"abc"), store=store)
    assert store.get_blob(result.file_id) == b"abc"


def test_upload_does_not_write_the_token_to_disk(store, uploaded):
    directory = store.files_dir / uploaded.file_id
    for path in directory.iterdir():
        assert uploaded.token.encode("utf-8") not in path.read_bytes()


# -- GET /api/files/{file_id} -------------------------------------------


@pytest.mark.parametrize(
    ("op", "expected"),
    [("read", "read"), ("edit", "edit"), ("full", "full")],
)
def test_read_reports_the_effective_permission(
    store, uploaded, narrow, op, expected
):
    token = narrow(uploaded.file_id, op)
    result = read_file(uploaded.file_id, token, store=store)
    assert result.permission == expected
    assert result.blob == b"nonce-and-ciphertext"


def test_read_fails_without_token(store, uploaded):
    with pytest.raises(MissingToken):
        read_file(uploaded.file_id, None, store=store)


def test_read_with_a_token_for_another_file_is_invalid(store):
    first = create_file(b"first", store=store)
    second = create_file(b"second", store=store)
    with pytest.raises(InvalidToken):
        read_file(second.file_id, first.token, store=store)


def test_read_unknown_file_with_matching_identifier_is_not_found(store, sign):
    unknown_id = "A" * 22
    token = sign(unknown_id, ["op = full"], root_key=b"z" * 32)
    with pytest.raises(NotFound):
        read_file(unknown_id, token, store=store)


def test_read_after_delete_is_not_found(store, uploaded):
    store.delete_file(uploaded.file_id)
    with pytest.raises(NotFound):
        read_file(uploaded.file_id, uploaded.token, store=store)


def test_read_expired_token(store, uploaded, narrow, now):
    token = narrow(
        uploaded.file_id, "read", caveats.format_expires(now - 1)
    )
    with pytest.raises(Expired):
        read_file(uploaded.file_id, token, store=store, now=now)


def test_read_revoked_token(store, uploaded, narrow, now):
    share_id = "9f2c41d07ab35e18"
    token = narrow(
        uploaded.file_id, "read", caveats.format_share_id(share_id)
    )
    store.revoke_share_id(uploaded.file_id, share_id)
    with pytest.raises(Revoked):
        read_file(uploaded.file_id, token, store=store, now=now)


def test_read_with_no_op_is_forbidden(store, uploaded, sign):
    token = sign(
        uploaded.file_id,
        [caveats.format_share_id("9f2c41d07ab35e18")],
    )
    with pytest.raises(Forbidden):
        read_file(uploaded.file_id, token, store=store)


# -- PUT /api/files/{file_id} -------------------------------------------


@pytest.mark.parametrize("op", ["edit", "full"])
def test_edit_with_edit_or_full_token(store, uploaded, narrow, op):
    token = narrow(uploaded.file_id, op)
    replace_file(uploaded.file_id, token, b"new blob", store=store)
    assert store.get_blob(uploaded.file_id) == b"new blob"


def test_read_cannot_edit(store, uploaded, narrow):
    token = narrow(uploaded.file_id, "read")
    with pytest.raises(Forbidden):
        replace_file(uploaded.file_id, token, b"hijacked", store=store)
    assert store.get_blob(uploaded.file_id) == b"nonce-and-ciphertext"


def test_no_op_token_cannot_edit(store, uploaded, sign):
    token = sign(
        uploaded.file_id,
        [caveats.format_share_id("9f2c41d07ab35e18")],
    )
    with pytest.raises(Forbidden):
        replace_file(uploaded.file_id, token, b"x", store=store)


def test_edit_fails_without_token(store, uploaded):
    with pytest.raises(MissingToken):
        replace_file(uploaded.file_id, None, b"x", store=store)


def test_edit_rejects_empty_body(store, uploaded):
    with pytest.raises(BadRequest):
        replace_file(uploaded.file_id, uploaded.token, b"", store=store)


def test_edit_rejects_over_one_mib(store, uploaded):
    with pytest.raises(TooLarge):
        replace_file(
            uploaded.file_id,
            uploaded.token,
            b"a" * (MAX_BLOB_SIZE + 1),
            store=store,
        )


def test_edit_accepts_exactly_one_mib(store, uploaded):
    replace_file(
        uploaded.file_id,
        uploaded.token,
        b"a" * MAX_BLOB_SIZE,
        store=store,
    )
    assert len(store.get_blob(uploaded.file_id)) == MAX_BLOB_SIZE


def test_edit_checks_authorization_before_the_body(store, uploaded, narrow):
    token = narrow(uploaded.file_id, "read")
    with pytest.raises(Forbidden):
        replace_file(
            uploaded.file_id,
            token,
            b"a" * (MAX_BLOB_SIZE + 1),
            store=store,
        )


def test_edit_expired_and_revoked_tokens(store, uploaded, narrow, now):
    expired = narrow(
        uploaded.file_id, "edit", caveats.format_expires(now - 1)
    )
    with pytest.raises(Expired):
        replace_file(uploaded.file_id, expired, b"x", store=store, now=now)

    share_id = "9f2c41d07ab35e18"
    revoked = narrow(
        uploaded.file_id, "edit", caveats.format_share_id(share_id)
    )
    store.revoke_share_id(uploaded.file_id, share_id)
    with pytest.raises(Revoked):
        replace_file(uploaded.file_id, revoked, b"x", store=store, now=now)


# -- permission matrix (acceptance item 13) -----------------------------


@pytest.mark.parametrize(
    ("op", "can_edit"),
    [("read", False), ("edit", True), ("full", True)],
)
def test_permission_matrix(store, op, can_edit, narrow):
    file = create_file(b"original", store=store)
    token = narrow(file.file_id, op)

    # Every permission can read.
    assert read_file(file.file_id, token, store=store).blob == b"original"

    if can_edit:
        replace_file(file.file_id, token, b"changed", store=store)
        assert store.get_blob(file.file_id) == b"changed"
    else:
        with pytest.raises(Forbidden):
            replace_file(file.file_id, token, b"changed", store=store)
        assert store.get_blob(file.file_id) == b"original"


def test_revocation_affects_tokens_derived_from_the_same_share(
    store, uploaded, mint, now
):
    """A token that copied a revoked share_id is rejected too."""
    share_id = "9f2c41d07ab35e18"
    first = mint(
        uploaded.file_id,
        caveats.format_op("read"),
        caveats.format_share_id(share_id),
    )
    derived = mint(
        uploaded.file_id,
        caveats.format_op("read"),
        caveats.format_expires(now + 3600),
        caveats.format_share_id(share_id),
        caveats.format_share_id("7" * 16),
    )

    store.revoke_share_id(uploaded.file_id, share_id)
    for token in (first, derived):
        with pytest.raises(Revoked):
            read_file(uploaded.file_id, token, store=store, now=now)


# -- attenuation (the share endpoint's building blocks) -----------------


def test_adding_op_full_does_not_widen_a_read_token(store, uploaded, narrow):
    token = narrow(uploaded.file_id, "read")
    macaroon = tokens.decode_token(token, uploaded.file_id)
    macaroon.add_first_party_caveat(caveats.format_op("full"))
    widened = macaroon.serialize()

    result = read_file(uploaded.file_id, widened, store=store)
    assert result.permission == "read"
    with pytest.raises(Forbidden):
        replace_file(uploaded.file_id, widened, b"x", store=store)


def test_adding_a_past_expiry_narrows_a_token(store, uploaded, narrow, now):
    token = narrow(uploaded.file_id, "read")
    macaroon = tokens.decode_token(token, uploaded.file_id)
    macaroon.add_first_party_caveat(caveats.format_expires(now - 1))
    narrowed = macaroon.serialize()

    with pytest.raises(Expired):
        read_file(uploaded.file_id, narrowed, store=store, now=now)


def test_share_style_attenuation_then_revocation(store, uploaded):
    """Mirror the flow documented in CORE_INTERFACE.md."""
    share_id = "9f2c41d07ab35e18"
    share = tokens.decode_token(uploaded.token, uploaded.file_id)
    share.add_first_party_caveat(caveats.format_op("read"))
    share.add_first_party_caveat(caveats.format_expires(1_900_000_000))
    share.add_first_party_caveat(caveats.format_share_id(share_id))
    share_token = share.serialize()
    store.add_issued_share_id(uploaded.file_id, share_id)

    assert read_file(uploaded.file_id, share_token, store=store).blob
    assert store.is_share_issued(uploaded.file_id, share_id)

    # The recipient derives a further token from the share before it is
    # revoked; the new token keeps the original share_id caveat.
    further = Macaroon.deserialize(share_token)
    further.add_first_party_caveat(caveats.format_share_id("8" * 16))
    further_token = further.serialize()

    store.revoke_share_id(uploaded.file_id, share_id)
    with pytest.raises(Revoked):
        read_file(uploaded.file_id, share_token, store=store)
    with pytest.raises(Revoked):
        read_file(uploaded.file_id, further_token, store=store)
