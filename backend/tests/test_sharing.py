"""Tests for the service functions behind share, revoke and delete."""

from __future__ import annotations

import dataclasses

import pytest

from macaroon_core import (
    MAX_CAVEATS,
    ShareResult,
    caveats,
    create_file,
    create_share,
    delete_file,
    ids,
    read_file,
    revoke_share,
    tokens,
)
from macaroon_core.errors import (
    BadRequest,
    CoreError,
    Expired,
    Forbidden,
    InvalidToken,
    MissingToken,
    NotFound,
    Revoked,
)

HOUR = 3600
MIN_LIFETIME = 60
MAX_LIFETIME = 2_592_000


def _permission(store, file_id, token, now):
    return read_file(file_id, token, store=store, now=now).permission


def _share(store, token, op="read", expires_in=HOUR, *, now):
    return create_share(token, op, expires_in, store=store, now=now)


def _unknown_file_token(sign):
    unknown_id = "A" * 22
    return sign(unknown_id, ["op = full"], root_key=b"z" * 32)


# -- POST /api/share ----------------------------------------------------


def test_share_result_is_a_frozen_dataclass(store, uploaded, now):
    result = _share(store, uploaded.token, now=now)
    assert isinstance(result, ShareResult)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.op = "full"


@pytest.mark.parametrize("op", ["read", "edit", "full"])
def test_full_token_can_share_any_op(store, uploaded, now, op):
    result = _share(store, uploaded.token, op, now=now)

    assert result.op == op
    assert result.expires_at == now + HOUR
    assert ids.is_valid_share_id(result.share_id)
    assert _permission(store, uploaded.file_id, result.token, now) == op


def test_share_id_is_recorded_as_issued(store, uploaded, now):
    result = _share(store, uploaded.token, now=now)
    assert result.share_id in store.get_issued_share_ids(uploaded.file_id)
    assert store.is_share_issued(uploaded.file_id, result.share_id)


def test_each_share_gets_a_new_share_id(store, uploaded, now):
    first = _share(store, uploaded.token, now=now)
    second = _share(store, uploaded.token, now=now)
    assert first.share_id != second.share_id
    assert store.get_issued_share_ids(uploaded.file_id) == {
        first.share_id,
        second.share_id,
    }


@pytest.mark.parametrize("op", ["read", "edit"])
def test_edit_token_can_narrow_or_keep_its_op(
    store, uploaded, narrow, now, op
):
    token = narrow(uploaded.file_id, "edit")
    result = _share(store, token, op, now=now)
    assert _permission(store, uploaded.file_id, result.token, now) == op


def test_edit_token_cannot_share_full(store, uploaded, narrow, now):
    token = narrow(uploaded.file_id, "edit")
    with pytest.raises(BadRequest):
        _share(store, token, "full", now=now)
    assert not store.get_issued_share_ids(uploaded.file_id)


@pytest.mark.parametrize("op", ["edit", "full"])
def test_read_token_cannot_raise_its_op(store, uploaded, narrow, now, op):
    token = narrow(uploaded.file_id, "read")
    with pytest.raises(BadRequest):
        _share(store, token, op, now=now)
    assert not store.get_issued_share_ids(uploaded.file_id)


def test_read_token_can_share_read(store, uploaded, narrow, now):
    token = narrow(uploaded.file_id, "read")
    result = _share(store, token, "read", now=now)
    assert _permission(store, uploaded.file_id, result.token, now) == "read"


def test_sharing_from_a_share_never_widens_it(store, uploaded, now):
    read_share = _share(store, uploaded.token, "read", now=now)
    with pytest.raises(BadRequest):
        _share(store, read_share.token, "edit", now=now)

    child = _share(store, read_share.token, "read", now=now)
    assert _permission(store, uploaded.file_id, child.token, now) == "read"


@pytest.mark.parametrize("op", ["", "admin", "delete", "FULL"])
def test_share_rejects_invalid_op(store, uploaded, now, op):
    with pytest.raises(BadRequest):
        _share(store, uploaded.token, op, now=now)


@pytest.mark.parametrize(
    "expires_in",
    [0, -1, MIN_LIFETIME - 1, MAX_LIFETIME + 1],
)
def test_share_rejects_out_of_range_expires_in(
    store, uploaded, now, expires_in
):
    with pytest.raises(BadRequest):
        _share(store, uploaded.token, "read", expires_in, now=now)
    assert not store.get_issued_share_ids(uploaded.file_id)


@pytest.mark.parametrize("expires_in", [MIN_LIFETIME, MAX_LIFETIME])
def test_share_accepts_the_lifetime_boundaries(
    store, uploaded, now, expires_in
):
    result = _share(store, uploaded.token, "read", expires_in, now=now)
    assert result.expires_at == now + expires_in


def test_share_expires_after_its_lifetime(store, uploaded, now):
    result = _share(store, uploaded.token, "read", MIN_LIFETIME, now=now)
    assert _permission(store, uploaded.file_id, result.token, now) == "read"
    with pytest.raises(Expired):
        read_file(
            uploaded.file_id,
            result.token,
            store=store,
            now=result.expires_at + 1,
        )


def test_share_does_not_change_the_callers_token(store, uploaded, now):
    original = uploaded.token
    result = _share(store, original, "read", now=now)
    assert result.token != original
    assert _permission(store, uploaded.file_id, original, now) == "full"


def test_share_requires_a_token(store, now):
    with pytest.raises(CoreError) as error:
        _share(store, None, now=now)
    assert error.value.status == 401


@pytest.mark.parametrize("token", ["", "not-a-token", "AAAA"])
def test_share_rejects_a_malformed_token(store, now, token):
    with pytest.raises(CoreError) as error:
        _share(store, token, now=now)
    assert error.value.status == 401


def test_share_for_an_unknown_file_is_not_found(store, sign, now):
    with pytest.raises(NotFound):
        _share(store, _unknown_file_token(sign), now=now)


def test_share_for_a_deleted_file_is_not_found(store, uploaded, now):
    store.delete_file(uploaded.file_id)
    with pytest.raises(NotFound):
        _share(store, uploaded.token, now=now)


def test_share_with_a_wrong_root_key_is_invalid(store, uploaded, sign, now):
    forged = sign(uploaded.file_id, ["op = full"], root_key=b"z" * 32)
    with pytest.raises(InvalidToken):
        _share(store, forged, now=now)
    assert not store.get_issued_share_ids(uploaded.file_id)


def test_share_with_an_expired_token(store, uploaded, narrow, now):
    token = narrow(uploaded.file_id, "full", caveats.format_expires(now - 1))
    with pytest.raises(Expired):
        _share(store, token, now=now)


def test_share_with_a_revoked_token(store, uploaded, narrow, now):
    share_id = "9f2c41d07ab35e18"
    token = narrow(uploaded.file_id, "full", caveats.format_share_id(share_id))
    store.revoke_share_id(uploaded.file_id, share_id)
    with pytest.raises(Revoked):
        _share(store, token, now=now)


def test_share_with_a_token_that_has_no_op(store, uploaded, sign, now):
    token = sign(
        uploaded.file_id,
        [caveats.format_share_id("9f2c41d07ab35e18")],
    )
    with pytest.raises((BadRequest, Forbidden)):
        _share(store, token, now=now)


def test_share_chain_stops_at_the_token_limits(store, uploaded, now):
    token = uploaded.token
    created = 0
    with pytest.raises(BadRequest):
        for _ in range(MAX_CAVEATS):
            token = _share(store, token, "read", now=now).token
            created += 1

    assert created >= 1
    # The rejected share must not be recorded as issued.
    assert len(store.get_issued_share_ids(uploaded.file_id)) == created


# -- POST /api/revoke ---------------------------------------------------


def test_full_token_can_revoke_an_issued_share(store, uploaded, now):
    share = _share(store, uploaded.token, now=now)
    revoke_share(uploaded.token, share.share_id, store=store, now=now)

    assert share.share_id in store.get_revoked_share_ids(uploaded.file_id)
    with pytest.raises(Revoked):
        read_file(uploaded.file_id, share.token, store=store, now=now)


def test_revoke_invalidates_tokens_derived_from_the_share(
    store, uploaded, now
):
    share = _share(store, uploaded.token, now=now)
    derived = tokens.decode_token(share.token, uploaded.file_id)
    derived.add_first_party_caveat(caveats.format_share_id("8" * 16))
    derived_token = derived.serialize()
    child = _share(store, share.token, "read", now=now)

    revoke_share(uploaded.token, share.share_id, store=store, now=now)

    for token in (share.token, derived_token, child.token):
        with pytest.raises(Revoked):
            read_file(uploaded.file_id, token, store=store, now=now)


def test_revoking_one_share_leaves_the_others_working(
    store, uploaded, now
):
    first = _share(store, uploaded.token, now=now)
    second = _share(store, uploaded.token, now=now)

    revoke_share(uploaded.token, first.share_id, store=store, now=now)

    assert _permission(store, uploaded.file_id, second.token, now) == "read"
    assert _permission(store, uploaded.file_id, uploaded.token, now) == "full"


def test_revoke_is_idempotent(store, uploaded, now):
    share = _share(store, uploaded.token, now=now)
    revoke_share(uploaded.token, share.share_id, store=store, now=now)
    revoke_share(uploaded.token, share.share_id, store=store, now=now)
    assert store.get_revoked_share_ids(uploaded.file_id) == {share.share_id}


@pytest.mark.parametrize("op", ["read", "edit"])
def test_read_and_edit_tokens_cannot_revoke(
    store, uploaded, narrow, now, op
):
    share = _share(store, uploaded.token, now=now)
    token = narrow(uploaded.file_id, op)
    with pytest.raises(Forbidden):
        revoke_share(token, share.share_id, store=store, now=now)
    assert not store.get_revoked_share_ids(uploaded.file_id)


def test_a_read_share_cannot_revoke(store, uploaded, now):
    target = _share(store, uploaded.token, now=now)
    read_share = _share(store, uploaded.token, "read", now=now)
    with pytest.raises(Forbidden):
        revoke_share(read_share.token, target.share_id, store=store, now=now)


def test_a_full_share_can_revoke(store, uploaded, now):
    target = _share(store, uploaded.token, now=now)
    full_share = _share(store, uploaded.token, "full", now=now)
    revoke_share(full_share.token, target.share_id, store=store, now=now)
    assert target.share_id in store.get_revoked_share_ids(uploaded.file_id)


def test_revoke_rejects_a_never_issued_share_id(store, uploaded, now):
    with pytest.raises(NotFound):
        revoke_share(
            uploaded.token, "9f2c41d07ab35e18", store=store, now=now
        )
    assert not store.get_revoked_share_ids(uploaded.file_id)


def test_revoke_cannot_target_a_share_of_another_file(store, uploaded, now):
    other = create_file(b"other", store=store)
    foreign = _share(store, other.token, now=now)
    with pytest.raises(NotFound):
        revoke_share(uploaded.token, foreign.share_id, store=store, now=now)
    assert not store.get_revoked_share_ids(other.file_id)


@pytest.mark.parametrize(
    "share_id",
    ["", "xyz", "9f2c41d0", "9F2C41D07AB35E18", "9f2c41d07ab35e18ff"],
)
def test_revoke_rejects_a_malformed_share_id(
    store, uploaded, now, share_id
):
    with pytest.raises(BadRequest):
        revoke_share(uploaded.token, share_id, store=store, now=now)


def test_revoke_checks_permission_before_the_share_id(
    store, uploaded, narrow, now
):
    token = narrow(uploaded.file_id, "edit")
    with pytest.raises(Forbidden):
        revoke_share(token, "not-hex", store=store, now=now)


def test_revoke_requires_a_token(store, now):
    with pytest.raises(CoreError) as error:
        revoke_share(None, "9f2c41d07ab35e18", store=store, now=now)
    assert error.value.status == 401


def test_revoke_for_an_unknown_file_is_not_found(store, sign, now):
    with pytest.raises(NotFound):
        revoke_share(
            _unknown_file_token(sign),
            "9f2c41d07ab35e18",
            store=store,
            now=now,
        )


def test_revoke_with_an_expired_token(store, uploaded, narrow, now):
    share = _share(store, uploaded.token, now=now)
    token = narrow(uploaded.file_id, "full", caveats.format_expires(now - 1))
    with pytest.raises(Expired):
        revoke_share(token, share.share_id, store=store, now=now)


# -- DELETE /api/files/{file_id} ----------------------------------------


def test_full_token_deletes_everything(store, uploaded, now):
    share = _share(store, uploaded.token, now=now)
    directory = store.files_dir / uploaded.file_id
    assert directory.exists()

    delete_file(uploaded.file_id, uploaded.token, store=store, now=now)

    assert not directory.exists()
    with pytest.raises(NotFound):
        store.get_root_key(uploaded.file_id)
    with pytest.raises(NotFound):
        store.get_blob(uploaded.file_id)
    for token in (uploaded.token, share.token):
        with pytest.raises(NotFound):
            read_file(uploaded.file_id, token, store=store, now=now)


def test_delete_leaves_other_files_alone(store, uploaded, now):
    other = create_file(b"other", store=store)
    delete_file(uploaded.file_id, uploaded.token, store=store, now=now)
    assert read_file(other.file_id, other.token, store=store).blob == b"other"


@pytest.mark.parametrize("op", ["read", "edit"])
def test_read_and_edit_tokens_cannot_delete(
    store, uploaded, narrow, now, op
):
    token = narrow(uploaded.file_id, op)
    with pytest.raises(Forbidden):
        delete_file(uploaded.file_id, token, store=store, now=now)
    assert store.get_blob(uploaded.file_id) == b"nonce-and-ciphertext"


def test_a_read_share_cannot_delete(store, uploaded, now):
    share = _share(store, uploaded.token, "read", now=now)
    with pytest.raises(Forbidden):
        delete_file(uploaded.file_id, share.token, store=store, now=now)
    assert store.get_blob(uploaded.file_id) == b"nonce-and-ciphertext"


def test_a_full_share_can_delete(store, uploaded, now):
    share = _share(store, uploaded.token, "full", now=now)
    delete_file(uploaded.file_id, share.token, store=store, now=now)
    with pytest.raises(NotFound):
        store.get_root_key(uploaded.file_id)


def test_delete_requires_a_token(store, uploaded, now):
    with pytest.raises(MissingToken):
        delete_file(uploaded.file_id, None, store=store, now=now)
    assert store.get_blob(uploaded.file_id) == b"nonce-and-ciphertext"


def test_delete_with_a_token_for_another_file_is_invalid(store, now):
    first = create_file(b"first", store=store)
    second = create_file(b"second", store=store)
    with pytest.raises(InvalidToken):
        delete_file(second.file_id, first.token, store=store, now=now)
    assert store.get_blob(second.file_id) == b"second"


def test_delete_unknown_file_is_not_found(store, sign, now):
    unknown_id = "A" * 22
    token = sign(unknown_id, ["op = full"], root_key=b"z" * 32)
    with pytest.raises(NotFound):
        delete_file(unknown_id, token, store=store, now=now)


def test_delete_twice_is_not_found(store, uploaded, now):
    delete_file(uploaded.file_id, uploaded.token, store=store, now=now)
    with pytest.raises(NotFound):
        delete_file(uploaded.file_id, uploaded.token, store=store, now=now)


def test_delete_with_an_expired_token(store, uploaded, narrow, now):
    token = narrow(uploaded.file_id, "full", caveats.format_expires(now - 1))
    with pytest.raises(Expired):
        delete_file(uploaded.file_id, token, store=store, now=now)
    assert store.get_blob(uploaded.file_id) == b"nonce-and-ciphertext"


def test_delete_with_a_revoked_token(store, uploaded, narrow, now):
    share_id = "9f2c41d07ab35e18"
    token = narrow(uploaded.file_id, "full", caveats.format_share_id(share_id))
    store.revoke_share_id(uploaded.file_id, share_id)
    with pytest.raises(Revoked):
        delete_file(uploaded.file_id, token, store=store, now=now)
    assert store.get_blob(uploaded.file_id) == b"nonce-and-ciphertext"
