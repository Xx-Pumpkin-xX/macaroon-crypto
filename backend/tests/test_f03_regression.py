"""Regression tests for F03: missing or malformed revocation state.

``shares.json`` is created together with the file. If it disappears later, an
empty state must not be invented: that would make previously revoked tokens
usable again. Reads must fail closed instead.
"""

from __future__ import annotations

import json

import pytest

from macaroon_core import (
    FileStore,
    create_file,
    create_share,
    read_file,
    replace_file,
)
from macaroon_core.errors import Revoked


def shares_path(store: FileStore, file_id: str):
    return store.files_dir / file_id / "shares.json"


def write_shares(store: FileStore, file_id: str, payload: object) -> None:
    shares_path(store, file_id).write_text(json.dumps(payload), encoding="utf-8")


def test_missing_state_fails_closed_for_share_accessors(store, uploaded):
    shares_path(store, uploaded.file_id).unlink()

    with pytest.raises(RuntimeError):
        store.get_issued_share_ids(uploaded.file_id)
    with pytest.raises(RuntimeError):
        store.get_revoked_share_ids(uploaded.file_id)
    with pytest.raises(RuntimeError):
        store.is_share_issued(uploaded.file_id, "0" * 16)
    with pytest.raises(RuntimeError):
        store.add_issued_share_id(uploaded.file_id, "0" * 16)
    with pytest.raises(RuntimeError):
        store.revoke_share_id(uploaded.file_id, "0" * 16)

    # Reads and rejected updates must not recreate an empty state.
    assert not shares_path(store, uploaded.file_id).exists()


def test_missing_state_fails_closed_for_file_endpoints(store, uploaded):
    shares_path(store, uploaded.file_id).unlink()

    with pytest.raises(RuntimeError):
        read_file(uploaded.file_id, uploaded.token, store=store)
    with pytest.raises(RuntimeError):
        replace_file(uploaded.file_id, uploaded.token, b"new", store=store)

    assert store.get_blob(uploaded.file_id) == b"nonce-and-ciphertext"


def test_missing_state_does_not_restore_revoked_token(store, uploaded, now):
    share = create_share(uploaded.token, "read", 60, store=store, now=now)
    store.revoke_share_id(uploaded.file_id, share.share_id)

    with pytest.raises(Revoked):
        read_file(uploaded.file_id, share.token, store=store, now=now)

    shares_path(store, uploaded.file_id).unlink()

    with pytest.raises(RuntimeError):
        read_file(uploaded.file_id, share.token, store=store, now=now)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"issued": []},
        {"revoked": []},
        {"issued": [], "revoked": {}},
        {"issued": "not-a-list", "revoked": []},
        {"issued": [], "revoked": None},
    ],
)
def test_missing_or_wrongly_typed_keys_fail_closed(store, uploaded, payload):
    write_shares(store, uploaded.file_id, payload)

    with pytest.raises(RuntimeError):
        store.get_revoked_share_ids(uploaded.file_id)


@pytest.mark.parametrize(
    "payload",
    [
        {"issued": ["not-a-share-id"], "revoked": []},
        {"issued": [], "revoked": ["not-a-share-id"]},
        {"issued": [], "revoked": [123]},
    ],
)
def test_invalid_share_ids_fail_closed(store, uploaded, payload):
    write_shares(store, uploaded.file_id, payload)

    with pytest.raises(RuntimeError):
        store.get_revoked_share_ids(uploaded.file_id)


def test_invalid_json_fails_closed(store, uploaded):
    shares_path(store, uploaded.file_id).write_bytes(b"{not json")

    with pytest.raises(RuntimeError):
        store.get_revoked_share_ids(uploaded.file_id)


def test_non_utf8_state_fails_closed(store, uploaded):
    shares_path(store, uploaded.file_id).write_bytes(b"\xff")

    with pytest.raises(RuntimeError):
        store.get_revoked_share_ids(uploaded.file_id)


def test_new_file_still_initializes_empty_state(store):
    result = create_file(b"new blob", store=store)

    assert shares_path(store, result.file_id).exists()
    assert store.get_issued_share_ids(result.file_id) == frozenset()
    assert store.get_revoked_share_ids(result.file_id) == frozenset()
