"""Tests for the per-file file-system store."""

from __future__ import annotations

import json
import os
import stat

import pytest

from macaroon_core import FileStore, ids
from macaroon_core.errors import NotFound


def test_create_returns_valid_id_key_and_blob(store):
    blob = b"nonce||ciphertext"
    file_id, root_key = store.create(blob)

    assert ids.is_valid_file_id(file_id)
    assert len(file_id) == 22
    assert len(root_key) == ids.ROOT_KEY_BYTES
    assert store.exists(file_id)
    assert store.get_blob(file_id) == blob
    assert store.get_root_key(file_id) == root_key


def test_create_generates_unique_ids(store):
    file_ids = {store.create(b"x")[0] for _ in range(20)}
    assert len(file_ids) == 20


def test_created_shares_start_empty(store):
    file_id, _ = store.create(b"x")
    assert store.get_issued_share_ids(file_id) == frozenset()
    assert store.get_revoked_share_ids(file_id) == frozenset()


def test_shares_file_has_the_documented_shape(store):
    file_id, _ = store.create(b"x")
    payload = json.loads(
        (store.files_dir / file_id / "shares.json").read_text("utf-8")
    )
    assert payload == {"issued": [], "revoked": []}


def test_replace_blob(store):
    file_id, root_key = store.create(b"old")
    store.replace_blob(file_id, b"new")
    assert store.get_blob(file_id) == b"new"
    assert store.get_root_key(file_id) == root_key


def test_stored_files_are_not_world_readable(store):
    file_id, _ = store.create(b"secret")
    directory = store.files_dir / file_id
    for name in ("blob", "root_key", "shares.json"):
        mode = stat.S_IMODE(os.stat(directory / name).st_mode)
        assert mode == 0o600, name
    assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700


@pytest.mark.parametrize(
    "file_id",
    [
        "does-not-exist",
        "",
        None,
        "../etc/passwd",
        "A" * 21,
        "A" * 23,
        "A" * 21 + "/",
        "A" * 21 + ".",
    ],
)
def test_unknown_or_malformed_file_id_is_not_found(store, file_id):
    with pytest.raises(NotFound):
        store.get_blob(file_id)
    with pytest.raises(NotFound):
        store.get_root_key(file_id)
    with pytest.raises(NotFound):
        store.replace_blob(file_id, b"x")


def test_unknown_file_is_not_found_for_share_reads(store):
    with pytest.raises(NotFound):
        store.get_issued_share_ids("A" * 22)


def test_path_traversal_does_not_escape_the_store(store):
    file_id, _ = store.create(b"x")
    escaped = store.root.parent / "escaped"
    # A traversal attempt is rejected before any path is built.
    with pytest.raises(NotFound):
        store.get_blob("../" + file_id)
    assert not escaped.exists()


def test_delete_file(store):
    file_id, _ = store.create(b"x")
    store.delete_file(file_id)
    assert not store.exists(file_id)
    with pytest.raises(NotFound):
        store.get_blob(file_id)
    with pytest.raises(NotFound):
        store.delete_file(file_id)


def test_issued_and_revoked_shares_persist(store, tmp_path):
    file_id, _ = store.create(b"x")
    first = "1" * 16
    second = "2" * 16

    store.add_issued_share_id(file_id, first)
    store.revoke_share_id(file_id, second)

    reopened = FileStore(tmp_path / "storage")
    assert reopened.get_issued_share_ids(file_id) == frozenset({first})
    assert reopened.get_revoked_share_ids(file_id) == frozenset({second})
    assert reopened.is_share_issued(file_id, first)
    assert not reopened.is_share_issued(file_id, second)


def test_share_updates_are_idempotent(store):
    file_id, _ = store.create(b"x")
    share_id = "9f2c41d07ab35e18"
    store.add_issued_share_id(file_id, share_id)
    store.add_issued_share_id(file_id, share_id)
    store.revoke_share_id(file_id, share_id)
    store.revoke_share_id(file_id, share_id)
    assert store.get_issued_share_ids(file_id) == frozenset({share_id})
    assert store.get_revoked_share_ids(file_id) == frozenset({share_id})


@pytest.mark.parametrize(
    "share_id",
    ["", "9F2C41D07AB35E18", "9f2c41d07ab35e1", "z" * 16, None, 123],
)
def test_invalid_share_ids_are_rejected(store, share_id):
    file_id, _ = store.create(b"x")
    with pytest.raises(ValueError):
        store.add_issued_share_id(file_id, share_id)
    with pytest.raises(ValueError):
        store.revoke_share_id(file_id, share_id)


def test_share_updates_need_an_existing_file(store):
    with pytest.raises(NotFound):
        store.add_issued_share_id("A" * 22, "9f2c41d07ab35e18")


def test_create_rejects_non_bytes(store):
    with pytest.raises(TypeError):
        store.create("not bytes")
