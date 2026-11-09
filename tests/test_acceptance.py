"""Black-box service acceptance and hostile-token cases from API spec v1."""
import hashlib
import hmac

import pytest
from pymacaroons import Macaroon
from macaroon_core import (
    FileStore, create_file, read_file, replace_file, create_share,
    revoke_share, delete_file, tokens, errors,
)

NOW = 1_800_000_000

@pytest.fixture
def setup(tmp_path):
    store = FileStore(tmp_path / 'storage')
    owner = create_file(b'original encrypted blob', store)
    return store, owner

@pytest.mark.parametrize('op', ['read', 'edit', 'full'])
@pytest.mark.parametrize('action', ['read', 'edit', 'revoke', 'delete'])
def test_permission_matrix(setup, op, action):
    store, owner = setup
    caller = create_share(owner.token, op, 60, store, NOW)
    target = create_share(owner.token, 'read', 60, store, NOW)
    calls = {
        'read': lambda: read_file(owner.file_id, caller.token, store, NOW),
        'edit': lambda: replace_file(owner.file_id, caller.token, b'changed', store, NOW),
        'revoke': lambda: revoke_share(caller.token, target.share_id, store, NOW),
        'delete': lambda: delete_file(owner.file_id, caller.token, store, NOW),
    }
    allowed = action == 'read' or (action == 'edit' and op != 'read') or op == 'full'
    if allowed:
        result = calls[action]()
        if action == 'read':
            assert result.blob == b'original encrypted blob'
            assert result.permission == op
        elif action == 'edit':
            assert read_file(owner.file_id, owner.token, store, NOW).blob == b'changed'
        elif action == 'revoke':
            with pytest.raises(errors.Revoked):
                read_file(owner.file_id, target.token, store, NOW)
        else:
            with pytest.raises(errors.NotFound):
                read_file(owner.file_id, owner.token, store, NOW)
    else:
        with pytest.raises(errors.Forbidden):
            calls[action]()
        assert read_file(owner.file_id, owner.token, store, NOW).blob == b'original encrypted blob'
        assert read_file(owner.file_id, target.token, store, NOW).blob

@pytest.mark.parametrize('parent', ['read', 'edit', 'full'])
@pytest.mark.parametrize('child', ['read', 'edit', 'full'])
def test_share_matrix(setup, parent, child):
    store, owner = setup
    first = create_share(owner.token, parent, 60, store, NOW)
    if ['read', 'edit', 'full'].index(child) > ['read', 'edit', 'full'].index(parent):
        with pytest.raises(errors.BadRequest):
            create_share(first.token, child, 120, store, NOW)
    else:
        second = create_share(first.token, child, 120, store, NOW)
        assert read_file(owner.file_id, second.token, store, NOW).permission == child
        with pytest.raises(errors.Expired):
            read_file(owner.file_id, second.token, store, NOW + 60)

@pytest.mark.parametrize('attack', ['edit', 'remove', 'reorder', 'signature', 'wrong_file', 'unknown', 'too_many', 'too_long'])
def test_hostile_tokens(setup, attack):
    store, owner = setup
    share = create_share(owner.token, 'read', 60, store, NOW)
    m = Macaroon.deserialize(share.token)
    file_id = owner.file_id
    if attack == 'edit':
        m.caveats[1].caveat_id = 'op = full'
    elif attack == 'remove':
        m.caveats.pop(1)
    elif attack == 'reorder':
        m.caveats.reverse()
    elif attack == 'signature':
        m.signature = '00' * 32
    elif attack == 'wrong_file':
        file_id = create_file(b'other', store).file_id
    elif attack == 'unknown':
        m.add_first_party_caveat('admin = true')
    elif attack == 'too_many':
        for _ in range(21):
            m.add_first_party_caveat('op = read')
    value = 'A' * 4097 if attack == 'too_long' else m.serialize()
    with pytest.raises(errors.InvalidToken):
        read_file(file_id, value, store, NOW)

@pytest.mark.parametrize('added', ['edit', 'full'])
def test_append_cannot_escalate(setup, added):
    store, owner = setup
    share = create_share(owner.token, 'read', 60, store, NOW)
    m = Macaroon.deserialize(share.token)
    m.add_first_party_caveat('op = ' + added)
    assert read_file(owner.file_id, m.serialize(), store, NOW).permission == 'read'
    with pytest.raises(errors.Forbidden):
        replace_file(owner.file_id, m.serialize(), b'attack', store, NOW)

@pytest.mark.parametrize('offset', [60, 61])
def test_expiry_boundary(setup, offset):
    store, owner = setup
    share = create_share(owner.token, 'read', 60, store, NOW)
    assert read_file(owner.file_id, share.token, store, NOW + 59).blob
    with pytest.raises(errors.Expired):
        read_file(owner.file_id, share.token, store, NOW + offset)


def test_revocation_cascades_only_to_descendants(setup):
    store, owner = setup
    first = create_share(owner.token, 'edit', 120, store, NOW)
    child = create_share(first.token, 'read', 60, store, NOW)
    sibling = create_share(owner.token, 'read', 60, store, NOW)
    revoke_share(owner.token, first.share_id, store, NOW)
    for token in (first.token, child.token):
        with pytest.raises(errors.Revoked):
            read_file(owner.file_id, token, store, NOW)
    assert read_file(owner.file_id, sibling.token, store, NOW).blob
    assert read_file(owner.file_id, owner.token, store, NOW).blob


def test_independent_hmac(setup):
    store, owner = setup
    share = create_share(owner.token, 'read', 60, store, NOW)
    m = Macaroon.deserialize(share.token)
    digest = lambda key, data: hmac.new(key, data, hashlib.sha256).digest()
    derived = digest(b'macaroons-key-generator', store.get_root_key(owner.file_id))
    signature = digest(derived, owner.file_id.encode())
    for c in m.caveats:
        signature = digest(signature, c.caveat_id.encode())
    assert signature.hex() == m.signature

@pytest.mark.parametrize('value,exception', [(None, errors.MissingToken), ('garbage', errors.InvalidToken)])
def test_guessed_id_without_capability(setup, value, exception):
    store, owner = setup
    with pytest.raises(exception):
        read_file(owner.file_id, value, store, NOW)

@pytest.mark.parametrize('index', range(4))
def test_remove_each_caveat(setup, index):
    store, owner = setup
    share = create_share(owner.token, 'read', 60, store, NOW)
    m = Macaroon.deserialize(share.token)
    m.caveats.pop(index)
    with pytest.raises(errors.InvalidToken):
        read_file(owner.file_id, m.serialize(), store, NOW)
