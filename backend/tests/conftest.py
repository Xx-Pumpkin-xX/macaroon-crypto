"""Shared fixtures for the macaroon core unit tests.

Run from the repository root so the installed, patched pymacaroons is used
instead of the vendored source tree:

    python -m pytest backend/tests
"""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    # Append, not insert: ``backend/pymacaroons`` is a source checkout and
    # must not shadow the installed package at the front of sys.path.
    sys.path.append(str(BACKEND_DIR))

import pytest  # noqa: E402
from pymacaroons import Macaroon  # noqa: E402

from macaroon_core import (  # noqa: E402
    FileStore,
    caveats,
    create_file,
    tokens,
)

NOW = 1_700_000_000


@pytest.fixture
def now() -> int:
    return NOW


@pytest.fixture
def store(tmp_path: Path) -> FileStore:
    return FileStore(tmp_path / "storage")


@pytest.fixture
def uploaded(store: FileStore):
    """A stored file plus the full token returned by upload."""
    return create_file(b"nonce-and-ciphertext", store=store)


@pytest.fixture
def mint(store: FileStore):
    """Mint a valid token for a stored file with arbitrary valid caveats."""

    def _mint(file_id: str, *token_caveats: str) -> str:
        root_key = store.get_root_key(file_id)
        return tokens.mint_token(file_id, root_key, token_caveats)

    return _mint


@pytest.fixture
def narrow(mint):
    """Mint a token with an ``op`` caveat plus optional extra caveats."""

    def _narrow(file_id: str, op: str, *extra: str) -> str:
        return mint(file_id, caveats.format_op(op), *extra)

    return _narrow


@pytest.fixture
def sign(store: FileStore):
    """Sign arbitrary caveats with the real root key.

    Used to build tokens that are authentic but violate the grammar, and to
    simulate tampering at the serialization level.
    """

    def _sign(
        file_id: str,
        token_caveats,
        *,
        location: str = tokens.TOKEN_LOCATION,
        root_key: bytes | None = None,
    ) -> str:
        key = root_key if root_key is not None else store.get_root_key(file_id)
        macaroon = Macaroon(
            location=location,
            identifier=file_id,
            key=key,
        )
        for text in token_caveats:
            macaroon.add_first_party_caveat(text)
        return macaroon.serialize()

    return _sign
