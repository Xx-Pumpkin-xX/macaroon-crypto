"""Tests for the caveat grammar (api-spec section 3)."""

from __future__ import annotations

import pytest

from macaroon_core import caveats
from macaroon_core.errors import BadRequest, InvalidToken


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("op = read", caveats.OpCaveat("read")),
        ("op = edit", caveats.OpCaveat("edit")),
        ("op = full", caveats.OpCaveat("full")),
        ("expires < 0", caveats.ExpiresCaveat(0)),
        ("expires < 1763164800", caveats.ExpiresCaveat(1763164800)),
        ("expires < 999999999999", caveats.ExpiresCaveat(999999999999)),
        (
            "share_id = 9f2c41d07ab35e18",
            caveats.ShareIdCaveat("9f2c41d07ab35e18"),
        ),
        (
            "share_id = 0000000000000000",
            caveats.ShareIdCaveat("0000000000000000"),
        ),
    ],
)
def test_parse_accepts_exact_forms(text, expected):
    assert caveats.parse_caveat(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "",
        "op=read",
        "op  = read",
        "op =  read",
        " op = read",
        "op = read ",
        "Op = read",
        "op = Read",
        "op = write",
        "op = fulls",
        "expires <",
        "expires < -1",
        "expires < abc",
        "expires < 1234567890123",
        "expires = 123456",
        "expires  < 123456",
        "share_id = 9F2C41D07AB35E18",
        "share_id = 9f2c41d07ab35e1",
        "share_id = 9f2c41d07ab35e18a",
        "share_id=9f2c41d07ab35e18",
        "admin = yes",
        "op = full\nextra",
    ],
)
def test_parse_rejects_everything_else(text):
    with pytest.raises(InvalidToken):
        caveats.parse_caveat(text)


def test_parse_rejects_non_strings():
    for value in (None, 1, b"op = full"):
        with pytest.raises(InvalidToken):
            caveats.parse_caveat(value)


def test_is_known_caveat():
    assert caveats.is_known_caveat("op = read")
    assert caveats.is_known_caveat("expires < 1")
    assert caveats.is_known_caveat("share_id = " + "a" * 16)
    assert not caveats.is_known_caveat("admin = yes")
    assert not caveats.is_known_caveat(None)


def test_lowest_op_wins():
    parsed = caveats.parse_caveats(["op = full", "op = read", "op = edit"])
    assert parsed.op == "read"
    assert parsed.count == 3


def test_no_op_caveat_is_none():
    parsed = caveats.parse_caveats(["expires < 10"])
    assert parsed.op is None


def test_earliest_expiry_wins():
    parsed = caveats.parse_caveats(
        ["op = read", "expires < 5000", "expires < 1000"]
    )
    assert parsed.expires_at == 1000


def test_every_share_id_is_kept():
    first = "1" * 16
    second = "2" * 16
    parsed = caveats.parse_caveats(
        [f"share_id = {first}", f"share_id = {second}", "op = read"]
    )
    assert parsed.share_ids == (first, second)


def test_parse_caveats_fails_closed_on_unknown_text():
    with pytest.raises(InvalidToken):
        caveats.parse_caveats(["op = read", "role = admin"])


@pytest.mark.parametrize("level", ["read", "edit", "full"])
def test_format_op_roundtrips(level):
    assert caveats.parse_caveat(caveats.format_op(level)) == caveats.OpCaveat(
        level
    )


def test_format_op_rejects_unknown_level():
    with pytest.raises(ValueError):
        caveats.format_op("admin")


@pytest.mark.parametrize("timestamp", [0, 1, 1763164800, 999999999999])
def test_format_expires_roundtrips(timestamp):
    assert caveats.parse_caveat(
        caveats.format_expires(timestamp)
    ) == caveats.ExpiresCaveat(timestamp)


@pytest.mark.parametrize("timestamp", [-1, 10**12, "1", 1.5, True, None])
def test_format_expires_rejects_bad_values(timestamp):
    with pytest.raises((TypeError, ValueError)):
        caveats.format_expires(timestamp)


def test_format_share_id_roundtrips():
    share_id = "9f2c41d07ab35e18"
    assert caveats.parse_caveat(
        caveats.format_share_id(share_id)
    ) == caveats.ShareIdCaveat(share_id)


@pytest.mark.parametrize(
    "share_id",
    ["", "9F2C41D07AB35E18", "9f2c41d07ab35e1", "z" * 16, 123, None],
)
def test_format_share_id_rejects_bad_values(share_id):
    with pytest.raises(ValueError):
        caveats.format_share_id(share_id)


@pytest.mark.parametrize("value", ["admin", "READ", "", None, 1, True, [], {}])
def test_validate_op(value):
    with pytest.raises(BadRequest):
        caveats.validate_op(value)


@pytest.mark.parametrize("level", caveats.PERMISSIONS)
def test_validate_op_accepts_permissions(level):
    assert caveats.validate_op(level) == level


@pytest.mark.parametrize("seconds", [60, 3600, 2_592_000])
def test_validate_expires_in_accepts_bounds(seconds):
    assert caveats.validate_expires_in(seconds) == seconds


@pytest.mark.parametrize(
    "seconds",
    [59, 2_592_001, -1, 1.5, "60", True, None],
)
def test_validate_expires_in_rejects_bad_values(seconds):
    with pytest.raises(BadRequest):
        caveats.validate_expires_in(seconds)
