"""HTTP tests for the first three API endpoints.

These exercise the Flask boundary only: status codes, JSON error shape,
headers, authorization parsing and the mapping of core errors. The macaroon
semantics themselves are covered by the core unit tests.
"""

from __future__ import annotations

import base64
import logging
import time

import pytest

import app as app_module
from macaroon_core import MAX_BLOB_SIZE, caveats, create_file


@pytest.fixture
def application(store):
    return app_module.create_app(store=store)


@pytest.fixture
def client(application):
    return application.test_client()


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def file_path(file_id: str) -> str:
    return f"/api/files/{file_id}"


def assert_error(response, status: int, code: str) -> None:
    assert response.status_code == status
    assert response.mimetype == "application/json"
    body = response.get_json()
    assert set(body) == {"error", "message"}
    assert body["error"] == code
    assert body["message"]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# -- POST /api/files ------------------------------------------------------


def test_upload_returns_file_id_and_full_token(client, store):
    response = client.post("/api/files", data=b"nonce-and-ciphertext")

    assert response.status_code == 201
    body = response.get_json()
    assert set(body) == {"file_id", "token"}
    assert len(body["file_id"]) == 22
    assert store.get_blob(body["file_id"]) == b"nonce-and-ciphertext"

    download = client.get(file_path(body["file_id"]), headers=bearer(body["token"]))
    assert download.status_code == 200
    assert download.data == b"nonce-and-ciphertext"
    assert download.headers["X-Permission"] == "full"


def test_upload_ignores_content_type(client):
    response = client.post("/api/files", data=b"blob", content_type="text/plain")
    assert response.status_code == 201


def test_upload_rejects_empty_body(client):
    assert_error(client.post("/api/files", data=b""), 400, "bad_request")


def test_upload_accepts_exactly_one_mib(client):
    response = client.post("/api/files", data=b"x" * MAX_BLOB_SIZE)
    assert response.status_code == 201


def test_upload_rejects_oversized_body(client):
    response = client.post("/api/files", data=b"x" * (MAX_BLOB_SIZE + 1))
    assert_error(response, 413, "too_large")


# -- GET /api/files/{file_id} --------------------------------------------


def test_download_returns_blob_and_security_headers(client, uploaded):
    response = client.get(file_path(uploaded.file_id), headers=bearer(uploaded.token))

    assert response.status_code == 200
    assert response.data == b"nonce-and-ciphertext"
    assert response.headers["Content-Type"] == "application/octet-stream"
    assert response.headers["X-Permission"] == "full"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000"
    assert "camera=()" in response.headers["Permissions-Policy"]


@pytest.mark.parametrize("op", ["read", "edit", "full"])
def test_download_reports_effective_permission(client, uploaded, narrow, op):
    token = narrow(uploaded.file_id, op)

    response = client.get(file_path(uploaded.file_id), headers=bearer(token))

    assert response.status_code == 200
    assert response.headers["X-Permission"] == op


def test_missing_authorization_header_is_missing_token(client, uploaded):
    assert_error(
        client.get(file_path(uploaded.file_id)),
        401,
        "missing_token",
    )


@pytest.mark.parametrize(
    "headers",
    [
        {"Authorization": "Bearer"},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer  abc"},
        {"Authorization": "Bearer abc def"},
    ],
)
def test_malformed_authorization_header_is_invalid(client, uploaded, headers):
    response = client.get(file_path(uploaded.file_id), headers=headers)
    assert_error(response, 401, "invalid_token")


def test_bearer_scheme_is_case_insensitive(client, uploaded):
    response = client.get(
        file_path(uploaded.file_id),
        headers={"Authorization": f"bearer {uploaded.token}"},
    )
    assert response.status_code == 200


def test_garbage_token_is_invalid(client, uploaded):
    response = client.get(
        file_path(uploaded.file_id),
        headers=bearer("not-a-token"),
    )
    assert_error(response, 401, "invalid_token")


def test_token_for_another_file_is_invalid(client, store, uploaded):
    other = create_file(b"other", store=store)
    response = client.get(
        file_path(uploaded.file_id),
        headers=bearer(other.token),
    )
    assert_error(response, 401, "invalid_token")


def test_unknown_file_is_not_found(client, sign):
    file_id = "A" * 22
    token = sign(file_id, [caveats.format_op("full")], root_key=b"z" * 32)

    assert_error(
        client.get(file_path(file_id), headers=bearer(token)),
        404,
        "not_found",
    )


def test_deleted_file_is_not_found(client, store, uploaded):
    store.delete_file(uploaded.file_id)

    assert_error(
        client.get(file_path(uploaded.file_id), headers=bearer(uploaded.token)),
        404,
        "not_found",
    )


def test_missing_revocation_state_fails_closed(client, store, uploaded):
    (store.files_dir / uploaded.file_id / "shares.json").unlink()

    response = client.get(
        file_path(uploaded.file_id),
        headers=bearer(uploaded.token),
    )
    assert_error(response, 500, "internal_error")


def test_expired_token_is_forbidden(client, uploaded, narrow):
    token = narrow(uploaded.file_id, "read", caveats.format_expires(1))

    assert_error(
        client.get(file_path(uploaded.file_id), headers=bearer(token)),
        403,
        "expired",
    )


def test_revoked_share_token_is_forbidden(client, store, uploaded, narrow):
    share_id = "0123456789abcdef"
    token = narrow(
        uploaded.file_id,
        "read",
        caveats.format_share_id(share_id),
    )
    store.revoke_share_id(uploaded.file_id, share_id)

    assert_error(
        client.get(file_path(uploaded.file_id), headers=bearer(token)),
        403,
        "revoked",
    )


def test_token_without_op_is_forbidden(client, uploaded, mint):
    token = mint(uploaded.file_id)

    assert_error(
        client.get(file_path(uploaded.file_id), headers=bearer(token)),
        403,
        "forbidden",
    )


def test_tampered_token_is_invalid(client, uploaded):
    # Keep the caveat grammar valid, so only the HMAC can reject the token.
    raw = unb64url(uploaded.token)
    tampered = raw.replace(b"op = full", b"op = edit")
    assert tampered != raw

    response = client.get(
        file_path(uploaded.file_id),
        headers=bearer(b64url(tampered)),
    )
    assert_error(response, 401, "invalid_token")


def test_non_utf8_identifier_is_rejected_with_401(client, uploaded):
    """F02 end-to-end: the core rejects the identifier before the HTTP 500 path."""
    raw = unb64url(uploaded.token)
    mutated = raw.replace(
        uploaded.file_id.encode("ascii"),
        b"\xff" * len(uploaded.file_id),
    )
    assert mutated != raw

    response = client.get(
        file_path(uploaded.file_id),
        headers=bearer(b64url(mutated)),
    )
    assert_error(response, 401, "invalid_token")


# -- PUT /api/files/{file_id} --------------------------------------------


@pytest.mark.parametrize("op", ["edit", "full"])
def test_edit_allowed_with_edit_or_full(client, store, uploaded, narrow, op):
    token = narrow(uploaded.file_id, op)

    response = client.put(
        file_path(uploaded.file_id),
        data=b"new-blob",
        headers=bearer(token),
    )

    assert response.status_code == 204
    assert response.data == b""
    assert store.get_blob(uploaded.file_id) == b"new-blob"


def test_edit_denied_with_read_token(client, store, uploaded, narrow):
    before = store.get_blob(uploaded.file_id)

    response = client.put(
        file_path(uploaded.file_id),
        data=b"new-blob",
        headers=bearer(narrow(uploaded.file_id, "read")),
    )

    assert_error(response, 403, "forbidden")
    assert store.get_blob(uploaded.file_id) == before


def test_edit_requires_authorization(client, uploaded):
    assert_error(
        client.put(file_path(uploaded.file_id), data=b"new-blob"),
        401,
        "missing_token",
    )


def test_edit_rejects_empty_body(client, uploaded):
    response = client.put(
        file_path(uploaded.file_id),
        data=b"",
        headers=bearer(uploaded.token),
    )
    assert_error(response, 400, "bad_request")


def test_edit_rejects_oversized_body(client, uploaded):
    response = client.put(
        file_path(uploaded.file_id),
        data=b"x" * (MAX_BLOB_SIZE + 1),
        headers=bearer(uploaded.token),
    )
    assert_error(response, 413, "too_large")


def test_edit_accepts_exactly_one_mib(client, store, uploaded):
    response = client.put(
        file_path(uploaded.file_id),
        data=b"x" * MAX_BLOB_SIZE,
        headers=bearer(uploaded.token),
    )

    assert response.status_code == 204
    assert store.get_blob(uploaded.file_id) == b"x" * MAX_BLOB_SIZE


def test_edit_with_token_for_another_file_is_invalid(client, store, uploaded):
    other = create_file(b"other", store=store)

    response = client.put(
        file_path(uploaded.file_id),
        data=b"new-blob",
        headers=bearer(other.token),
    )
    assert_error(response, 401, "invalid_token")


# -- routing, error shape and headers ------------------------------------


def test_unknown_api_route_returns_json_404(client):
    assert_error(client.get("/api/unknown"), 404, "not_found")


def test_api_root_returns_json_404(client):
    assert_error(client.get("/api"), 404, "not_found")


def test_wrong_method_returns_json_405(client, uploaded):
    assert_error(
        client.patch(file_path(uploaded.file_id)),
        405,
        "bad_request",
    )


def test_error_responses_keep_security_headers(client, uploaded):
    response = client.get(
        file_path(uploaded.file_id),
        headers=bearer("garbage"),
    )

    assert response.status_code == 401
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"


# -- logging and unexpected errors ---------------------------------------


def test_logs_do_not_contain_token_or_root_key(
    client,
    application,
    store,
    uploaded,
    caplog,
):
    root_key = store.get_root_key(uploaded.file_id)

    with caplog.at_level(logging.INFO, logger=application.logger.name):
        response = client.get(
            file_path(uploaded.file_id),
            headers=bearer(uploaded.token),
        )

    assert response.status_code == 200
    assert uploaded.token not in caplog.text
    assert root_key.hex() not in caplog.text
    assert base64.b64encode(root_key).decode("ascii") not in caplog.text
    assert "GET" in caplog.text
    assert f"/api/files/{uploaded.file_id}" in caplog.text
    assert "200" in caplog.text


def test_logs_include_error_code(client, application, uploaded, caplog):
    with caplog.at_level(logging.INFO, logger=application.logger.name):
        client.get(
            file_path(uploaded.file_id),
            headers=bearer("garbage"),
        )

    assert "invalid_token" in caplog.text
    assert uploaded.token not in caplog.text


def test_unexpected_error_returns_generic_json(
    client,
    application,
    uploaded,
    monkeypatch,
    caplog,
):
    def boom(*args, **kwargs):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(app_module, "replace_file", boom)

    with caplog.at_level(logging.INFO, logger=application.logger.name):
        response = client.put(
            file_path(uploaded.file_id),
            data=b"new-blob",
            headers=bearer(uploaded.token),
        )

    assert_error(response, 500, "internal_error")
    assert "secret detail" not in response.get_data(as_text=True)
    assert "secret detail" not in caplog.text
    assert "internal_error" in caplog.text


# -- helpers for share / revoke / delete ----------------------------------

SHARE = "/api/share"
REVOKE = "/api/revoke"
UNKNOWN_ID = "A" * 22


def post_share(client, token, op="read", expires_in=3600):
    return client.post(
        SHARE,
        json={"op": op, "expires_in": expires_in},
        headers=bearer(token),
    )


def make_share(client, token, op="read", expires_in=3600) -> dict:
    response = post_share(client, token, op, expires_in)
    assert response.status_code == 200
    return response.get_json()


def post_revoke(client, token, share_id):
    return client.post(
        REVOKE,
        json={"share_id": share_id},
        headers=bearer(token),
    )


def get_file(client, file_id, token):
    return client.get(file_path(file_id), headers=bearer(token))


# -- POST /api/share ------------------------------------------------------


def test_share_returns_token_and_metadata(client, store, uploaded):
    before = int(time.time())
    response = post_share(client, uploaded.token, "read", 3600)
    after = int(time.time())

    assert response.status_code == 200
    body = response.get_json()
    assert set(body) == {"token", "share_id", "op", "expires_at"}
    assert body["op"] == "read"
    assert len(body["share_id"]) == 16
    assert before + 3600 <= body["expires_at"] <= after + 3600
    assert store.is_share_issued(uploaded.file_id, body["share_id"])

    download = get_file(client, uploaded.file_id, body["token"])
    assert download.status_code == 200
    assert download.headers["X-Permission"] == "read"


@pytest.mark.parametrize("op", ["read", "edit", "full"])
def test_full_token_can_share_every_level(client, uploaded, op):
    body = make_share(client, uploaded.token, op)

    assert body["op"] == op
    download = get_file(client, uploaded.file_id, body["token"])
    assert download.headers["X-Permission"] == op


def test_edit_token_can_share_edit_but_not_full(client, uploaded, narrow):
    token = narrow(uploaded.file_id, "edit")

    assert make_share(client, token, "edit")["op"] == "edit"
    assert_error(post_share(client, token, "full"), 400, "bad_request")


@pytest.mark.parametrize("op", ["edit", "full"])
def test_read_token_cannot_raise_its_op(client, store, uploaded, narrow, op):
    token = narrow(uploaded.file_id, "read")

    assert_error(post_share(client, token, op), 400, "bad_request")
    assert not store.get_issued_share_ids(uploaded.file_id)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{",
        b"[]",
        b'"read"',
        b"null",
        b"{}",
        b'{"op": "read"}',
        b'{"expires_in": 3600}',
        b'{"op": 1, "expires_in": 3600}',
        b'{"op": "admin", "expires_in": 3600}',
        b'{"op": "read", "expires_in": "3600"}',
        b'{"op": "read", "expires_in": true}',
        b'{"op": "read", "expires_in": 3600.5}',
        b'{"op": "read", "expires_in": 59}',
        b'{"op": "read", "expires_in": 2592001}',
    ],
)
def test_share_rejects_a_bad_body(client, store, uploaded, raw):
    response = client.post(
        SHARE,
        data=raw,
        content_type="application/json",
        headers=bearer(uploaded.token),
    )

    assert_error(response, 400, "bad_request")
    assert not store.get_issued_share_ids(uploaded.file_id)


def test_share_ignores_content_type(client, uploaded):
    response = client.post(
        SHARE,
        data=b'{"op": "read", "expires_in": 3600}',
        content_type="text/plain",
        headers=bearer(uploaded.token),
    )
    assert response.status_code == 200


def test_share_accepts_lifetime_boundaries(client, uploaded):
    assert make_share(client, uploaded.token, "read", 60)["op"] == "read"
    assert make_share(client, uploaded.token, "read", 2_592_000)["op"] == "read"


def test_share_requires_authorization(client):
    response = client.post(SHARE, json={"op": "read", "expires_in": 3600})
    assert_error(response, 401, "missing_token")


@pytest.mark.parametrize(
    "headers",
    [
        {"Authorization": "Bearer"},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer abc def"},
    ],
)
def test_share_malformed_header_is_invalid(client, headers):
    response = client.post(
        SHARE,
        json={"op": "read", "expires_in": 3600},
        headers=headers,
    )
    assert_error(response, 401, "invalid_token")


def test_share_garbage_token_is_invalid(client):
    assert_error(post_share(client, "not-a-token"), 401, "invalid_token")


def test_share_unknown_file_is_not_found(client, sign):
    token = sign(UNKNOWN_ID, [caveats.format_op("full")], root_key=b"z" * 32)
    assert_error(post_share(client, token), 404, "not_found")


def test_share_deleted_file_is_not_found(client, store, uploaded):
    store.delete_file(uploaded.file_id)
    assert_error(post_share(client, uploaded.token), 404, "not_found")


def test_share_expired_token_is_forbidden(client, uploaded, narrow):
    token = narrow(uploaded.file_id, "full", caveats.format_expires(1))
    assert_error(post_share(client, token), 403, "expired")


def test_share_revoked_token_is_forbidden(client, store, uploaded, narrow):
    share_id = "0123456789abcdef"
    token = narrow(uploaded.file_id, "full", caveats.format_share_id(share_id))
    store.revoke_share_id(uploaded.file_id, share_id)

    assert_error(post_share(client, token), 403, "revoked")


def test_share_checks_the_token_before_the_body(client, uploaded):
    """Spec 3.1: 401 comes before 400, even for an unreadable body."""
    response = client.post(
        SHARE,
        data=b"{",
        content_type="application/json",
        headers=bearer("garbage"),
    )
    assert_error(response, 401, "invalid_token")

    response = client.post(SHARE, data=b"{", content_type="application/json")
    assert_error(response, 401, "missing_token")


def test_share_response_keeps_security_headers(client, uploaded):
    response = post_share(client, uploaded.token)

    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_share_logs_do_not_contain_tokens(client, application, uploaded, caplog):
    with caplog.at_level(logging.INFO, logger=application.logger.name):
        body = make_share(client, uploaded.token)

    assert uploaded.token not in caplog.text
    assert body["token"] not in caplog.text
    assert "POST" in caplog.text
    assert SHARE in caplog.text


# -- POST /api/revoke -----------------------------------------------------


def test_revoke_returns_204_and_cuts_off_the_share(client, store, uploaded):
    share = make_share(client, uploaded.token)

    response = post_revoke(client, uploaded.token, share["share_id"])

    assert response.status_code == 204
    assert response.data == b""
    assert share["share_id"] in store.get_revoked_share_ids(uploaded.file_id)
    assert_error(
        get_file(client, uploaded.file_id, share["token"]),
        403,
        "revoked",
    )


def test_revoke_also_cuts_off_derived_tokens(client, uploaded):
    parent = make_share(client, uploaded.token)
    child = make_share(client, parent["token"])

    assert post_revoke(client, uploaded.token, parent["share_id"]).status_code == 204

    for token in (parent["token"], child["token"]):
        assert_error(get_file(client, uploaded.file_id, token), 403, "revoked")


def test_revoke_leaves_other_shares_working(client, uploaded):
    first = make_share(client, uploaded.token)
    second = make_share(client, uploaded.token)

    post_revoke(client, uploaded.token, first["share_id"])

    assert get_file(client, uploaded.file_id, second["token"]).status_code == 200
    assert get_file(client, uploaded.file_id, uploaded.token).status_code == 200


def test_revoke_is_idempotent(client, uploaded):
    share = make_share(client, uploaded.token)

    assert post_revoke(client, uploaded.token, share["share_id"]).status_code == 204
    assert post_revoke(client, uploaded.token, share["share_id"]).status_code == 204


@pytest.mark.parametrize("op", ["read", "edit"])
def test_revoke_needs_full(client, store, uploaded, narrow, op):
    share = make_share(client, uploaded.token)

    response = post_revoke(client, narrow(uploaded.file_id, op), share["share_id"])

    assert_error(response, 403, "forbidden")
    assert not store.get_revoked_share_ids(uploaded.file_id)


def test_revoke_never_issued_share_is_not_found(client, store, uploaded):
    response = post_revoke(client, uploaded.token, "9f2c41d07ab35e18")

    assert_error(response, 404, "not_found")
    assert not store.get_revoked_share_ids(uploaded.file_id)


def test_revoke_cannot_target_another_files_share(client, store, uploaded):
    other = create_file(b"other", store=store)
    foreign = make_share(client, other.token)

    response = post_revoke(client, uploaded.token, foreign["share_id"])

    assert_error(response, 404, "not_found")
    assert not store.get_revoked_share_ids(other.file_id)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{",
        b"[]",
        b"{}",
        b'{"share_id": null}',
        b'{"share_id": 5}',
        b'{"share_id": "zzzz"}',
        b'{"share_id": "9F2C41D07AB35E18"}',
        b'{"share_id": "9f2c41d07ab35e1"}',
    ],
)
def test_revoke_rejects_a_bad_body(client, uploaded, raw):
    response = client.post(
        REVOKE,
        data=raw,
        content_type="application/json",
        headers=bearer(uploaded.token),
    )
    assert_error(response, 400, "bad_request")


def test_revoke_requires_authorization(client):
    response = client.post(REVOKE, json={"share_id": "9f2c41d07ab35e18"})
    assert_error(response, 401, "missing_token")


def test_revoke_garbage_token_is_invalid(client):
    response = post_revoke(client, "not-a-token", "9f2c41d07ab35e18")
    assert_error(response, 401, "invalid_token")


def test_revoke_unknown_file_is_not_found(client, sign):
    token = sign(UNKNOWN_ID, [caveats.format_op("full")], root_key=b"z" * 32)
    assert_error(post_revoke(client, token, "9f2c41d07ab35e18"), 404, "not_found")


def test_revoke_checks_permission_before_the_body(client, uploaded, narrow):
    """403 comes before 400: an Edit token learns nothing about the body."""
    response = client.post(
        REVOKE,
        data=b"{",
        content_type="application/json",
        headers=bearer(narrow(uploaded.file_id, "edit")),
    )
    assert_error(response, 403, "forbidden")


# -- DELETE /api/files/{file_id} -----------------------------------------


def test_delete_removes_the_file(client, store, uploaded):
    share = make_share(client, uploaded.token)

    response = client.delete(
        file_path(uploaded.file_id),
        headers=bearer(uploaded.token),
    )

    assert response.status_code == 204
    assert response.data == b""
    assert not (store.files_dir / uploaded.file_id).exists()
    for token in (uploaded.token, share["token"]):
        assert_error(get_file(client, uploaded.file_id, token), 404, "not_found")


def test_delete_leaves_other_files_alone(client, store, uploaded):
    other = create_file(b"other", store=store)

    client.delete(file_path(uploaded.file_id), headers=bearer(uploaded.token))

    assert get_file(client, other.file_id, other.token).data == b"other"


@pytest.mark.parametrize("op", ["read", "edit"])
def test_delete_needs_full(client, store, uploaded, narrow, op):
    response = client.delete(
        file_path(uploaded.file_id),
        headers=bearer(narrow(uploaded.file_id, op)),
    )

    assert_error(response, 403, "forbidden")
    assert store.get_blob(uploaded.file_id) == b"nonce-and-ciphertext"


def test_delete_requires_authorization(client, store, uploaded):
    assert_error(
        client.delete(file_path(uploaded.file_id)),
        401,
        "missing_token",
    )
    assert store.get_blob(uploaded.file_id) == b"nonce-and-ciphertext"


@pytest.mark.parametrize(
    "headers",
    [
        {"Authorization": "Bearer"},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer abc def"},
    ],
)
def test_delete_malformed_header_is_invalid(client, uploaded, headers):
    response = client.delete(file_path(uploaded.file_id), headers=headers)
    assert_error(response, 401, "invalid_token")


def test_delete_garbage_token_is_checked_before_the_file_exists(client):
    """Spec 3.1: 401 comes before 404, so unknown ids leak nothing."""
    assert_error(
        client.delete(file_path(UNKNOWN_ID), headers=bearer("garbage")),
        401,
        "invalid_token",
    )
    assert_error(client.delete(file_path(UNKNOWN_ID)), 401, "missing_token")


def test_delete_unknown_file_is_not_found(client, sign):
    token = sign(UNKNOWN_ID, [caveats.format_op("full")], root_key=b"z" * 32)

    response = client.delete(file_path(UNKNOWN_ID), headers=bearer(token))

    assert_error(response, 404, "not_found")


def test_delete_with_token_for_another_file_is_invalid(client, store, uploaded):
    other = create_file(b"other", store=store)

    response = client.delete(
        file_path(uploaded.file_id),
        headers=bearer(other.token),
    )

    assert_error(response, 401, "invalid_token")
    assert store.get_blob(uploaded.file_id) == b"nonce-and-ciphertext"


def test_delete_twice_is_not_found(client, uploaded):
    first = client.delete(file_path(uploaded.file_id), headers=bearer(uploaded.token))
    second = client.delete(file_path(uploaded.file_id), headers=bearer(uploaded.token))

    assert first.status_code == 204
    assert_error(second, 404, "not_found")


def test_delete_expired_and_revoked_tokens(client, store, uploaded, narrow):
    expired = narrow(uploaded.file_id, "full", caveats.format_expires(1))
    assert_error(
        client.delete(file_path(uploaded.file_id), headers=bearer(expired)),
        403,
        "expired",
    )

    share_id = "0123456789abcdef"
    revoked = narrow(uploaded.file_id, "full", caveats.format_share_id(share_id))
    store.revoke_share_id(uploaded.file_id, share_id)
    assert_error(
        client.delete(file_path(uploaded.file_id), headers=bearer(revoked)),
        403,
        "revoked",
    )
    assert store.get_blob(uploaded.file_id) == b"nonce-and-ciphertext"


def test_delete_response_keeps_security_headers(client, uploaded):
    response = client.delete(
        file_path(uploaded.file_id),
        headers=bearer(uploaded.token),
    )

    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"


# -- unsupported methods --------------------------------------------------


@pytest.mark.parametrize("method", ["get", "put", "delete"])
def test_share_and_revoke_only_accept_post(client, method):
    for path in (SHARE, REVOKE):
        assert_error(getattr(client, method)(path), 405, "bad_request")


# -- the example flow from api-spec section 7 -----------------------------


def test_spec_example_flow(client, store):
    upload = client.post("/api/files", data=b"nonce-and-ciphertext")
    assert upload.status_code == 201
    file_id = upload.get_json()["file_id"]
    token_a = upload.get_json()["token"]

    share_b = make_share(client, token_a, "read", 86400)
    token_b = share_b["token"]

    response = get_file(client, file_id, token_b)
    assert response.status_code == 200
    assert response.headers["X-Permission"] == "read"

    response = client.put(file_path(file_id), data=b"x", headers=bearer(token_b))
    assert_error(response, 403, "forbidden")

    share_c = make_share(client, token_b, "read", 3600)
    token_c = share_c["token"]
    assert share_c["share_id"] != share_b["share_id"]

    assert post_revoke(client, token_a, share_b["share_id"]).status_code == 204

    for token in (token_b, token_c):
        assert_error(get_file(client, file_id, token), 403, "revoked")

    response = client.delete(file_path(file_id), headers=bearer(token_a))
    assert response.status_code == 204

    assert_error(get_file(client, file_id, token_a), 404, "not_found")


@pytest.mark.parametrize("path", ["/", "/view.html", "/network.html", "/js/app.js"])
def test_frontend_responses_carry_browser_security_headers(client, path):
    response = client.get(path)

    assert response.status_code == 200
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000"
    assert "includeSubDomains" not in response.headers["Strict-Transport-Security"]
    assert response.headers["Permissions-Policy"].startswith("camera=()")
    assert response.headers["Referrer-Policy"] == "no-referrer"
