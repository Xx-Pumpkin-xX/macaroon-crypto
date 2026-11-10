"""HTTP tests for the first three API endpoints.

These exercise the Flask boundary only: status codes, JSON error shape,
headers, authorization parsing and the mapping of core errors. The macaroon
semantics themselves are covered by the core unit tests.
"""

from __future__ import annotations

import base64
import logging

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
        client.delete(file_path(uploaded.file_id)),
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
