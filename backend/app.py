"""Flask HTTP layer for the API endpoints.

    POST   /api/files                -> create_file
    GET    /api/files/{file_id}      -> read_file
    PUT    /api/files/{file_id}      -> replace_file
    POST   /api/share                -> create_share
    POST   /api/revoke               -> revoke_share
    DELETE /api/files/{file_id}      -> delete_file

All capability rules live in :mod:`macaroon_core`; this module only translates
HTTP requests, core errors and response headers. It never logs tokens, root
keys or blobs.
"""

from __future__ import annotations

import logging
from pathlib import Path

from flask import Flask, Response, g, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from macaroon_core import (
    MAX_BLOB_SIZE,
    CoreError,
    FileStore,
    InvalidToken,
    MissingToken,
    TooLarge,
    create_file,
    create_share,
    delete_file,
    read_file,
    replace_file,
    revoke_share,
)

OCTET_STREAM = "application/octet-stream"
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

# Pages may only run scripts, styles and fonts from this server, and may only
# talk to this server. This limits what injected content could do with the
# file key in the URL fragment.
# The pages use none of these browser features.
PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


def _bearer_token() -> str:
    """Read ``Authorization: Bearer <token>`` from the request.

    A missing header is ``missing_token``; a present but malformed header is
    ``invalid_token``. Token syntax and length are checked by the core.
    """
    header = request.headers.get("Authorization")
    if header is None:
        raise MissingToken()

    scheme, separator, value = header.partition(" ")
    if (
        not separator
        or scheme.lower() != "bearer"
        or not value
        or any(character.isspace() for character in value)
    ):
        raise InvalidToken()
    return value


def _json_object() -> dict:
    """Parse the JSON request body; anything but an object becomes ``{}``.

    Spec 3.1: token errors (401/403/404) come before argument errors (400).
    The core authenticates the token first and only then validates ``op``,
    ``expires_in`` and ``share_id``. So a bad body must not fail here: the
    helpers below turn a missing or wrongly typed field into a value that the
    core rejects with ``400 bad_request`` after authentication.
    """
    data = request.get_json(force=True, silent=True)
    return data if isinstance(data, dict) else {}


def _text_field(body: dict, name: str) -> str:
    value = body.get(name)
    return value if isinstance(value, str) else ""  # "" is rejected by the core


def _int_field(body: dict, name: str) -> int:
    value = body.get(name)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return 0  # out of the 60..2592000 range, rejected by the core


def _is_api_request() -> bool:
    path = request.path
    return path == "/api" or path.startswith("/api/")


def create_app(store: FileStore | None = None) -> Flask:
    """Build the Flask app. Tests pass their own ``FileStore``."""
    app = Flask(__name__, static_folder=None)
    app.config["FILE_STORE"] = store if store is not None else FileStore()
    app.config["MAX_CONTENT_LENGTH"] = MAX_BLOB_SIZE + 1
    app.logger.setLevel(logging.INFO)

    # Flask's default exception logger writes a traceback, which can contain
    # attacker-controlled values. The spec allows only method, path, status
    # and error code; finalize_response logs exactly those.
    def _quiet_exception_logger(_exc_info) -> None:
        return None

    app.log_exception = _quiet_exception_logger  # type: ignore[method-assign]

    def file_store() -> FileStore:
        return app.config["FILE_STORE"]

    # -- routes -----------------------------------------------------------

    @app.post("/api/files")
    def upload_file():
        blob = request.get_data(cache=False)
        result = create_file(blob, file_store())
        return jsonify(file_id=result.file_id, token=result.token), 201

    @app.get("/api/files/<file_id>")
    def download_file(file_id: str):
        token = _bearer_token()
        result = read_file(file_id, token, file_store())

        response = Response(result.blob, mimetype=OCTET_STREAM)
        response.headers["X-Permission"] = result.permission
        return response

    @app.put("/api/files/<file_id>")
    def edit_file(file_id: str):
        # Check the header before touching the body: a malformed header must
        # be 401 even if the body is huge.
        token = _bearer_token()
        blob = request.get_data(cache=False)
        replace_file(file_id, token, blob, file_store())
        return Response(status=204)

    @app.post("/api/share")
    def share():
        token = _bearer_token()
        body = _json_object()
        result = create_share(
            token,
            _text_field(body, "op"),
            _int_field(body, "expires_in"),
            file_store(),
        )
        return jsonify(
            token=result.token,
            share_id=result.share_id,
            op=result.op,
            expires_at=result.expires_at,
        )

    @app.post("/api/revoke")
    def revoke():
        token = _bearer_token()
        body = _json_object()
        revoke_share(token, _text_field(body, "share_id"), file_store())
        return Response(status=204)

    @app.delete("/api/files/<file_id>")
    def remove_file(file_id: str):
        token = _bearer_token()
        delete_file(file_id, token, file_store())
        return Response(status=204)

    # -- frontend ---------------------------------------------------------

    @app.get("/")
    def frontend_index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/<any(demo, network, how, lab, results, view):page>.html")
    def frontend_page(page: str):
        return send_from_directory(FRONTEND_DIR, f"{page}.html")

    # Only these folders are served, so no static route can shadow /api/...
    @app.get("/<any(css, js, fonts):folder>/<path:name>")
    def frontend_asset(folder: str, name: str):
        return send_from_directory(FRONTEND_DIR / folder, name)

    # -- error handlers ---------------------------------------------------

    @app.errorhandler(CoreError)
    def handle_core_error(error: CoreError):
        g.error_code = error.code
        return jsonify(error=error.code, message=error.message), error.status

    @app.errorhandler(RequestEntityTooLarge)
    def handle_too_large(_error: RequestEntityTooLarge):
        g.error_code = TooLarge.code
        return jsonify(error=TooLarge.code, message=TooLarge.message), 413

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        if not _is_api_request():
            return error.get_response()

        status = error.code or 500
        if status == 404:
            code, message = "not_found", "Not found."
        elif status == 405:
            code, message = "bad_request", "Method not allowed."
        else:
            code = "bad_request"
            message = error.description or "Bad request."

        g.error_code = code
        return jsonify(error=code, message=message), status

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        # Flask resolves HTTPException to the more specific handler above, but
        # guard in case a future Flask version changes that dispatch.
        if isinstance(error, HTTPException):
            return handle_http_error(error)

        g.error_code = "internal_error"
        return (
            jsonify(
                error="internal_error",
                message="Internal server error.",
            ),
            500,
        )

    # -- response headers and safe logging --------------------------------

    @app.after_request
    def finalize_response(response: Response) -> Response:
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Browsers only honour HSTS on HTTPS, so local HTTP runs are unaffected.
        # No includeSubDomains: the demo runs on a shared parent domain.
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["Permissions-Policy"] = PERMISSIONS_POLICY
        if not _is_api_request():
            response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        # Method, path, status and error code only. No query string, headers,
        # tokens, keys or bodies.
        app.logger.info(
            "%s %s %s %s",
            request.method,
            request.path,
            response.status_code,
            getattr(g, "error_code", "-"),
        )
        return response

    return app


if __name__ == "__main__":
    create_app().run(threaded=True)
