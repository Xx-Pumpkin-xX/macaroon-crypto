"""Flask HTTP layer for the first three API endpoints.

    POST /api/files                  -> create_file
    GET  /api/files/{file_id}        -> read_file
    PUT  /api/files/{file_id}        -> replace_file

All capability rules live in :mod:`macaroon_core`; this module only translates
HTTP requests, core errors and response headers. It never logs tokens, root
keys or blobs.
"""

from __future__ import annotations

import logging

from flask import Flask, Response, g, jsonify, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from macaroon_core import (
    MAX_BLOB_SIZE,
    CoreError,
    FileStore,
    InvalidToken,
    MissingToken,
    TooLarge,
    create_file,
    read_file,
    replace_file,
)

OCTET_STREAM = "application/octet-stream"


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


def _is_api_request() -> bool:
    path = request.path
    return path == "/api" or path.startswith("/api/")


def create_app(store: FileStore | None = None) -> Flask:
    """Build the Flask app. Tests pass their own ``FileStore``."""
    app = Flask(__name__, static_folder=None)
    app.config["FILE_STORE"] = store if store is not None else FileStore()
    app.config["MAX_CONTENT_LENGTH"] = MAX_BLOB_SIZE
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
