"""Errors raised by the macaroon core.

Each error carries the ``error`` code and HTTP status from
``docs/spec/api-spec.md`` section 5, so the Flask layer can serialize it
without another mapping table.
"""

from __future__ import annotations


class CoreError(Exception):
    """Base class for all errors the web layer knows how to answer."""

    code = "bad_request"
    status = 400
    message = "Bad request."

    def __init__(self, message: str | None = None) -> None:
        if message is not None:
            self.message = message
        super().__init__(self.message)


class BadRequest(CoreError):
    code = "bad_request"
    status = 400
    message = "Bad request."


class MissingToken(CoreError):
    code = "missing_token"
    status = 401
    message = "Authorization token is required."


class InvalidToken(CoreError):
    code = "invalid_token"
    status = 401
    message = "The token is invalid."


class Expired(CoreError):
    code = "expired"
    status = 403
    message = "This share has expired."


class Revoked(CoreError):
    code = "revoked"
    status = 403
    message = "This share has been revoked."


class Forbidden(CoreError):
    code = "forbidden"
    status = 403
    message = "This token does not allow this operation."


class NotFound(CoreError):
    code = "not_found"
    status = 404
    message = "Not found."


class TooLarge(CoreError):
    code = "too_large"
    status = 413
    message = "The file is larger than 1 MiB."


__all__ = [
    "CoreError",
    "BadRequest",
    "MissingToken",
    "InvalidToken",
    "Expired",
    "Revoked",
    "Forbidden",
    "NotFound",
    "TooLarge",
]
