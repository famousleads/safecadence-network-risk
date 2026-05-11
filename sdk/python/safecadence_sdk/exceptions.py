"""Exception hierarchy for the SafeCadence SDK."""

from __future__ import annotations


class SafeCadenceError(Exception):
    """Base class for all SDK errors."""

    def __init__(self, message: str, *, status_code: int | None = None,
                 response_body: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class AuthError(SafeCadenceError):
    """Raised on 401/403 responses — bad or missing API key, or insufficient scope."""


class RateLimitError(SafeCadenceError):
    """Raised on 429 responses. Honor the Retry-After header if present."""

    def __init__(self, message: str, *, retry_after: float | None = None,
                 status_code: int | None = None,
                 response_body: str | None = None) -> None:
        super().__init__(message, status_code=status_code, response_body=response_body)
        self.retry_after = retry_after


class NotFound(SafeCadenceError):
    """Raised on 404 responses."""
