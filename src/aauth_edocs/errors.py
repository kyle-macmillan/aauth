"""AAuth error handling.

Internal-experimentation scope: a small error-code set covering the branches
our flows actually take, carried as ``{"error": ..., "detail": ...}`` JSON
bodies (the shape of §12.5.2 without the RFC 9457 ceremony).
"""

from __future__ import annotations

# Codes our flows branch on (subset of §12.5.3 / §12.5.4 tables).
INVALID_REQUEST = "invalid_request"
INVALID_SIGNATURE = "invalid_signature"
INVALID_TOKEN = "invalid_token"
EXPIRED = "expired"
DENIED = "denied"
GONE = "gone"
SERVER_ERROR = "server_error"


class AAuthError(Exception):
    """A protocol error with an HTTP status and a JSON body."""

    def __init__(self, code: str, status: int = 400, detail: str | None = None):
        super().__init__(detail or code)
        self.code = code
        self.status = status
        self.detail = detail

    def body(self) -> dict:
        out = {"error": self.code}
        if self.detail:
            out["detail"] = self.detail
        return out

    @classmethod
    def from_response(cls, status: int, body: dict | None) -> "AAuthError":
        body = body or {}
        return cls(body.get("error", SERVER_ERROR), status, body.get("detail"))
