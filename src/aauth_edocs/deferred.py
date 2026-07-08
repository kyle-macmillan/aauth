"""Deferred responses (§12.4-lite) and interaction codes.

Server side: an in-memory PendingStore whose entries render the 202/terminal
/410 responses of the deferred pattern. Client side: `poll()` implements the
GET loop. Interaction codes are random and single-use — the Crockford
alphabet, rate limits, and folding rules are skipped for internal use.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Callable

from .errors import AAuthError, DENIED, GONE, SERVER_ERROR


@dataclass
class _Pending:
    status: str = "pending"  # pending | done
    result_status: int = 200
    result_body: dict = field(default_factory=dict)
    result_headers: dict = field(default_factory=dict)
    requirement: str | None = None  # AAuth-Requirement header value while pending
    retry_after: int = 0
    picked_up: bool = False


class PendingStore:
    """Pending requests plus their single-use interaction codes."""

    def __init__(self, base_path: str = "/pending"):
        self.base_path = base_path
        self._items: dict[str, _Pending] = {}
        self._codes: set[str] = set()

    # -- lifecycle ---------------------------------------------------------
    def create(self, *, requirement: str | None = None, retry_after: int = 0) -> str:
        pid = secrets.token_urlsafe(16)
        self._items[pid] = _Pending(requirement=requirement, retry_after=retry_after)
        return pid

    def location(self, pid: str) -> str:
        return f"{self.base_path}/{pid}"

    def resolve(self, pid: str, body: dict, *, status: int = 200, headers: dict | None = None) -> None:
        item = self._items[pid]
        item.status = "done"
        item.result_status = status
        item.result_body = body
        item.result_headers = headers or {}

    def set_requirement(self, pid: str, requirement: str) -> None:
        self._items[pid].requirement = requirement

    def deny(self, pid: str, *, error: str = DENIED, status: int = 403, detail: str | None = None) -> None:
        self.resolve(pid, AAuthError(error, status, detail).body(), status=status)

    def response(self, pid: str) -> tuple[int, dict, dict]:
        """(status, headers, body) for a poll of this pending URL."""
        item = self._items.get(pid)
        if item is None or item.picked_up:
            return 410, {}, AAuthError(GONE, 410).body()
        if item.status == "pending":
            headers = {
                "Location": self.location(pid),
                "Retry-After": str(item.retry_after),
                "Cache-Control": "no-store",
            }
            if item.requirement:
                headers["AAuth-Requirement"] = item.requirement
            return 202, headers, {"status": "pending"}
        item.picked_up = True  # terminal responses are delivered once (§14.3)
        return item.result_status, item.result_headers, item.result_body

    # -- interaction codes (§12.3.3.1-lite) --------------------------------
    def new_code(self) -> str:
        code = secrets.token_hex(4).upper()
        self._codes.add(code)
        return code

    def consume_code(self, code: str) -> bool:
        """True exactly once per issued code."""
        try:
            self._codes.remove(code)
            return True
        except KeyError:
            return False


def poll(
    url: str,
    http,
    *,
    default_interval: float = 2.0,
    timeout: float = 60.0,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.time,
) -> dict:
    """Client side of §12.4.4: GET until a terminal response.

    `http` is requests.Session-compatible. Returns the 200 body; raises
    AAuthError built from the body for terminal errors or on timeout.
    """
    deadline = now() + timeout
    while True:
        response = http.get(url)
        if response.status_code == 200:
            return response.json()
        if response.status_code != 202:
            try:
                body = response.json()
            except ValueError:
                body = None
            raise AAuthError.from_response(response.status_code, body)
        if now() >= deadline:
            raise AAuthError(SERVER_ERROR, 408, f"gave up polling {url}")
        retry_after = response.headers.get("Retry-After")
        sleep(float(retry_after) if retry_after is not None else default_interval)
