"""Reusable agent-side coordination for AAuth resource authorization.

This module owns the Person Server exchange, deferred polling, and
resource-scoped token cache.  It deliberately knows nothing about MCP methods
or application-specific claims such as eDocs dataflows.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from dataclasses import dataclass
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from .deferred import poll
from .errors import AAuthError, INVALID_REQUEST, INVALID_TOKEN, SERVER_ERROR
from .headers import APPROVAL, parse_requirement
from .httpsig import HttpRequest, peek_jwt, sign
from .ids import DWK_PERSON, well_known_url
from .keys import SigningKey, jwk_thumbprint
from .metadata import Metadata, fetch_metadata
from .tokens import check_resource_challenge


def _url_origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def resource_origin(url: str) -> str:
    return _url_origin(url)


@dataclass(frozen=True)
class ApprovalRequired:
    """A deferred authorization that must be resolved by a trusted host.

    ``pending_url`` is intentionally opaque.  The coordinator only polls it;
    it does not infer application or consent semantics from its path.
    """

    pending_url: str
    resource_origin: str
    headers: dict[str, str]
    approval_url: str | None = None


class AuthorizationCoordinator:
    """Exchange resource tokens and cache final tokens by resource origin."""

    def __init__(self, *, key: SigningKey, agent_token: str, transport) -> None:
        self.key = key
        self.agent_token = agent_token
        self.transport = transport
        self._tokens: dict[str, str] = {}

    @property
    def agent_id(self) -> str:
        return peek_jwt(self.agent_token)[1]["sub"]

    @property
    def ps_url(self) -> str | None:
        return peek_jwt(self.agent_token)[1].get("ps")

    def token_for(self, resource_url: str) -> str | None:
        return self._tokens.get(resource_origin(resource_url))

    def invalidate(self, resource_url: str) -> None:
        self._tokens.pop(resource_origin(resource_url), None)

    def begin(
        self,
        resource_token: str,
        *,
        resource_url: str,
        exchange_fields: dict | None = None,
    ) -> str | ApprovalRequired:
        """Start a PS exchange, returning a token or deferred approval event."""
        origin = resource_origin(resource_url)
        check_resource_challenge(
            resource_token,
            resource=origin,
            agent=self.agent_id,
            agent_jkt=self.key.thumbprint,
        )
        if not self.ps_url:
            raise AAuthError(
                INVALID_REQUEST,
                400,
                "agent token has no ps claim — no PS to exchange at",
            )

        metadata = fetch_metadata(self.ps_url, DWK_PERSON, self.transport)
        endpoint = metadata.endpoint("token_endpoint")
        if not endpoint:
            raise AAuthError(
                INVALID_REQUEST,
                400,
                f"{self.ps_url} has no token_endpoint",
            )

        request = HttpRequest("POST", endpoint, {})
        sign(request, self.key, self.agent_token)
        body = {"resource_token": resource_token}
        body.update(exchange_fields or {})
        response = self.transport.request(
            "POST",
            endpoint,
            headers=request.headers,
            json=body,
        )
        if response.status_code == 200:
            return self._accept(response.json(), expected_origin=origin)
        if response.status_code == 202:
            return self._approval_required(response, resource_origin=origin)
        raise AAuthError.from_response(response.status_code, response.json())

    async def begin_async(
        self,
        resource_token: str,
        *,
        resource_url: str,
        exchange_fields: dict | None = None,
    ) -> str | ApprovalRequired:
        """Async counterpart to :meth:`begin` for async clients.

        Transports may provide ``get_async`` and ``request_async`` methods.
        Synchronous transports remain supported for in-process tests.
        """
        origin = resource_origin(resource_url)
        check_resource_challenge(
            resource_token,
            resource=origin,
            agent=self.agent_id,
            agent_jkt=self.key.thumbprint,
        )
        if not self.ps_url:
            raise AAuthError(
                INVALID_REQUEST,
                400,
                "agent token has no ps claim — no PS to exchange at",
            )

        metadata_url = well_known_url(self.ps_url, DWK_PERSON)
        metadata_response = await self._get_async(metadata_url)
        if metadata_response.status_code != 200:
            raise AAuthError(
                SERVER_ERROR,
                502,
                f"metadata fetch failed: {metadata_url} -> "
                f"{metadata_response.status_code}",
            )
        metadata = Metadata(metadata_response.json())
        if metadata.get("issuer") != self.ps_url:
            raise AAuthError(
                INVALID_TOKEN,
                detail=f"metadata issuer {metadata.get('issuer')!r} "
                f"!= {self.ps_url!r}",
            )
        endpoint = metadata.endpoint("token_endpoint")
        if not endpoint:
            raise AAuthError(
                INVALID_REQUEST,
                400,
                f"{self.ps_url} has no token_endpoint",
            )

        request = HttpRequest("POST", endpoint, {})
        sign(request, self.key, self.agent_token)
        body = {"resource_token": resource_token}
        body.update(exchange_fields or {})
        response = await self._request_async(
            "POST",
            endpoint,
            headers=request.headers,
            json=body,
        )
        if response.status_code == 200:
            return self._accept(response.json(), expected_origin=origin)
        if response.status_code == 202:
            return self._approval_required(response, resource_origin=origin)
        raise AAuthError.from_response(response.status_code, response.json())

    def complete(
        self,
        approval: ApprovalRequired,
        *,
        default_interval: float = 2.0,
        timeout: float = 60.0,
        sleep=None,
        now=None,
    ) -> str:
        """Poll an opaque deferred URL and cache the resulting final token."""
        options = {
            "default_interval": default_interval,
            "timeout": timeout,
        }
        if sleep is not None:
            options["sleep"] = sleep
        if now is not None:
            options["now"] = now
        body = poll(approval.pending_url, self.transport, **options)
        return self._accept(body, expected_origin=approval.resource_origin)

    async def complete_async(
        self,
        approval: ApprovalRequired,
        *,
        default_interval: float = 2.0,
        timeout: float = 60.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        now: Callable[[], float] = time.monotonic,
    ) -> str:
        """Poll a deferred URL without blocking the caller's event loop."""
        deadline = now() + timeout
        while True:
            response = await self._get_async(approval.pending_url)
            if response.status_code == 200:
                return self._accept(
                    response.json(),
                    expected_origin=approval.resource_origin,
                )
            if response.status_code != 202:
                try:
                    body = response.json()
                except ValueError:
                    body = None
                raise AAuthError.from_response(response.status_code, body)
            if now() >= deadline:
                raise AAuthError(
                    SERVER_ERROR,
                    408,
                    f"gave up polling {approval.pending_url}",
                )
            retry_after = response.headers.get("Retry-After")
            await sleep(
                float(retry_after)
                if retry_after is not None
                else default_interval
            )

    async def _get_async(self, url: str):
        method = getattr(self.transport, "get_async", None)
        if method is None:
            return self.transport.get(url)
        result = method(url)
        return await result if inspect.isawaitable(result) else result

    async def _request_async(self, method: str, url: str, **kwargs):
        request = getattr(self.transport, "request_async", None)
        if request is None:
            return self.transport.request(method, url, **kwargs)
        result = request(method, url, **kwargs)
        return await result if inspect.isawaitable(result) else result

    def _approval_required(
        self,
        response,
        *,
        resource_origin: str,
    ) -> ApprovalRequired:
        approval_url = None
        requirement_header = response.headers.get("AAuth-Requirement")
        if requirement_header:
            requirement, params = parse_requirement(requirement_header)
            if requirement == APPROVAL:
                candidate = params.get("url")
                if candidate is not None:
                    if (
                        not isinstance(candidate, str)
                        or not self.ps_url
                        or _url_origin(candidate) != _url_origin(self.ps_url)
                    ):
                        raise AAuthError(
                            INVALID_TOKEN,
                            detail="approval URL is not on the agent's Person Server",
                        )
                    approval_url = candidate
        return ApprovalRequired(
            pending_url=response.headers["Location"],
            resource_origin=resource_origin,
            headers=dict(response.headers),
            approval_url=approval_url,
        )

    def _accept(self, body: dict, *, expected_origin: str) -> str:
        try:
            auth_token = body["auth_token"]
            _, claims = peek_jwt(auth_token)
            token_agent = claims.get("agent")
            token_jwk = (claims.get("cnf") or {}).get("jwk")
        except (KeyError, TypeError, ValueError) as error:
            raise AAuthError(
                INVALID_TOKEN,
                detail="PS returned a malformed auth token",
            ) from error

        if token_agent != self.agent_id:
            raise AAuthError(
                INVALID_TOKEN,
                detail="PS returned an auth token for a different agent",
            )
        if not isinstance(token_jwk, dict) or jwk_thumbprint(token_jwk) != self.key.thumbprint:
            raise AAuthError(
                INVALID_TOKEN,
                detail="PS returned an auth token for a different key",
            )
        if claims.get("aud") != expected_origin:
            raise AAuthError(
                INVALID_TOKEN,
                detail="PS returned an auth token for a different resource",
            )

        self._tokens[expected_origin] = auth_token
        return auth_token
