"""Agent-side SDK: a session that signs every request with the agent's key,
presenting its agent token — or, once authorized, a per-resource auth token —
via Signature-Key (§5.2.3, §9.4.2).

The transport seam lets the same session run over real HTTP
(RequestsTransport) or Flask test clients (see tests). A transport needs two
methods: ``request(method, url, headers=None, json=None) ->
TransportResponse`` and ``get(url)`` (the shape JwksResolver/fetch_metadata/
poll expect).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlsplit

import requests

from .deferred import poll
from .errors import AAuthError, INVALID_REQUEST, INVALID_TOKEN
from .headers import AUTH_TOKEN, parse_requirement
from .httpsig import HttpRequest, peek_jwt, sign
from .ids import DWK_AGENT, DWK_PERSON
from .keys import SigningKey, jwk_thumbprint
from .metadata import fetch_metadata
from .tokens import check_resource_challenge


@dataclass
class TransportResponse:
    """Response shape shared by transports; .status_code/.json() also satisfy
    what fetch_metadata, JwksResolver, and poll expect of a response."""

    status_code: int
    headers: dict = field(default_factory=dict)
    body: Any = None

    def json(self):
        return self.body


class RequestsTransport:
    """Real-HTTP transport over a requests.Session."""

    def __init__(self, session: requests.Session | None = None):
        self._session = session or requests.Session()

    def request(self, method: str, url: str, headers: dict | None = None, json: Any = None) -> TransportResponse:
        response = self._session.request(method, url, headers=headers, json=json)
        try:
            body = response.json()
        except ValueError:
            body = None
        return TransportResponse(response.status_code, dict(response.headers), body)

    def get(self, url: str) -> TransportResponse:
        return self.request("GET", url)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


class AgentSession:
    """Holds the agent's key + tokens and signs every request.

    On a 401 auth-token challenge (§6.6) the session automatically exchanges
    the enclosed resource token at its PS and retries; expired cached auth
    tokens are evicted and re-acquired the same way.

    `on_pending(location, headers)` is called once when a PS consent decision
    is deferred (202), before polling starts — a hook for whatever stands in
    for the user (demos/tests use it to POST the consent decision).
    """

    def __init__(
        self,
        key: SigningKey,
        agent_token: str,
        transport=None,
        on_pending: Callable[[str, dict], None] | None = None,
    ):
        self.key = key
        self.agent_token = agent_token
        self.transport = transport or RequestsTransport()
        self.on_pending = on_pending
        self._auth_tokens: dict[str, str] = {}  # resource origin -> auth token

    @classmethod
    def enroll(cls, ap_url: str, local: str, transport=None, ps: str | None = None) -> "AgentSession":
        """Generate a key and obtain an agent token from the AP (§4.5-lite:
        the AP's open /issue endpoint stands in for a real enrollment
        ceremony)."""
        transport = transport or RequestsTransport()
        key = SigningKey.generate()
        md = fetch_metadata(ap_url, DWK_AGENT, transport)
        issue_url = md.endpoint("issue_endpoint") or f"{ap_url}/issue"
        response = transport.request(
            "POST", issue_url, json={"local": local, "jwk": key.public_jwk, "ps": ps}
        )
        if response.status_code != 200:
            raise AAuthError.from_response(response.status_code, response.json())
        return cls(key, response.json()["agent_token"], transport)

    @classmethod
    def enroll_subagent(cls, ap_url: str, parent: "AgentSession", local_suffix: str) -> "AgentSession":
        """Issue a first-level sub-agent token whose local part is parent+suffix."""
        transport = parent.transport
        key = SigningKey.generate()
        parent_local = parent.agent_id.removeprefix("aauth:").split("@", 1)[0]
        md = fetch_metadata(ap_url, DWK_AGENT, transport)
        issue_url = md.endpoint("issue_endpoint") or f"{ap_url}/issue"
        response = transport.request(
            "POST",
            issue_url,
            json={
                "local": f"{parent_local}+{local_suffix}",
                "jwk": key.public_jwk,
                "ps": parent.ps_url,
                "parent_agent": parent.agent_id,
            },
        )
        if response.status_code != 200:
            raise AAuthError.from_response(response.status_code, response.json())
        return cls(key, response.json()["agent_token"], transport)

    @property
    def agent_id(self) -> str:
        return peek_jwt(self.agent_token)[1]["sub"]

    @property
    def ps_url(self) -> str | None:
        return peek_jwt(self.agent_token)[1].get("ps")

    # -- requests ------------------------------------------------------------
    def request(self, method: str, url: str, headers: dict | None = None, json: Any = None) -> TransportResponse:
        origin = _origin(url)
        for _ in range(3):  # initial try + evict-retry + post-exchange retry
            token = self._auth_tokens.get(origin, self.agent_token)
            req = HttpRequest(method, url, dict(headers or {}))
            sign(req, self.key, token)
            response = self.transport.request(method, url, headers=req.headers, json=json)
            if response.status_code == 403 and origin in self._auth_tokens:
                del self._auth_tokens[origin]
                continue
            if response.status_code != 401:
                return response
            handled = False
            if origin in self._auth_tokens:  # cached auth token no longer good
                del self._auth_tokens[origin]
                handled = True
            requirement_header = response.headers.get("AAuth-Requirement")
            if requirement_header:
                requirement, params = parse_requirement(requirement_header)
                if requirement == AUTH_TOKEN and "resource-token" in params:
                    resource_token = params["resource-token"]
                    check_resource_challenge(  # §6.7.3
                        resource_token, resource=origin, agent=self.agent_id, agent_jkt=self.key.thumbprint
                    )
                    self.exchange(resource_token)
                    handled = True
            if not handled:
                return response
        return response

    def get(self, url: str, **kwargs) -> TransportResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> TransportResponse:
        return self.request("POST", url, **kwargs)

    # -- authorization (§6.1 + §7.1) ------------------------------------------
    def authorize(
        self,
        resource_url: str,
        scope: str | None = None,
        dataflow: dict | None = None,
    ) -> str:
        """Proactive path: request a resource token at the resource's
        authorization endpoint, then exchange it at the PS.

        Exactly one of `scope` or `dataflow` is required.
        """
        if (scope is None) == (dataflow is None):
            raise AAuthError(INVALID_REQUEST, 400, "exactly one of scope or dataflow is required")
        md = fetch_metadata(resource_url, "aauth-resource.json", self.transport)
        endpoint = md.endpoint("authorization_endpoint")
        if not endpoint:
            raise AAuthError(INVALID_REQUEST, 400, f"{resource_url} has no authorization_endpoint")
        req = HttpRequest("POST", endpoint, {})
        sign(req, self.key, self.agent_token)
        body = {"dataflow": dataflow} if dataflow is not None else {"scope": scope}
        response = self.transport.request("POST", endpoint, headers=req.headers, json=body)
        if response.status_code != 200:
            raise AAuthError.from_response(response.status_code, response.json())
        resource_token = response.json()["resource_token"]
        check_resource_challenge(
            resource_token, resource=_origin(resource_url), agent=self.agent_id, agent_jkt=self.key.thumbprint
        )
        return self.exchange(resource_token)

    def exchange(
        self,
        resource_token: str,
        *,
        subagent_token: str | None = None,
        upstream_token: str | None = None,
        upstream_aud: str | None = None,
    ) -> str:
        """Send a resource token to the PS token endpoint (§7.1.3); handle a
        deferred consent 202 by polling (§12.4). Caches and returns the auth
        token."""
        if not self.ps_url:
            raise AAuthError(INVALID_REQUEST, 400, "agent token has no ps claim — no PS to exchange at")
        md = fetch_metadata(self.ps_url, DWK_PERSON, self.transport)
        req = HttpRequest("POST", md.endpoint("token_endpoint"), {})
        sign(req, self.key, self.agent_token)
        body = {"resource_token": resource_token}
        if subagent_token is not None:
            body["subagent_token"] = subagent_token
        if upstream_token is not None:
            body["upstream_token"] = upstream_token
        if upstream_aud is not None:
            body["upstream_aud"] = upstream_aud
        response = self.transport.request("POST", req.url, headers=req.headers, json=body)
        if response.status_code == 200:
            body = response.json()
        elif response.status_code == 202:
            location = response.headers["Location"]
            if self.on_pending:
                self.on_pending(location, response.headers)
            body = poll(location, self.transport)
        else:
            raise AAuthError.from_response(response.status_code, response.json())

        auth_token = body["auth_token"]
        _, claims = peek_jwt(auth_token)  # §9.4.4-lite: it's for us and our key
        if claims.get("agent") != self.agent_id or jwk_thumbprint(claims["cnf"]["jwk"]) != self.key.thumbprint:
            raise AAuthError(INVALID_TOKEN, detail="PS returned an auth token for a different agent/key")
        self._auth_tokens[claims["aud"]] = auth_token
        return auth_token

    def request_permission(
        self,
        action: str,
        *,
        description: str | None = None,
        parameters: dict | None = None,
        mission: dict | None = None,
    ) -> bool:
        """Ask the PS for permission to perform an action (§7.4-lite)."""
        if not self.ps_url:
            raise AAuthError(INVALID_REQUEST, 400, "agent token has no ps claim — no PS for permission")
        md = fetch_metadata(self.ps_url, DWK_PERSON, self.transport)
        endpoint = md.endpoint("permission_endpoint")
        if not endpoint:
            raise AAuthError(INVALID_REQUEST, 400, f"{self.ps_url} has no permission_endpoint")

        body = {"action": action}
        if description is not None:
            body["description"] = description
        if parameters is not None:
            body["parameters"] = parameters
        if mission is not None:
            body["mission"] = mission

        req = HttpRequest("POST", endpoint, {})
        sign(req, self.key, self.agent_token)
        response = self.transport.request("POST", req.url, headers=req.headers, json=body)
        if response.status_code == 202:
            location = response.headers["Location"]
            if self.on_pending:
                self.on_pending(location, response.headers)
            result = poll(location, self.transport)
        elif response.status_code == 200:
            result = response.json()
        else:
            raise AAuthError.from_response(response.status_code, response.json())

        if result.get("permission") != "granted":
            raise AAuthError(INVALID_REQUEST, detail="permission was not granted")
        return True
