from urllib.parse import urlsplit

import pytest
from flask import Flask

from aauth_edocs import SigningKey, agent_id, issue_agent_token, static_resolver
from aauth_edocs.agent import TransportResponse

AP = "https://ap.example"
RESOURCE = "https://resource.example"
PS = "https://ps.example"


class LoopbackTransport:
    """Routes by URL host to Flask test clients — same code path as HTTP."""

    def __init__(self):
        self._clients = {}

    def add(self, url: str, app: Flask) -> None:
        self._clients[urlsplit(url).netloc] = app.test_client()

    def request(self, method, url, headers=None, json=None):
        client = self._clients.get(urlsplit(url).netloc)
        if client is None:
            return TransportResponse(404, {}, {"error": "unknown host"})
        kwargs = {"method": method, "headers": headers or {}}
        if json is not None:
            kwargs["json"] = json
        response = client.open(url, **kwargs)
        return TransportResponse(response.status_code, dict(response.headers), response.get_json(silent=True))

    def get(self, url):
        return self.request("GET", url)


@pytest.fixture
def ap_key():
    return SigningKey.generate(kid="ap-1")


@pytest.fixture
def agent_key():
    return SigningKey.generate(kid="agent-1")


@pytest.fixture
def resource_key():
    return SigningKey.generate(kid="res-1")


@pytest.fixture
def ps_key():
    return SigningKey.generate(kid="ps-1")


@pytest.fixture
def agent():
    return agent_id("assistant", "ap.example")


@pytest.fixture
def resolver(ap_key, resource_key, ps_key):
    """Dict-backed KeyResolver covering all in-test issuers."""
    return static_resolver({AP: ap_key.public_jwk, RESOURCE: resource_key.public_jwk, PS: ps_key.public_jwk})


@pytest.fixture
def agent_token(ap_key, agent_key, agent):
    return issue_agent_token(
        issuer=AP, agent=agent, agent_jwk=agent_key.public_jwk, key=ap_key, ps=PS
    )
