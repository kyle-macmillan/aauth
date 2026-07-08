import pytest

from aauth_edocs import AAuthError, HttpRequest, sign, verify
from conftest import AP


def make_request(url="https://resource.example/api/docs", method="GET", headers=None):
    return HttpRequest(method=method, url=url, headers=headers or {})


def test_sign_verify_roundtrip(agent_key, agent_token, resolver, agent):
    request = sign(make_request(), agent_key, agent_token)
    assert "Signature" in request.headers
    result = verify(request, resolver)
    assert result.claims["sub"] == agent
    assert result.header["typ"] == "aa-agent+jwt"
    assert set(result.covered) >= {"@method", "@authority", "@path", "signature-key"}


@pytest.mark.parametrize("tamper", ["method", "path", "authority"])
def test_tampered_request_fails(agent_key, agent_token, resolver, tamper):
    request = sign(make_request(), agent_key, agent_token)
    if tamper == "method":
        request.method = "DELETE"
    elif tamper == "path":
        request.url = "https://resource.example/api/admin"
    else:
        request.url = "https://evil.example/api/docs"
    with pytest.raises(AAuthError, match="signature"):
        verify(request, resolver)


def test_query_covered_when_present(agent_key, agent_token, resolver):
    request = sign(make_request(url="https://resource.example/api/docs?id=1"), agent_key, agent_token)
    assert "@query" in verify(request, resolver).covered
    request.url = "https://resource.example/api/docs?id=2"
    with pytest.raises(AAuthError):
        verify(request, resolver)


def test_authorization_and_mission_auto_covered(agent_key, agent_token, resolver):
    headers = {"Authorization": "AAuth opaque", "AAuth-Mission": 'approver="https://ps.example";s256="h"'}
    request = sign(make_request(headers=headers), agent_key, agent_token)
    covered = verify(request, resolver).covered
    assert "authorization" in covered and "aauth-mission" in covered
    # binding: changing the access token invalidates the signature (§6.4)
    request.headers["Authorization"] = "AAuth stolen"
    with pytest.raises(AAuthError):
        verify(request, resolver)


def test_missing_headers(resolver):
    with pytest.raises(AAuthError, match="missing signature headers"):
        verify(make_request(), resolver)


def test_stale_created_rejected(agent_key, agent_token, resolver):
    request = sign(make_request(), agent_key, agent_token, now=lambda: 1000.0)
    with pytest.raises(AAuthError, match="window"):
        verify(request, resolver, now=lambda: 1000.0 + 600)
    # ...but fine within the window
    verify(sign(make_request(), agent_key, agent_token), resolver)


def test_wrong_key_signs_request(agent_token, resolver):
    """Stolen token + attacker key: PoP check must fail."""
    from aauth_edocs import SigningKey

    attacker = SigningKey.generate()
    request = sign(make_request(), attacker, agent_token)
    with pytest.raises(AAuthError, match="signature verification failed"):
        verify(request, resolver)


def test_unknown_issuer_rejected(agent_key, agent):
    from aauth_edocs import issue_agent_token, static_resolver, SigningKey

    rogue_ap = SigningKey.generate()
    token = issue_agent_token(issuer="https://rogue.example", agent=agent, agent_jwk=agent_key.public_jwk, key=rogue_ap)
    request = sign(make_request(), agent_key, token)
    with pytest.raises(AAuthError, match="unknown issuer"):
        verify(request, static_resolver({AP: SigningKey.generate().public_jwk}))
