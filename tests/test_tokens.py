import pytest

from aauth_edocs import (
    AAuthError,
    check_resource_challenge,
    issue_agent_token,
    issue_auth_token,
    issue_resource_token,
    peek_jwt,
    verify_agent_token,
    verify_auth_token,
    verify_resource_token,
)
from conftest import AP, PS, RESOURCE

DATAFLOW = {"data": "data", "function": "read"}


def test_agent_token_roundtrip(agent_token, resolver, agent_key, agent):
    claims = verify_agent_token(agent_token, resolver, signing_jwk=agent_key.public_jwk)
    assert claims["sub"] == agent
    assert claims["iss"] == AP
    assert claims["ps"] == PS
    header, _ = peek_jwt(agent_token)
    assert header["typ"] == "aa-agent+jwt"


def test_agent_token_wrong_signing_key(agent_token, resolver):
    from aauth_edocs import SigningKey

    other = SigningKey.generate()
    with pytest.raises(AAuthError, match="cnf.jwk"):
        verify_agent_token(agent_token, resolver, signing_jwk=other.public_jwk)


def test_agent_token_expired(ap_key, agent_key, agent, resolver):
    stale = issue_agent_token(
        issuer=AP, agent=agent, agent_jwk=agent_key.public_jwk, key=ap_key, now=lambda: 1000.0
    )
    with pytest.raises(AAuthError, match="expired"):
        verify_agent_token(stale, resolver, now=lambda: 1000.0 + 25 * 3600)


def test_wrong_typ_rejected(resource_key, agent_key, agent, resolver):
    rt = issue_resource_token(
        issuer=RESOURCE, aud=PS, agent=agent, agent_jkt=agent_key.thumbprint, dataflow=DATAFLOW, key=resource_key
    )
    with pytest.raises(AAuthError, match="typ"):
        verify_agent_token(rt, resolver)


def test_resource_token_roundtrip(resource_key, agent_key, agent, resolver):
    mission = {"approver": PS, "s256": "x" * 43}
    rt = issue_resource_token(
        issuer=RESOURCE,
        aud=PS,
        agent=agent,
        agent_jkt=agent_key.thumbprint,
        dataflow=DATAFLOW,
        mission=mission,
        key=resource_key,
    )
    claims = verify_resource_token(rt, resolver, aud=PS, agent=agent, agent_jkt=agent_key.thumbprint)
    assert claims["dataflow"] == DATAFLOW
    assert claims["mission"] == mission


def test_resource_token_controller_satisfies_as_aud(resource_key, agent_key, agent, resolver):
    """Sentinel path: RT aud is the sentinel; controller names this AS."""
    sentinel = "https://sentinel.example"
    as_url = "https://as.example"
    rt = issue_resource_token(
        issuer=RESOURCE,
        aud=sentinel,
        agent=agent,
        agent_jkt=agent_key.thumbprint,
        dataflow=DATAFLOW,
        controller=as_url,
        key=resource_key,
    )
    claims = verify_resource_token(rt, resolver, aud=as_url, agent=agent, agent_jkt=agent_key.thumbprint)
    assert claims["aud"] == sentinel
    assert claims["controller"] == as_url


def test_resource_token_wrong_aud(resource_key, agent_key, agent, resolver):
    rt = issue_resource_token(
        issuer=RESOURCE, aud="https://other.example", agent=agent, agent_jkt=agent_key.thumbprint,
        dataflow=DATAFLOW, key=resource_key,
    )
    with pytest.raises(AAuthError, match="aud"):
        verify_resource_token(rt, resolver, aud=PS)


def test_resource_token_wrong_jkt(resource_key, agent_key, agent, resolver):
    rt = issue_resource_token(
        issuer=RESOURCE, aud=PS, agent=agent, agent_jkt="not-the-key", dataflow=DATAFLOW, key=resource_key
    )
    with pytest.raises(AAuthError, match="agent_jkt"):
        verify_resource_token(rt, resolver, aud=PS, agent_jkt=agent_key.thumbprint)


def test_challenge_check_agent_side(resource_key, agent_key, agent, resolver):
    rt = issue_resource_token(
        issuer=RESOURCE, aud=PS, agent=agent, agent_jkt=agent_key.thumbprint, dataflow=DATAFLOW, key=resource_key
    )
    # without a resolver (no signature check) and with one
    for kr in (None, resolver):
        claims = check_resource_challenge(
            rt, resource=RESOURCE, agent=agent, agent_jkt=agent_key.thumbprint, key_resolver=kr
        )
        assert claims["aud"] == PS
    with pytest.raises(AAuthError, match="different agent"):
        check_resource_challenge(rt, resource=RESOURCE, agent="aauth:other@x", agent_jkt=agent_key.thumbprint)
    with pytest.raises(AAuthError, match="iss"):
        check_resource_challenge(rt, resource="https://evil.example", agent=agent, agent_jkt=agent_key.thumbprint)


def test_auth_token_roundtrip(ps_key, agent_key, agent, resolver):
    at = issue_auth_token(
        issuer=PS, dwk="aauth-person.json", aud=RESOURCE, agent=agent,
        cnf_jwk=agent_key.public_jwk, sub="user-123", dataflow=DATAFLOW, key=ps_key,
    )
    claims = verify_auth_token(at, resolver, aud=RESOURCE, signing_jwk=agent_key.public_jwk)
    assert claims["sub"] == "user-123"
    assert claims["agent"] == agent
    assert claims["dataflow"] == DATAFLOW


def test_resource_and_auth_token_dataflow_roundtrip(resource_key, ps_key, agent_key, agent, resolver):
    dataflow = {"data": "patient-42", "function": "avg_bp"}
    rt = issue_resource_token(
        issuer=RESOURCE,
        aud=PS,
        agent=agent,
        agent_jkt=agent_key.thumbprint,
        dataflow=dataflow,
        key=resource_key,
    )
    rt_claims = verify_resource_token(rt, resolver, aud=PS, agent=agent, agent_jkt=agent_key.thumbprint)
    assert rt_claims["dataflow"] == dataflow

    at = issue_auth_token(
        issuer=PS,
        dwk="aauth-person.json",
        aud=RESOURCE,
        agent=agent,
        cnf_jwk=agent_key.public_jwk,
        sub="user-123",
        dataflow=dataflow,
        key=ps_key,
    )
    claims = verify_auth_token(at, resolver, aud=RESOURCE, signing_jwk=agent_key.public_jwk)
    assert claims["dataflow"] == dataflow


def test_auth_token_wrong_aud_and_cnf(ps_key, agent_key, agent, resolver):
    from aauth_edocs import SigningKey

    at = issue_auth_token(
        issuer=PS, dwk="aauth-person.json", aud=RESOURCE, agent=agent,
        cnf_jwk=agent_key.public_jwk, sub="u", dataflow=DATAFLOW, key=ps_key,
    )
    with pytest.raises(AAuthError, match="aud"):
        verify_auth_token(at, resolver, aud="https://other.example")
    with pytest.raises(AAuthError, match="cnf.jwk"):
        verify_auth_token(at, resolver, aud=RESOURCE, signing_jwk=SigningKey.generate().public_jwk)


def test_auth_token_missing_dataflow_rejected(ps_key, agent_key, agent, resolver):
    """A forged token without dataflow must not verify."""
    import base64
    import json

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    forged = ".".join(
        [
            b64({"alg": "none", "typ": "aa-auth+jwt", "kid": ps_key.kid}),
            b64({"iss": PS, "dwk": "aauth-person.json", "aud": RESOURCE, "agent": agent, "sub": "u",
                 "cnf": {"jwk": agent_key.public_jwk}, "exp": 4102444800}),
            "",
        ]
    )
    with pytest.raises(AAuthError):
        verify_auth_token(forged, resolver, aud=RESOURCE)


def test_alg_none_rejected(ps_key, agent_key, agent, resolver):
    """A forged unsigned token must not verify."""
    import base64
    import json

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    forged = ".".join(
        [
            b64({"alg": "none", "typ": "aa-auth+jwt", "kid": ps_key.kid}),
            b64({"iss": PS, "dwk": "aauth-person.json", "aud": RESOURCE, "agent": agent, "sub": "u",
                 "cnf": {"jwk": agent_key.public_jwk}, "dataflow": DATAFLOW, "exp": 4102444800}),
            "",
        ]
    )
    with pytest.raises(AAuthError):
        verify_auth_token(forged, resolver, aud=RESOURCE)
