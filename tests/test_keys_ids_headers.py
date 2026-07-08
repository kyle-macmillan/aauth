import pytest

from aauth_edocs import (
    AAuthError,
    MissionRef,
    SigningKey,
    agent_id,
    build_authorization,
    build_capabilities,
    build_requirement,
    jwk_thumbprint,
    parse_agent_id,
    parse_authorization,
    parse_capabilities,
    parse_requirement,
    verify_raw,
    well_known_url,
)


def test_key_sign_verify_roundtrip():
    key = SigningKey.generate()
    sig = key.sign(b"hello")
    assert verify_raw(key.public_jwk, b"hello", sig)
    assert not verify_raw(key.public_jwk, b"tampered", sig)
    assert not verify_raw(SigningKey.generate().public_jwk, b"hello", sig)


def test_key_jwk_roundtrip_and_thumbprint():
    key = SigningKey.generate(kid="k1")
    restored = SigningKey.from_private_jwk(key.private_jwk())
    assert restored.public_jwk == key.public_jwk
    assert key.thumbprint == jwk_thumbprint(key.public_jwk)
    # thumbprint ignores non-required members like kid
    jwk = dict(key.public_jwk)
    del jwk["kid"]
    assert jwk_thumbprint(jwk) == key.thumbprint


def test_agent_id_roundtrip():
    aid = agent_id("assistant-v2", "agent.example")
    assert aid == "aauth:assistant-v2@agent.example"
    assert parse_agent_id(aid) == ("assistant-v2", "agent.example")


@pytest.mark.parametrize("bad", ["assistant@x.example", "aauth:@x.example", "aauth:a", "aauth:a@"])
def test_agent_id_malformed(bad):
    with pytest.raises(ValueError):
        parse_agent_id(bad)


def test_well_known_url():
    assert well_known_url("https://ps.example", "aauth-person.json") == (
        "https://ps.example/.well-known/aauth-person.json"
    )


def test_requirement_roundtrip():
    value = build_requirement("auth-token", resource_token="eyJ.x.y")
    requirement, params = parse_requirement(value)
    assert requirement == "auth-token"
    assert params["resource-token"] == "eyJ.x.y"


def test_requirement_interaction_params():
    value = build_requirement("interaction", url="https://r.example/interact", code="A1B2")
    requirement, params = parse_requirement(value)
    assert requirement == "interaction"
    assert params == {"url": "https://r.example/interact", "code": "A1B2"}


def test_requirement_bad_header():
    with pytest.raises(AAuthError):
        parse_requirement("nonsense=;;;")


def test_mission_ref_roundtrip():
    ref = MissionRef(approver="https://ps.example", s256="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    parsed = MissionRef.from_header(ref.to_header())
    assert parsed == ref
    assert MissionRef.from_claim(ref.to_claim()) == ref


def test_capabilities_roundtrip():
    value = build_capabilities(["interaction", "clarification", "payment"])
    assert parse_capabilities(value) == ["interaction", "clarification", "payment"]


def test_authorization_roundtrip():
    assert parse_authorization(build_authorization("opaque-token")) == "opaque-token"
    with pytest.raises(AAuthError):
        parse_authorization("Bearer nope")
