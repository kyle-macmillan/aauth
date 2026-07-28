import pytest

from aauth_edocs import (
    AAuthError,
    Dataflow,
    hash_function_args,
    check_resource_challenge,
    issue_agent_token,
    issue_auth_token,
    issue_conditional_auth_token,
    issue_resource_token,
    peek_jwt,
    verify_agent_token,
    verify_auth_token,
    verify_conditional_auth_token,
    verify_resource_token,
)
from conftest import AP, PS, RESOURCE


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
        issuer=RESOURCE, aud=PS, agent=agent, agent_jkt=agent_key.thumbprint, scope="data.read", key=resource_key
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
        scope="data.read data.write",
        mission=mission,
        key=resource_key,
    )
    claims = verify_resource_token(rt, resolver, aud=PS, agent=agent, agent_jkt=agent_key.thumbprint)
    assert claims["scope"] == "data.read data.write"
    assert claims["mission"] == mission
    assert "input_edoc_ids" not in claims


def test_resource_token_wrong_aud(resource_key, agent_key, agent, resolver):
    rt = issue_resource_token(
        issuer=RESOURCE, aud="https://other.example", agent=agent, agent_jkt=agent_key.thumbprint,
        scope="data.read", key=resource_key,
    )
    with pytest.raises(AAuthError, match="aud"):
        verify_resource_token(rt, resolver, aud=PS)


def test_resource_token_wrong_jkt(resource_key, agent_key, agent, resolver):
    rt = issue_resource_token(
        issuer=RESOURCE, aud=PS, agent=agent, agent_jkt="not-the-key", scope="s", key=resource_key
    )
    with pytest.raises(AAuthError, match="agent_jkt"):
        verify_resource_token(rt, resolver, aud=PS, agent_jkt=agent_key.thumbprint)


def test_challenge_check_agent_side(resource_key, agent_key, agent, resolver):
    rt = issue_resource_token(
        issuer=RESOURCE, aud=PS, agent=agent, agent_jkt=agent_key.thumbprint, scope="s", key=resource_key
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
        cnf_jwk=agent_key.public_jwk, sub="user-123", scope="data.read", key=ps_key,
    )
    claims = verify_auth_token(at, resolver, aud=RESOURCE, signing_jwk=agent_key.public_jwk)
    assert claims["sub"] == "user-123"
    assert claims["agent"] == agent


def test_auth_token_needs_sub_or_scope(ps_key, agent_key, agent):
    with pytest.raises(ValueError, match="sub or scope"):
        issue_auth_token(
            issuer=PS, dwk="aauth-person.json", aud=RESOURCE, agent=agent,
            cnf_jwk=agent_key.public_jwk, key=ps_key,
        )


def test_auth_token_wrong_aud_and_cnf(ps_key, agent_key, agent, resolver):
    from aauth_edocs import SigningKey

    at = issue_auth_token(
        issuer=PS, dwk="aauth-person.json", aud=RESOURCE, agent=agent,
        cnf_jwk=agent_key.public_jwk, sub="u", key=ps_key,
    )
    with pytest.raises(AAuthError, match="aud"):
        verify_auth_token(at, resolver, aud="https://other.example")
    with pytest.raises(AAuthError, match="cnf.jwk"):
        verify_auth_token(at, resolver, aud=RESOURCE, signing_jwk=SigningKey.generate().public_jwk)


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
                 "cnf": {"jwk": agent_key.public_jwk}, "exp": 4102444800}),
            "",
        ]
    )
    with pytest.raises(AAuthError):
        verify_auth_token(forged, resolver, aud=RESOURCE)


EDOC_SOURCE = "aauth:source@ap.example"
EDOC_ID = "doc-123"
EDOC_CONTROLLERS = ("https://as-a.example", "https://as-b.example")
EDOC_INPUTS = ("edoc://alice/input-a", "edoc://alice/input-b")
SENTINEL = "https://sentinel.example"
CONTROLLER_AS = PS


def _prerequisite() -> Dataflow:
    return Dataflow(
        source="aauth:upstream@ap.example",
        function="prepare@1",
        document="doc-input",
        destination="aauth:destination@ap.example",
    )


def _conditional_token(ps_key, agent_key, agent, **changes):
    values = {
        "issuer": CONTROLLER_AS,
        "aud": SENTINEL,
        "agent": agent,
        "cnf_jwk": agent_key.public_jwk,
        "scope": "identity@1",
        "source_agent": EDOC_SOURCE,
        "edoc_id": EDOC_ID,
        "controllers": EDOC_CONTROLLERS,
        "prerequisite": _prerequisite(),
        "key": ps_key,
    }
    values.update(changes)
    return issue_conditional_auth_token(**values)


def _verify_conditional(token, resolver, agent_key, requesting_agent, **changes):
    values = {
        "issuer": CONTROLLER_AS,
        "aud": SENTINEL,
        "agent": requesting_agent,
        "signing_jwk": agent_key.public_jwk,
        "source_agent": EDOC_SOURCE,
        "scope": "identity@1",
        "edoc_id": EDOC_ID,
        "controllers": EDOC_CONTROLLERS,
    }
    values.update(changes)
    return verify_conditional_auth_token(token, resolver, **values)


def test_conditional_auth_token_roundtrip(ps_key, agent_key, agent, resolver):
    token = _conditional_token(ps_key, agent_key, agent)

    assert _verify_conditional(token, resolver, agent_key, agent) == _prerequisite()
    header, claims = peek_jwt(token)
    assert header["typ"] == "aa-conditional-auth+jwt"
    assert claims["dwk"] == "aauth-access.json"
    assert claims["aud"] == SENTINEL


def test_conditional_auth_token_requires_dataflow(ps_key, agent_key, agent):
    with pytest.raises(ValueError, match="Dataflow"):
        _conditional_token(ps_key, agent_key, agent, prerequisite={})
    with pytest.raises(ValueError, match="fields"):
        _conditional_token(
            ps_key,
            agent_key,
            agent,
            prerequisite=Dataflow(source="", function="f", document="d", destination="b"),
        )


@pytest.mark.parametrize(
    ("expected", "message"),
    [
        ({"issuer": "https://other-as.example"}, "issuer"),
        ({"aud": "https://other-sentinel.example"}, "aud"),
        ({"agent": "aauth:other@ap.example"}, "agent"),
        ({"source_agent": "aauth:other@ap.example"}, "source_agent"),
        ({"scope": "other@1"}, "scope"),
        ({"edoc_id": "doc-456"}, "edoc_id"),
        ({"controllers": tuple(reversed(EDOC_CONTROLLERS))}, "controllers"),
    ],
)
def test_conditional_auth_token_binding_mismatch(
    ps_key, agent_key, agent, resolver, expected, message
):
    token = _conditional_token(ps_key, agent_key, agent)

    with pytest.raises(AAuthError, match=message):
        _verify_conditional(token, resolver, agent_key, agent, **expected)


def test_conditional_auth_token_wrong_confirmation_key(ps_key, agent_key, agent, resolver):
    from aauth_edocs import SigningKey

    token = _conditional_token(ps_key, agent_key, agent)
    with pytest.raises(AAuthError, match="cnf.jwk"):
        _verify_conditional(
            token,
            resolver,
            agent_key,
            agent,
            signing_jwk=SigningKey.generate().public_jwk,
        )


def test_conditional_auth_token_rejects_wrong_dwk(ps_key, agent_key, agent, resolver):
    from joserfc import jwt as joserfc_jwt
    from joserfc.jwk import OKPKey

    token = _conditional_token(ps_key, agent_key, agent)
    header, claims = peek_jwt(token)
    claims["dwk"] = "aauth-person.json"
    malformed = joserfc_jwt.encode(
        header,
        claims,
        OKPKey.import_key(ps_key.private_jwk()),
        algorithms=["EdDSA"],
    )

    with pytest.raises(AAuthError, match="dwk"):
        _verify_conditional(malformed, resolver, agent_key, agent)


@pytest.mark.parametrize(
    "prerequisite",
    [
        None,
        {},
        {"source": "a", "function": "f", "document": "d"},
        {"source": "a", "function": "f", "document": "d", "destination": "b", "extra": "x"},
        {"source": "", "function": "f", "document": "d", "destination": "b"},
        {"source": "a", "function": 1, "document": "d", "destination": "b"},
    ],
)
def test_conditional_auth_token_rejects_malformed_prerequisite(
    ps_key, agent_key, agent, resolver, prerequisite
):
    from joserfc import jwt as joserfc_jwt
    from joserfc.jwk import OKPKey

    token = _conditional_token(ps_key, agent_key, agent)
    header, claims = peek_jwt(token)
    claims["prerequisite"] = prerequisite
    malformed = joserfc_jwt.encode(
        header,
        claims,
        OKPKey.import_key(ps_key.private_jwk()),
        algorithms=["EdDSA"],
    )

    with pytest.raises(AAuthError, match="prerequisite"):
        _verify_conditional(malformed, resolver, agent_key, agent)


def test_conditional_and_normal_auth_types_are_not_interchangeable(
    ps_key, agent_key, agent, resolver
):
    conditional = _conditional_token(ps_key, agent_key, agent)
    with pytest.raises(AAuthError, match="typ"):
        verify_auth_token(conditional, resolver, aud=SENTINEL)

    normal = issue_auth_token(
        issuer=CONTROLLER_AS,
        dwk="aauth-access.json",
        aud=SENTINEL,
        agent=agent,
        cnf_jwk=agent_key.public_jwk,
        scope="identity@1",
        source_agent=EDOC_SOURCE,
        edoc_id=EDOC_ID,
        controllers=EDOC_CONTROLLERS,
        key=ps_key,
    )
    with pytest.raises(AAuthError, match="typ"):
        _verify_conditional(normal, resolver, agent_key, agent)


def test_edocs_resource_token_roundtrip(resource_key, agent_key, agent, resolver):
    function_args = {"query": "termination", "limit": 20}
    token = issue_resource_token(
        issuer=RESOURCE,
        aud=PS,
        agent=agent,
        agent_jkt=agent_key.thumbprint,
        scope="identity@1",
        source_agent=EDOC_SOURCE,
        edoc_id=EDOC_ID,
        controllers=EDOC_CONTROLLERS,
        function_args=function_args,
        key=resource_key,
    )

    claims = verify_resource_token(
        token,
        resolver,
        aud=PS,
        agent=agent,
        agent_jkt=agent_key.thumbprint,
        source_agent=EDOC_SOURCE,
        scope="identity@1",
        edoc_id=EDOC_ID,
        controllers=EDOC_CONTROLLERS,
        function_args_hash=hash_function_args({"limit": 20, "query": "termination"}),
    )
    assert claims["source_agent"] == EDOC_SOURCE
    assert claims["edoc_id"] == EDOC_ID
    assert claims["controllers"] == list(EDOC_CONTROLLERS)
    assert claims["function_args"] == function_args
    assert claims["function_args_hash"] == hash_function_args(function_args)


def test_edocs_resource_token_binds_direct_input_edocs(
    resource_key, agent_key, agent, resolver
):
    token = issue_resource_token(
        issuer=RESOURCE,
        aud=PS,
        agent=agent,
        agent_jkt=agent_key.thumbprint,
        scope="identity@1",
        source_agent=EDOC_SOURCE,
        edoc_id=EDOC_ID,
        controllers=EDOC_CONTROLLERS,
        input_edoc_ids=EDOC_INPUTS,
        key=resource_key,
    )

    claims = verify_resource_token(
        token,
        resolver,
        aud=PS,
        input_edoc_ids=EDOC_INPUTS,
    )

    assert claims["input_edoc_ids"] == list(EDOC_INPUTS)


@pytest.mark.parametrize(
    "input_edoc_ids",
    [
        ("edoc://alice/input-a", "edoc://alice/input-a"),
        ("",),
        ("edoc://alice/input-a", 7),
        "edoc://alice/input-a",
    ],
)
def test_edocs_resource_token_rejects_invalid_direct_inputs(
    resource_key, agent_key, agent, input_edoc_ids
):
    with pytest.raises(ValueError, match="input_edoc_ids"):
        issue_resource_token(
            issuer=RESOURCE,
            aud=PS,
            agent=agent,
            agent_jkt=agent_key.thumbprint,
            scope="identity@1",
            source_agent=EDOC_SOURCE,
            edoc_id=EDOC_ID,
            controllers=EDOC_CONTROLLERS,
            input_edoc_ids=input_edoc_ids,
            key=resource_key,
        )


def test_edocs_auth_token_roundtrip(ps_key, agent_key, agent, resolver):
    token = issue_auth_token(
        issuer=PS,
        dwk="aauth-person.json",
        aud=RESOURCE,
        agent=agent,
        cnf_jwk=agent_key.public_jwk,
        scope="identity@1",
        source_agent=EDOC_SOURCE,
        edoc_id=EDOC_ID,
        controllers=EDOC_CONTROLLERS,
        key=ps_key,
    )

    claims = verify_auth_token(
        token,
        resolver,
        aud=RESOURCE,
        signing_jwk=agent_key.public_jwk,
        source_agent=EDOC_SOURCE,
        scope="identity@1",
        edoc_id=EDOC_ID,
        controllers=EDOC_CONTROLLERS,
    )
    assert claims["source_agent"] == EDOC_SOURCE
    assert claims["edoc_id"] == EDOC_ID
    assert claims["controllers"] == list(EDOC_CONTROLLERS)


@pytest.mark.parametrize(
    "edocs",
    [
        {"source_agent": EDOC_SOURCE},
        {"source_agent": EDOC_SOURCE, "edoc_id": EDOC_ID},
        {"edoc_id": EDOC_ID, "controllers": EDOC_CONTROLLERS},
    ],
)
def test_edocs_claim_group_required_at_issuance(resource_key, agent_key, agent, edocs):
    with pytest.raises(ValueError, match="together"):
        issue_resource_token(
            issuer=RESOURCE,
            aud=PS,
            agent=agent,
            agent_jkt=agent_key.thumbprint,
            scope="identity@1",
            key=resource_key,
            **edocs,
        )


@pytest.mark.parametrize("controllers", [["https://as.example", "https://as.example"], [""]])
def test_edocs_controllers_validated_at_issuance(resource_key, agent_key, agent, controllers):
    with pytest.raises(ValueError, match="controllers"):
        issue_resource_token(
            issuer=RESOURCE,
            aud=PS,
            agent=agent,
            agent_jkt=agent_key.thumbprint,
            scope="identity@1",
            source_agent=EDOC_SOURCE,
            edoc_id=EDOC_ID,
            controllers=controllers,
            key=resource_key,
        )


def test_edocs_controllers_may_be_empty(resource_key, agent_key, agent, resolver):
    token = issue_resource_token(
        issuer=RESOURCE,
        aud=PS,
        agent=agent,
        agent_jkt=agent_key.thumbprint,
        scope="identity@1",
        source_agent=EDOC_SOURCE,
        edoc_id=EDOC_ID,
        controllers=[],
        key=resource_key,
    )

    claims = verify_resource_token(token, resolver, aud=PS, controllers=[])
    assert claims["controllers"] == []


@pytest.mark.parametrize(
    ("expected", "message"),
    [
        ({"source_agent": "aauth:other@ap.example"}, "source_agent"),
        ({"scope": "other@1"}, "scope"),
        ({"edoc_id": "doc-456"}, "edoc_id"),
        ({"controllers": ("https://as-b.example", "https://as-a.example")}, "controllers"),
    ],
)
def test_edocs_resource_token_binding_mismatch(
    resource_key, agent_key, agent, resolver, expected, message
):
    token = issue_resource_token(
        issuer=RESOURCE,
        aud=PS,
        agent=agent,
        agent_jkt=agent_key.thumbprint,
        scope="identity@1",
        source_agent=EDOC_SOURCE,
        edoc_id=EDOC_ID,
        controllers=EDOC_CONTROLLERS,
        key=resource_key,
    )

    with pytest.raises(AAuthError, match=message):
        verify_resource_token(token, resolver, aud=PS, **expected)


def test_signed_incomplete_edocs_claim_group_rejected(resource_key, agent_key, agent, resolver):
    from joserfc import jwt as joserfc_jwt
    from joserfc.jwk import OKPKey

    token = issue_resource_token(
        issuer=RESOURCE,
        aud=PS,
        agent=agent,
        agent_jkt=agent_key.thumbprint,
        scope="identity@1",
        key=resource_key,
    )
    header, claims = peek_jwt(token)
    claims["source_agent"] = EDOC_SOURCE
    malformed = joserfc_jwt.encode(
        header,
        claims,
        OKPKey.import_key(resource_key.private_jwk()),
        algorithms=["EdDSA"],
    )

    with pytest.raises(AAuthError, match="incomplete eDocs"):
        verify_resource_token(malformed, resolver, aud=PS)


def test_signed_non_list_controllers_rejected(resource_key, agent_key, agent, resolver):
    from joserfc import jwt as joserfc_jwt
    from joserfc.jwk import OKPKey

    token = issue_resource_token(
        issuer=RESOURCE,
        aud=PS,
        agent=agent,
        agent_jkt=agent_key.thumbprint,
        scope="identity@1",
        source_agent=EDOC_SOURCE,
        edoc_id=EDOC_ID,
        controllers=EDOC_CONTROLLERS,
        key=resource_key,
    )
    header, claims = peek_jwt(token)
    claims["controllers"] = "https://as-a.example"
    malformed = joserfc_jwt.encode(
        header,
        claims,
        OKPKey.import_key(resource_key.private_jwk()),
        algorithms=["EdDSA"],
    )

    with pytest.raises(AAuthError, match="JSON list"):
        verify_resource_token(malformed, resolver, aud=PS)


def test_signed_resource_token_rejects_arguments_digest_mismatch(
    resource_key, agent_key, agent, resolver
):
    from joserfc import jwt as joserfc_jwt
    from joserfc.jwk import OKPKey

    token = issue_resource_token(
        issuer=RESOURCE,
        aud=PS,
        agent=agent,
        agent_jkt=agent_key.thumbprint,
        scope="search@1",
        source_agent=EDOC_SOURCE,
        edoc_id=EDOC_ID,
        controllers=EDOC_CONTROLLERS,
        function_args={"query": "approved"},
        key=resource_key,
    )
    header, claims = peek_jwt(token)
    claims["function_args"] = {"query": "changed"}
    malformed = joserfc_jwt.encode(
        header,
        claims,
        OKPKey.import_key(resource_key.private_jwk()),
        algorithms=["EdDSA"],
    )

    with pytest.raises(AAuthError, match="does not match function_args"):
        verify_resource_token(malformed, resolver, aud=PS)
