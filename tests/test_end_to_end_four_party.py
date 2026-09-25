"""M4 exit criterion: the primitives compose into the four-party flow shape
without any HTTP servers — the in-process equivalent of interop-demo-profile
Surfaces 1-4 (docs/specs/interop-demo-profile.md).

Roles played inline: AP (issues agent token), PS (approves a mission),
Resource (issues resource token with aud=AS), AS (issues auth token).
PS federation over HTTP is exercised in tests/test_phase3_four_party.py.
"""

import base64
import hashlib
import json

from aauth_edocs import (
    DWK_ACCESS,
    HttpRequest,
    MissionRef,
    SigningKey,
    agent_id,
    check_resource_challenge,
    issue_agent_token,
    issue_auth_token,
    issue_resource_token,
    sign,
    static_resolver,
    verify,
    verify_auth_token,
    verify_resource_token,
)

AP, PS, AS, RESOURCE = (
    "https://ap.example",
    "https://ps.example",
    "https://as.example",
    "https://resource.example",
)
DATAFLOW = {"data": "data", "function": "read"}


def test_four_party_flow_composes():
    # --- setup: keys, identities, one shared resolver (stands in for JWKS) --
    ap_key, ps_key, as_key, resource_key = (
        SigningKey.generate(kid=k) for k in ("ap", "ps", "as", "res")
    )
    agent_key = SigningKey.generate(kid="agent")
    agent = agent_id("assistant", "ap.example")
    resolver = static_resolver(
        {
            AP: ap_key.public_jwk,
            PS: ps_key.public_jwk,
            AS: as_key.public_jwk,
            RESOURCE: resource_key.public_jwk,
        }
    )

    # --- AP issues the agent token (§5.2) ----------------------------------
    agent_token = issue_agent_token(
        issuer=AP, agent=agent, agent_jwk=agent_key.public_jwk, key=ap_key, ps=PS
    )

    # --- Surface 1: PS approves a mission (§8.2) ---------------------------
    blob_bytes = json.dumps(
        {"approver": PS, "agent": agent, "approved_at": "2026-07-08T00:00:00Z", "description": "# Test mission"}
    ).encode()
    s256 = base64.urlsafe_b64encode(hashlib.sha256(blob_bytes).digest()).rstrip(b"=").decode()
    mission = MissionRef(approver=PS, s256=s256)
    assert MissionRef.from_header(mission.to_header()) == mission

    # --- Surface 2: agent signs authorize; resource echoes mission into RT --
    request = HttpRequest("POST", f"{RESOURCE}/authorize", {"AAuth-Mission": mission.to_header()})
    sign(request, agent_key, agent_token)

    seen = verify(request, resolver)
    assert seen.header["typ"] == "aa-agent+jwt"
    assert seen.claims["sub"] == agent
    assert seen.claims["ps"] == PS
    incoming_mission = MissionRef.from_header(request.get_header("AAuth-Mission"))

    # four-party: resource token aud is the AS, not the agent's PS (§4.1.4)
    resource_token = issue_resource_token(
        issuer=RESOURCE,
        aud=AS,
        agent=seen.claims["sub"],
        agent_jkt=agent_key.thumbprint,
        dataflow=DATAFLOW,
        mission=incoming_mission.to_claim(),
        key=resource_key,
    )

    # --- Surface 3: agent challenge check (§6.7.3) -------------------------
    rt_claims = check_resource_challenge(
        resource_token, resource=RESOURCE, agent=agent, agent_jkt=agent_key.thumbprint, key_resolver=resolver
    )
    assert rt_claims["aud"] == AS
    assert rt_claims["mission"] == mission.to_claim()

    # --- Surface 4: AS evaluates policy and issues auth token ---------------
    # (PS federation is HTTP in production; here we exercise the AS side
    # primitives the PS would receive back — §9.3, §9.4.1)
    as_view = verify_resource_token(
        resource_token, resolver, aud=AS, agent=agent, agent_jkt=agent_key.thumbprint
    )
    auth_token = issue_auth_token(
        issuer=AS,
        dwk=DWK_ACCESS,
        aud=as_view["iss"],
        agent=as_view["agent"],
        cnf_jwk=agent_key.public_jwk,
        dataflow=as_view["dataflow"],
        mission=as_view["mission"],
        key=as_key,
    )

    # --- agent presents auth token; resource verifies AS-issued grant -------
    api_request = sign(HttpRequest("GET", f"{RESOURCE}/api/documents", {}), agent_key, auth_token)
    presented = verify(api_request, resolver)
    assert presented.header["typ"] == "aa-auth+jwt"
    claims = verify_auth_token(presented.token, resolver, aud=RESOURCE, signing_jwk=agent_key.public_jwk)
    assert claims["iss"] == AS
    assert claims["dwk"] == DWK_ACCESS
    assert "sub" not in claims
    assert claims["dataflow"] == DATAFLOW
    assert claims["mission"]["s256"] == s256
