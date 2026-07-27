"""M1 exit criterion: the primitives compose into the three-party flow shape
without any HTTP servers — the in-process equivalent of interop-demo-profile
Surfaces 1-3 (docs/specs/interop-demo-profile.md) plus auth-token issuance.

Roles played inline: AP (issues agent token), PS (approves a mission, issues
the auth token), Resource (verifies requests, issues the resource token,
serves the API call).
"""

import base64
import hashlib
import json

from aauth_edocs import (
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

AP, PS, RESOURCE = "https://ap.example", "https://ps.example", "https://resource.example"
DATAFLOW = {"data": "data", "function": "read"}


def test_three_party_flow_composes():
    # --- setup: keys, identities, one shared resolver (stands in for JWKS) --
    ap_key, ps_key, resource_key = (SigningKey.generate(kid=k) for k in ("ap", "ps", "res"))
    agent_key = SigningKey.generate(kid="agent")
    agent = agent_id("assistant", "ap.example")
    resolver = static_resolver(
        {AP: ap_key.public_jwk, PS: ps_key.public_jwk, RESOURCE: resource_key.public_jwk}
    )

    # --- AP issues the agent token (§5.2) ----------------------------------
    agent_token = issue_agent_token(
        issuer=AP, agent=agent, agent_jwk=agent_key.public_jwk, key=ap_key, ps=PS
    )

    # --- Surface 1: PS approves a mission; agent verifies s256 over the
    #     exact blob bytes (§8.2) ------------------------------------------
    blob_bytes = json.dumps(
        {"approver": PS, "agent": agent, "approved_at": "2026-07-08T00:00:00Z", "description": "# Test mission"}
    ).encode()
    s256 = base64.urlsafe_b64encode(hashlib.sha256(blob_bytes).digest()).rstrip(b"=").decode()
    mission = MissionRef(approver=PS, s256=s256)
    assert MissionRef.from_header(mission.to_header()) == mission

    # --- Surface 2: agent signs a request to the resource carrying
    #     AAuth-Mission; resource verifies and echoes the mission reference
    #     into the resource token ------------------------------------------
    request = HttpRequest("POST", f"{RESOURCE}/authorize", {"AAuth-Mission": mission.to_header()})
    sign(request, agent_key, agent_token)

    seen = verify(request, resolver)  # resource-side
    assert seen.header["typ"] == "aa-agent+jwt"
    assert seen.claims["sub"] == agent
    assert seen.claims["ps"] == PS  # resource discovers the agent's PS (§6)
    incoming_mission = MissionRef.from_header(request.get_header("AAuth-Mission"))

    resource_token = issue_resource_token(
        issuer=RESOURCE,
        aud=seen.claims["ps"],
        agent=seen.claims["sub"],
        agent_jkt=agent_key.thumbprint,
        dataflow=DATAFLOW,
        mission=incoming_mission.to_claim(),
        key=resource_key,
    )

    # --- Surface 3 (agent side): challenge check — the token names the
    #     resource we called, us, and our key (§6.7.3) ----------------------
    rt_claims = check_resource_challenge(
        resource_token, resource=RESOURCE, agent=agent, agent_jkt=agent_key.thumbprint, key_resolver=resolver
    )
    assert rt_claims["mission"] == mission.to_claim()

    # --- PS token endpoint: verifies the resource token is addressed to it
    #     and issues the auth token bound to the agent's key (§7.1, §9.4) ---
    ps_view = verify_resource_token(resource_token, resolver, aud=PS, agent=agent)
    auth_token = issue_auth_token(
        issuer=PS,
        dwk="aauth-person.json",
        aud=ps_view["iss"],
        agent=ps_view["agent"],
        cnf_jwk=agent_key.public_jwk,
        sub="user-alice",
        dataflow=ps_view["dataflow"],
        mission=ps_view["mission"],
        key=ps_key,
    )

    # --- Surface 4 shape: agent presents the auth token on an API call;
    #     resource verifies signature + token binding (§9.4.2/.3) -----------
    api_request = sign(HttpRequest("GET", f"{RESOURCE}/api/documents", {}), agent_key, auth_token)
    presented = verify(api_request, resolver)
    assert presented.header["typ"] == "aa-auth+jwt"
    claims = verify_auth_token(presented.token, resolver, aud=RESOURCE, signing_jwk=agent_key.public_jwk)
    assert claims["sub"] == "user-alice"
    assert claims["dataflow"] == DATAFLOW
    assert claims["mission"]["s256"] == s256  # mission context survived the whole chain
