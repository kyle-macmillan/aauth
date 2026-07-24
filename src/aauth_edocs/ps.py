"""Person Server: exchanges resource tokens for auth tokens (§7.1, §9.3).

Three-party (resource token aud == this PS): the PS asserts identity —
directed sub per resource (§15.1) — and consent for the requested scope.
Four-party (aud == an AS): the PS federates, calling the AS token endpoint
signed with the jwks_uri scheme (§9.1.1), and relays the auth token.

Internal-experimentation scope: one hardcoded person per PS, consent via a
`policy` hook (default: grant everything) with a plain HTTP endpoint standing
in for the user's consent UI when the policy defers.
"""

from __future__ import annotations

import hashlib
import json
from typing import Callable, Literal, TypedDict

from flask import Flask, request, session

from .agent import RequestsTransport
from .deferred import PendingStore
from .errors import AAuthError, DENIED, INVALID_REQUEST, INVALID_TOKEN, SERVER_ERROR
from .headers import APPROVAL, CLAIMS, CLARIFICATION, INTERACTION, build_requirement, parse_requirement
from .httpsig import HttpRequest, peek_jwt, sign_server, verify
from .ids import DWK_ACCESS, DWK_PERSON, DWK_SENTINEL
from .keys import SigningKey, jwk_thumbprint
from .metadata import JwksResolver, build_metadata, fetch_metadata
from .tokens import AGENT_TYP, issue_auth_token, verify_agent_token, verify_auth_token, verify_resource_token

# policy(agent_claims, resource_token_claims) -> "grant" | "pending" | "deny"
Policy = Callable[[dict, dict], str]
PermissionPolicy = Callable[[dict, dict], str]


class GrantContext(TypedDict, total=False):
    """State threaded through a /token request from verification to issuance."""

    resource_token: str
    rt_claims: dict
    agent_claims: dict
    subagent_claims: dict | None
    agent_token: str
    requested_scope: str | None
    requested_dataflow: dict | None
    clarification_rounds: int
    clarification_response: str
    upstream_claims: dict | None
    act_agent: str | None
    as_pending_url: str


class PermissionContext(TypedDict):
    """State for a pending /permission request."""

    kind: Literal["permission"]
    agent_claims: dict
    request: dict


PendingContext = GrantContext | PermissionContext


def directed_sub(person: str, resource: str) -> str:
    """Pairwise pseudonymous user id per resource (§15.1)."""
    return "u_" + hashlib.sha256(f"{person}|{resource}".encode()).hexdigest()[:16]


def create_ps(
    issuer: str,
    key: SigningKey | None = None,
    person: str = "user-alice",
    policy: Policy | None = None,
    permission_policy: PermissionPolicy | None = None,
    transport=None,
    agent_bindings: dict[str, str] | None = None,
    consents: set[tuple[str, str, str, str]] | None = None,
) -> Flask:
    app = Flask("aauth-ps")
    app.secret_key = f"aauth-edocs-dev-ps:{issuer}"
    key = key or SigningKey.generate(kid="ps")
    transport = transport or RequestsTransport()
    resolver = JwksResolver(transport)
    store = PendingStore(base_path=f"{issuer}/pending")
    pending_requests: dict[str, PendingContext] = {}  # pid -> context for the consent decision
    interaction_requests: dict[str, GrantContext] = {}
    agent_bindings = agent_bindings if agent_bindings is not None else {}
    consents = consents if consents is not None else set()
    app.extensions["aauth_ps"] = {
        "issuer": issuer,
        "key": key,
        "person": person,
        "store": store,
        "agent_bindings": agent_bindings,
        "consents": consents,
        "interactions": interaction_requests,
    }

    @app.errorhandler(AAuthError)
    def aauth_error(error: AAuthError):
        return error.body(), error.status

    @app.get("/.well-known/aauth-person.json")
    def ps_metadata():
        return dict(
            build_metadata(
                issuer,
                jwks_uri=f"{issuer}/jwks.json",
                token_endpoint=f"{issuer}/token",
                permission_endpoint=f"{issuer}/permission",
                login_endpoint=f"{issuer}/login/start",
                name="aauth-edocs demo PS",
            )
        )

    @app.get("/jwks.json")
    def ps_jwks():
        return {"keys": [key.public_jwk]}

    @app.post("/login")
    def login():
        """Dev authentication stub for the configured local person."""
        requested_person = (request.get_json(force=True) or {}).get("person")
        if requested_person != person:
            raise AAuthError(DENIED, 403, "unknown person")
        session["person"] = person
        return {"person": person}

    @app.post("/logout")
    def logout():
        session.clear()
        return {"status": "logged_out"}

    @app.post("/login/start")
    def third_party_login():
        body = request.get_json(force=True) or {}
        if body.get("ps") != issuer:
            raise AAuthError(INVALID_REQUEST, 400, "ps does not match this person server")
        start_path = body.get("start_path") or "/"
        if not isinstance(start_path, str) or not start_path.startswith("/") or start_path.startswith("//"):
            raise AAuthError(INVALID_REQUEST, 400, "start_path must be a relative path")
        return {"status": "ok", "start_path": start_path, "person": person}

    @app.post("/token")
    def token_endpoint():
        # §7.1.3: signed POST from the agent, presenting its agent token
        verified = verify(_incoming(), resolver)
        if verified.header.get("typ") != AGENT_TYP:
            raise AAuthError(INVALID_TOKEN, 401, "token endpoint expects an agent token")
        body = request.get_json(force=True) or {}
        resource_token = body.get("resource_token")
        if not resource_token:
            raise AAuthError(INVALID_REQUEST, 400, "resource_token is required")

        agent_claims, subagent_claims, presented_token = _resolve_agent_identity(verified, body)
        act_agent = agent_claims["sub"] if subagent_claims else None
        upstream_claims = _resolve_upstream_claims(body, agent_claims)
        if upstream_claims:
            act_agent = upstream_claims["agent"]

        rt_claims = _verify_incoming_resource_token(resource_token, agent_claims, subagent_claims)
        _check_dataflow_request(rt_claims, body)

        context: GrantContext = {
            "resource_token": resource_token,
            "rt_claims": rt_claims,
            "agent_claims": agent_claims,
            "subagent_claims": subagent_claims,
            "agent_token": presented_token,
            "requested_scope": body.get("scope"),
            "requested_dataflow": body.get("dataflow"),
            "clarification_rounds": 0,
            "upstream_claims": upstream_claims,
            "act_agent": act_agent,
        }
        _check_binding(context)
        return _dispatch_grant(context)

    def _resolve_agent_identity(verified, body: dict) -> tuple[dict, dict | None, str]:
        """Resolve (agent_claims, subagent_claims, presented_token) for direct or delegated sub-agent requests."""
        agent_claims = verified.claims
        presented_token = verified.token
        if not agent_claims.get("parent_agent"):
            return agent_claims, None, presented_token
        parent_token = body.get("subagent_token")
        if not parent_token:
            raise AAuthError(INVALID_TOKEN, 401, "sub-agent requests require parent subagent_token")
        parent_claims = verify_agent_token(parent_token, resolver)
        if parent_claims.get("sub") != agent_claims["parent_agent"]:
            raise AAuthError(INVALID_TOKEN, 401, "subagent_token is not the parent agent")
        return parent_claims, agent_claims, parent_token

    def _resolve_upstream_claims(body: dict, agent_claims: dict) -> dict | None:
        """Verify the optional upstream auth token relayed for a federated request (§6.7.2)."""
        upstream_token = body.get("upstream_token")
        if not upstream_token:
            return None
        upstream_aud = body.get("upstream_aud") or peek_jwt(upstream_token)[1].get("aud")
        upstream_claims = verify_auth_token(upstream_token, resolver, aud=upstream_aud)
        if upstream_claims.get("agent") != agent_claims["sub"]:
            raise AAuthError(INVALID_TOKEN, 401, "upstream token agent mismatch")
        return upstream_claims

    def _verify_incoming_resource_token(resource_token: str, agent_claims: dict, subagent_claims: dict | None) -> dict:
        """Verify the resource token and, for sub-agent requests, its binding to the sub-agent key."""
        _, peeked = peek_jwt(resource_token)
        rt_claims = verify_resource_token(
            resource_token,
            resolver,
            aud=peeked.get("aud"),
            agent=agent_claims["sub"],
            agent_jkt=jwk_thumbprint((subagent_claims or agent_claims)["cnf"]["jwk"]),
        )
        if subagent_claims and rt_claims.get("agent_jkt") != jwk_thumbprint(subagent_claims["cnf"]["jwk"]):
            raise AAuthError(INVALID_TOKEN, 401, "resource token is not bound to the sub-agent key")
        return rt_claims

    def _check_dataflow_request(rt_claims: dict, body: dict) -> None:
        """A dataflow-scoped resource token doesn't accept a separate scope request."""
        if rt_claims.get("dataflow") is None:
            return
        if body.get("scope") is not None:
            raise AAuthError(INVALID_REQUEST, 400, "scope is not allowed when resource token has dataflow")
        requested_df = body.get("dataflow")
        if requested_df is not None and requested_df != rt_claims["dataflow"]:
            raise AAuthError(DENIED, 403, "requested dataflow does not match resource token")

    def _check_binding(context: GrantContext) -> None:
        bound_person = agent_bindings.get(context["agent_claims"]["sub"])
        if bound_person is not None and bound_person != person:
            raise AAuthError(DENIED, 403, "agent is already bound to another person")

    def _dispatch_grant(context: GrantContext):
        """Apply the consent policy to a verified token request: issue, defer, or deny."""
        rt_claims = context["rt_claims"]
        already_consented = _consent_key(context) in consents
        decision = "grant" if already_consented else (policy(context["agent_claims"], rt_claims) if policy else "grant")
        if decision == "deny":
            raise AAuthError(DENIED, 403, "consent denied by policy")
        if decision == "clarification":
            return _defer_clarification(context)
        if decision == "grant":
            if rt_claims.get("interaction"):
                return _defer_interaction(context)
            return _issue_and_remember(context)
        # pending: user consent needed (§12.3.4 approval — no user URL to visit,
        # the decision arrives via the /consent endpoint)
        pid = store.create(requirement=build_requirement(APPROVAL), retry_after=0)
        pending_requests[pid] = context
        status, headers, response_body = store.response(pid)
        return response_body, status, headers

    def _defer_clarification(context: GrantContext):
        if context["clarification_rounds"] >= 5:
            raise AAuthError(DENIED, 403, "clarification round limit reached")
        context["clarification_rounds"] += 1
        pid = store.create(requirement=build_requirement(CLARIFICATION), retry_after=0)
        pending_requests[pid] = context
        status, headers, body = store.response(pid)
        body.update({"question": "Please clarify this access request.", "round": context["clarification_rounds"]})
        return body, status, headers

    def _defer_interaction(context: GrantContext):
        pid = store.create(retry_after=0)
        store.set_requirement(pid, build_requirement(INTERACTION, url=f"{issuer}/interaction/{pid}"))
        interaction_requests[pid] = context
        status, headers, body = store.response(pid)
        body["interaction"] = context["rt_claims"].get("interaction")
        return body, status, headers

    def _issue_and_remember(context: GrantContext) -> dict:
        result = _issue(context)
        _remember_grant(context)
        return result

    def _remember_grant(context: GrantContext) -> None:
        agent_bindings[context["agent_claims"]["sub"]] = person
        consents.add(_consent_key(context))

    def _consent_key(context: GrantContext) -> tuple[str, str, str, str]:
        rt_claims = context["rt_claims"]
        agent_claims = context.get("subagent_claims") or context["agent_claims"]
        if rt_claims.get("dataflow") is not None:
            grant = _canonical_dataflow(rt_claims["dataflow"])
        else:
            grant = rt_claims.get("scope") or ""
        return person, agent_claims["sub"], rt_claims["iss"], grant

    def _canonical_dataflow(dataflow: dict) -> str:
        return json.dumps(dataflow, sort_keys=True, separators=(",", ":"))

    def _issue(context: GrantContext) -> dict:
        """Issue (three-party) or federate for (four-party) an auth token."""
        rt_claims = context["rt_claims"]
        agent_claims = context.get("subagent_claims") or context["agent_claims"]
        resource = rt_claims["iss"]
        act = {"agent": context["act_agent"]} if context.get("act_agent") else None

        if rt_claims["aud"] == issuer and "aauth_as" not in app.extensions:  # three-party: PS asserts identity (§7.1.4)
            if rt_claims.get("dataflow") is not None:
                token = issue_auth_token(
                    issuer=issuer,
                    dwk=DWK_PERSON,
                    aud=resource,
                    agent=agent_claims["sub"],
                    cnf_jwk=agent_claims["cnf"]["jwk"],
                    sub=directed_sub(person, resource),
                    dataflow=_granted_dataflow(context),
                    mission=rt_claims.get("mission"),
                    act=act,
                    key=key,
                )
            else:
                token = issue_auth_token(
                    issuer=issuer,
                    dwk=DWK_PERSON,
                    aud=resource,
                    agent=agent_claims["sub"],
                    cnf_jwk=agent_claims["cnf"]["jwk"],
                    sub=directed_sub(person, resource),
                    scope=_granted_scope(context),
                    mission=rt_claims.get("mission"),
                    act=act,
                    key=key,
                )
            return {"auth_token": token, "expires_in": 3600}

        # four-party: federate with the AS/sentinel the resource named (§9.3)
        as_url = rt_claims["aud"]
        as_md = _fetch_grant_metadata(as_url, transport)
        req = HttpRequest("POST", as_md.endpoint("token_endpoint"), {})
        sign_server(req, key, issuer, DWK_PERSON)
        response = transport.request(
            "POST",
            req.url,
            headers=req.headers,
            json={"resource_token": context["resource_token"], "agent_token": context["agent_token"]},
        )
        if response.status_code == 202:
            return _handle_as_pending(context, response)
        if response.status_code != 200:
            raise AAuthError.from_response(response.status_code, response.json())
        auth_token = response.json()["auth_token"]
        _check_as_token(context, as_url, resource, agent_claims, auth_token)
        return {"auth_token": auth_token, "expires_in": response.json().get("expires_in", 3600)}

    def _granted_scope(context: GrantContext) -> str | None:
        rt_scope = context["rt_claims"].get("scope")
        requested = context.get("requested_scope")
        if requested is None:
            return rt_scope
        allowed = set((rt_scope or "").split())
        requested_set = set(requested.split())
        if not requested_set <= allowed:
            raise AAuthError(DENIED, 403, "requested scope exceeds resource token scope")
        return requested

    def _granted_dataflow(context: GrantContext) -> dict:
        return context["rt_claims"]["dataflow"]

    def _fetch_grant_metadata(issuer: str, transport):
        """Discover token endpoint at aud: classic AS or eDocs sentinel."""
        last_error = None
        for dwk in (DWK_ACCESS, DWK_SENTINEL):
            try:
                return fetch_metadata(issuer, dwk, transport)
            except AAuthError as error:
                last_error = error
        raise last_error or AAuthError(SERVER_ERROR, 502, f"no grant metadata at {issuer}")

    def _handle_as_pending(context: GrantContext, response):
        requirement, params = parse_requirement(response.headers["AAuth-Requirement"])
        as_pending_url = response.headers["Location"]
        if requirement == CLAIMS:
            claims_response = transport.request(
                "POST",
                as_pending_url,
                json={"claims": {"sub": directed_sub(person, context["rt_claims"]["iss"]), "person": person}},
            )
            if claims_response.status_code != 200:
                raise AAuthError.from_response(claims_response.status_code, claims_response.json())
            final = transport.get(as_pending_url)
            if final.status_code != 200:
                raise AAuthError.from_response(final.status_code, final.json())
            auth_token = final.json()["auth_token"]
            as_url = context["rt_claims"]["aud"]
            _check_as_token(context, as_url, context["rt_claims"]["iss"], context["agent_claims"], auth_token)
            return {"auth_token": auth_token, "expires_in": final.json().get("expires_in", 3600)}

        if requirement in (INTERACTION, APPROVAL):
            pid = store.create(retry_after=0)
            store.set_requirement(pid, build_requirement(requirement, **params))
            relay_context = {**context, "as_pending_url": as_pending_url}
            if requirement == INTERACTION:
                interaction_requests[pid] = relay_context
            else:
                pending_requests[pid] = relay_context
            status, headers, body = store.response(pid)
            body["as_requirement"] = requirement
            return body, status, headers

        raise AAuthError(INVALID_REQUEST, 400, f"unsupported AS requirement {requirement!r}")

    def _check_as_token(context: GrantContext, as_url: str, resource: str, agent_claims: dict, auth_token: str) -> None:
        # §9.1.3-lite: sanity-check what the AS issued before relaying
        _, claims = peek_jwt(auth_token)
        rt_claims = context["rt_claims"]
        if (
            claims.get("iss") != as_url
            or claims.get("aud") != resource
            or claims.get("agent") != agent_claims["sub"]
            or jwk_thumbprint(claims["cnf"]["jwk"]) != jwk_thumbprint(agent_claims["cnf"]["jwk"])
        ):
            raise AAuthError(SERVER_ERROR, 502, "AS returned a token that does not match the request")
        if rt_claims.get("dataflow") is not None:
            if claims.get("dataflow") != rt_claims["dataflow"] or "scope" in claims:
                raise AAuthError(SERVER_ERROR, 502, "AS returned a token that does not match the request")
        elif not set((claims.get("scope") or "").split()) <= set((rt_claims.get("scope") or "").split()):
            raise AAuthError(SERVER_ERROR, 502, "AS returned a token that does not match the request")

    @app.post("/permission")
    def permission_endpoint():
        verified = verify(_incoming(), resolver)
        if verified.header.get("typ") != AGENT_TYP:
            raise AAuthError(INVALID_TOKEN, 401, "permission endpoint expects an agent token")
        body = request.get_json(force=True) or {}
        if not body.get("action"):
            raise AAuthError(INVALID_REQUEST, 400, "action is required")

        decision = permission_policy(verified.claims, body) if permission_policy else "grant"
        if decision == "deny":
            raise AAuthError(DENIED, 403, "permission denied by policy")
        if decision == "grant":
            return {"permission": "granted"}
        if decision == "pending":
            pid = store.create(requirement=build_requirement(APPROVAL), retry_after=0)
            pending_requests[pid] = {
                "kind": "permission",
                "agent_claims": verified.claims,
                "request": body,
            }
            status, headers, response_body = store.response(pid)
            return response_body, status, headers
        raise AAuthError(INVALID_REQUEST, 400, f"unsupported permission decision {decision!r}")

    @app.get("/pending/<pid>")
    def pending(pid: str):
        status, headers, body = store.response(pid)
        return body, status, headers

    @app.post("/pending/<pid>")
    def clarify(pid: str):
        context = pending_requests.get(pid)
        if context is None:
            raise AAuthError(INVALID_REQUEST, 404, "no such pending clarification")
        body = request.get_json(force=True) or {}
        action = body.get("action")
        if action == "clarification_response":
            context["clarification_response"] = body.get("response", "")
            return _resolve_grant(pid, context)
        if action == "updated_request":
            resource_token = body.get("resource_token")
            if not resource_token:
                raise AAuthError(INVALID_REQUEST, 400, "resource_token is required")
            context["rt_claims"] = _verify_updated_resource_token(resource_token, context)
            context["resource_token"] = resource_token
            return _resolve_grant(pid, context)
        raise AAuthError(INVALID_REQUEST, 400, "unsupported clarification action")

    def _verify_updated_resource_token(resource_token: str, context: GrantContext) -> dict:
        _, peeked = peek_jwt(resource_token)
        claims = verify_resource_token(
            resource_token,
            resolver,
            aud=peeked.get("aud"),
            agent=context["agent_claims"]["sub"],
            agent_jkt=jwk_thumbprint(context["agent_claims"]["cnf"]["jwk"]),
        )
        original = context["rt_claims"]
        if claims.get("iss") != original.get("iss") or claims.get("aud") != original.get("aud"):
            raise AAuthError(INVALID_TOKEN, 400, "updated resource token changed issuer or audience")
        return claims

    def _resolve_grant(pid: str, context: GrantContext) -> dict:
        """Issue the grant for a resolved pending request and record it with the store."""
        result = _issue_and_remember(context)
        store.resolve(pid, result)
        pending_requests.pop(pid, None)
        return {"status": "recorded"}

    @app.delete("/pending/<pid>")
    def cancel_clarification(pid: str):
        if pending_requests.pop(pid, None) is None:
            raise AAuthError(INVALID_REQUEST, 404, "no such pending clarification")
        store.deny(pid, error=DENIED, detail="clarification cancelled")
        return {"status": "cancelled"}

    @app.post("/consent/<pid>")
    def consent(pid: str):
        """Dev stand-in for the user's consent UI."""
        if session.get("person") != person:
            raise AAuthError(INVALID_REQUEST, 401, "login required")
        context = pending_requests.pop(pid, None)
        if context is None:
            raise AAuthError(INVALID_REQUEST, 404, "no such pending consent")
        decision = (request.get_json(force=True) or {}).get("decision")
        if decision == "grant":
            if context.get("kind") == "permission":
                store.resolve(pid, {"permission": "granted"})
                return {"status": "recorded"}
            if context.get("as_pending_url"):
                _complete_as_pending(pid, context)
                return {"status": "recorded"}
            _check_binding(context)
            store.resolve(pid, _issue_and_remember(context))
        else:
            store.deny(pid, detail="the user declined the request")
        return {"status": "recorded"}

    @app.post("/interaction/<pid>")
    def interaction(pid: str):
        if session.get("person") != person:
            raise AAuthError(INVALID_REQUEST, 401, "login required")
        context = interaction_requests.pop(pid, None)
        if context is None:
            raise AAuthError(INVALID_REQUEST, 404, "no such pending interaction")
        decision = (request.get_json(force=True) or {}).get("decision")
        if decision == "grant":
            if context.get("as_pending_url"):
                _complete_as_pending(pid, context)
                return {"status": "recorded"}
            store.resolve(pid, _issue_and_remember(context))
        else:
            store.deny(pid, detail="resource interaction denied")
        return {"status": "recorded"}

    def _complete_as_pending(pid: str, context: GrantContext) -> None:
        response = transport.request("POST", context["as_pending_url"], json={"decision": "grant"})
        if response.status_code != 200:
            raise AAuthError.from_response(response.status_code, response.json())
        final = transport.get(context["as_pending_url"])
        if final.status_code != 200:
            raise AAuthError.from_response(final.status_code, final.json())
        auth_token = final.json()["auth_token"]
        _check_as_token(
            context,
            context["rt_claims"]["aud"],
            context["rt_claims"]["iss"],
            context["agent_claims"],
            auth_token,
        )
        _remember_grant(context)
        store.resolve(pid, {"auth_token": auth_token, "expires_in": final.json().get("expires_in", 3600)})

    return app


def _incoming() -> HttpRequest:
    return HttpRequest(request.method, request.url, dict(request.headers.items()))
