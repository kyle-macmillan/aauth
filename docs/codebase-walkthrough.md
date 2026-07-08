# aauth-edocs Codebase Walkthrough

This repo is a compact, internal-demo implementation of
`draft-hardt-oauth-aauth-protocol-09`, with the companion
`draft-hardt-httpbis-signature-key-04` used for the `Signature-Key` request
header. Local copies of both drafts live in `docs/specs/` and are the reference
texts for the section numbers below.

The implementation is intentionally smaller than the draft. It keeps the core
shape of AAuth: proof-of-possession HTTP signatures, agent/resource/auth tokens,
well-known metadata, resource challenges, Person Server consent, Access Server
federation, permission requests, and sub-agent delegation. It skips production
hardening such as HTTPS enforcement, full identifier grammar, complete
structured error bodies, persistent stores, JWKS cache-control policy, and real
human UI.

## Protocol Map

AAuth is organized around five roles:

| Draft role | Spec anchor | Code |
| --- | --- | --- |
| Agent | Section 5, Section 13.2 | `src/aauth_edocs/agent.py` |
| Agent Provider (AP) | Section 5.2, Section 4.5 | `src/aauth_edocs/ap.py` |
| Resource | Section 6, Section 13.3 | `src/aauth_edocs/resource.py` |
| Person Server (PS) | Section 7 | `src/aauth_edocs/ps.py` |
| Access Server (AS) | Section 9 | `src/aauth_edocs/asrv.py` |

The shared protocol primitives are in:

| Primitive | Spec anchor | Code |
| --- | --- | --- |
| HTTP Message Signatures profile | AAuth Section 12.7, SigKey Sections 3.5 and 3.6 | `httpsig.py` |
| Tokens | Sections 5.2, 6.7, 9.4 | `tokens.py` |
| Metadata and JWKS discovery | Sections 12.8, 12.10 | `metadata.py`, `ids.py` |
| Requirement, mission, capability headers | Sections 8.7, 12.1, 12.3 | `headers.py` |
| Deferred responses and interaction codes | Sections 12.3.3, 12.4 | `deferred.py` |
| Key generation and thumbprints | Section 12.7.1, RFC 7638 references | `keys.py` |

## Core Flow

The central invariant is that every meaningful request is signed. The agent
holds a private Ed25519 key. A presented JWT contains `cnf.jwk`, and the HTTP
Message Signature must verify with that public key. This turns the JWT from a
bearer credential into a proof-of-possession credential.

In code, `AgentSession.request()` signs outbound requests with either the
agent token or a cached auth token. It uses `sign()` from `httpsig.py`, which
sets:

- `Signature-Key: sig=jwt;jwt="<token>"`
- `Signature-Input`
- `Signature`

`httpsig.verify()` is the server-side entry point. It parses the three signature
headers, checks that the AAuth-mandated covered components are present
(`@method`, `@authority`, `@path`, and `signature-key`), validates the `created`
timestamp, verifies the JWT using issuer metadata, extracts `cnf.jwk`, and then
verifies the HTTP signature. This corresponds to the AAuth HTTP Message
Signatures profile in Section 12.7 and the SigKey `jwt` scheme in Section 3.6.

For PS-to-AS federation, the PS does not present an agent JWT as its own
credential. It signs with `sign_server()`, which uses:

```http
Signature-Key: sig=jwks_uri;id="<ps>";dwk="aauth-person.json";kid="<kid>"
```

That maps to SigKey Section 3.5 and AAuth Section 9.1.1.

## Agent Provider

`create_ap()` in `ap.py` implements the demo Agent Provider:

- `GET /.well-known/aauth-agent.json` publishes AP metadata.
- `GET /jwks.json` publishes the AP signing key.
- `POST /issue` issues `aa-agent+jwt` agent tokens.

The draft treats agent token acquisition as a real enrollment ceremony
(Sections 4.5 and 5.2.1). This repo deliberately makes `/issue` open for local
experimentation. The useful part for the rest of the protocol is preserved:
the AP-issued token has `typ: aa-agent+jwt`, `dwk: aauth-agent.json`, `sub`,
`cnf.jwk`, optional `ps`, and optional `parent_agent`.

Sub-agent issuance also lives here. If `parent_agent` is supplied, `/issue`
enforces the local-part naming rule from Section 10.2.1 and rejects nested
sub-agents, matching the single-level rule in Section 10.2.2.

## Agent SDK

`AgentSession` in `agent.py` is the client-side protocol loop:

1. Enrollment calls AP metadata and `/issue`, then stores the private key and
   agent token.
2. Every `get()` or `post()` call signs the HTTP request.
3. If a resource returns `401` with `AAuth-Requirement:
   requirement=auth-token; resource-token="..."`, the agent verifies the
   resource-token challenge per Section 6.7.3 and exchanges it at the PS token
   endpoint.
4. If the PS returns a deferred `202`, the agent invokes `on_pending()` and
   then polls the pending URL via `poll()`.
5. The returned auth token is cached by resource origin and presented on later
   calls.

There is also a proactive path, `authorize(resource_url, scope)`, for Section
6.1. It calls the resource authorization endpoint directly to obtain a resource
token, then exchanges it at the PS.

The cached-token behavior is intentionally pragmatic: one auth token is cached
per origin. If a cached token receives `403`, the agent evicts it and retries
with the agent token so the resource can issue a fresh challenge for the
required scope.

## Resource

`resource.py` provides Flask helpers for the resource side of Sections 4.1.1,
4.1.3, 4.1.4, and 6.

For identity-based access, `require_aauth_identity()` verifies an agent-token
signed request and places the verified request on `flask.g.aauth`. This is the
drop-in API-key replacement path from Section 4.1.1 and Section 13.1.

For auth-token access, `install_resource()` adds:

- `GET /.well-known/aauth-resource.json`
- `GET /jwks.json`
- `POST /authorize`

The authorization endpoint implements Section 6.1 and Section 6.2. It verifies
the agent token, reads the requested scope, and mints an `aa-resource+jwt` with:

- `iss` = resource issuer
- `aud` = resource AS if configured, otherwise the agent token's PS
- `agent` = requesting agent id
- `agent_jkt` = thumbprint of the agent signing key
- `scope` = requested scope

`require_auth_token()` protects application endpoints. If the request is signed
with an auth token, the resource verifies it per the implemented subset of
Section 9.4.3 and checks scope containment. If the request is signed with an
agent token, it returns the Section 6.6 challenge with a fresh resource token in
`AAuth-Requirement`.

## Person Server

`create_ps()` in `ps.py` is the largest module because the PS is where user
consent, person identity, and federation meet.

It publishes:

- `GET /.well-known/aauth-person.json`
- `GET /jwks.json`
- `POST /token`
- `POST /permission`
- demo login and pending-decision endpoints

The token endpoint implements Section 7.1.3. It verifies the agent-token signed
request, verifies the resource token, checks whether the agent is already bound
to another person, evaluates the local `policy` hook, and either issues an auth
token, denies, asks for clarification, or creates a pending approval.

For three-party access, where `resource_token.aud` is the PS issuer, `_issue()`
creates a PS-issued `aa-auth+jwt`:

- `iss` = PS issuer
- `dwk` = `aauth-person.json`
- `aud` = resource issuer
- `agent` and `cnf.jwk` = authorized agent or sub-agent
- `sub` = directed person identifier
- `scope` = granted scope

The directed identifier is generated by `directed_sub(person, resource)`, which
implements the privacy idea from Section 15.1: the same person gets a stable
pseudonymous subject per resource, not one global identifier.

For four-party access, where `resource_token.aud` is an AS, `_issue()` federates
to the AS token endpoint. The PS signs that call with `jwks_uri`, as required
by Section 9.1.1, relays the agent token and resource token, validates the AS
auth token per Section 9.1.3, and returns it to the agent.

The PS remembers successful grants in two in-memory structures:

- `agent_bindings`: agent id -> person id, enforcing Section 14.11's concern
  that one agent should not silently become associated with multiple people.
- `consents`: `(person, agent, resource, scope)`, so remembered consent is
  scoped to the specific agent rather than shared across all agents for the
  same person.

The PS also exposes the demo permission endpoint from Section 7.4. A signed
agent request includes an `action` plus optional description, parameters, and
mission. The `permission_policy` hook decides `grant`, `deny`, or `pending`.
This repo does not define universal permission semantics; the draft leaves the
meaning of the action and parameters to the PS/person/application context.

## Access Server

`create_as()` in `asrv.py` implements the Access Server side of Section 9.

It publishes:

- `GET /.well-known/aauth-access.json`
- `GET /jwks.json`
- `POST /token`
- pending URLs for deferred AS decisions

The AS token endpoint only accepts PS callers authenticated with
`Signature-Key` scheme `jwks_uri`. It then verifies:

1. the agent token,
2. the resource token with `aud` equal to the AS issuer,
3. `resource_token.agent` equals the agent token subject,
4. `resource_token.agent_jkt` matches the agent token `cnf.jwk`.

A policy hook returns one of:

- granted scope string,
- `None` for deny,
- a deferred requirement dict such as `{"requirement": "claims"}`,
  `{"requirement": "interaction"}`, `{"requirement": "approval"}`, or
  `{"requirement": "payment"}`.

The AS-issued auth token uses `dwk: aauth-access.json` and is scope-oriented.
When claims are supplied through the claims-required pending flow, the AS can
include a `sub` claim as well.

The PS can also collapse with the AS in one Flask app by passing an existing
app and alternate route paths to `create_as()`. That exercises the Section
9.3.4 deployment shape without adding another server process.

## Tokens

`tokens.py` owns the three JWT types from the draft:

| Token | Spec anchor | Builder | Verifier |
| --- | --- | --- | --- |
| Agent token | Section 5.2 | `issue_agent_token()` | `verify_agent_token()` |
| Resource token | Section 6.7 | `issue_resource_token()` | `verify_resource_token()`, `check_resource_challenge()` |
| Auth token | Section 9.4 | `issue_auth_token()` | `verify_auth_token()` |

All builders set `jti`, `iat`, `exp`, JOSE `typ`, and `kid`. They use EdDSA
through `joserfc`. The verifier implementations cover the claims the demo flows
depend on: JWT signature, `typ`, expiry, `aud`, agent binding, `cnf.jwk`, and
`agent_jkt`.

The implementation does not currently enforce every lifetime cap, identifier
syntax rule, revocation rule, or act-chain validation from the draft. Those are
documented as intentional simplifications in `IMPLEMENTATION_PLAN.md`.

## Metadata and Key Discovery

`metadata.py` implements the well-known metadata pattern from Section 12.10:

```text
{issuer}/.well-known/{dwk}
```

The `dwk` values are defined in `ids.py`:

- `aauth-agent.json`
- `aauth-person.json`
- `aauth-access.json`
- `aauth-resource.json`

`fetch_metadata()` keeps the high-value issuer check: the JSON document's
`issuer` must match the issuer URL used to fetch it. `JwksResolver` then follows
`jwks_uri` and caches keys by `(jwks_uri, kid)`.

This is a light version of Section 12.8. It does not implement HTTP cache
headers, refresh floors, egress controls, or 24-hour expiry. For the in-process
demo and tests, the important property is that JWT verification is rooted in
the issuer's published metadata.

## Headers and Deferred Responses

`headers.py` handles the Structured Field headers used by the implemented
flows:

- `AAuth-Requirement` from Section 12.3
- `AAuth-Mission` from Section 8.7
- `AAuth-Capabilities` from Section 12.1
- `Authorization: AAuth ...` from Section 6.4, although two-party mode is not
  implemented

`deferred.py` implements the polling pattern from Section 12.4. `PendingStore`
creates pending URLs, returns `202` responses with `Location`, `Retry-After`,
`Cache-Control: no-store`, and optional `AAuth-Requirement`, and delivers a
terminal response exactly once. `poll()` is the agent-side GET loop.

Interaction codes exist as random, single-use demo codes. The full Crockford
alphabet, folding, expiry, and rate-limit requirements from Section 12.3.3.1
are not implemented.

## Delegation and Sub-Agents

The implemented delegation support covers the parent-mediated sub-agent model
from Section 10.2.3.

The AP issues a sub-agent token with `parent_agent`. The sub-agent calls a
resource and receives a resource token bound to the sub-agent key. The parent
then calls the PS token endpoint, signing with the parent's key and presenting
the sub-agent token in `subagent_token`. The PS checks:

- the presented agent token is the parent,
- `subagent_token.parent_agent` points to that parent,
- the resource token is bound to the sub-agent key.

When successful, the issued auth token is bound to the sub-agent key and has
`agent` equal to the sub-agent id. The `act.agent` claim records the parent.
That gives the resource enough information to see both who is acting and who
mediated the authorization.

The repo also supports a simplified upstream-token call-chain path: an agent
can present an upstream auth token to the PS, and the PS records `act.agent`
for the downstream token. Full multi-hop act-chain policy is beyond the demo.

## What Is Intentionally Not Implemented

The following are either explicitly skipped for this internal demo or left as
future work:

- Resource-managed two-party `AAuth-Access` mode from Section 4.1.2 and
  Section 6.4.
- Missions as a full PS-managed lifecycle from Section 8. The header and
  mission reference data shape exist, but mission creation/log/completion is
  skipped for now.
- Audit endpoint from Section 7.5.
- Production consent and interaction UI.
- Real TLS/server identifier enforcement from Section 12.9 and Section 14.15.
- Full `Signature-Error` machinery from the Signature-Key draft Section 5.
- Revocation from Section 12.6.
- Complete JWKS caching and egress controls from Section 12.8.
- Full deferred-response state machine details such as `Prefer: wait`, 429
  backoff, and `interacting` status.

## Test Guide

The tests are the best executable walkthrough:

| Test file | What it covers |
| --- | --- |
| `tests/test_keys_ids_headers.py` | keys, identifiers, headers |
| `tests/test_httpsig.py` | HTTP signatures and `Signature-Key` |
| `tests/test_tokens.py` | agent/resource/auth token builders and verifiers |
| `tests/test_metadata_deferred.py` | metadata, JWKS resolution, pending polling |
| `tests/test_phase2_identity.py` | identity-based access |
| `tests/test_phase3_three_party.py` | PS-asserted resource access, consent, clarification, interaction |
| `tests/test_phase3_four_party.py` | PS-to-AS federation, AS pending requirements, PS/AS collapse |
| `tests/test_phase5_permission.py` | permission endpoint |
| `tests/test_phase6_delegation.py` | sub-agent and call-chain delegation |
| `tests/test_end_to_end.py` | combined happy-path coverage |
| `tests/interop/test_cross_check.py` | compatibility checks against the external Python `aauth` library |

For a quick confidence check:

```bash
uv run pytest -q
```

At the time this walkthrough was written, the suite passes with `98 passed, 1
skipped`.
