# AAuth + eDocs Demo Implementation Plan

This is the restartable handoff for extending AAuth to support the eDocs
authorization flow. It replaces the original base-AAuth implementation plan,
which no longer described the current code or intended architecture.

Target for the first vertical slice: the Wednesday demo described below.
Traditional AAuth remains on `aauth/main`; all eDocs extension work belongs on
`aauth/edocs-demo` and `mcp-aauth/edocs-demo`.

**Last handoff update:** 2026-07-27. The original vertical slice now works
through a real MCP SDK tool call. Section 12 records the completed work and
Section 13 is the current resume point.

## 1. Current repository state

### `mcp-python-sdk`

- Branch: `aauth-auth-middleware-hook`
- Commit: `290211f2` (pushed)
- Adds the Streamable HTTP authentication middleware hook used by
  `mcp-aauth`.
- Relevant files:
  - `src/mcp/server/lowlevel/server.py`
  - `src/mcp/server/mcpserver/server.py`
- The current working tree has an unrelated local `uv.lock` modification.
  Preserve it unless its owner explicitly asks otherwise.

### `aauth`

- Extension branch: `edocs-demo`.
- Current commit: `5acabda`.
- Remote `origin/edocs-demo`: `5b434e7`; the local branch is two commits
  ahead and has not been pushed.
- The branch now includes the core models and claims, conditional controller
  tokens, exact controller policy decisions, unanimous Sentinel aggregation,
  optional eDocs behavior in the existing AS, the Sentinel HTTP flow, generic
  downstream-denial relay through pending polling, and authenticated consent
  review.
- Latest complete test result: **182 passed, 1 skipped**.
- Session commits after the pulled Sentinel implementation:
  - `4c591fc fix: relay downstream denials through polling`
  - `5acabda feat: expose verified pending consent details`
- Relevant implementation files:
  - `src/aauth_edocs/edocs.py` — eDocs dataflow/domain models
  - `src/aauth_edocs/tokens.py` — normal, resource, and conditional claims
  - `src/aauth_edocs/controller.py` — exact controller policy decisions
  - `src/aauth_edocs/sentinel.py` — Sentinel HTTP flow and aggregation
  - `src/aauth_edocs/ps.py` — generic PS approval, review, relay, and polling
  - `src/aauth_edocs/agent.py` — existing generic synchronous agent flow
- Relevant tests:
  - `tests/test_sentinel.py`
  - `tests/test_sentinel_http.py`
  - `tests/test_phase3_four_party.py`
  - `tests/test_phase3_three_party.py`
- Older prototypes exist at `origin/edocs` and `origin/chz/sentinel`.
  They are reference material only and must not be merged wholesale. They
  predate the header-preservation and optional-dependency work on `main`,
  trust a resource-supplied controller for routing, and contain only a
  stubbed provenance check.

### `mcp-aauth`

- Branch: `edocs-demo`
- Current commit: `4d980ca`.
- Remote `origin/edocs-demo`: `41470ee`; the local branch is six commits
  ahead and has not been pushed.
- Generated `src/mcp_aauth/__pycache__/` and `tests/__pycache__/` directories
  are untracked and must not be committed.
- Latest complete test result: **62 passed**.
- Session commits:
  - `c4d8496 feat: add eDocs MCP authorization flow`
  - `b6feaa5 feat: request eDocs resource tokens over signed HTTP`
  - `c7f76d5 refactor: keep eDocs demo outside mcp-aauth API`
  - `6103fad test: receive Sentinel denial through polling`
  - `85b1f2e test: harden eDocs MCP authorization boundary`
  - `4d980ca test: review verified eDocs consent claims`
- Implemented:
  - ASGI-to-AAuth request conversion preserving the signed request target
    and HTTP headers;
  - OAuth/AAuth credential routing;
  - AAuth agent request verification;
  - `Signature-Key` scheme `jwt` enforcement;
  - `aa-agent+jwt` enforcement;
  - AAuth ASGI middleware and public middleware factory;
  - end-to-end MCP SDK authentication-hook integration;
  - `AAuthAgentHTTPAuth`, which applies the agent's signature to outgoing
    HTTP requests;
  - generic `aa-auth+jwt` verification and ASGI middleware in
    `src/mcp_aauth/verification.py`;
  - a full eDocs success and conditional-denial path through a real MCP tool
    in `tests/test_edocs_end_to_end.py`;
  - negative final-boundary tests for issuer, audience, token type,
    proof-of-possession, eDoc, function, source, and destination mismatches.
- No eDocs resource or function abstraction is exported by `mcp_aauth`.
  eDocs-specific resource state and `identity@1` are deliberately test-local
  in `tests/test_edocs_end_to_end.py`.

### Other workspace repositories

- `eDocs-research/main` was pulled to `6733a49`. The relevant new memo is
  `memos/aauth-update-6-21/memo.tex`; it selects representative agents and
  provider-side computation for this project.
- `eDocs-system/kyle/rules` contains a large local Iceberg/Delta Sharing
  implementation, but Iceberg work is explicitly out of scope for this
  AAuth/MCP demo and must not be mixed into the current branches.

## 2. Architecture and trust boundaries

The resource creates a signed proposed dataflow but performs no access-policy
evaluation:

```text
Agent -> Resource -> Person Server -> Sentinel -> every controller AS
                                                   |
Resource <- Agent <- Person Server <- Sentinel auth token
```

The roles behave as follows:

- **Resource**: identifies the requested operation and eDoc, issues the
  resource token, and later enforces the final token's cryptographic and
  request bindings. It has no ACL or policy callback.
- **Person Server (PS)**: represents the person accountable for the agent,
  obtains explicit user approval, and forwards the resource token to its
  audience.
- **Sentinel**: appears as a standard AS to the upstream PS and a standard PS
  to downstream ASes. It owns the authoritative controller, function, resource
  binding, and provenance registries. It does not replace controller policy.
- **Controller AS**: owns and evaluates its controller's dataflow policies.
- **Agent**: owns the request-signing key, obtains the resource/auth tokens,
  and presents the final Sentinel token to the MCP resource.

The Sentinel must remain as transparent as possible to traditional AAuth:

- publish `aauth-access.json` toward upstream PSes;
- publish `aauth-person.json` toward downstream ASes;
- use the standard `aa-auth+jwt` for the final resource authorization;
- introduce no `aauth-sentinel.json` metadata or final-token type.

The only new token type is an AS-to-Sentinel conditional approval that cannot
be used directly at a resource.

## 3. Dataflow and person-accountability model

A dataflow is:

```text
(A, f, D, B)
```

- `A`: source agent;
- `f`: registered function identifier;
- `D`: eDoc identifier;
- `B`: destination/requesting agent.

Although A and B are represented operationally by agent identifiers, policy
accountability is tied to people through AAuth:

- each agent token identifies exactly one PS through its `ps` claim;
- each PS enforces AAuth's one-agent-to-one-person binding;
- the destination PS's signed participation and explicit user approval tie B
  to the accountable person;
- a pre-provisioned PS-signed resource binding ties A to the resource.

Do not add a global person identifier to resource tokens or policies.

### Resource-qualified identifiers and unknown-eDoc discovery

An eDoc identifier must be qualified by the resource issuer rather than treated
as a globally unique resource-chosen string. It may be represented as the pair
`(resource_issuer, local_edoc_id)` or as a resource-owned URI. This prevents one
resource from impersonating another resource's identifier without requiring a
separate registration or Sentinel-assigned ID.

The signed resource token is the discovery assertion for an eDoc that the
Sentinel does not yet know. The Sentinel first verifies the token and its
provisioned resource issuer/key binding, then selects candidate controllers:

- if `resource_token.controllers` is non-empty, that list replaces the
  resource-owner AS for this eDoc;
- if it is empty, use the resource owner's provisioned AS;
- the resource-owner-AS association is trusted Sentinel configuration and is
  not supplied by the resource token.

The Sentinel contacts every candidate AS. A candidate becomes authoritative
only after authenticating itself and returning a valid decision for the exact
qualified eDoc and proposed dataflow. If every candidate confirms, the
Sentinel caches that set as the authoritative controller mapping. Subsequent
requests use the cached mapping; a resource token cannot replace it by
supplying a different advisory list.

The eDocs claim group must still include `controllers`, but it may be an empty
JSON list to request the resource-owner-AS fallback. Duplicate or empty-string
controller entries remain invalid.

This model protects eDoc identity but does not prove content identity. A
resource cannot claim another issuer's qualified ID, but it can copy document
bytes and publish them under a new qualified ID that it owns. Detecting that
requires a content digest, signed provenance, or an external ownership
registry. Those integrity mechanisms are deliberately deferred; for the demo,
the Sentinel records and audits the resource/key and controller assertions it
actually verified.

The proactive resource authorization request supplies:

```json
{
  "scope": "identity@1",
  "edoc_id": "doc-123"
}
```

The resource derives A from its configuration/binding and B from the verified
agent token. Its resource token contains the normal AAuth claims plus:

```json
{
  "aud": "https://sentinel.example",
  "source_agent": "aauth:source@ap.example",
  "scope": "identity@1",
  "edoc_id": "doc-123",
  "agent": "aauth:destination@ap.example",
  "controllers": [
    "https://as-a.example",
    "https://as-b.example"
  ]
}
```

`controllers` is advisory:

- the PS may display it or use it when deciding whether to seek approval;
- the Sentinel must not use it for routing or authorization;
- the Sentinel resolves the authoritative controller list from `edoc_id` in
  its own registry.

## 4. Core eDocs extension in `aauth`

Add explicit models and validators for:

- `Dataflow(source, function, document, destination)`;
- an exact-match rule whose condition is either absent or one positive
  prerequisite `Dataflow`;
- `FunctionDescriptor` with immutable ID, description, implementation URI,
  and digest;
- a PS-signed resource binding containing only source PS, resource issuer,
  and resource-key thumbprint; the source agent is the registry key;
- an injected in-memory Sentinel registry containing:
  - resource bindings;
  - `edoc_id -> controller AS URLs`;
  - function descriptors;
  - materialized dataflows.

The Wednesday policy subset is:

```text
X
X | Y
```

with these semantics:

- policy matching is exact and default-deny;
- `X | Y` means "allow X if Y has materialized";
- the AS evaluates whether X matches its policy;
- the AS signs and returns Y to the Sentinel;
- the Sentinel tests exact membership of Y in its provenance set.

Boolean `AND`/`OR`/`NOT`, wildcards, sets, transitive derivation, and cycle
checking are future work. The eventual condition representation should be able
to evolve into a boolean expression tree without changing `Dataflow`.

Register `identity@1` for the first demo:

```text
identity@1(D) = D
```

The Sentinel stores its descriptor and digest. The actual callable is local to
the demo resource; a future deployment may retrieve an immutable
implementation from GitHub or another registry.

## 5. Conditional authorization tokens

A controller AS returns:

- standard `aa-auth+jwt` when it approves unconditionally;
- `aa-conditional-auth+jwt` when its matching rule has prerequisite Y;
- a denial when no rule matches.

The conditional token must be signed by the AS and contain:

- the same issuer, resource audience, agent, agent-key, scope, source-agent,
  and eDoc bindings as the proposed request;
- the prerequisite dataflow Y.

Only the Sentinel accepts `aa-conditional-auth+jwt`. An ordinary AAuth
resource must reject it by token type. Do not encode a condition as an
ignorable claim on a normal auth token: an older verifier could otherwise
mistake an unevaluated conditional authorization for a completed grant.

## 6. Sentinel flow

For a PS request to the Sentinel:

1. Verify the HTTP request is signed by a PS using the standard `jwks_uri`
   server scheme.
2. Verify the agent token, resource token, and their agent/key bindings.
3. Require the signed PS issuer to equal the agent token's `ps`.
4. Verify `resource_token.aud` is the Sentinel.
5. Resolve the resource token issuer/key and require it to match the
   pre-provisioned PS-signed resource binding for `source_agent`.
6. Require exactly one scope value and resolve it in the function registry.
7. Construct `(source_agent, scope, edoc_id, agent)`.
8. Resolve every authoritative controller AS from the Sentinel registry.
9. Call each AS with the original resource token and agent token, signing as a
   standard PS.
10. Cryptographically verify every AS response and all request bindings.
11. For conditional responses, require the prerequisite tuple to be present
    in the Sentinel's materialized set.
12. Require unanimous approval. A denial, malformed token, failed condition,
    or unavailable AS prevents final token issuance.
13. Mint a standard Sentinel-issued `aa-auth+jwt` bound to the resource,
    requesting agent/key, scope, source agent, eDoc, and authoritative
    controllers.
14. Add the proposed tuple to the materialized-provenance set.
15. Return the final token to the PS, which relays it to the agent.

For Wednesday, token issuance is treated as materialization. This is an
explicit optimistic simplification: an issued token that is never exercised
will still appear in provenance. A later version must record materialization
after verified execution instead.

## 7. Person Server behavior

The destination PS must:

- validate the agent/resource-token bindings using existing AAuth behavior;
- place the request in a pending state;
- expose a minimal authenticated browser page showing:
  - requesting agent;
  - source agent;
  - resource;
  - function;
  - eDoc ID;
  - advisory controllers;
- provide Approve and Deny actions;
- only forward to the Sentinel after explicit approval;
- relay Sentinel success or denial through the existing polling flow.

A configured single-person login/session remains acceptable for the demo. It
must still require a login before accepting the approval action.

## 8. MCP resource extension

On `mcp-aauth/edocs-demo`, add a Starlette/ASGI resource application beside
the MCP route:

- `/.well-known/aauth-resource.json`;
- resource JWKS;
- proactive authorization endpoint;
- `/mcp`.

The authorization endpoint:

- requires an agent-signed request;
- accepts exactly one scope and one `edoc_id`;
- verifies that the document exists and the function is supported;
- derives A and B rather than accepting them from request JSON;
- issues the extended resource token with `aud=Sentinel`;
- performs no policy evaluation.

The MCP authentication path:

- requires `Signature-Key` scheme `jwt`;
- requires final token type `aa-auth+jwt`;
- requires the configured Sentinel issuer;
- verifies resource audience and agent proof-of-possession;
- rejects intermediate AS and conditional tokens.

The MCP materialization tool:

- accepts `edoc_id` and function ID;
- requires the final token's source, function, eDoc, destination, audience,
  issuer, and key bindings to match;
- executes the locally registered `identity@1`;
- returns the eDoc unchanged.

These are enforcement checks for the decision expressed by the Sentinel token,
not resource-side access-control policy.

## 9. Wednesday demo topology and scenarios

Run:

- one Agent Provider;
- source and destination Person Servers;
- one MCP resource;
- one Sentinel;
- two controller Access Servers;
- in-memory resources, policies, functions, controller mappings, and
  provenance.

### Successful flow

1. Agent requests `(A, identity@1, D, B)`.
2. Resource issues a resource token with `aud=Sentinel`.
3. B's PS returns a pending response and browser approval URL.
4. The user opens the page, logs in, reviews the tuple, and approves.
5. PS forwards the resource and agent tokens to the Sentinel.
6. Sentinel contacts both authoritative ASes.
7. Both approve and every prerequisite is present.
8. Sentinel mints the final token and records the tuple.
9. Agent presents the final token over MCP.
10. Resource executes `identity@1` and returns D.

### Denied flow

1. Both controller ASes are contacted.
2. One AS returns a conditional token containing prerequisite Y.
3. Y is not present in Sentinel provenance.
4. Sentinel denies the request.
5. No final auth token is issued.
6. The proposed tuple is not added to provenance.

## 10. Tests and acceptance criteria

### Core/token tests

- Resource binding attestation rejects tampered source, resource, key, or PS.
- Extended resource/auth claims round-trip correctly.
- Conditional tokens cannot pass ordinary auth-token verification.
- Exact rules match only the complete tuple.
- No matching rule is denied.
- Present prerequisite succeeds; missing prerequisite fails.

### Sentinel tests

- PS signer must match the requesting agent token's `ps`.
- Resource token issuer/key/source must match its provisioned binding.
- Advisory controllers do not affect routing.
- Every registry-mapped AS is contacted.
- All ASes must approve.
- AS tokens are signature-verified rather than merely decoded.
- Wrong issuer, audience, agent, key, function, eDoc, or source is rejected.
- A failed condition produces no final token or provenance entry.
- Successful issuance records the proposal.

### PS tests

- Anonymous users cannot approve.
- Approval page displays the complete proposal and advisory controllers.
- Approve forwards; Deny does not.
- Sentinel denial is relayed to the polling agent.

### MCP tests

- Proactive authorization creates the correct Sentinel-audience token.
- Only a Sentinel-issued final auth token reaches the tool.
- Mismatched function/eDoc/source tokens are rejected.
- No local ACL or policy callback participates.
- Full success and conditional-denial flows work end to end.

## 11. Explicitly deferred work

- Boolean condition trees and wildcard/set-valued policies.
- Persistent controller, function, resource-binding, policy, and provenance
  stores.
- Durable qualified-eDoc discovery caches and resource-owner-AS associations.
- Content digests, signed provenance, or external ownership registries for
  detecting copied content published under a new qualified identifier.
- Recording materialization after verified execution rather than issuance.
- External function retrieval and runtime digest enforcement.
- Verifier/TEE claim integrity.
- Transformed-output registration and derived provenance.
- Production user authentication.
- Remaining AAuth draft conformance gaps such as `expires` handling and full
  error taxonomy.

## 12. Work completed in the 2026-07-27 session

The complete tested flow is now:

```text
Person requests f(D)
  -> agent finds the MCP resource
  -> resource authenticates the agent and issues a resource token
  -> agent submits the resource token to its PS
  -> PS exposes verified review facts and records the person's decision
  -> PS forwards the unchanged agent/resource tokens to the Sentinel
  -> Sentinel contacts every authoritative controller AS
  -> Sentinel checks conditional prerequisites and unanimous approval
  -> PS relays the final token or denial through the opaque polling URL
  -> agent signs a real MCP request with the final token
  -> MCP middleware and the application enforce the final bindings
  -> `identity@1` executes only after every check succeeds
```

Specific completed behavior:

- Pulled five new `aauth/edocs-demo` commits through `5b434e7`, adding the
  complete Sentinel/controller authorization flow.
- Added generic standard `aa-auth+jwt` verification to `mcp-aauth`:
  `verify_aauth_authorization`, `AAuthAuthorizationMiddleware`, and
  `aauth_authorization`.
- Exercised a successful Sentinel-issued token through the real MCP SDK
  Streamable HTTP authentication hook and a real MCP tool call.
- Exercised a missing conditional prerequisite: no final token, no MCP
  execution, and no provenance entry.
- Completed the initial resource-token request over agent-signed HTTP.
- Removed the temporary public `EdocsResource` API after agreeing on the
  layering rule: MCP is generic, AAuth builds on MCP, and eDocs builds on
  AAuth. The fake resource and `identity@1` implementation are now test-local.
- Fixed generic PS deferred error delivery. Human approval records the
  decision; the waiting agent receives the original Sentinel/AS denial,
  status, and detail through its opaque pending URL.
- Added authenticated `GET /consent/<pid>` review of already-verified request
  facts. It is read-only, exposes no raw tokens, and disappears after decision.
- Hardened the final MCP boundary. Controller-issued, wrong-audience,
  conditional, wrong-proof-key, wrong-eDoc, wrong-function, wrong-source, and
  wrong-destination requests all fail with zero successful function
  executions.

Important decisions made during this session:

- Do not build the Iceberg/Delta Sharing implementation in this phase.
- Do not add a standalone PS HTML page yet. The intended user experience is a
  person working with a conversational agent; the host should render a
  trusted structured approval prompt analogous to Codex command approvals.
- The human approval happens only after the resource has authenticated the
  agent and issued the signed resource token. The approval display is derived
  from PS-verified claims, not from agent-authored chat text.
- A function is selected by identifier for a request; it is not newly
  registered on every invocation.
- Resource/application code owns executable function implementations. The
  eDocs extension owns function identity, descriptors, dataflow semantics,
  controllers, and policy. Generic `mcp-aauth` owns neither.

## 13. Current resume point: generic AAuth-aware MCP clients

The next milestone is client-side composition, in this order:

### 13.1 Generic AAuth coordinator in `aauth`

Add a reusable coordinator alongside `src/aauth_edocs/agent.py` that is
independent of MCP and can be shared by multiple server-specific clients. It
should own:

- agent identity, signing key, and agent token;
- PS identity and generic resource-token exchange;
- pending requirements and opaque polling;
- an approval-required event/callback for a trusted host UI;
- resource-origin-scoped final-token caching;
- retry inputs/results, without interpreting tool arguments or eDocs claims.

The coordinator must not know about `f(D)`, eDocs, Sentinels, or controllers.
The existing synchronous `AgentSession` is useful reference behavior but
should not be copied blindly into an MCP-specific class.

### 13.2 Generic MCP adapter in `mcp-aauth`

Build on the coordinator and the standard MCP SDK client. Each MCP server still
has its own client/session; the reusable AAuth coordinator may be shared among
them. The adapter should:

- sign outgoing MCP HTTP requests as the agent;
- recognize an AAuth resource-token requirement;
- pass the resource token to the coordinator;
- surface a structured approval-required event to the host;
- wait for the human decision and poll the opaque URL;
- retry the original MCP request with the resource-scoped final auth token.

Start from `src/mcp_aauth/client.py`, which currently only signs requests with
a supplied token. Keep `mcp-python-sdk` generic; use its existing custom
authentication hook rather than adding AAuth code there.

### 13.3 Explicit eDocs client/host extension

Only after generic AAuth works, add the explicit eDocs layer. It should:

- construct or recognize requests for a registered function over an eDoc;
- interpret the PS-verified eDocs claim group for display;
- render source, function, eDoc, destination, and controllers in a trusted
  host permission prompt;
- enforce eDocs dataflow claims at the application boundary.

For the current demo, keep this extension on `mcp-aauth/edocs-demo` and outside
the generic `mcp_aauth` public API (the integration test is the current
example). If it becomes reusable, make it a distinct package such as
`mcp-aauth-edocs`, depending on generic `mcp-aauth` and the eDocs extension in
`aauth/edocs-demo`.

### 13.4 Intended host experience

The target experience is Codex/Claude-like:

```text
Person: "Analyze D in this way."
Agent: discovers the resource and proposes f(D).
Host: pauses and renders the PS-verified authorization request.
Person: approves or denies in the same conversational interface.
Agent: resumes automatically with the final token or reports the denial.
```

The agent must not be able to approve itself or control the trusted approval
card as ordinary chat text. The host sends the person's decision directly to
the PS. Native MCP approval prompts may be useful presentation surfaces, but
standard MCP tool approval is not automatically an AAuth approval credential;
the host integration must bind the authenticated person, exact verified
request, pending approval ID, and decision.

## 14. Review protocol

Before making it:

1. Present the exact proposed files, APIs, claim validation, and tests.
2. Reference the current implementation by line.
3. Explain every design decision.
4. Wait for explicit approval.

Continue using the same approval boundary for every subsequent code change and
before every commit or push.
