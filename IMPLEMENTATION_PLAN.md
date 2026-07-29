# AAuth + eDocs Demo Implementation Plan

This is the restartable handoff for extending AAuth to support the eDocs
authorization flow. It replaces the original base-AAuth implementation plan,
which no longer described the current code or intended architecture.

Target for the first vertical slice: the Wednesday demo described below.
Traditional AAuth remains on `aauth/main`; reusable eDocs extension work
belongs on `aauth/edocs-demo` and `mcp-aauth/edocs-demo`, while Codex-specific
composition and UI behavior belongs in `mcp-aauth-codex`.

**Last handoff update:** 2026-07-28. The reusable provider, mutable policy,
shared function registry, derived-output policy, dashboard, and multi-agent
demo work is implemented and tested. Section 16 is the authoritative handoff;
older milestone sections remain as design history.

## 1. Current repository state

### `mcp-python-sdk`

- Branch: `aauth-auth-middleware-hook`
- Commit: `290211f2` (pushed)
- Adds the Streamable HTTP authentication middleware hook used by
  `mcp-aauth`.
- Relevant files:
  - `src/mcp/server/lowlevel/server.py`
  - `src/mcp/server/mcpserver/server.py`
- The working tree is clean.

### `aauth`

- Extension branch: `edocs-demo`.
- Current commit: `601ec4c` (pushed).
- The branch now includes the core models and claims, conditional controller
  tokens, exact controller policy decisions, unanimous Sentinel aggregation,
  optional eDocs behavior in the existing AS, the Sentinel HTTP flow, generic
  downstream-denial relay through pending polling, and authenticated consent
  review.
- Session commits after the pulled Sentinel implementation include:
  - `4c591fc fix: relay downstream denials through polling`
  - `5acabda feat: expose verified pending consent details`
  - `50bb3cb docs: update eDocs demo implementation handoff`
  - `601ec4c feat: coordinate deferred eDocs consent`
- Relevant implementation files:
  - `src/aauth_edocs/edocs.py` — eDocs dataflow/domain models
  - `src/aauth_edocs/tokens.py` — normal, resource, and conditional claims
  - `src/aauth_edocs/controller.py` — exact controller policy decisions
  - `src/aauth_edocs/sentinel.py` — Sentinel HTTP flow and aggregation
  - `src/aauth_edocs/ps.py` — generic PS approval, review, relay, and polling
  - `src/aauth_edocs/agent.py` — existing generic synchronous agent flow
  - `src/aauth_edocs/coordinator.py` — reusable deferred authorization
    coordinator
  - `src/aauth_edocs/edocs_consent.py` — trusted host consent review/decision
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
- Current commit: `a59a9da` (pushed).
- Session commits:
  - `c4d8496 feat: add eDocs MCP authorization flow`
  - `b6feaa5 feat: request eDocs resource tokens over signed HTTP`
  - `c7f76d5 refactor: keep eDocs demo outside mcp-aauth API`
  - `6103fad test: receive Sentinel denial through polling`
  - `85b1f2e test: harden eDocs MCP authorization boundary`
  - `4d980ca test: review verified eDocs consent claims`
  - `a59a9da feat: coordinate AAuth challenges in MCP clients`
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

### `mcp-aauth-codex`

- Branch: `main`.
- Current commit: `6d0b980` (pushed to
  `kyle-macmillan/mcp-aauth-codex`).
- Provides the Codex-specific stdio MCP proxy, trusted elicitation UI bridge,
  runnable localhost composition, and end-to-end process tests.
- Uses the adjacent `aauth`, `mcp-aauth`, and forked MCP SDK repositories
  without adding Codex-specific behavior to those packages.
- The live demo composes an Agent Provider, Person Server, Sentinel, two
  controller ASes, and one eDocs MCP resource. Asking Codex to invoke
  `identity@1` on `doc-123` now completes the real approval and authorization
  flow.
- The next milestone is specified in
  `mcp-aauth-codex/INTERFACES_PLAN.md` from the workspace root.

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
- Added the reusable `AuthorizationCoordinator` in `aauth`. It owns the
  resource-token exchange, opaque pending polling, and resource-scoped final
  token cache without interpreting MCP or eDocs semantics.
- Added the generic `mcp-aauth` client coordination hook. It recognizes AAuth
  resource challenges, pauses for a trusted approval callback, completes
  pending authorization, and retries with the final token.
- Created and pushed the standalone `mcp-aauth-codex` repository. Its stdio
  proxy adapts Codex to the Streamable HTTP resource without modifying Codex
  or adding Codex behavior to the generic packages.
- Added a Codex elicitation that renders only Person Server-verified eDocs
  facts and submits the person's decision directly to the PS. The prompt
  occurs after the resource token exists and before the PS forwards the
  request to the Sentinel.
- Kept Codex's strict elicitation-schema compatibility adjustment local to
  `mcp-aauth-codex`.
- Added a runnable localhost composition and process tests using the forked
  MCP SDK's public custom-authentication hook. The real Codex demo now
  completes `identity@1` on `doc-123`.

Important decisions made during this session:

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
- Codex compatibility behavior belongs in `mcp-aauth-codex`, not in generic
  `mcp-aauth` or the MCP SDK.
- The production-facing connection remains Streamable HTTP. The stdio server
  is only the local Codex adapter.

## 13. Current resume point: exact invocations and operator interfaces

The generic coordinator, MCP adapter, Codex host bridge, and runnable
Streamable HTTP demo described by the previous resume point are complete. The
next session must begin with the exact-argument authorization foundation in
`mcp-aauth-codex/INTERFACES_PLAN.md`; do not begin with dashboard styling or
multi-provider composition.

### 13.1 Exact function arguments

The current authorization binds `(source, function, document, destination)`.
That is insufficient for parameterized server-side functions because a token
for one filter or search could be reused with different arguments.

First:

- canonicalize normalized JSON function arguments;
- bind them through resource, controller, conditional, and final tokens;
- include them in `Dataflow`, exact controller policies, consent review, and
  final resource enforcement;
- add function input schemas to descriptors; and
- preserve the existing empty-argument `identity@1` behavior.

Run all `aauth` and `mcp-aauth` tests after this foundation. Only proceed when
argument reordering is equivalent and any argument-value change is rejected.

### 13.2 Three provider/resource domains

After the foundation passes, replace the single hard-coded demo resource with
Alice, Bob, and Carol. Each provider has:

- one distinct resource owner and source agent;
- one Streamable HTTP MCP server with a multi-file catalog;
- one owning AS selected through the Sentinel's trusted binding; and
- one combined resource/AS administration dashboard.

Every provider accepts CSV, Parquet, and PDF files. Catalog metadata is
discoverable through MCP without approval; file bytes are not. Codex sees one
aggregated provider-qualified catalog.

### 13.3 Server-side functions

Implement and advertise:

- `select_and_filter_table_rows@1` for bounded CSV/Parquet projection and
  filtering; and
- `search_pdf_text@1` for bounded PDF text search.

Use a proactive, agent-signed resource authorization request containing the
eDoc, function, and normalized arguments. The final MCP call must execute the
same exact invocation. Continue treating token issuance as materialization;
execution receipts remain deferred.

### 13.4 Dashboards

Provider dashboards manage uploads, display metadata, enablement, compatible
functions, and exact `X`/`X | Y` dataflow policy. The Sentinel dashboard
manages trusted provider/resource/AS bindings and function registration and
shows mappings, authorization outcomes, and provenance.

These are reset-on-launch localhost interfaces: use server-rendered pages, no
login, no persistent database, no raw download, and no permanent deletion.
Keep resource state in the resource service and policy state in the AS even
though the provider dashboard presents them together.

### 13.5 Repository boundary

- Reusable eDocs argument and policy semantics belong in `aauth`.
- Multi-provider composition, file execution, dashboards, and Codex
  aggregation belong in `mcp-aauth-codex`.
- Do not add eDocs-specific behavior to `mcp-aauth` or `mcp-python-sdk`.
- The complete decision record, interfaces, function schemas, tests, and
  assumptions are in `mcp-aauth-codex/INTERFACES_PLAN.md`.

## 14. Review protocol

Before making it:

1. Present the exact proposed files, APIs, claim validation, and tests.
2. Reference the current implementation by line.
3. Explain every design decision.
4. Wait for explicit approval.

Continue using the same approval boundary for every subsequent code change and
before every commit or push.

## 15. Current handoff: exact invocation and DuckDB execution

### Completed in this session

- Function arguments are opaque normalized JSON at the AAuth boundary. AAuth
  canonicalizes, hashes, binds, and compares them, but does not validate a
  function schema or interpret SQL.
- Empty arguments remain valid and have a stable digest.
- Resource tokens retain the full argument object and its digest. Controller,
  conditional, and final authorization tokens bind the digest. The client
  retains and resends the original arguments, and the resource recomputes the
  digest before execution.
- Remembered PS consent for an eDocs invocation includes the argument digest,
  preventing consent for one invocation from authorizing changed arguments.
- Function schemas remain descriptive discovery/UI metadata. The resource
  owns runtime applicability and execution; the implementation may be loaded
  from any trusted source when its immutable descriptor/digest agrees with the
  AS and Sentinel.
- The demo resource resolves an opaque eDoc ID to its own DuckDB database and
  executes `query_table@1` only after final Sentinel-backed authorization.
  AAuth performs no SQL validation.
- `mcp-aauth-codex/scripts/setup_demo_db.py` creates the resettable demo
  database and catalog. Filenames are metadata, never resource identity.

### Repositories and implementation commits

- `aauth`, branch `edocs-demo`:
  - `4ff9f98` binds exact function arguments across authorization tokens.
  - `55673bc` removes schema/SQL semantics from AAuth and binds remembered
    consent to the invocation digest.
- `mcp-aauth`, branch `edocs-demo`:
  - `ed734ed` covers exact argument enforcement.
  - `12d909e` adapts the end-to-end resource test to proactive authorization.
- `mcp-aauth-codex`, branch `main`:
  - `5f9d97b` adds proactive authorization, opaque eDoc routing, the resource
    function-loader boundary, DuckDB setup/execution, and integration tests.
- `mcp-python-sdk`, branch `aauth-auth-middleware-hook`, remains unchanged and is
  consumed from the local fork.
- `eDocs-research` and all LaTeX-related material remain untouched.

### Verification

- `aauth`: 212 passed, 1 skipped.
- `mcp-aauth`: 68 passed.
- `mcp-aauth-codex`: 19 passed, including the real stdio proxy and live
  resource/authorization flow.

### Next session starting point

Start in `mcp-aauth-codex`. Generalize the proven single-resource vertical
slice into the Alice/Bob/Carol provider topology described in
`INTERFACES_PLAN.md`: distinct resource/AS domains, provider-qualified
catalog discovery, and opaque eDoc routing. Reuse `FunctionLoader`,
`DemoResource.authorize`, and `DemoResource.execute`; do not introduce an
AAuth-side query language or schema validator. Add dashboards only after
multi-provider routing and isolation pass end-to-end tests.

## 16. Current handoff: reusable providers, live administration, functions,
derived outputs, and multiple agent sessions

### 16.1 Repository and branch state

- `aauth`
  - Branch: `edocs-demo`.
  - Remote: `origin` (`kyle-macmillan/aauth`).
  - Owns reusable eDocs policy, provenance, and derived-output semantics.
- `mcp-aauth`
  - Branch: `edocs-demo`.
  - Remote: `origin` (`kyle-macmillan/mcp-aauth`).
  - Remains unchanged in this session. It continues to own generic MCP/AAuth
    transport and middleware behavior.
- `mcp-python-sdk`
  - Branch: `aauth-auth-middleware-hook`.
  - Remotes: `origin` and upstream MCP SDK.
  - Remains unchanged in this session.
- `mcp-edocs-provider`
  - Branch: `main`.
  - Remote: `origin` (`kyle-macmillan/mcp-edocs-provider`).
  - Owns reusable provider catalogs, function loaders/registries, protected
    provider execution, provider binding, and MCP/HTTP construction.
- `mcp-aauth-codex`
  - Branch: `main`.
  - Remote: `origin` (`kyle-macmillan/mcp-aauth-codex`).
  - Owns Codex-facing tools, localhost composition, dashboards, seeded data,
    SQL runtime, and launchers.
- `eDocs-system`
  - Branch: `kyle/rules`.
  - Contains a separate dirty implementation effort and an untracked
    `docs/implementation-brief.md`.
  - It was inspected but not changed or committed by this AAuth demo session.

### 16.2 Provider discovery and routing

- The Codex proxy exposes only:
  - `list_providers`;
  - `list_resources(provider_id)`;
  - `invoke_edocs_function(resource_uri, function_id, arguments)`; and,
    when the demo registry URL is configured,
  - `register_edocs_function`.
- Provider configuration is a private proxy-side directory, not an MCP
  resource. Codex sees public provider names and descriptions, then explicitly
  calls the selected provider to discover its current resources.
- Alice, Bob, and Carol have distinct resource issuers, MCP endpoints, Access
  Servers, source agents, signing keys, catalogs, and DuckDB files.
- The provider ID is repeated during authorization and execution. A directory
  entry that routes Alice to Bob's endpoint is rejected before consent or
  materialization.
- Resource discovery returns only resource identity and descriptive metadata.
  Media type, compatible functions, enabled functions, filenames, and private
  storage paths are not presented as resource-owned authorization facts.

### 16.3 Standalone reusable provider package

`mcp-edocs-provider` was extracted so generic eDocs/provider behavior does not
live in the Codex integration repository. It includes:

- a thread-safe mutable `ProviderCatalog`;
- runtime catalog insertion, metadata updates, and enable/disable behavior;
- `ProviderResource` authorization and final-token enforcement;
- injected `FunctionLoader` and `LoadedFunction` interfaces;
- a thread-safe shared `MutableFunctionRegistry`;
- public MCP catalog discovery;
- provider identity enforcement;
- protected generic function execution; and
- an optional post-execution materialization recorder.

The package contains no Codex UI, seeded demo data, or controller policy.

### 16.4 Mutable controller policy

`aauth_edocs` now provides:

- `ControllerPolicyEvaluator`, allowing the AS to consume a policy interface
  rather than one concrete policy type;
- thread-safe `MutableControllerPolicy`;
- stable rule IDs;
- list, create, replace, delete, and exact evaluation operations;
- duplicate target and rule-ID rejection;
- framework-neutral policy/dataflow JSON parsing and serialization; and
- concurrent read/write coverage.

Each provider receives an independent policy store. Policy changes take effect
immediately without changing catalogs or prior provenance. Restarting the
demo restores the seeded policies.

No Flask application or production administration protocol was added to
`aauth_edocs`. The localhost demo control panel is only an adapter over these
reusable objects.

### 16.5 Demo control panel

The demo starts one unauthenticated localhost control service at:

```text
http://127.0.0.1:8721/demo
```

It is explicitly development-only and is not exposed through the agent-facing
MCP server. Alice, Bob, and Carol tabs support:

- CSV upload into provider-private DuckDB storage;
- document rename and enable/disable;
- live function tables showing ID, description, SQL/artifact, and
  provider-specific policy status;
- concise policy cards displaying function, document selector, source,
  destination, exact arguments, and prerequisite;
- add-policy selectors populated from live documents, agents, functions, and
  materialized prerequisites; and
- a separate edit dialog so policy lists do not expand into large forms.

The Sentinel tab shows:

- demo agent identities;
- resource bindings;
- authoritative controllers;
- registered functions and actual SQL/artifacts;
- materialized dataflows; and
- registered derived eDocs with producer provenance and output digests.

Routine Werkzeug and Uvicorn access logs are disabled so background HTTP
traffic does not overwrite the Codex terminal UI. Warnings and errors remain
visible.

### 16.6 Shared function registry and agent-created functions

- One shared mutable function registry is used by Sentinel and all three
  providers in the demo.
- The demo seeds:
  - `query_table@1`;
  - `identity@1`;
  - `department_counts@1`;
  - `average_salary_by_department@1`; and
  - `employee_count@1`.
- The dashboard and Codex tool can register new schema-conforming artifacts.
- The generic registration envelope contains function ID, description, input
  schema, and implementation `{runtime, source}`.
- The current demo runtime accepts one read-only SQL `SELECT`/`WITH`
  statement. The server computes the immutable descriptor digest.
- Registration makes a function discoverable and executable but creates no
  invocation policy.
- Providers execute newly registered functions through one protected generic
  MCP executor, so MCP tools do not need to be dynamically rebuilt.
- End-to-end coverage proves:
  1. Codex registers a SQL function;
  2. the function appears in the shared registry;
  3. Alice denies its invocation without a policy;
  4. Alice adds an exact policy; and
  5. the unchanged invocation succeeds.

### 16.7 Future derived-output policies and materialization

Authorization issuance is no longer treated as proof of execution.
`aggregate_controller_decisions` issues the final token without modifying
materialization state. After a provider function completes successfully, the
provider invokes the injected demo recorder.

The recorder creates a `DerivedEdoc` containing:

- a unique opaque `derived_...` ID;
- an `edoc://derived/...` URI;
- the exact producer dataflow;
- a stable producer fingerprint;
- an output content digest;
- the producer destination as custodian; and
- inherited controllers.

`Dataflow.document` can now contain `OutputOf(exact_producer)` in controller
policy. The selector can be created before any output exists. A
`MutableControllerPolicy` resolves a later concrete derived ID through trusted
provenance and matches the other exact dataflow fields.

Alice's seeded policies are:

```text
Alice source → query_table@1(employee directory, engineering args) → Codex

Any output of the exact producer above may flow as:
Codex → identity@1(derived output) → Carol
```

There is no corresponding Bob destination rule. Tests prove that the future
rule does not match an unknown output, begins matching Carol after successful
materialization, and still rejects Bob.

For the single-process demo, the successful provider calls an injected
recorder directly. A production split deployment still requires a signed
provider execution receipt and a remotely accessible derived-resource
service. The latter is deliberately deferred.

### 16.8 Multiple Codex agent sessions

The demo now generates distinct keys, agent tokens, and environment files for:

- Producer: `aauth:codex@demo.local`;
- Carol: `aauth:carol@demo.local`; and
- Bob: `aauth:bob@demo.local`.

Files live under:

```text
.demo-state/agents/{producer,carol,bob}.{env,jwk,token}
```

Each file is mode `0600`; all three key paths and agent-token subjects are
distinct. `scripts/run_agent.sh` launches one role. The existing
`scripts/run_demo.sh` launches only Producer.

`scripts/run_multi_agent_demo.sh` starts the shared backend and opens a tiled
`tmux` session with Producer, Carol, and Bob Codex panes. The three windows
share providers, Sentinel, registry, and control panel but receive only their
own credentials.

Carol and Bob can currently demonstrate independent identities and public
catalog discovery. Actual invocation of producer-derived outputs remains
deferred with the derived-resource service and dynamic provider destination
handling, per the explicit scope decision.

### 16.9 Verification at this handoff

- `aauth`: 221 passed, 1 skipped.
- `mcp-edocs-provider`: 7 passed.
- `mcp-aauth-codex`: 22 passed.
- Provider isolation, misrouting rejection, live policy mutation, restart,
  shared-function registration, denial-before-policy, execution-after-policy,
  post-execution derived-eDoc registration, Carol/Bob output-policy matching,
  multi-agent credential isolation, real stdio, and live HTTP/MCP flows are
  covered.
- Dashboard JavaScript passes `node --check`.
- Shell launchers pass `bash -n`.
- All affected repositories pass `git diff --check`.

### 16.10 Direct-input lineage in resource tokens

The next policy milestone is transitive enforcement over derived eDocs. If an
eDoc such as `g(f(D))` is governed, the resource must declare that `f(D)` is a
direct input so the Sentinel can retain Alice's policy authority throughout
the derived-data lineage.

The agreed token boundary is:

- the eDocs resource token carries a signed `input_edoc_ids` JSON list;
- the list contains direct inputs only, not the transitive closure;
- the Sentinel verifies the resource issuer/key binding, persists the direct
  edges, and derives the transitive ancestry from its trusted registry;
- later assertions for a known eDoc must not redefine its registered inputs;
- source eDocs use an empty input list; and
- local execution makes this a signed resource assertion, not proof that the
  resource disclosed every input it actually used.

The first TDD step is now present in `tests/test_tokens.py`. It specifies:

- round-trip issuance and verification of two direct input eDoc IDs;
- exact verification binding for `input_edoc_ids`;
- rejection of duplicate, empty, non-string, and non-list values; and
- omission of the claim from traditional non-eDocs resource tokens.

The new eDocs tests intentionally fail because `issue_resource_token` does not
yet accept `input_edoc_ids`; the traditional resource-token compatibility test
passes.

The next implementation slice is confined to
`src/aauth_edocs/tokens.py`:

1. Add optional `input_edoc_ids` issuance and verification parameters.
2. Validate and encode the claim as a canonical JSON list.
3. Include it in the complete eDocs claim group and exact binding checks.
4. Preserve claim omission for non-eDocs AAuth tokens.
5. Make the focused token tests pass before propagating lineage through
   Sentinel aggregation, controller decisions, and final auth tokens.

### 16.11 Deferred work

- Replace the in-process materialization callback with a signed execution
  receipt before treating this as a production trust boundary.
- Direct-input lineage (`input_edoc_ids`) for transitive controller retention
  remains deferred per §16.10.
- Assign a Git remote to `mcp-edocs-provider`, then push its `main` branch.
