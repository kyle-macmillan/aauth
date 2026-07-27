# AAuth + eDocs Demo Implementation Plan

This is the restartable handoff for extending AAuth to support the eDocs
authorization flow. It replaces the original base-AAuth implementation plan,
which no longer described the current code or intended architecture.

Target for the first vertical slice: the Wednesday demo described below.
Traditional AAuth remains on `aauth/main`; all eDocs extension work belongs on
`aauth/edocs-demo` and `mcp-aauth/edocs-demo`.

## 1. Current repository state

### `python-sdk`

- Branch: `aauth-auth-middleware-hook`
- Commit: `290211f`
- Pushed and clean when this plan was written.
- Adds the Streamable HTTP authentication middleware hook used by
  `mcp-aauth`.

### `aauth`

- Extension branch: `edocs-demo`, created from `main` at `b85bc86`.
- The branch now includes the core models and claims, conditional controller
  tokens, exact controller policy decisions, unanimous Sentinel aggregation,
  optional eDocs behavior in the existing AS, and the Sentinel HTTP flow.
- Latest complete test result: 178 passed, 1 skipped.
- `main` and `origin/main` were both at `b85bc86`.
- Older prototypes exist at `origin/edocs` and `origin/chz/sentinel`.
  They are reference material only and must not be merged wholesale. They
  predate the header-preservation and optional-dependency work on `main`,
  trust a resource-supplied controller for routing, and contain only a
  stubbed provenance check.

### `mcp-aauth`

- Branch: `edocs-demo`
- Commit: `41470ee`
- The working tree was clean when this plan was written.
- `41470ee` was also local `main`, but had not been pushed;
  `origin/main` remained at `e39c24c`.
- Last complete test result: 47 passed.
- Implemented:
  - ASGI-to-AAuth request conversion preserving the signed request target
    and HTTP headers;
  - OAuth/AAuth credential routing;
  - AAuth agent request verification;
  - `Signature-Key` scheme `jwt` enforcement;
  - `aa-agent+jwt` enforcement;
  - AAuth ASGI middleware and public middleware factory;
  - end-to-end MCP SDK authentication-hook integration;
  - `AAuthAgentHTTPAuth`, which applies the agent's signature to each final
    outgoing HTTP request.

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
- Automatic MCP challenge/retry.
- Production user authentication.
- Remaining AAuth draft conformance gaps such as `expires` handling and full
  error taxonomy.

## 12. Resume point and review protocol

Completed on `aauth/edocs-demo`:

- immutable `Dataflow`, `ExactRule`, `FunctionDescriptor`, and three-field
  `ResourceBinding` models;
- injected in-memory `SentinelRegistry`;
- extended resource and auth token claims for source agent, eDoc ID, and
  controllers;
- complete-group, shape, and exact expected-binding validation;
- Sentinel-only conditional authorization token issuance and verification;
- exact-match, default-deny controller policy evaluation;
- normal and conditional controller decisions addressed to the Sentinel;
- optional eDocs behavior in the existing AAuth AS while preserving its
  traditional AAuth path;
- unanimous multi-controller aggregation, prerequisite checking, final
  resource-audience token issuance, and provenance recording;
- a Sentinel HTTP adapter that authenticates the destination PS, verifies the
  original agent and resource tokens, enforces provisioned resource bindings
  and registries, calls every authoritative controller AS, and returns the
  aggregate final token;
- 178 passed, 1 skipped.

The next proposed logical change should connect the existing Person Server
approval and federation behavior to the eDocs fields and run the complete
Agent -> Resource -> PS -> Sentinel -> controller ASes flow in one integration
test. The PS must display the full proposed dataflow and advisory controllers,
require authenticated approval, forward the unchanged agent and resource
tokens, and relay the Sentinel's final token or denial.

Before making it:

1. Present the exact proposed files, APIs, claim validation, and tests.
2. Reference the current implementation by line.
3. Explain every design decision.
4. Wait for explicit approval.

Continue using the same approval boundary for every subsequent code change and
before every commit or push.
