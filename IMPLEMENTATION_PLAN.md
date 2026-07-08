# AAuth Protocol Implementation Plan

Target spec: **draft-hardt-oauth-aauth-protocol-09** (July 2026), with its normative
companion **draft-hardt-httpbis-signature-key-04**. Local copies of both are in
`docs/specs/` — treat those as the source of truth; section references below
(e.g., §6.7.1) point into the AAuth draft unless prefixed with "SigKey".

This plan was authored after a full read of both drafts. It is written for an
implementer starting from an empty repo.

---

## 0. Status and scope revisions (2026-07-08 — read this first)

**Scope revision:** this implementation is for **internal experimentation only,
not production**. Later sections were written before that decision; read them
through this lens — keep the protocol essence (PoP HTTP signatures, the three
token types, challenge/deferred flows), skip hardening that only an adversary
or an IETF reviewer would notice.

**M1 (Phases 0–1) and M2 (Phase 2, identity-based access) are complete.**
Phase 2 added `ap.py` (Agent Provider Flask app with open `/issue` enrollment),
`agent.py` (`AgentSession` with an injectable transport; `RequestsTransport`
for real HTTP, a loopback test-client transport in tests), `resource.py`
(`require_aauth_identity` decorator + `install_metadata`), the
`demo/01_identity_based.py` real-HTTP demo, and `tests/test_phase2_identity.py`.
Actual layout differs from §3 below:
import package is `aauth_edocs` (PyPI name `aauth` is taken by an existing
implementation we test against), with flat modules instead of a `core/`
subpackage: `keys / ids / errors / headers / httpsig / signature-key-in-httpsig
/ tokens / metadata / deferred`. Tests in `tests/` + `tests/interop/`.

**Simplifications applied (carry forward to later phases):**
- No https enforcement, charset/IDN identifier rules, or port/path pedantry —
  dummy names and plain-HTTP localhost throughout.
- JWKS discovery: simple dict cache, refetch on unknown kid. No cache-header
  policy, fetch floors, 24h expiry, or egress admission.
- Small error set (`{"error", "detail"}` JSON bodies), no RFC 9457 ceremony,
  no Signature-Error header.
- Interaction codes: random single-use strings; no Crockford alphabet, rate
  limits, or folding.
- Deferred loop: 202/Location/Retry-After polling only; no 429 backoff, no
  `Prefer: wait`, no `interacting` status.
- No lifetime-cap enforcement, act-chain/sub-agent verification, or token68
  pedantry. Ed25519 only (`alg: EdDSA`, matching other implementations).
- Later phases: stub consent pages (no markdown sanitizer ceremony), in-memory
  stores by default, SQLite only where persistence helps a demo, no rate
  limits/revocation until a demo needs them.

**Ecosystem findings (from github.com/dickhardt/AAuth):**
- Existing implementations: TypeScript reference SDK (`aauth-dev/packages-js`),
  Python `christian-posta/aauth-python-library` (PyPI `aauth`/`aauth-signing`),
  Go, .NET, a Keycloak AS extension, and `christian-posta/aauth-person-server`
  (use as PS design reference in Phase 3).
- The author's `interop-demo-profile.md` (vendored in `docs/specs/`) defines 5
  verifiable surfaces; our end-to-end test covers Surfaces 1–4 in-process, and
  later phase demos should follow it.
- `tests/interop/` cross-checks against the PyPI `aauth` lib
  (`uv sync --group interop`): JWK thumbprints and the RFC 9421 signature base
  are compatible. Known drift in their lib: `Signature` header uses unpadded
  base64url (RFC 8941 says standard base64 — we follow the RFC), auth-token
  `act` semantics predate draft-05, errors predate draft-09's RFC 9457.

---

## 1. Stated assumptions (confirm or override before Phase 0)

1. **Language: Python 3.10+, managed with `uv`, HTTP servers in Flask.** Chosen to
   match the sibling `eDocs-system` project (Flask + SQLAlchemy + uv + hatchling +
   pytest), since this implementation will presumably integrate with eDocs later.
2. **Scope: the full protocol, all five roles** (Agent, Agent Provider, Resource,
   Person Server, Access Server), built as one Python package with role-specific
   subpackages, delivered in phases so each phase is independently useful. If the
   real goal is narrower (e.g., only "eDocs as an AAuth resource" or only an agent
   client), cut phases from the back — the phase order below matches the spec's own
   incremental-adoption ladder (§13), so any prefix of it is a coherent product.
3. **Companion specs referenced but NOT implemented:** AAuth Events
   (I-D.hardt-aauth-events), AAuth Bootstrap ceremonies (I-D.hardt-aauth-bootstrap —
   we self-issue agent tokens via our own AP instead), R3 vocabularies
   (I-D.hardt-aauth-r3), and real payment settlement (x402/MPP — we stub the 402
   path). These are explicitly out of scope in the AAuth draft or optional.
4. **Dev-mode HTTP:** the spec mandates HTTPS everywhere (§12.9, §14.15). For local
   development/tests, gate a single explicit `allow_insecure_http` config flag that
   relaxes the `https` scheme checks for `localhost`/`127.0.0.1` only. All normative
   validation stays on by default.
5. **Consent UI is minimal.** The PS and Resource interaction pages are bare
   HTML forms sufficient to drive the flows (approve/deny buttons, code entry,
   clarification textbox). No real product UI.

---

## 2. Protocol crash course (what you're building)

AAuth gives every agent its own cryptographic identity and replaces bearer
credentials with proof-of-possession on every request:

- The agent holds a signing key (Ed25519). Its **Agent Provider (AP)** issues an
  **agent token** (JWT, `typ: aa-agent+jwt`) binding that key (`cnf.jwk`) to an
  agent identifier `aauth:local@domain` (§5).
- Every request the agent makes carries an **HTTP Message Signature** (RFC 9421)
  over at least `@method @authority @path signature-key`, with the JWT presented in
  the **`Signature-Key`** header (`sig=jwt;jwt="..."`) (§12.7, SigKey §3.6).
- Implemented/planned **resource access modes**:
  1. **Identity-based** — resource verifies the signature + agent token, applies
     its own ACL. Replaces API keys.
  2. **PS-asserted (three-party)** — resource issues a **resource token**
     (`typ: aa-resource+jwt`, `aud` = the agent's **Person Server** from the agent
     token's `ps` claim); the agent exchanges it at the PS **token endpoint** for an
     **auth token** (`typ: aa-auth+jwt`) asserting user identity/consent; the
     resource applies its own policy to the claims (§6, §7).
  3. **Federated (four-party)** — resource token's `aud` is the resource's
     **Access Server**; the PS (never the agent) federates to the AS token
     endpoint and relays the auth token back (§9).
- **Out of scope:** Resource-managed two-party access (§4.1.2 / §6.4) and its
  `AAuth-Access` opaque-token flow are intentionally not planned for this repo.
- **Agent governance** is orthogonal (§4.4): with a PS, an agent can create a
  **mission** (natural-language scope, hashed to `s256`, referenced via the
  **`AAuth-Mission`** header), request per-action **permission**, log **audit**
  records, and relay **interactions** to the user through the PS.
- Cross-cutting primitives (§12): the **`AAuth-Requirement`** response header
  (Structured Field Dictionary; values `agent-token`, `auth-token`, `interaction`,
  `approval`, `clarification`, `claims`), **deferred responses** (202 + `Location`
  pending URL + polling state machine), **interaction codes** (Crockford base32),
  RFC 9457 `application/problem+json` errors, **token revocation** by `jti`,
  **well-known metadata** documents, and **JWKS discovery/caching**.

Key insight for sequencing: *everything* is built from the same small set of
primitives — three JWT types, one signature profile, one requirement/deferred
pattern, and four metadata documents. Get those right in a core library first and
each role becomes thin.

---

## 3. Proposed repo layout

```
aauth-edocs/
├── pyproject.toml              # hatchling, uv-managed, like eDocs-system
├── IMPLEMENTATION_PLAN.md      # this file
├── docs/specs/                 # local copies of the two drafts (already present)
├── src/aauth/
│   ├── core/                   # role-independent protocol primitives (Phase 1)
│   │   ├── identifiers.py      # aauth: URIs (§5.1), server identifiers (§12.9)
│   │   ├── keys.py             # Ed25519/P-256 keypairs, JWK, RFC 7638 thumbprints
│   │   ├── tokens.py           # build/verify agent, resource, auth tokens
│   │   ├── httpsig.py          # RFC 9421 profile: sign + verify (§12.7)
│   │   ├── signature_key.py    # Signature-Key header, schemes jwt / jwks_uri
│   │   ├── headers.py          # AAuth-Requirement/-Access/-Capabilities/-Mission
│   │   ├── metadata.py         # 4 well-known docs: models, publish, fetch+validate
│   │   ├── jwks_cache.py       # discovery + caching rules (§12.8)
│   │   ├── deferred.py         # server-side pending store + client-side poll loop
│   │   ├── codes.py            # interaction codes (§12.3.3.1)
│   │   └── errors.py           # problem+json bodies, Signature-Error (SigKey §5)
│   ├── agent/                  # agent SDK: signed HTTP client + requirement loop
│   ├── ap/                     # agent provider: metadata + agent-token issuance
│   ├── resource/               # Flask helpers: verify middleware, authz endpoint,
│   │                           #   resource-token issuance
│   ├── ps/                     # person server: token/mission/permission/audit/
│   │                           #   interaction endpoints, consent pages, storage
│   └── asrv/                   # access server: token endpoint, policy hooks
│                               #   ("asrv" because "as" is a Python keyword)
├── demo/                       # runnable end-to-end demos, one per access mode
└── tests/
    ├── unit/                   # per core module
    └── integration/            # multi-role flows via Flask test clients
```

Suggested dependencies (all mature, keep the list short):
- `cryptography` — Ed25519/ECDSA keys and signatures.
- `joserfc` (or `PyJWT>=2.x`) — JWS/JWT with EdDSA + ES256, JWK, thumbprints.
  `joserfc` is the cleaner choice for JWK handling; either works.
- `http-sfv` — RFC 8941 Structured Fields parse/serialize (used by
  `Signature-Key`, `AAuth-Requirement`, `AAuth-Mission`, `AAuth-Capabilities`,
  `Signature-Input`).
- `http-message-signatures` (PyPI) — RFC 9421 canonicalization. **Evaluate it in
  Phase 1**; if it can't cleanly express the AAuth profile (custom key resolution
  from `Signature-Key`, mandated components, `created` window), implement the
  profile subset directly on `http-sfv` + `cryptography` — the AAuth profile is
  narrow (only derived components `@method @authority @path` plus a few headers,
  single `created` param), so a focused implementation is ~200 lines and avoids
  fighting a general library.
- `flask`, `flask-sqlalchemy` (server roles; SQLite storage like eDocs-system),
  `requests` (agent SDK + server-to-server calls), `pytest`.

---

## 4. Phases

Each phase ends with named tests passing. Do not start a phase until the previous
phase's verification gate is green.

### Phase 0 — Scaffolding

- `pyproject.toml` mirroring eDocs-system conventions (hatchling, uv, pytest dev
  group), package skeleton, empty modules, CI-runnable `uv run pytest`.
- **Verify:** `uv sync && uv run pytest` runs (0 tests is fine).

### Phase 1 — Core primitives (the load-bearing phase)

Everything else is assembled from these. Implement with exhaustive unit tests;
every MUST in the referenced sections should have a test.

1. **Identifiers** (§5.1, §12.9): parse/validate/compare `aauth:local@domain`
   (charset, 255-char limit, `+` sub-agent delimiter reserved, case-sensitive
   exact match); server identifiers (https, host-only, no port/path/trailing
   slash, lowercase, exact string compare); endpoint URL rules.
2. **Keys** (§12.7.1–.2): Ed25519 generate/serialize as JWK (MUST), P-256 ES256
   (SHOULD); RFC 7638 JWK thumbprints (for `agent_jkt`).
3. **Token build/verify** (§5.2, §6.7, §9.4): one module, three token types.
   - Builders take claims + signing key, emit compact JWTs with correct `typ`,
     `kid`, `dwk`. Enforce lifetime caps at build time: agent ≤24h, resource
     ≤5min (SHOULD), auth ≤1h (MUST) and ≤ agent-token `exp` (§7.7).
   - Verifiers implement the numbered checklists **exactly as written**:
     agent token §5.2.4 (7 steps), resource token §6.7.2 (7 steps, including the
     sub-agent variant of step 6), resource-challenge §6.7.3 (agent side), auth
     token §9.4.3 (split: JWT-trust steps 1–4 / request-context-binding steps
     5–9, including the structured `cnf.jwk` failure ordering in step 7), agent-
     side auth-token checks §9.4.4, upstream token §9.4.5. `alg: none` MUST be
     rejected everywhere. Key discovery is injected (see 6) so unit tests can
     stub it.
4. **HTTP Message Signatures profile** (§12.7): sign(request, key, covered
   components) and verify(request) with:
   - mandated covered components `@method @authority @path signature-key`;
     `authorization` added when `Authorization: AAuth` present (§6.4);
     `aauth-mission` added when that header is present (§6.1); support server-
     required `additional_signature_components` from resource metadata.
   - `created` REQUIRED, validity window default 60s (configurable via
     `signature_window` metadata); honor `expires` when present (§12.7.4.1).
   - Server verification per §12.7.4 steps 1–6 with the exact Signature-Error
     codes from SigKey §5.4 (`invalid_request`, `invalid_input` +
     `required_input`, `invalid_signature`, `unsupported_algorithm`,
     `invalid_key`, `unknown_key`, `invalid_jwt`, `expired_jwt`).
5. **Signature-Key header** (SigKey §3): serialize/parse the Structured Field
   Dictionary; implement scheme `jwt` (agents — the only scheme agents may use,
   §12.7.2) and scheme `jwks_uri` (used by the PS when calling the AS, §9.1.1).
   Ignore `hwk`/`jkt-jwt`/`x509` beyond rejecting them for AAuth agent requests.
6. **Metadata + JWKS discovery** (§12.10, §12.8): dataclasses for the four
   documents (`aauth-agent.json`, `aauth-person.json`, `aauth-access.json`,
   `aauth-resource.json`) with per-role required fields; fetcher that enforces
   *issuer == fetch-URL origin* (§12.10 host-poisoning check); JWKS cache that
   respects HTTP cache headers, refreshes on unknown `kid`, refreshes-once on
   same-`kid` verify failure, floors fetches at 1/minute per issuer, and expires
   entries at 24h (§12.8). Egress admission hook (deny non-https, deny private
   ranges in prod mode).
7. **AAuth headers** (§12.1, §12.3.1, §8.7): build/parse
   `AAuth-Requirement` (Dictionary member `requirement` with parameters;
   unknown params ignored), `AAuth-Capabilities` (List of Tokens; unknown values
   ignored; unknown params on items ignored), `AAuth-Mission`
   (`approver` + `s256` with the syntax rules of §8.7).
8. **Deferred responses** (§12.4): server-side pending-request store
   (unguessable same-origin `Location` URLs, per-poll caller re-authentication,
   410 after terminal, expiry) and the client-side polling state machine from
   §12.4.4 (202→GET loop, `Retry-After` respect, default 5s, +5s linear backoff
   on 429, `Prefer: wait=N` passthrough, terminal codes 200/403/408/410,
   `status: interacting` handling, unrecognized status ⇒ keep polling,
   unrecognized requirement on 202 ⇒ may keep polling §12.3.2).
9. **Interaction codes** (§12.3.3.1): Crockford base32 alphabet, ≥40 bits (8+
   symbols) from a CSPRNG, presentational hyphens stripped before compare,
   case-insensitive with I/L→1 O→0 folding, single-use, rate-limited with
   terminal failure after N attempts, expiry bound to pending request.
10. **Errors** (§12.5): `application/problem+json` bodies with required `error`
    member; token-endpoint error table (§12.5.3) and polling error table
    (§12.5.4) as enums.

**Verify:** unit test suite covering every numbered verification step and every
table in the sections above; round-trip tests (build → verify) for all three
token types and the signature profile; negative tests for each rejection rule.

### Phase 2 — Identity-based access (AP + agent SDK + resource middleware)

The "replaces API keys" milestone (§4.1.1, §6.3, §13 step 1).

- **`aauth.ap`**: minimal agent provider — Flask app publishing
  `/.well-known/aauth-agent.json` + JWKS, plus a Python API (and a trivial
  authenticated endpoint) that issues agent tokens for a generated keypair,
  with optional `ps` claim. (Real enrollment ceremonies are Bootstrap-spec
  territory; ours is deliberately simple.)
- **`aauth.agent`**: `AAuthSession` — a requests-style client holding key +
  agent token; signs every request per the profile; handles 401
  `requirement=agent-token` by retrying with the agent token (§6.3); exposes
  the deferred-poll loop from Phase 1.
- **`aauth.resource`**: Flask decorator/middleware `@require_aauth_identity`
  that runs §12.7.4 verification + §5.2.4 agent-token verification, exposes
  `g.aauth.agent_id`, and emits the 401 challenges (`requirement=agent-token`,
  Signature-Error headers) on failure. Publishes `aauth-resource.json`
  (`access_mode: agent-token`) + optional JWKS.
- **Demo `demo/01_identity_based.py`**: AP + resource + agent, agent calls a
  protected endpoint, resource ACLs by agent identifier.

**Verify:** integration test — unsigned request → 401 `requirement=agent-token`;
signed request → 200 with correct identity; tampered method/path/authority/key →
401 `invalid_signature`; expired agent token → `expired_jwt`; clock-skewed
`created` → rejected.

### Phase 3 — PS-asserted access (three-party)

The heart of the protocol (§4.1.3, §6.6, §6.7, §7, §9.4).

- **Resource additions**: issue resource tokens (aud = agent's `ps` claim) from
  the authorization endpoint (§6.2.2) and via 401
  `requirement=auth-token; resource-token="..."` challenges (§6.6, including
  step-up re-challenge of already-authorized requests); accept & verify auth
  tokens per §9.4.3 (`dwk: aauth-person.json` issuer path); enforce
  auth-token-exp ≤ agent-token-exp rejection (§7.7).
- **`aauth.ps`** (the biggest new component):
  - `/.well-known/aauth-person.json` + JWKS.
  - **Token endpoint** (§7.1): signed POST with `resource_token` +
    optional `justification`, `login_hint`, `tenant`, `domain_hint`, `prompt`,
    `platform`, `device`, `capabilities`; verify resource token (§6.7.2);
    agent–person binding store (§14.11: one agent ↔ one person, established at
    first consent, never reassignable without revocation); consent decisions
    (immediate grant if remembered, else 202 `requirement=interaction` to the
    PS's own consent page); issue auth tokens (`dwk: aauth-person.json`,
    directed pairwise `sub` per resource §15.1, scope ≤ resource-token scope);
    concurrent independent pending requests (§7.1.2).
  - **Consent page**: authenticated approve/deny (session-cookie stub is fine,
    but the endpoint MUST authenticate — §14.10), showing agent identity,
    resource, scope descriptions (from resource metadata), justification
    (markdown-sanitized — §14.5; use a strict sanitizer or render as plain text).
  - **Clarification chat** (§7.3): user question → 202
    `requirement=clarification` with body fields; agent POSTs
    `action=clarification_response` / `action=updated_request` (new resource
    token must match iss/agent/agent_jkt) / DELETE to cancel; round limit (5).
  - **Resource-initiated interaction** (§7.1.5): resource token `interaction`
    claim → PS interstitial → redirect to resource's interaction endpoint with
    PS callback → error mapping per §7.2.1.
- **Agent additions**: resource-challenge verification (§6.7.3), PS token
  endpoint client, auth-token response verification (§9.4.4), auth-token cache +
  re-authorization on expiry (§7.7), present auth token via Signature-Key on
  subsequent calls (§9.4.2).
- **Revocation** (§12.6): `revocation_endpoint` on the resource; PS can revoke
  an auth token by `jti`; caller identity checks.

**Verify:** integration test of the full Figure-4 flow with scripted user
consent; deny → polling `denied` 403; expired resource token → fresh-token
retry path; directed `sub` differs across two resources for the same user;
same `(iss, sub)` stable across logins for one resource; second person cannot
claim an already-bound agent; revoked auth token rejected by resource.

### Phase 4 — Federated access (four-party)

§4.1.4, §9. Reuses almost everything; the new work is the AS and the PS's
federation client.

- **`aauth.asrv`**: `/.well-known/aauth-access.json` + JWKS; token endpoint
  accepting signed POSTs from PSes (Signature-Key scheme `jwks_uri` — verify by
  fetching the PS's metadata/JWKS); pluggable policy hook that can return:
  direct grant, 202 `requirement=claims` (+ `required_claims`, accept claims
  POST to pending URL §9.2), 202 `requirement=interaction` (user binds PS at
  AS), 202 `requirement=approval`, 402 payment stub, or 403. Issue auth tokens
  (`dwk: aauth-access.json`).
- **PS federation** (§9.3): route on resource-token `aud` (self ⇒ three-party;
  other ⇒ fetch `{aud}/.well-known/aauth-access.json`, call AS token endpoint,
  run the deferred loop §9.1.2, answer `claims` with directed sub + consented
  identity claims, relay `interaction`/`clarification` down to user/agent as
  appropriate); verify received auth token per §9.1.3 (7 steps) before handing
  it to the agent.
- Resource config switch: `aud = AS URL` when an AS is configured.
- **PS-AS collapse** (§9.3.4) falls out of the aud-routing if the same server
  mounts both roles — add a test, not new code.

**Verify:** integration test of Figure-5 end-to-end (agent never talks to AS);
claims-required subflow; interaction-based PS↔AS trust bootstrap; scope
narrowing by AS; PS rejects AS token with wrong `aud`/`cnf`/broader scope.

### Phase 5 — Governance: missions + PS endpoints

§4.4, §7.4–7.6, §8.

- **Mission lifecycle** (§8): mission endpoint (proposal → optional
  clarification → approval); mission blob with required/optional fields
  (§8.2); **store the exact response bytes** — `s256` is the base64url SHA-256
  of the byte-exact blob, no re-serialization; two states (active/terminated);
  `mission_terminated` 403 error (§8.6); mission log accumulating every
  agent↔PS interaction (§8.3).
- **`AAuth-Mission` header** (§8.7) end-to-end: agent sends it (signed, added
  to covered components) on resource requests; mission-aware resource copies
  the reference into resource tokens; PS verifies `mission.approver == self`
  (§6.7.2 step 7); mission reference lands in auth tokens; resources/ASes never
  dereference the blob.
- **Permission endpoint** (§7.4): action/description/parameters/mission;
  granted/denied (+ deferred for user-in-the-loop); `approved_tools` bypass.
- **Audit endpoint** (§7.5): fire-and-forget 201, mission required, logged.
- **Interaction endpoint** (§7.6): types `interaction` (relay w/ two-pending-URL
  semantics + `max_wait` + `interaction_unavailable` 424 fallback), `payment`
  (same relay shape), `question` (returns `answer`), `completion` (user accepts
  ⇒ mission terminated, or clarification ⇒ continues); `user_unreachable`
  terminal error; PS-first relay preference in the agent SDK (§12.3.3.2).
- Mission-aware consent: PS remembers consent within a mission (§6.7.1),
  evaluates token/permission requests against mission log.
- Capabilities plumbing (§12.1): agent unions its own + mission-granted
  capabilities into `AAuth-Capabilities` on resource requests, and the
  `capabilities` body param on PS requests.

**Verify:** integration test — mission proposal/approval; governed three-party
access carrying the mission reference into the auth token; permission grant &
deny; audit record in mission log; completion flow terminating the mission;
post-termination request → `mission_terminated`; s256 byte-exactness test
(reordered-JSON must fail).

### Phase 6 (optional, defer unless needed) — Delegation, third-party login

- **Call chaining** (§10.1, §9.4.5): resource-as-agent (`upstream_token` body
  param, routing by `mission.approver`/`iss` from the upstream auth token, `act`
  chain construction, interaction chaining §10.1.2).
- **Sub-agents** (§10.2): `parent_agent` claim, `+` local-part naming,
  single-level-depth enforcement (PS rejects sub-agent-signed token requests;
  AP refuses sub-sub-agents), parent-mediated authorization
  (`subagent_token` param, auth token bound to sub-agent key with
  `act.agent` = parent).
- **Third-party login** (§11): `login_endpoint` with `ps` validation and
  `start_path` open-redirect defense.

These are well-specified but sit on top of everything else; the core library
should keep them in mind (e.g., `act` claim already modeled in Phase 1 token
code, `parent_agent` accepted by the agent-token verifier) so Phase 6 is additive.

---

## 5. Cross-cutting implementation notes

- **Traceability:** every verifier function should carry a docstring citing its
  spec section, and each numbered step a comment (`# §6.7.2 step 4`). The test
  suite is the conformance record.
- **Markdown is untrusted everywhere** (§14.5): justifications, clarifications,
  mission descriptions, metadata `description`s. In server-rendered pages either
  render as escaped plain text or use a strict allowlist sanitizer. Never
  interpolate into HTML unescaped.
- **Time:** single injectable clock for tests (signature windows, token exp,
  pending expiry all need clock control).
- **Storage:** SQLite via flask-sqlalchemy per role (pattern from eDocs-system):
  PS stores persons, agent bindings, consents, missions + logs, pending
  requests, issued tokens (by `jti`); AS stores PS trust, pendings, issued
  tokens; Resource stores issued resource tokens.
- **Config objects per role**, not globals: issuer URL, keys, endpoints,
  signature window, dev-mode flag.
- **Interop check (stretch):** the TypeScript reference implementation
  (github.com/aauth-dev/packages-js) and .NET SDK (github.com/aauth-dev/
  dotnet-samples) exist (§17). If time permits, verify our resource against
  their agent or vice versa; at minimum, borrow their test vectors if published.
- **Known spec TODOs** (§7.1.3, §7.3.2.1): recommended sections for
  justification/clarification markdown are undefined in draft-09 — treat as
  free-form.

## 6. Suggested milestone checkpoints

| Milestone | Deliverable | Rough size |
|---|---|---|
| M1 (Phases 0–1) | `aauth.core` + full unit suite | the biggest single chunk; ~half the total effort |
| M2 (Phase 2) | API-key-replacement demo | small |
| M3 (Phase 3) | three-party demo w/ consent | large |
| M4 (Phase 4) | four-party demo | medium |
| M5 (Phase 5) | governed mission demo | medium-large |
| M6 (Phase 6) | delegation/login | only if needed |

## 7. Open questions for the project owner

1. Confirm Python/Flask (assumption #1) — or should this be TypeScript to track
   the reference implementation?
2. Is the end goal a general AAuth library, or specifically wiring eDocs-system's
   sentinel/verifier as AAuth resources (in which case Phase 2–3 resource-side
   work should target those apps directly and PS/AS could be thinner)?
3. Any need for Phase 6 (delegation/sub-agents) in the first iteration?
4. Should the PS authenticate real users (OIDC federation) or is a stub
   local-account login acceptable for now? (Plan assumes stub.)
