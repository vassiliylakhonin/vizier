# Vizier v0.2 architecture

## Decision

Vizier v0.2 remains a `build-to-learn` experiment. It keeps the v0.1
deterministic before-action decision and adds an Action Covenant lifecycle that
binds one accepted draft to authorization evidence and a reported outcome. It
does not claim market validation, independent identity, or independent evidence.

## Product gate

- Economic buyer: hypothesis: a founding engineer, platform lead, or security
  engineering lead responsible for an action-taking agent.
- Painful trigger: hypothesis: a production release that gives an agent write,
  payment, deletion, messaging, permission, or code-execution authority.
- Current workaround: unknown; likely application-specific allowlists, tool
  wrappers, IAM controls, and manual approval.
- Evidence: none from interviews, paid pilots, or production integrations.
- Disconfirming evidence: governance and audit layers in the existing portfolio
  have not demonstrated a standalone budget line.
- Smallest learning test: put the verified API in front of five developers who
  already operate action-taking agents and measure repeated before-action calls,
  not sign-ups or compliments.
- Pivot signal: no participant can name a recent blocked release, incident, or
  paid workaround owned by this buyer.

## Boundaries

The v0.1 domain core remains isolated from every transport. The covenant module
is a second deep module that composes the existing policies and a cryptographic
JWS adapter without placing a model in the privileged decision path:

```text
REST / A2A / MCP
        |
boundary validation and protocol mapping
        |
verifyAction(request, trust context)
        |
policies -> decision -> risk -> receipt

model / human / system semantic compiler (untrusted)
        |
ActionCovenantDraft -> principal acceptance -> activateActionCovenant
        |
authorizeActionCovenant(exact action, evidence, invalidation signals)
        |
signed AuthorizationReceipt -> executor -> signed OutcomeReceipt
```

Both cores are deterministic except for identity, time, and ES256 signing.
Tests inject identities and time and generate real P-256 keys. No database is
required yet; covenants and receipts are immutable caller-held representations,
not durability claims.

## Contract decisions

- `principal` is required but nullable. `null` means explicitly unknown and
  yields `REVIEW`; an omitted field is malformed input.
- `BLOCK` has priority over `REVIEW`, which has priority over `ALLOW`.
- A transport with no configured integration credential evaluates requests but
  adds `AUTHORITY_SOURCE_UNTRUSTED`, so it cannot return `ALLOW`. A2A preserves
  this evaluation-only lane when enforcement is configured so protocol probes
  and prospective integrations can test the contract without receiving
  enforcement authority.
- A sensitive action must be delegated and also listed in
  `authority.constraints.allowed_sensitive_actions` to avoid review.
- A monetary limit with a missing/invalid amount or mismatched currency yields
  `REVIEW`; exceeding the limit yields `BLOCK`.
- Target deny rules take precedence over allow rules.
- Request hashing uses documented sorted-key canonical JSON plus SHA-256. This
  is deterministic but is not claimed to implement RFC 8785.
- Agent Card signing uses a separate RFC 8785 canonicalization path and a
  standard A2A v1 `signatures[]` ES256 JWS. The protected header declares
  `alg`, `typ`, `kid`, and a same-origin `jku`; the matching public key is served
  from `/.well-known/jwks.json`.
- A draft has no authority until an authenticated integration supplies an
  acceptance from the same principal, bound to the exact draft hash.
- One covenant authorizes only an exact canonical action. The ordinary delegated
  authority policies run again inside that narrower boundary.
- Missing, wrong-type, future, or stale evidence yields `REVIEW`; covenant hash
  mismatch, expiry, action mismatch, or a matching invalidation signal yields
  `BLOCK`.
- Invalidation rules are intentionally a shallow primitive exact-match language,
  not JSONPath, regex, code, or model evaluation.
- Authorization receipts expire after five minutes or with the covenant,
  whichever comes first. Outcome recording verifies that execution began within
  that window.
- Authorization and outcome JWS values use a dedicated key and distinct
  protected `typ` values. The public receipt key shares the existing JWKS
  document but must have a different `kid` from the Agent Card key.

## Planned repository structure

```text
src/
  core/          # schemas, policies, decision, risk, receipts
  covenants/     # activation, evidence/invalidation checks, outcome binding
  crypto/        # reusable P-256 JWS primitive
  transport/     # REST, A2A JSON-RPC, MCP adapters
packages/sdk/    # thin TypeScript client
packages/gated-deploy/ # private dogfood integration for Worker deploys
tests/           # unit and transport integration tests
examples/        # copy-paste requests
docs/            # architecture, threat model, API docs
```

## Protocol baseline checked on 2026-08-09

- A2A specification v1.0.1: Agent Card discovery at
  `/.well-known/agent-card.json`; JSON-RPC binding uses `SendMessage`, PascalCase
  method names, `application/json`, and the `A2A-Version: 1.0` header.
- MCP specification 2026-07-28: modern MCP is stateless and carries version,
  identity, and capabilities per request; `server/discover` is mandatory.
  Streamable HTTP remains a single endpoint but no longer assumes the legacy
  `initialize` handshake.
- Cloudflare Worker: current compatibility date, `nodejs_compat`, generated
  binding types after configuration changes, structured observability, no
  request-scoped global state, and Web Crypto for IDs and hashes.

## Implemented milestones

The v0.1 path includes typed schemas, six structured policy evaluations,
decision aggregation, transparent risk scoring, bounded input traversal,
SHA-256 request receipts, REST, A2A, MCP, a TypeScript SDK, and tests. Durable
policy storage and principal-issued delegation remain outside this milestone.

The additive v0.2 path includes strict draft and lifecycle schemas, hash-bound
principal acceptance, exact action checks, evidence freshness, invalidation
signals, signed authorization receipts, signed outcome receipts, three REST
resources, SDK signature verification through JWKS, and the gated-deploy
executor adapter. The model is represented only through draft provenance and is
never called by the Worker.

## Internal deployment integration

`packages/gated-deploy` is the first full lifecycle caller. Its action type and
target are fixed to `deploy_worker` and `worker:vizier`. It represents a dirty
worktree as an invalidation signal, invokes Wrangler without a shell only after
the SDK verifies a signed `ALLOW`, and records the observed exit status. A
failure to record the outcome is exposed as `outcome_unrecorded`.

One explicit `VIZIER_V0_2_BOOTSTRAP=1` path retains the v0.1 gate solely to
deploy the first server version that contains the new endpoints. It is not the
normal path after v0.2 is live.

This controls the normal repository deployment command but cannot stop an agent
that already has unrestricted shell access to Cloudflare credentials from
calling Wrangler directly. The package is private and exists to collect internal
repeat-use evidence before any broader executor is built.
