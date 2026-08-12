# Vizier v0.1 architecture

## Decision

Vizier v0.1 is a `build-to-learn` experiment: one deterministic authorization
decision before an AI agent performs an external action. The current milestone
includes the domain core and three protocol adapters. It does not claim market
validation or a complete identity system.

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

The domain core is isolated from every transport:

```text
REST / A2A / MCP
        |
boundary validation and protocol mapping
        |
verifyAction(request, trust context)
        |
policies -> decision -> risk -> receipt
```

The core is deterministic except for receipt identity and creation time. Tests
inject both values. No database is required yet; the receipt is an immutable
representation returned to the caller, not a durability claim.

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

## Planned repository structure

```text
src/
  core/          # schemas, policies, decision, risk, receipts
  transport/     # REST, A2A JSON-RPC, MCP (later milestones)
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

## Implemented milestone

The repository now includes typed schemas, six structured policy evaluations,
decision aggregation, transparent risk scoring, bounded input traversal,
SHA-256 request receipts, REST, A2A, MCP, a TypeScript SDK, and tests. Durable
policy storage, signed delegation, and receipt signing remain outside this
milestone. The public Agent Card is signed; authorization receipts are not.

## Internal deployment integration

`packages/gated-deploy` is a narrow caller of the public REST API. Its action
type and target are fixed to `deploy_worker` and `worker:vizier`. It refuses a
dirty worktree and invokes Wrangler without a shell only after the SDK validates
an `ALLOW` response and its receipt hash. The integration credential is read
from macOS Keychain.

This controls the normal repository deployment command but cannot stop an agent
that already has unrestricted shell access to Cloudflare credentials from
calling Wrangler directly. The package is private and exists to collect internal
repeat-use evidence before any broader executor is built.
