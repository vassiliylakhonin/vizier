# Vizier

Every agent. Every action. Verified.

Vizier is a small authorization layer for action-taking AI agents. Before an
agent calls a tool, API, MCP server, A2A agent, or internal service, it sends the
proposed action to Vizier.

```text
Agent
  |
ActionCovenantDraft -> principal acceptance
  |
Vizier authorization kernel
  |
ALLOW / REVIEW / BLOCK
  |
Tool / API / Agent -> OutcomeReceipt
```

The decision path is deterministic. It checks delegated actions, principal
identity, amount limits, targets, sensitive operations, and whether the request
came through the authenticated integration boundary. Every response includes
policy results and a SHA-256 receipt hash. The additive v0.2 Action Covenant
lifecycle also binds one exact action to fresh evidence and invalidation signals,
then signs both the authorization and its reported outcome.

Status: experimental v0.2. The live API version is reported by the public
`/docs` endpoint. There are no production users, paid pilots, or usage claims.
Authority and evidence are still supplied
by the integrating application rather than loaded from independent stores. Read the [threat
model](docs/THREAT_MODEL.md) before placing this service in an execution path.

Live endpoint: <https://vizier.vassiliy-lakhonin.workers.dev>. Discovery,
health, documentation, and evaluation-only A2A calls are public. REST, MCP, and
A2A enforcement require a private integration credential; no public demo
credential is issued.

## 60-second quickstart

Requirements: Node.js 24 or newer.

```bash
npm install
npx wrangler dev --local --var VIZIER_API_KEY:local-development-key
```

In another terminal:

```bash
curl -sS http://127.0.0.1:8787/v1/verify \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer local-development-key' \
  --data @examples/allow.json
```

The response starts with:

```json
{
  "decision": "ALLOW",
  "risk_score": 0,
  "reason_codes": [],
  "explanation": "The proposed action is within the supplied delegated authority and constraints."
}
```

Try the other decisions:

```bash
curl -sS http://127.0.0.1:8787/v1/verify \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer local-development-key' \
  --data @examples/block.json

curl -sS http://127.0.0.1:8787/v1/verify \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer local-development-key' \
  --data @examples/review.json
```

## API

`POST /v1/verify` accepts one proposed action and its delegated authority.
Malformed requests return a structured error and never produce `ALLOW`.
When `VIZIER_API_KEY` is absent, the service is in evaluation mode: valid
requests can return `REVIEW` or `BLOCK`, never `ALLOW`. When the secret is
configured, REST and MCP verification calls require `Authorization: Bearer
<key>`. A2A also accepts an anonymous evaluation call for discovery and
conformance checks, but that call can return only `REVIEW` or `BLOCK`.

```json
{
  "agent": { "id": "procurement-agent-01", "owner": "acme-corp" },
  "principal": { "id": "acme-corp" },
  "action": {
    "type": "purchase",
    "target": "supplier.example",
    "parameters": { "amount": 8200, "currency": "USD" }
  },
  "authority": {
    "allowed_actions": ["purchase"],
    "constraints": { "max_amount": 10000, "currency": "USD" }
  },
  "context": {
    "request_id": "order-1842",
    "timestamp": null,
    "source": "rest"
  }
}
```

`principal` must be present. Set it to `null` when the principal is unknown;
Vizier returns `REVIEW`. Omitting the field is a validation error.

Decision priority is `BLOCK`, then `REVIEW`, then `ALLOW`. The numeric risk
score explains accumulated risk but does not override policy results.

### Action Covenant lifecycle

The v0.2 resources are additive; `/v1/verify` remains compatible.

1. `POST /v1/covenants` accepts a strict `ActionCovenantDraft` plus a
   principal acceptance bound to the draft hash. A model may produce the draft,
   but it cannot activate it by naming itself as the principal.
2. `POST /v1/authorizations` checks covenant integrity and expiry, exact action
   equality, evidence presence and freshness, shallow exact-match invalidation
   signals, and the existing delegated-authority policies. It returns a compact
   ES256 authorization JWS for every decision.
3. The executor acts only on `ALLOW` before the receipt expires.
4. `POST /v1/outcomes` verifies the authorization receipt, binds the reported
   execution outcome, checks exact forbidden-effect rules, and returns a compact
   ES256 outcome JWS.

All three resources require authenticated enforcement and
`RECEIPT_SIGNING_KEY`; there is no evaluation-only activation path. Covenants
are caller-held immutable envelopes in this milestone. Vizier does not persist
them or retrieve evidence independently.

## Integration rule

Call Vizier immediately before the external action. Treat timeout, invalid JSON,
`REVIEW`, and `BLOCK` as stop conditions.

```ts
const decision = await vizier.verify(proposedAction);

if (decision.decision === "ALLOW") {
  await executeAction();
}
```

The thin TypeScript client lives in `packages/sdk`:

```ts
import { Vizier } from "@vizier/sdk";

const vizier = new Vizier({
  baseUrl: "http://127.0.0.1:8787",
  apiKey: process.env.VIZIER_API_KEY,
});
const decision = await vizier.verify(request);
```

The API key belongs only in a controlled backend or orchestrator. Do not expose it
to the action-taking agent. This key authenticates the integration; it does not
prove that each supplied delegation was issued by the principal.

## Policy rules

| Rule | Result |
| --- | --- |
| No authenticated integration credential is configured | `REVIEW / AUTHORITY_SOURCE_UNTRUSTED` |
| Action is absent from `allowed_actions` | `BLOCK / ACTION_NOT_DELEGATED` |
| Principal is `null` | `REVIEW / PRINCIPAL_UNVERIFIED` |
| Amount exceeds `max_amount` | `BLOCK / AUTHORITY_LIMIT_EXCEEDED` |
| Amount or currency cannot be checked | `REVIEW` |
| Target is blocked or absent from an allowlist | `BLOCK` |
| Sensitive action lacks explicit sensitive authority | `REVIEW / SENSITIVE_ACTION_REVIEW` |

The default sensitive actions are `transfer_funds`, `delete_data`,
`deploy_worker`, `execute_code`, `send_external_message`,
`modify_permissions`, and `sign_contract`.

## Protocol endpoints

- `GET /.well-known/agent-card.json` returns an A2A v1.0 Agent Card with a
  canonical ES256 JWS in `signatures[]` when `AGENT_CARD_SIGNING_KEY` is
  configured.
- `GET /.well-known/jwks.json` returns the matching public key. The JWS protected
  header points to this endpoint through a same-origin `jku`.
- `POST /a2a` implements the A2A v1.0 JSON-RPC `SendMessage` method. Anonymous
  requests run only in evaluation mode; a wrong supplied credential is rejected.
- `POST /mcp` implements MCP `2026-07-28` with `server/discover`, `tools/list`,
  and `tools/call` for `vizier_verify_action`.

Only the current protocol revisions above are implemented. The MCP endpoint is
stateless and does not implement the legacy `initialize` session.

## Receipts

Each successful verification returns a receipt ID, creation time, request hash,
decision, risk score, rule IDs, and reason codes. Object keys are sorted before
SHA-256 hashing. This canonicalization is documented and tested, but it is not
an RFC 8785 claim.

Legacy `/v1/verify` receipts remain unsigned and caller-held for compatibility.
The SDK validates the complete response, checks decision-to-receipt consistency,
and recomputes the request hash before returning a decision.

Action Covenant authorization and outcome receipts are compact ES256 JWS values.
They use a dedicated receipt key and protected `typ` values for domain
separation. The SDK obtains the matching public key from
`/.well-known/jwks.json`, verifies the signature, and recomputes the covenant,
request, action, evidence, signal, authorization-token, and outcome bindings
before returning. Signed does not mean persisted, independently timestamped, or
principal-issued.

## Development

```bash
npm run typecheck
npm test
npm run build
npm run check
```

`npm run build` compiles `@vizier/sdk`, compiles the private gated-deploy tool,
and runs a Cloudflare deployment dry run. It does not deploy the Worker.

To prepare an enforcement deployment after reviewing the threat model:

```bash
npx wrangler whoami
npx wrangler secret put VIZIER_API_KEY
npx wrangler secret put AGENT_CARD_SIGNING_KEY
npx wrangler secret put RECEIPT_SIGNING_KEY
npx wrangler deploy
```

`AGENT_CARD_SIGNING_KEY` and `RECEIPT_SIGNING_KEY` are separate private P-256
JWKs with distinct `kid` values, `alg: "ES256"`, `use: "sig"`, and stable key
identifiers. Wrangler stores them as secrets; they must not be committed. A
malformed configured key fails the affected signed surface instead of silently
downgrading it.

The first deployment bootstraps the gate. After the same integration credential
has been stored in macOS Keychain under service `com.vizier.gated-deploy` and
account `VIZIER_API_KEY`, subsequent deployments use:

```bash
npm run deploy:gated
```

The private tool accepts no command arguments. It drafts and accepts a five-minute
covenant for the current commit, the fixed `deploy_worker` action, and the fixed
`worker:vizier` target. A worktree snapshot is freshness evidence and a dirty
worktree is an invalidation signal. It runs `wrangler deploy --strict` only after
the SDK verifies a signed `ALLOW` receipt, then records a signed success or
failure outcome. If outcome recording fails after execution, the command returns
`outcome_unrecorded` and a non-zero exit code instead of reporting a complete lifecycle.

The first v0.2 deployment must use the already-live v0.1 gate to break the
bootstrap cycle:

```bash
VIZIER_V0_2_BOOTSTRAP=1 npm run deploy:gated
```

This bypass is explicit and should be used only for the one deployment that
introduces the covenant endpoints and receipt key. Normal subsequent runs use
the covenant lifecycle.

This wrapper is an integration test, not an operating-system security boundary.
An agent with unrestricted shell access and Cloudflare credentials can bypass it
by invoking Wrangler directly. A production integration must expose only the
wrapper capability and keep both Cloudflare and Vizier credentials outside the
action-taking agent.

The deployment command is intentionally not part of `npm run build`. Without
the secret, a deployment remains evaluation-only and cannot return `ALLOW`.

The Worker uses no D1, KV, Durable Object, queue, AI model, or outbound fetch.
The repository structure and protocol sources are documented in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/ADR-0001-ACTION-COVENANTS.md](docs/ADR-0001-ACTION-COVENANTS.md),
[docs/CLAIMS.md](docs/CLAIMS.md), and
[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).

## What is deferred

Independent principal authentication, durable policy/evidence/receipt storage,
principal-signed delegation and acceptance, billing, dashboards, reputation
models, payment settlement, and LLM policy evaluation inside the privileged kernel
remain outside v0.2. See
[FUTURE.md](FUTURE.md).
