# Vizier

Every agent. Every action. Verified.

Vizier is a small authorization layer for action-taking AI agents. Before an
agent calls a tool, API, MCP server, A2A agent, or internal service, it sends the
proposed action to Vizier.

```text
Agent
  |
Vizier
  |
ALLOW / REVIEW / BLOCK
  |
Tool / API / Agent
```

The decision path is deterministic. It checks delegated actions, principal
identity, amount limits, targets, sensitive operations, and whether the request
came through the authenticated integration boundary. Every response includes
policy results and a SHA-256 receipt hash.

Status: experimental v0.1. There are no production users, paid pilots, or usage
claims. Authority is still supplied by the integrating application rather than
loaded from an independent policy store. Read the [threat
model](docs/THREAT_MODEL.md) before placing this service in an execution path.

Live endpoint: <https://vizier.vassiliy-lakhonin.workers.dev>. Discovery,
health, and documentation routes are public. Verification requires a private
integration credential; no public demo credential is issued.

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
configured, verification calls require `Authorization: Bearer <key>`.

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

- `GET /.well-known/agent-card.json` returns an A2A v1.0 Agent Card.
- `POST /a2a` implements the A2A v1.0 JSON-RPC `SendMessage` method.
- `POST /mcp` implements MCP `2026-07-28` with `server/discover`, `tools/list`,
  and `tools/call` for `vizier_verify_action`.

Only the current protocol revisions above are implemented. The MCP endpoint is
stateless and does not implement the legacy `initialize` session.

## Receipts

Each successful verification returns a receipt ID, creation time, request hash,
decision, risk score, rule IDs, and reason codes. Object keys are sorted before
SHA-256 hashing. This canonicalization is documented and tested, but it is not
an RFC 8785 claim.

Receipts are not stored or signed in v0.1. The caller must retain them.
The SDK validates the complete response, checks decision-to-receipt
consistency, and recomputes the request hash before returning a decision.

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
npx wrangler deploy
```

The first deployment bootstraps the gate. After the same integration credential
has been stored in macOS Keychain under service `com.vizier.gated-deploy` and
account `VIZIER_API_KEY`, subsequent deployments use:

```bash
npm run deploy:gated
```

The private tool accepts no command arguments. It submits the current clean Git
commit, the fixed `deploy_worker` action, and the fixed `worker:vizier` target.
It runs `wrangler deploy --strict` only after a validated `ALLOW` receipt. A
`REVIEW`, `BLOCK`, timeout, malformed response, missing credential, or dirty
worktree stops the deployment.

This wrapper is an integration test, not an operating-system security boundary.
An agent with unrestricted shell access and Cloudflare credentials can bypass it
by invoking Wrangler directly. A production integration must expose only the
wrapper capability and keep both Cloudflare and Vizier credentials outside the
action-taking agent.

The deployment command is intentionally not part of `npm run build`. Without
the secret, a deployment remains evaluation-only and cannot return `ALLOW`.

No D1, KV, Durable Object, queue, AI model, or external network call is used.
The repository structure and protocol sources are documented in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/CLAIMS.md](docs/CLAIMS.md), and
[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).

## What is deferred

Independent principal authentication, durable policy storage, signed
delegation, signed receipts, billing, dashboards, reputation models, payment
settlement, and LLM policy evaluation are outside v0.1. See
[FUTURE.md](FUTURE.md).
