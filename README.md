# Vizier

Deterministic authorization before an AI agent causes an external side effect.

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

Status: experimental v0.2.1, deployed on the public Worker. There are no
production users, paid pilots, or usage claims. Authority, principal acceptance,
evidence, invalidation signals, and outcomes are still supplied by the
integrating application rather than loaded or observed independently. Read the
[threat model](docs/THREAT_MODEL.md) before placing this service in an execution
path.

Public surfaces:

- Worker: <https://vizier.vassiliy-lakhonin.workers.dev>
- Live field reference: <https://vizier.vassiliy-lakhonin.workers.dev/docs>
- OpenAPI 3.1 contract: <https://vizier.vassiliy-lakhonin.workers.dev/openapi.json>
- AI discovery catalog: <https://vizier.vassiliy-lakhonin.workers.dev/.well-known/ai-catalog.json>
- MCP server manifest: <https://vizier.vassiliy-lakhonin.workers.dev/.well-known/mcp.json>
- MCP Registry entry: `io.github.vassiliylakhonin/vizier`
- Agent Card: <https://vizier.vassiliy-lakhonin.workers.dev/.well-known/agent-card.json>
- Public key set: <https://vizier.vassiliy-lakhonin.workers.dev/.well-known/jwks.json>

Discovery, health, documentation, and evaluation-only A2A and MCP calls are
public. REST, MCP, and A2A enforcement require a private integration credential;
no public demo credential is issued. Action Covenant resources are authenticated
REST endpoints in v0.2.1. `GET /v1/insights` is also authenticated and returns
only aggregate operational counts from the metadata-only audit store.

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
JSON bodies are capped at 1 MiB, 64 levels, and 50,000 aggregate values before
recursive schema validation.
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

The v0.2.1 resources are additive; `/v1/verify` remains compatible.

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
remain caller-held immutable envelopes in this milestone. Vizier stores bounded
operational metadata and hashes asynchronously, but not full action parameters,
evidence, signals, outcome effects, JWS tokens, or signing material. It does not
retrieve evidence independently.

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
| Authority requires reversibility and the action is not declared reversible | `REVIEW / IRREVERSIBLE_ACTION_REVIEW` |

The default sensitive actions are `transfer_funds`, `delete_data`,
`deploy_worker`, `execute_code`, `send_external_message`,
`modify_permissions`, and `sign_contract`.

`action.is_reversible` is an integration-supplied assertion, not an independently
verified property. `require_review_for_irreversible` fails to `REVIEW` when that
assertion is absent or false; it cannot prove a true assertion is accurate.

## Protocol endpoints

- `GET /openapi.json` and `GET /.well-known/openapi.json` return the same
  OpenAPI 3.1 contract for `/v1/verify`, `/v1/covenants`,
  `/v1/authorizations`, `/v1/outcomes`, and the authenticated
  `/v1/insights`. Request schemas are emitted from the same Zod definitions
  used at the runtime boundary.
- `GET /.well-known/ai-catalog.json` routes machines to the A2A Agent Card, the
  OpenAPI contract, and the MCP server manifest.
- `GET /.well-known/agent-card.json` returns an A2A v1.0 Agent Card with a
  canonical ES256 JWS in `signatures[]` when `AGENT_CARD_SIGNING_KEY` is
  configured.
- `GET /.well-known/jwks.json` returns the matching public key. The JWS protected
  header points to this endpoint through a same-origin `jku`.
- `POST /a2a` implements the A2A v1.0 JSON-RPC `SendMessage` method. Anonymous
  requests run only in evaluation mode; a wrong supplied credential is rejected.
- `POST /mcp` implements MCP `2026-07-28` with `server/discover`, `tools/list`,
  and `tools/call` for `vizier_verify_action`. The same endpoint also answers
  the session handshake used by shipping clients: `initialize`,
  `notifications/initialized`, `ping`, `tools/list`, and `tools/call` over
  `2025-06-18`, `2025-03-26`, or `2024-11-05`. The request body selects the
  profile: only `2026-07-28` carries its protocol version in `params._meta`.
- `GET /.well-known/mcp.json` returns the MCP server manifest, the same document
  published to the MCP Registry from `server.json` at the repository root.

The session profile exists because no off-the-shelf client speaks the stateless
profile yet. Measured 2026-09-02 against the deployed Worker: a standard
`initialize` was rejected with `-32600`, so the endpoint could not be connected
from any MCP client. The stateless contract is unchanged; the session profile is
additive and shares one verification path.

### MCP enforcement proxy pilot

`packages/mcp-proxy` is a private `build-to-learn` adapter for placing one
existing MCP server behind Vizier. It is not deployed, published to npm, or
presented as production-ready. The proxy:

- exposes only the configured upstream tool names;
- authenticates every MCP request with a proxy-specific Bearer token;
- maps the exact tool name and arguments to one `mcp_tool_call` verification;
- forwards the unchanged MCP request only after a verified `ALLOW`;
- stops on `REVIEW`, `BLOCK`, timeout, invalid Vizier output, or upstream error;
- replaces the incoming credential with a separate upstream credential; and
- logs integration ID, request ID, tool name, decision, receipt ID, outcome, and
  latency without logging arguments or secrets.

Build the private package:

```bash
npm run build --workspace @vizier/mcp-proxy
```

Configure one participant and one upstream MCP server. Generate independent
random values for the proxy client token, Vizier API key, and upstream token;
do not reuse any of them:

```bash
export VIZIER_BASE_URL="http://127.0.0.1:8787"
export VIZIER_API_KEY="local-development-key"
export VIZIER_PROXY_INTEGRATION_ID="pilot-acme"
export VIZIER_PROXY_CLIENT_TOKEN="replace-with-a-random-client-token"
export VIZIER_PROXY_AGENT_ID="coding-agent-01"
export VIZIER_PROXY_AGENT_OWNER="acme"
export VIZIER_PROXY_PRINCIPAL_ID="platform-team"
export VIZIER_PROXY_UPSTREAM_ID="filesystem"
export VIZIER_PROXY_UPSTREAM_URL="http://127.0.0.1:8791/mcp"
export VIZIER_PROXY_UPSTREAM_BEARER_TOKEN="replace-with-upstream-token"
export VIZIER_PROXY_ALLOWED_TOOLS="write_file"
npm exec --workspace @vizier/mcp-proxy -- vizier-mcp-proxy
```

Point the pilot MCP client at `http://127.0.0.1:8790/mcp`, use
`VIZIER_PROXY_CLIENT_TOKEN` as its Bearer credential, and remove its direct
access to the upstream URL and credential. The proxy is not an enforcement
boundary if the agent can still reach the upstream server, read either backend
credential, or use a shell with equivalent authority.

## Connect an MCP client

The credential is optional at connect time. An anonymous `tools/call` runs in
evaluation mode: the decision is real but the supplied authority is untrusted, so
it can never return `ALLOW`. The credential unlocks enforcement results, and a
credential that is supplied and wrong is rejected with `-32001`.

```bash
claude mcp add --transport http vizier \
  https://vizier.vassiliy-lakhonin.workers.dev/mcp
```

Add the header once you hold a credential:

```bash
claude mcp add --transport http vizier \
  https://vizier.vassiliy-lakhonin.workers.dev/mcp \
  --header "Authorization: Bearer <integration-credential>"
```

Any client that accepts a Streamable HTTP URL works the same way. Verify the
handshake without a client:

```bash
curl -sS https://vizier.vassiliy-lakhonin.workers.dev/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1.0"}}}'
```

### Registry listing

`server.json` at the repository root is the MCP Registry entry for
`io.github.vassiliylakhonin/vizier`, published on 2026-09-02 and validated
against the `2025-12-11` server schema. It carries no `repository` block: the
source repository is private, and an entry pointing at a URL that answers 404 is
worse than no link at all. The namespace is claimed through the GitHub account,
not the repository. Republish after any change to the endpoint or the manifest:

```bash
mcp-publisher login github
mcp-publisher publish
```

Read the live entry back:

```bash
curl -sS "https://registry.modelcontextprotocol.io/v0/servers?search=vizier"
```

An unrelated `io.github.pipeworx-io/vizier` is listed in the same registry. The
namespace is what separates them, so a search by bare name returns both.

`tests/discovery-contracts.test.ts` holds `server.json` and the served
`/.well-known/mcp.json` to the same content, so a registry listing cannot drift
away from the endpoint the Worker serves.

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
before returning. Signed does not mean independently timestamped or
principal-issued. Vizier persists only selected receipt metadata and hashes; the
complete signed receipt and token remain caller-held.

`GET /v1/insights` exposes authenticated decision counts, lifecycle totals,
average legacy risk score, and reported failure/violation count. These are
best-effort operational aggregates: asynchronous audit writes can fail, and the
numbers are not proof of production adoption or complete execution history.
Metadata is retained for 30 days and pruned daily by a scheduled Worker handler.

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

The public Worker completed its one-time v0.1-to-v0.2 bootstrap on 2026-08-24.
After the integration credential has been stored in macOS Keychain under service
`com.vizier.gated-deploy` and account `VIZIER_API_KEY`, normal deployments use:

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

A new Worker name or fresh environment that does not expose the covenant
endpoints needs one explicit bootstrap deployment through its existing v0.1
gate:

```bash
VIZIER_V0_2_BOOTSTRAP=1 npm run deploy:gated
```

This bypass is only for the deployment that introduces the covenant endpoints
and receipt key. Do not set `VIZIER_V0_2_BOOTSTRAP` for normal deployments of the
public Vizier Worker; they use the covenant lifecycle.

This wrapper is an integration test, not an operating-system security boundary.
An agent with unrestricted shell access and Cloudflare credentials can bypass it
by invoking Wrangler directly. A production integration must expose only the
wrapper capability and keep both Cloudflare and Vizier credentials outside the
action-taking agent.

The deployment command is intentionally not part of `npm run build`. Without
the secret, a deployment remains evaluation-only and cannot return `ALLOW`.

The Worker uses D1 only for an asynchronous, metadata-only operational audit
trail. The authorization decision path does not depend on D1 availability. It
uses no KV, Durable Object, queue, AI model, or outbound fetch. `npm run check`
applies every D1 migration in order to an in-memory SQLite database and verifies
that legacy payload-bearing columns are removed.
The repository structure and protocol sources are documented in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/ADR-0001-ACTION-COVENANTS.md](docs/ADR-0001-ACTION-COVENANTS.md),
[docs/PILOT.md](docs/PILOT.md),
[docs/CLAIMS.md](docs/CLAIMS.md), and
[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).

## What is deferred

Independent principal authentication, durable policy/evidence/full-receipt storage,
principal-signed delegation and acceptance, billing, dashboards, reputation
models, payment settlement, and LLM policy evaluation inside the privileged kernel
remain outside v0.2.1. See
[FUTURE.md](FUTURE.md).
