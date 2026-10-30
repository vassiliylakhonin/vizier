# Authorization quickstart

Vizier is the last check at an action boundary: Interaction Trust can assess the
caller, Output Verification and specialist gates can check evidence, and Financial
Guard or Escrow can identify payment concerns. None of those results is an
execution grant. Your own trusted guard must require a Vizier ALLOW for the exact
action before invoking the protected tool, and enforce its own transaction and
replay controls.

## Try three local examples

With Node 24+, run `npm ci` and `npm run dev`, then in another terminal:

```sh
for example in allow block review; do
  printf '\n%s\n' "$example"
  curl -sS -D - -X POST http://127.0.0.1:8787/v1/verify/evaluate \
    -H 'Content-Type: application/json' --data-binary "@examples/$example.json"
done
```

These are synthetic policy scenarios, not grants. Anonymous evaluation never
returns ALLOW: the normally permissive `allow` scenario becomes REVIEW (or can
be BLOCK under stricter configuration). The server sets
`X-Vizier-Evaluation-Only: true` and `X-Vizier-Allow-Impossible: true`; MCP uses
result `_meta` and A2A uses task `metadata` with `evaluation_only` and
`allow_impossible`. Existing decision response bodies remain unchanged.

## Get a signed delegation

The principal owns the private key, controls the action and limits, and mints a
short-lived grant. The server operator registers only the public key. In a safe
local directory, for the procurement example:

```sh
node scripts/mint-grant.mjs keygen --kid acme-2026-09 --out principal.jwk.json
cat > grant.json <<'JSON'
{
  "iss": "acme-corp",
  "sub": "procurement-agent-01",
  "authority": {
    "allowed_actions": ["purchase"],
    "constraints": { "max_amount": 10000, "currency": "USD" }
  }
}
JSON
node scripts/mint-grant.mjs sign --key principal.jwk.json --grant grant.json --ttl 3600
```

Register the public JWK for `acme-corp` with the operator; never share the private
file with the agent or commit it. See [delegation setup](DELEGATION_GRANTS.md)
for registration, grant audience and rotation. The request must use the exact
signed authority, principal and agent. The API key identifies the integration;
it is not the owner's delegation. In required-grant mode a missing or invalid
grant cannot yield ALLOW.

## Put the check immediately before the tool

The `authorize` helper is available in SDK v0.5.15 and later. It
requires a configured integration credential and grant, validates the service
response and request hash, and refuses REVIEW, BLOCK, wrong identities, expired
grants and caller-asserted provenance. The configured service and its HTTPS
connection must be trusted: the legacy `/v1/verify` receipt is unsigned and this
helper does not verify it as a JWS.

```ts
import { readFile } from "node:fs/promises";
import { Vizier } from "@agenda-intelligence/vizier-sdk";

const vizier = new Vizier({ baseUrl: process.env.VIZIER_URL!, apiKey: process.env.VIZIER_API_KEY! });
const grant = (await readFile(process.env.VIZIER_GRANT_FILE!, "utf8")).trim();
const request = {
  agent: { id: "procurement-agent-01", owner: "acme-corp" },
  principal: { id: "acme-corp" },
  action: { type: "purchase", target: "supplier.example", parameters: { amount: 8200, currency: "USD" } },
  authority: { allowed_actions: ["purchase"], constraints: { max_amount: 10000, currency: "USD" } },
  context: { request_id: "example-01", timestamp: null, source: "rest" as const },
  grant,
};
const result = await vizier.authorize(request); // throws unless verified ALLOW
// Only a separate trusted executor may perform the exact checked action here.
// It must prevent request substitution and handle retries/replay atomically.
console.log(result.receipt.id);
```

The helper does not execute an action, enforce exclusivity, consume the grant or
record an outcome. If the service is unreachable or a response is invalid, stop.
For an actual integration, bind execution to the same immutable action, prevent
agent access to the underlying credentials, and design idempotency and human
review. Covenant authorization and outcome receipts have their own signed
formats; see [the covenant contract](ADR-0001-ACTION-COVENANTS.md). Required-grant
mode currently blocks legacy covenant authorization, which has no grant field.

## Starting points for owner policy

These are templates to adapt and sign, not policies automatically installed by
Vizier or assurances of legal compliance. Choose explicit targets, amount limits,
short expiry, and review requirements for your environment.

| Workflow | Example starting authority | Additional operator controls |
| --- | --- | --- |
| Payments | `allowed_actions: ["settle_payment"]`, exact `allowed_targets`, amount and currency limits | Protected payment credential, idempotency and human approval as appropriate |
| Procurement | `allowed_actions: ["purchase"]`, allowlisted suppliers, amount and currency limits | Owner signs scope and limits; validate invoice and counterparty independently |
| Research | `allowed_actions: ["read"]`, allowlisted data sources | Enforce read-only credentials at the underlying service |
| External tool | A named action and allowlisted endpoint | Guard the tool itself and restrict downstream credentials |

For denied actions inspect `decision`, `reason_codes` and `policy_results`;
correct the underlying authorization or evidence and request a new evaluation.
Do not expand an authority independently of the principal-signed grant.
