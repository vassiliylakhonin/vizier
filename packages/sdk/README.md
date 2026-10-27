# @agenda-intelligence/vizier-sdk

Official TypeScript client for **Vizier** — deterministic authorization & audit firewall for AI agents.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Vizier verifies proposed agent actions (purchases, database queries, deployments, money transfers, external messages) against strictly delegated constraints before execution.

---

## 📦 Installation

```bash
npm install @agenda-intelligence/vizier-sdk@0.5.14
```

---

## 🚀 Quickstart

```ts
import { Vizier } from "@agenda-intelligence/vizier-sdk";

const vizier = new Vizier({
  baseUrl: "https://vizier.agendamcp.dpdns.org",
  apiKey: process.env.VIZIER_API_KEY,
});

// The owner must register a public key and sign a matching short-lived grant.
// Keep the private signing key outside the agent and this integration.
const decision = await vizier.verify({
  agent: { id: "procurement-agent-01", owner: "acme-corp" },
  principal: { id: "acme-corp" },
  action: {
    type: "purchase",
    target: "supplier.example",
    parameters: { amount: 820, currency: "USD" },
  },
  authority: {
    allowed_actions: ["purchase"],
    constraints: {
      max_amount: 1000,
      currency: "USD",
      allowed_targets: ["supplier.example"],
    },
  },
  grant: process.env.VIZIER_GRANT_JWS!,
  context: { source: "rest" },
});

// Authorization alone does not execute the purchase.
console.log(decision.decision, decision.reason_codes);
```

---

The hosted service requires a valid owner-signed grant; an API key alone is not
owner permission. Without the matching grant this example returns `BLOCK`. See
[delegation setup](https://github.com/vassiliylakhonin/vizier/blob/main/docs/DELEGATION_GRANTS.md)
before connecting a real executor.

## 🔑 Features

* **Deterministic Policies**: No probabilistic LLM-in-the-loop decisions. Strict mathematical rule enforcement.
* **Request-bound Receipts**: SHA-256 canonical JSON hash (`receipt.request_hash`). These receipts are unsigned and do not independently authenticate the issuer.
* **Delegation Grants**: Support for principal-signed JWS delegation grants (`grant` field).
* **Action Covenants**: Full lifecycle support (`activateCovenant`, `authorizeCovenant`, `recordOutcome`).
* **Edge API**: Hosted on Cloudflare Workers; end-to-end latency depends on the caller and network.

---

## 🌐 Links

* **Live Interactive Playground**: [https://vizier.agendamcp.dpdns.org/playground](https://vizier.agendamcp.dpdns.org/playground)
* **GitHub Repository**: [https://github.com/vassiliylakhonin/vizier](https://github.com/vassiliylakhonin/vizier)
* **OpenAPI 3.1 Contract**: [https://vizier.agendamcp.dpdns.org/openapi.json](https://vizier.agendamcp.dpdns.org/openapi.json)


## Explicit human reviews

`submitHumanReview(request)` explicitly stores the exact action and supplied
evidence in the administrative queue for seven days. `claimHumanReview(request,
id, token)` verifies ES256, issuer, audience, expiry and the hash of the original
locally retained request, then atomically consumes the operator's approval once.
The client does not approve, sign, broadcast or change Financial Guard verdicts.
Keep the separate reviewer key out of the integration. See the repository's
human-review documentation and `/reviews` on your trusted Vizier origin.
