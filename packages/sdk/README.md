# @vizier/sdk

Official TypeScript client for **Vizier** — deterministic authorization & audit firewall for AI agents.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Vizier verifies proposed agent actions (purchases, database queries, deployments, money transfers, external messages) against strictly delegated constraints before execution.

---

## 📦 Installation

```bash
npm install https://github.com/vassiliylakhonin/vizier/releases/download/v0.5.3/vizier-sdk-0.5.3.tgz
```

---

## 🚀 Quickstart

```ts
import { Vizier } from "@vizier/sdk";

const vizier = new Vizier({
  baseUrl: "https://vizier.vassiliy-lakhonin.workers.dev",
  apiKey: process.env.VIZIER_API_KEY,
});

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
  context: { source: "rest" },
});

if (decision.decision === "ALLOW") {
  console.log("Action authorized! Receipt hash:", decision.receipt.request_hash);
  // Proceed with execution
} else {
  console.error("Action blocked:", decision.explanation, decision.reason_codes);
}
```

---

## 🔑 Features

* **Deterministic Policies**: No probabilistic LLM-in-the-loop decisions. Strict mathematical rule enforcement.
* **Cryptographic Receipts**: SHA-256 canonical JSON hash (`receipt.request_hash`) on every response for tamper-evident audit trails.
* **Delegation Grants**: Support for principal-signed JWS delegation grants (`grant` field).
* **Action Covenants**: Full lifecycle support (`activateCovenant`, `authorizeCovenant`, `recordOutcome`).
* **Sub-25ms Latency**: Designed to run against Cloudflare Workers globally distributed on the edge.

---

## 🌐 Links

* **Live Interactive Playground**: [https://vizier.vassiliy-lakhonin.workers.dev/playground](https://vizier.vassiliy-lakhonin.workers.dev/playground)
* **GitHub Repository**: [https://github.com/vassiliylakhonin/vizier](https://github.com/vassiliylakhonin/vizier)
* **OpenAPI 3.1 Contract**: [https://vizier.vassiliy-lakhonin.workers.dev/openapi.json](https://vizier.vassiliy-lakhonin.workers.dev/openapi.json)


## Explicit human reviews

`submitHumanReview(request)` explicitly stores the exact action and supplied
evidence in the administrative queue for seven days. `claimHumanReview(request,
id, token)` verifies ES256, issuer, audience, expiry and the hash of the original
locally retained request, then atomically consumes the operator's approval once.
The client does not approve, sign, broadcast or change Financial Guard verdicts.
Keep the separate reviewer key out of the integration. See the repository's
human-review documentation and `/reviews` on your trusted Vizier origin.
