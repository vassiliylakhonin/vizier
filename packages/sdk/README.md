# @vizier/sdk

Official TypeScript client for **Vizier** — deterministic authorization & audit firewall for AI agents.

[![npm version](https://img.shields.io/npm/v/@vizier/sdk.svg)](https://www.npmjs.com/package/@vizier/sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Vizier verifies proposed agent actions (purchases, database queries, deployments, money transfers, external messages) against strictly delegated constraints before execution.

---

## 📦 Installation

```bash
npm install @vizier/sdk
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
