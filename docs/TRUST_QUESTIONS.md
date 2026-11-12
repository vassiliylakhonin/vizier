# Four trust questions: what Vizier answers today

A reviewer evaluating an agent-action control can ask four questions about any
action an agent takes:

1. **Who granted the authority?**
2. **What exact action does it cover?**
3. **Who confirmed that action?**
4. **How can anyone prove that only the permitted action ran?**

This page states, for each question, what is implemented, what is not, and where
the evidence is. It is a self-assessment by the maintainer, not an independent
audit. Vizier has no production users or revenue (see [CLAIMS.md](CLAIMS.md)).
Status below is for the repository at v0.5.17 plus the changes described in
the [CHANGELOG](../CHANGELOG.md) "Unreleased" section.

| Question | Status | One line |
| --- | --- | --- |
| 1. Who granted authority | Advanced, with gaps | Owner-signed grants verified against out-of-band keys; no revocation, no key rotation tooling |
| 2. What exact action | Strongest | Covenants bind one exact action; request hash is in every receipt |
| 3. Who confirmed it | Works, single-operator | Signed approvals, quorum, Telegram/webhook; one reviewer credential |
| 4. Proof of permitted-only execution | Partial | Signed authorization and outcome tokens on the covenant path; outcome is reported by the integration |

## 1. Who granted the authority?

**Implemented**

- Optional principal-signed covenant acceptance (`acceptance_jws`), verified
  against the same out-of-band key registry and stored inside the hashed covenant.
- Delegation grants are compact ES256 JWS tokens, `typ vizier-delegation+jws`,
  signed by the principal and verified against keys registered out of band
  (`VIZIER_PRINCIPAL_KEYS`). Decisions make no network call for keys.
  ([DELEGATION_GRANTS.md](DELEGATION_GRANTS.md))
- The `authority` in the request must canonicalize byte for byte to what the
  principal signed. A grant that does not verify is `BLOCK`, never a downgrade to
  caller-asserted authority.
- Required-grant mode (v0.5.6) blocks requests without a valid grant. Receipts
  record `authority_provenance` (`principal_signed`, `trusted_integration` or
  `unverified`) and the grant `jti`, issuer, subject, key id and expiry.
- Registering two keys for one principal supports rotation by overlap.

**Gaps (acknowledged)**

- Revocation is operator-driven: `POST /v1/grants/revoke` or the
  `VIZIER_REVOKED_GRANTS` secret, by grant id. It is not principal-signed, and
  anyone with the integration credential can revoke.
- A grant proves delegation of a shape of action, not that a human looked at a
  particular action.
- Key registration is a deployment-time operation by the operator, so the
  operator is the root of trust for which principals exist.
- Optional grant mode (the self-hosting default) still accepts caller-asserted
  authority. Receipts from that mode do not establish owner delegation.
- Covenant acceptance is principal-signed only when the integration sends
  `acceptance_jws`; unsigned acceptance remains an integration assertion unless
  the operator sets `VIZIER_REQUIRE_SIGNED_ACCEPTANCE=true`. A signature proves
  the key holder accepted that draft hash, not that a human read it.
  ([FUTURE.md](../FUTURE.md))

## 2. What exact action does it cover?

**Implemented**

- Every `/v1/verify` receipt carries a SHA-256 hash of the canonicalized
  request, so a decision is bound to the exact action and parameters.
- An Action Covenant holds one exact action, delegated authority, evidence
  freshness rules, exact-match invalidation signals, forbidden effects and an
  expiry. Vizier recomputes covenant integrity before authorizing.
  ([ADR-0001](ADR-0001-ACTION-COVENANTS.md))
- The Worker-deployment pilot pins account, Worker, version and traffic
  percentage; changed versions and out-of-scope targets are blocked in the
  recorded demo ([WORKER_DEPLOY_DEMO.md](WORKER_DEPLOY_DEMO.md)).

**Gaps (acknowledged)**

- Exact-match rules are deliberately shallow. Semantic conditions are not
  evaluated; models may draft a covenant but never authorize it.
- Vizier checks policy and permission. It does not establish that supplied
  evidence or signals are true.
- A guard protects only the path it controls. An agent with direct tool
  credentials can bypass it; the MCP proxy only helps if direct access is removed.

## 3. Who confirmed the action?

**Implemented**

- `REVIEW` decisions route to human approval. Approval artifacts are signed and
  bound to the plan; a replayed approval does not execute twice in the
  Worker-deployment pilot.
- Quorum mode (4-eyes): the proposer cannot approve its own action, approvals
  bind to the action hash, any rejection vetoes, and a proposal is consumed once.
- Python SDK handlers for Telegram buttons, a webhook and a CLI prompt.

**Gaps (acknowledged)**

- The review queue is single-operator. Reviewer identity is one credential, not
  a directory of named approvers. Use a buyer-owned instance
  ([INTEGRATION_OFFER.md](INTEGRATION_OFFER.md)).
- Review records are visible for a short window (about seven days in the
  queue API) and audit metadata is deleted after 30 days. This is not a
  long-term approval ledger.
- Telegram and webhook confirmations are transport conveniences. They do not
  prove which human acted.

## 4. How can anyone prove only the permitted action was executed?

**Implemented**

- Covenant path: Vizier signs an authorization JWS bound to the covenant, full
  request, action, evidence, decision and a short execution window. The executor
  reports an outcome against a valid `ALLOW`, and Vizier signs a second JWS over
  the authorization, covenant, outcome and any forbidden-effect violations.
  Tampering with either is detectable against the published JWKS.
- Legacy `/v1/verify`: the response `receipt` object is unsigned. When the
  service has a receipt signing key and the caller sends
  `X-Vizier-Receipt: jws`, the response also carries `receipt_jws`, an ES256
  signature over that exact receipt.
- The Worker-deployment adapter journals its execution state before the cloud
  call and keeps uncertain outcomes unresolved until reconciled.

**Gaps (acknowledged)**

- The integration reports the outcome. Vizier does not observe the effect, so a
  signed outcome proves what was reported, not what happened. (The financial
  reservation review is an experimental exception for EVM wallets.)
- The SDK `authorize()` helper requests `receipt_jws` and verifies it against the
  published JWKS, including that it signs the exact returned `receipt`. If the
  service returns none, `authorize()` tolerates that and trusts the configured
  service over HTTPS as before.
- Grants are reusable by default. A principal can sign `single_use: true`,
  which spends the grant at `ALLOW` (atomic in D1). It is spent on the decision,
  not on execution success, and execution idempotency is still the
  integration's job. Without the D1 binding, enforcement of a single-use
  grant fails closed (`BLOCK`, `GRANT_SINGLE_USE_STATE_UNAVAILABLE`) rather
  than trusting per-isolate memory.
- No transparency log, independent timestamp or durable full-receipt store.
  Callers hold their receipts.

## What would move each answer

| Question | Next step | Tracking |
| --- | --- | --- |
| 1 | Principal-signed revocation; making signed acceptance the default | [FUTURE.md](../FUTURE.md) |
| 3 | A second independent approval transport (OpenAgentEmail consumer, draft PR) | PR #132 |
| 4 | Execution-confirmed (not decision-time) single-use spend, transparency log | not started |
