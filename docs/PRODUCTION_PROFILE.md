# Secure production profile (checklist)

A configuration checklist for an operator running Vizier in front of a real
action. Each line says what the code does when the setting is on. Nothing here
is a certification, and no production deployment has been checked against it.

## Vizier service

- Set `VIZIER_API_KEY` (integration) and, separately, `VIZIER_REVIEWER_KEY` (human review decisions). Give the agent neither.
- Register owner public keys in `VIZIER_PRINCIPAL_KEYS` and set `VIZIER_SIGNED_GRANT_MODE=required`. Without required mode a request without a grant is not refused for that reason; with it, a missing or invalid grant is `BLOCK` (`GRANT_REQUIRED`). Migrate every caller to grants first.
- Bind D1 and apply all migrations. Without D1: single-use grants and budgets fail closed (`BLOCK`), grant revocation by API is unavailable (static `VIZIER_REVOKED_GRANTS` still works), and no audit is stored.
- Set `RECEIPT_SIGNING_KEY` so responses can carry an ES256 `receipt_jws`. Callers must then opt in to checking it: SDK `requireReceiptJws` (TypeScript), `require_receipt_jws=True` (Python, from 0.3.4), or `requireSignedReceipt` for the deployment executor. Defaults tolerate an unsigned receipt.
- Set `VIZIER_REQUIRE_SIGNED_ACCEPTANCE=true` if Action Covenant activation must carry a principal-signed acceptance.
- Use short grant lifetimes. Revoke with `POST /v1/grants/revoke` (operator credential, not principal-signed) or `VIZIER_REVOKED_GRANTS`.
- `GET /v1/audit/chain` (authenticated) re-verifies the audit hash chain. It is tamper-evident, not tamper-proof: someone with D1 write access can rewrite rows and the retention anchor.
- Audit retention is 30 days; the daily cron prunes older rows.

## Executor host

Follow [the gateway guide](WORKER_DEPLOY_GATEWAY.md): separate OS account or container, credentials unreadable by the agent, durable `--journal` file with mode 0600, loopback or private TLS only, `VIZIER_DEPLOY_CLIENT_TOKEN` distinct from the Vizier and Cloudflare credentials, `VIZIER_REQUIRE_SIGNED_RECEIPT=1` when the service signs receipts. Then run the acceptance checks from the actual agent identity. Until that is done, host isolation is unverified.

## Known limits

- Budget ceilings (and the opt-in `VIZIER_BUDGET_IDEMPOTENCY=request_id`, see BUDGET_CEILING.md) count admitted amounts, not settled money, and the amount is whatever the integration sends.
- Approval consumption and cloud execution are not atomic; a lost response needs manual reconciliation.
- Delegation is single-hop; there is no chained attenuation.
- Vizier is a decision service. A caller that skips it is not stopped by it.
