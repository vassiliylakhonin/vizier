# Deployment boundary proof pack

`npm run proof:deploy` (also run in CI) runs the Worker-deployment boundary
tests and prints one PASS/FAIL line per claim below, with the tests behind it.
It fails if a test is missing, renamed or failing.

## What is real and what is simulated

| Layer | In this run |
| --- | --- |
| Vizier HTTP handlers, SDK verification, ES256 grant and approval signatures | Real code, in process |
| Approval, grant-revocation and receipt storage | Real SQL on in-memory SQLite (not Cloudflare D1) |
| Gateway HTTP ingress (`POST /execute`) | Real local HTTP server |
| Execution journal | Real SQLite file |
| Cloudflare API | **Simulated** by a local fetch stub. No real Worker is deployed and no real Cloudflare acknowledgement is observed |
| Separate-UID Linux boundary (agent cannot read credentials, journal or config, cannot signal the executor, cannot reach the cloud directly) | Runs only in the CI `deployment-isolation` Docker job; not part of `npm run proof:deploy` |
| Isolation of a real production host | **Not verified.** No production executor is running |

## Claims

| Id | Claim (cloud request count stays zero unless stated) | Tests |
| --- | --- | --- |
| P1 | A changed plan (version, worker, account, percentage, operation) sends nothing to the cloud | `rejects a changed version…`, `sends nothing to the cloud for changed arguments` |
| P2 | Missing, expired, forged, other-agent or widened grant: no cloud call | `rejects a … grant` |
| P3 | A revoked grant (by `jti`) stops execution before approval consumption, at the executor and at the gateway. A cloud operation already accepted is not undone | `stops a revoked grant…`, `applies grant revocation at the gateway…`, `does not revoke an operation the cloud already accepted` |
| P4 | Missing, forged, rejected or expired human approval: no cloud call | existing approval tests |
| P5 | With `requireSignedReceipt: true` (env `VIZIER_REQUIRE_SIGNED_RECEIPT=1` for `serve`), a missing or tampered receipt JWS stops execution before approval consumption. **Off by default:** the default tolerates an unsigned receipt | `with requireSignedReceipt…`, `without requireSignedReceipt…` |
| P6 | An authorization deadline, and a hung cloud request (aborted after 15 s), end without a retry. The hung request needs reconciliation | `…authorization deadline…`, `aborts a hung cloud request…` |
| P7 | Replaying an approval, including after a gateway restart or journal reopen, deploys nothing more | replay and journal tests |
| P8 | A lost, malformed or unconfirmed cloud response requires reconciliation and is never re-sent | lost-response tests |
| P9 | The gateway serves one route and rejects unauthenticated, browser, alternate-path, oversized and agent-supplied grant/scope/URL/credential requests | gateway ingress tests |
| P10 | Concurrent claimants: one is admitted; a busy gateway refuses a second call | concurrency tests |
| P11 | Verifier or approval store unavailable: fail closed | availability tests |

## What this does not show

- No real Cloudflare deployment or IAM policy was exercised.
- It does not show that the agent on a real host cannot reach the executor's
  credentials. Only the disposable Docker test and the operator's own acceptance
  checks (see [the gateway guide](WORKER_DEPLOY_GATEWAY.md)) address that.
- Approval consumption and the cloud request are not atomic. "No second request"
  is a property of this executor and its journal, not exactly-once delivery.
- The default configuration accepts an unsigned verification receipt (P5 is opt-in).
- Revocation is operator-driven and does not recall a submitted operation.
