# Live Worker deployment demo — 2026-10-13

The maintainer exercised the v0.5.9 adapter candidate against **production
Vizier v0.5.8** and a real disposable Cloudflare Worker. Both signed owner scope
and the separate reviewer protocol were used. The reviewer step was automated
synthetic QA on the owner's authorization; this is not a customer's manual
approval, independent adoption, or proof of adversarial OS containment.

The final successful run completed **8 scenarios** from 11:37 to 11:38 UTC.
Its two authorized deployment POSTs were each confirmed with a read-only GET,
and the Worker served the expected static B response. Each refusal made zero
deployment requests and left the independently read cloud history unchanged.

| Client proposal | Adapter result | Deployment POSTs |
| --- | --- | ---: |
| Change the approved version | Stopped: approval does not bind that request | 0 |
| Select another Worker | Stopped: outside fixed scope | 0 |
| Create a resource | Stopped: unsupported operation | 0 |
| Present an expired signed grant | Stopped: policy BLOCK | 0 |
| Omit human-review approval | Stopped: authorization required | 0 |
| Deploy the exact approved B version | Deployment ID/version/100% confirmed; served B | 1 |
| Replay that consumed approval | Stopped: approval unavailable | 0 |
| Send two concurrent requests with a fresh shared approval | One deployment; one refusal | 1 |

The synthetic client had no secret environment variables and its Node
permissions denied reading cloud credentials and opening a direct network
connection. Signer, reviewer, executor and client ran in separate processes.
The trusted maintainer still held administrator access: this demonstrates the
selected integration path, not a guarantee that an administrator cannot bypass it.

## What the live test caught

v0.5.8 incorrectly expected Cloudflare's richer documented POST response. The
real API acknowledged a committed deployment with only `{id}`. Cloud history
and the served B response confirmed the effect; no POST was retried automatically.
A separately approved return to static A captured the same short response.

The v0.5.9 fix confirms an ID-only acknowledgement through exactly one matching
history row. Absent, duplicate, mismatched or unavailable history remains
unresolved. A captured-response regression failed twice before the fix and
passes afterward. Those two diagnostic deployments precede the final successful
run and are recorded separately in the evidence; they are not hidden as test successes.

## Evidence and cleanup

[Sanitized trace](worker-deploy-live-demo-2026-10-13.json) records timestamps,
compiled adapter SHA-256, review hashes, receipt/deployment IDs, actual outcomes
and cleanup. It contains no signing keys, credentials, grants, approval tokens,
customer inputs or private telemetry. API observations are maintainer evidence,
not a signed independent execution certificate.

The temporary Worker was deleted after capture, and the original inventory of
14 Workers was restored exactly. Its URL is therefore not a continuing demo
service. No production Worker, owner-key registry or deployment workflow was
switched to this adapter.

[Install and reproduce in your own sandbox](WORKER_DEPLOY_PILOT.md) ·
[Request an assisted integration](INTEGRATION_OFFER.md)
