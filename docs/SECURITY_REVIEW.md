# Security review

Reviewed on 2026-08-24 after adding Action Covenants. This was a source-based
repository review, not an external penetration test.

## Findings and disposition

| Severity | Finding | Disposition |
| --- | --- | --- |
| High | Public callers could supply their own authority and receive `ALLOW`. | Mitigated: unauthenticated calls cannot return `ALLOW`; REST and MCP enforcement require the configured Bearer credential, while A2A exposes a separate anonymous evaluation lane that forces untrusted authority. Principal-issued delegation remains a later milestone. |
| Medium | Nested JSON had a byte limit but no depth or aggregate-node limit. | Fixed: requests above 32 levels or 4,096 values are rejected before recursive validation. |
| Medium | The SDK accepted incomplete or inconsistent authorization responses. | Fixed: the SDK validates all response fields, cross-checks policy and receipt fields, and recomputes the request hash. |
| Medium | A malformed signing secret could create an unnoticed downgrade to an unsigned Agent Card. | Fixed: a configured but invalid key fails the discovery endpoint; the matching JWKS exposes only the public key. |
| High | A model-produced draft could be mistaken for delegated authority. | Mitigated: a draft cannot activate unless the authenticated integration supplies an acceptance from the same principal bound to the exact draft hash; the default core authorization context is untrusted. Principal-signed acceptance remains deferred. |
| High | A decision receipt could be changed or replayed for another action. | Mitigated for the covenant path: compact ES256 JWS binds issuer, covenant, complete request, exact action, evidence, signals, decision, rules, and expiry. The SDK verifies the signature and all hashes through same-origin JWKS. Legacy `/v1/verify` receipts remain unsigned. |
| Medium | Execution could succeed without durable post-execution proof. | Partially mitigated: the executor records a signed outcome and reports `outcome_unrecorded` as a distinct failure state. Vizier still trusts the executor's report and does not persist it. |

The remediations are covered by transport and SDK regression tests. The full
test suite and Cloudflare dry-run build passed after the changes.

## Residual limits

- The Bearer key authenticates an integration, not the principal named in each
  request. Keep the key in a controlled backend and away from the action-taking
  agent.
- Delegated authority and covenant acceptance are not signed by the principal or
  loaded from a principal-controlled policy store.
- Covenant authorization and outcome receipts are signed but not persisted or
  independently timestamped. Legacy verification receipts remain unsigned.
- The integration supplies evidence, invalidation signals, and outcomes; Vizier
  binds them but cannot establish their truth or completeness.
- The Agent Card and covenant receipts use separate keys and protected types.
  Neither authenticates a principal.
- Target matching is exact string matching; adapters must supply canonical IDs.
- Rate limiting and production edge access controls are not configured here.

Do not treat v0.2 as a complete identity, evidence, or delegation boundary. For a public
pilot, configure `VIZIER_API_KEY`, restrict who can call enforcement endpoints,
configure a separate `RECEIPT_SIGNING_KEY`, add edge rate limiting, and execute
only after a valid, unexpired signed `ALLOW` response.
