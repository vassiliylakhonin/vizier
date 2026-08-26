# Security review

Reviewed on 2026-08-26 after adding the private MCP enforcement proxy. This was a source-based
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
| High | A proxy could expose authenticated upstream discovery or tool execution to callers that have no integration authority. | Mitigated for the pilot adapter: every MCP request requires a proxy-specific Bearer token before any body parsing or upstream request. |
| High | A caller could bypass discovery filtering and invoke an unlisted tool directly. | Mitigated: the proxy checks the local tool allowlist before verification and never forwards an unlisted name, even if a verifier is misconfigured. |
| High | Forwarding the inbound Authorization header could leak the proxy credential to the upstream server. | Mitigated: the proxy constructs a fresh header set and uses a separate optional upstream Bearer token. Neither the client token nor the Vizier key is forwarded. |
| Medium | A remote plaintext endpoint or network-bound pilot listener could expose credentials. | Mitigated: the CLI binds only to loopback hosts, and non-loopback Vizier and upstream URLs must use HTTPS. |
| Medium | A malicious upstream could return oversized, deeply nested, or malformed JSON. | Mitigated: request and response bodies are capped at 64 KiB, JSON complexity is bounded, response media type and JSON-RPC ID are validated, and invalid content is replaced with a stable error. |

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
- The MCP proxy is a private one-upstream pilot adapter. It has no durable
  metrics store, streaming support, semantic argument policy, or protection
  against an agent that can reach the upstream service by another route.

Do not treat v0.2 as a complete identity, evidence, or delegation boundary. For a public
pilot, configure `VIZIER_API_KEY`, restrict who can call enforcement endpoints,
configure a separate `RECEIPT_SIGNING_KEY`, add edge rate limiting, and execute
only after a valid, unexpired signed `ALLOW` response.
