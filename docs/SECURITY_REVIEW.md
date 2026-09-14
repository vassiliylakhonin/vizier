# Security review

Reviewed on 2026-08-31 after adding D1 audit instrumentation and action
reversibility. This was a source-based repository review, not an external
penetration test.

## Findings and disposition

| Severity | Finding | Disposition |
| --- | --- | --- |
| High | Public callers could supply their own authority and receive `ALLOW`. | Mitigated: unauthenticated calls cannot return `ALLOW`; REST and MCP enforcement require the configured Bearer credential, while A2A exposes a separate anonymous evaluation lane that forces untrusted authority. Principal-issued delegation remains a later milestone. |
| Medium | Nested JSON had a byte limit but no depth or aggregate-node limit. | Fixed: requests above 64 levels or 50,000 values are rejected before recursive validation. |
| High | A 100 MiB JSON cap could exhaust the Worker's 128 MiB memory because encoded chunks, joined bytes, decoded text, and the parsed graph coexist. | Fixed: Worker and proxy bodies are capped at 1 MiB, including chunked bodies, before parsing. |
| High | The first D1 schema retained full verification requests and outcome effects, including arbitrary tool arguments and possible secrets. | Fixed by migration `0002`: the audit adapter stores bounded metadata and hashes only; parameters, targets, identities, evidence, signals, effects, tokens, and signing material are excluded. |
| Medium | `/v1/insights` accepted evaluation mode and its SDK method trusted arbitrary successful JSON. | Fixed: the endpoint requires configured enforcement and a valid Bearer token, appears in OpenAPI/discovery, and the SDK validates a strict aggregate contract. |
| Medium | Audit metadata had no bounded retention or executable migration regression check. | Fixed: a daily scheduled handler deletes rows older than 30 days, and `npm run check` applies the ordered migrations to seeded in-memory SQLite and asserts that sensitive legacy columns are absent. |
| Medium | The SDK accepted incomplete or inconsistent authorization responses. | Fixed: the SDK validates all response fields, cross-checks policy and receipt fields, and recomputes the request hash. |
| Medium | A malformed signing secret could create an unnoticed downgrade to an unsigned Agent Card. | Fixed: a configured but invalid key fails the discovery endpoint; the matching JWKS exposes only the public key. |
| High | A model-produced draft could be mistaken for delegated authority. | Mitigated: a draft cannot activate unless the authenticated integration supplies an acceptance from the same principal bound to the exact draft hash; the default core authorization context is untrusted. Principal-signed acceptance remains deferred. |
| High | A decision receipt could be changed or replayed for another action. | Mitigated for the covenant path: compact ES256 JWS binds issuer, covenant, complete request, exact action, evidence, signals, decision, rules, and expiry. The SDK verifies the signature and all hashes through same-origin JWKS. Legacy `/v1/verify` receipts remain unsigned. |
| Medium | Execution could succeed without durable post-execution proof. | Partially mitigated: the executor records a signed outcome and reports `outcome_unrecorded` as a distinct failure state. Vizier still trusts the executor's report; D1 retains only bounded outcome metadata and a hash, not independent execution proof. |
| High | A proxy could expose authenticated upstream discovery or tool execution to callers that have no integration authority. | Mitigated for the pilot adapter: every MCP request requires a proxy-specific Bearer token before any body parsing or upstream request. |
| High | A caller could bypass discovery filtering and invoke an unlisted tool directly. | Mitigated: the proxy checks the local tool allowlist before verification and never forwards an unlisted name, even if a verifier is misconfigured. |
| High | Forwarding the inbound Authorization header could leak the proxy credential to the upstream server. | Mitigated: the proxy constructs a fresh header set and uses a separate optional upstream Bearer token. Neither the client token nor the Vizier key is forwarded. |
| Medium | A remote plaintext endpoint or network-bound pilot listener could expose credentials. | Mitigated: the CLI binds only to loopback hosts, and non-loopback Vizier and upstream URLs must use HTTPS. |
| Medium | A malicious upstream could return oversized, deeply nested, or malformed JSON. | Mitigated: request and response bodies are capped at 1 MiB, JSON complexity is bounded, response media type and JSON-RPC ID are validated, and invalid content is replaced with a stable error. |

## September 14, 2026 Review (Post-v0.3 Surface Hardening)

Reviewed after the introduction of the Transparent AI Proxy, Quorum Gate, Multi-Tenant API Keys, and Webhook HITL.

| Severity | Finding | Disposition |
| --- | --- | --- |
| Critical | Transparent proxy streaming (`stream: true`) bypassed post-LLM tool call inspection (DLP, sanctions, quorum, circuit breaker). | Fixed: streaming is rejected with `400 streaming_tools_unsupported` whenever tools or functions are configured; pure text streams return with `X-Vizier-Status: STREAMING_UNINSPECTED_OUTPUT`. |
| Critical | Quorum approvals could be replayed across different actions or parameters because the proxy checked only proposal approval status without binding action hashes. | Fixed: the transparent proxy computes the SHA-256 hash of the tool action (`fnName` + parameters) and rejects mismatches with `403 QUORUM_ACTION_MISMATCH`. Expired proposals are rejected with `403 PROPOSAL_EXPIRED`. |
| Critical | Webhook HITL handler in Python SDK failed open on non-JSON or HTML 200 HTTP responses. | Fixed: strict fail-closed parsing requiring schema-valid JSON object with boolean `approved: true`. Any parsing error or non-JSON body yields `approved=False`. |
| High | Transparent proxy accepted arbitrary caller-controlled `X-Upstream-Url` and leaked inbound Vizier tenant Bearer credentials to upstream servers. | Fixed: destination URLs are validated against authorized HTTPS origins (`api.openai.com` and configured allowlists); loopback/private destinations are blocked; client `Authorization` headers are never forwarded upstream. |
| High | Multi-tenant "monthly" API key quotas were monotonic lifetime counters that never reset. | Fixed: added migration `0005_api_keys_quota_period.sql` tracking `period_month` (`YYYY-MM`). Rollovers reset effective usage to zero and increments update atomically. |
| Medium | Live playground returned 401 Unauthorized in production deployments when calling `/v1/verify` without credentials. | Fixed: added safe evaluation route `/v1/verify/evaluate` (with anonymous rate limiting and no audit log writes) and added API key storage to the playground interface. |
| Low | License mismatch between root MIT license and Python SDK `pyproject.toml` (Apache-2.0). | Fixed: aligned Python SDK package metadata and classifiers to MIT. |

The remediations are covered by transport and SDK regression tests. The full
test suite and Cloudflare dry-run build passed after the changes.

## Residual limits

- The Bearer key authenticates an integration, not the principal named in each
  request. Keep the key in a controlled backend and away from the action-taking
  agent.
- Delegated authority and covenant acceptance are not signed by the principal or
  loaded from a principal-controlled policy store.
- Complete covenant authorization and outcome receipts remain caller-held and
  are not independently timestamped. D1 persists selected metadata and hashes;
  legacy verification receipts remain unsigned.
- The integration supplies evidence, invalidation signals, and outcomes; Vizier
  binds them but cannot establish their truth or completeness.
- The Agent Card and covenant receipts use separate keys and protected types.
  Neither authenticates a principal.
- Target matching is exact string matching; adapters must supply canonical IDs.
- Rate limiting and production edge access controls are not configured here.
- Audit metadata uses 30-day time-based retention and asynchronous writes can
  undercount. There is no per-integration selective deletion because integration
  identifiers are not stored; `/v1/insights` remains operational
  instrumentation, not a complete ledger or adoption proof.
- The MCP proxy is a private one-upstream pilot adapter. It has no durable
  metrics store, streaming support, semantic argument policy, or protection
  against an agent that can reach the upstream service by another route.

Do not treat v0.2 as a complete identity, evidence, or delegation boundary. For a public
pilot, configure `VIZIER_API_KEY`, restrict who can call enforcement endpoints,
configure a separate `RECEIPT_SIGNING_KEY`, add edge rate limiting, and execute
only after a valid, unexpired signed `ALLOW` response.
