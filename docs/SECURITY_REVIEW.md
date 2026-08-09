# Security review

Reviewed on 2026-08-09 before the first deployment. This was a source-based
repository review, not an external penetration test.

## Findings and disposition

| Severity | Finding | Disposition |
| --- | --- | --- |
| High | Public callers could supply their own authority and receive `ALLOW`. | Mitigated: the default mode cannot return `ALLOW`; enforcement requires the configured Bearer credential on REST, A2A, and MCP verification calls. Principal-issued delegation remains a later milestone. |
| Medium | Nested JSON had a byte limit but no depth or aggregate-node limit. | Fixed: requests above 32 levels or 4,096 values are rejected before recursive validation. |
| Medium | The SDK accepted incomplete or inconsistent authorization responses. | Fixed: the SDK validates all response fields, cross-checks policy and receipt fields, and recomputes the request hash. |

The remediations are covered by transport and SDK regression tests. The full
test suite and Cloudflare dry-run build passed after the changes.

## Residual limits

- The Bearer key authenticates an integration, not the principal named in each
  request. Keep the key in a controlled backend and away from the action-taking
  agent.
- Delegated authority is not signed or loaded from a principal-controlled
  policy store.
- Receipts are not persisted or signed.
- Target matching is exact string matching; adapters must supply canonical IDs.
- Rate limiting and production edge access controls are not configured here.

Do not treat v0.1 as a complete identity or delegation boundary. For a public
pilot, configure `VIZIER_API_KEY`, restrict who can call enforcement endpoints,
add edge rate limiting, and execute only after a valid `ALLOW` response.
