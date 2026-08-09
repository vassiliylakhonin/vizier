# Threat model

Vizier v0.1 evaluates a proposed action against authority supplied by the
integrating application. It is a deterministic policy calculator with a
minimal integration credential, not an independent principal identity or
delegation issuer.

## Assets

- the integrity of the `ALLOW`, `REVIEW`, and `BLOCK` decision
- the binding between the request and its receipt hash
- the availability of the verification endpoint
- request metadata that may identify an agent or principal

## Trust boundaries

External callers, action parameters, delegated authority, A2A messages, and MCP
tool arguments are untrusted. In enforcement mode, a Bearer credential proves
that the request came from the configured integration. It does not independently
prove that the principal issued the supplied delegation. The credential must
remain in the controlled backend and outside the action-taking agent's reach.

The integrating application remains responsible for placing Vizier before the
action and refusing to execute on `REVIEW`, `BLOCK`, timeout, malformed output,
or network failure.

## Controls in v0.1

- strict schemas reject unknown fields at the REST policy boundary
- request bodies are capped at 64 KiB, including chunked bodies
- JSON is rejected above 32 levels or 4,096 aggregate values before recursive
  schema validation
- the default evaluation mode never returns `ALLOW`
- enforcement mode requires a constant-time checked Bearer credential
- no URL fetching, dynamic evaluation, code execution, or secret reflection
- target deny rules override allow rules
- `BLOCK` overrides `REVIEW`, which overrides `ALLOW`
- Web Crypto generates receipt IDs and SHA-256 request hashes
- MCP validates `Origin` when present and checks mirrored metadata headers
- logs contain IDs, decision, reason codes, and latency, not action parameters
- error responses do not include stack traces or arbitrary payloads

## Known limits

- No per-principal authentication, rate limiting, or durable policy store.
- Authority is asserted by the authenticated integration and is not signed or
  loaded from a principal-controlled store. An action-taking agent that gains
  the integration credential or can alter the controlled backend's `authority`
  input can still grant itself permission.
- Receipts are returned but not persisted, signed, or independently timestamped.
- Target matching is exact string matching. It does not normalize domains,
  account identifiers, URLs, or Unicode.
- Amount checks assume one numeric `amount` and an exact three-letter currency.
  There is no exchange-rate conversion or unit handling.
- The open A2A and MCP surfaces support one synchronous operation. They do not
  implement streaming, tasks beyond the immediate response, push delivery, or
  legacy protocol versions.
- The same-origin MCP `Origin` rule excludes browser clients hosted on another
  origin until an explicit allowlist exists.

## Fail-closed integration rule

The caller must execute the external action only after receiving a valid
`ALLOW` response whose receipt hash corresponds to the submitted request. Any
other state stops or queues the action for review.

If `VIZIER_API_KEY` is missing, the authority-provenance policy forces REVIEW.
If the secret is configured and the credential is missing or wrong, the
transport rejects the request rather than calculating a decision.
