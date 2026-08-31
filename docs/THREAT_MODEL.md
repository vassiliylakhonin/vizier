# Threat model

Vizier v0.2 evaluates a proposed action against authority, covenant evidence,
and invalidation signals supplied by the integrating application. It is a
deterministic authorization and receipt-signing service with a minimal
integration credential, not an independent principal identity, delegation
issuer, evidence oracle, or execution observer.

## Assets

- the integrity of the `ALLOW`, `REVIEW`, and `BLOCK` decision
- the binding between the request and its receipt hash
- the availability of the verification endpoint
- request metadata that may identify an agent or principal
- the confidentiality and integrity of metadata retained in D1
- the private Agent Card signing key
- the private authorization and outcome receipt signing key
- the binding from accepted draft to covenant, exact action, authorization, and
  reported outcome

## Trust boundaries

External callers, drafts, action parameters, delegated authority, evidence,
invalidation signals, outcomes, A2A messages, and MCP tool arguments are
untrusted. In enforcement mode, a Bearer credential proves
that the request came from the configured integration. It does not independently
prove that the principal issued the supplied delegation. The credential must
remain in the controlled backend and outside the action-taking agent's reach.

A draft marked `MODEL` is still untrusted data. The model cannot activate it:
activation requires an acceptance naming the same principal and the exact draft
hash over an authenticated integration. In v0.2 this acceptance is an integration
assertion, not a principal signature.

The integrating application remains responsible for placing Vizier before the
action and refusing to execute on `REVIEW`, `BLOCK`, timeout, malformed output,
or network failure.

## Runtime controls

- strict schemas reject unknown fields at the REST policy boundary
- request bodies are capped at 1 MiB, including chunked bodies
- JSON is rejected above 64 levels or 50,000 aggregate values before recursive
  schema validation
- the default evaluation mode never returns `ALLOW`
- enforcement mode requires a constant-time checked Bearer credential
- anonymous A2A calls remain evaluation-only even when enforcement is configured;
  a supplied invalid credential is rejected
- no URL fetching, dynamic evaluation, code execution, or secret reflection
- target deny rules override allow rules
- `BLOCK` overrides `REVIEW`, which overrides `ALLOW`
- Web Crypto generates receipt IDs and SHA-256 request hashes
- the public Agent Card carries an A2A v1 `signatures[]` ES256 JWS; its protected `jku`
  resolves to the matching same-origin JWKS
- Action Covenant resources are unavailable in evaluation mode and fail closed
  when either enforcement or receipt signing is not configured
- a covenant hash binds the complete accepted draft and activation envelope
- exact canonical action equality narrows the existing delegated-authority check
- evidence observations are bounded and checked for presence, type, future time,
  and maximum age
- invalidation matching is bounded to shallow primitive exact equality; it does
  not execute expressions, regex, paths, code, or model calls
- authorization and outcome receipts use compact ES256 JWS with separate
  protected `typ` values and a dedicated signing key
- the SDK verifies each signed receipt with the same-origin JWKS and recomputes
  every material hash before returning it
- outcome recording accepts only a valid `ALLOW` receipt and verifies that
  execution started before authorization expiry
- exact forbidden-effect rules produce a signed `VIOLATION` rather than hiding
  the reported outcome
- a malformed configured signing key fails the discovery request instead of
  silently returning an unsigned Agent Card
- MCP validates `Origin` when present and checks mirrored metadata headers
- logs contain IDs, decision, reason codes, and latency, not action parameters
- D1 stores bounded operational metadata and hashes, not action parameters,
  targets, agent or principal IDs, evidence, signals, outcome effects, JWS
  tokens, credentials, or signing material
- D1 writes run after the response through `waitUntil()` and cannot turn a
  decision fail-open or fail-closed
- audit insights require configured enforcement plus the correct Bearer token
  and are validated by the SDK against a strict response contract
- a daily scheduled handler removes audit metadata older than 30 days across
  verification, covenant, authorization, and outcome tables
- the repository check applies the ordered migrations to in-memory SQLite and
  asserts that legacy payload-bearing columns are absent
- error responses do not include stack traces or arbitrary payloads
- the private MCP proxy requires its own Bearer token for tool calls, replaces
  it with a separate upstream credential, and never forwards the Vizier key
- the MCP proxy publishes only configured upstream tools, binds the complete
  tool arguments into the verification request, and forwards only on `ALLOW`
- malformed or oversized upstream JSON is rejected instead of reflected to the
  client
- the proxy returns its own minimal `server/discover` response rather than
  reflecting authenticated upstream discovery metadata

## Known limits

- No per-principal authentication, rate limiting, durable policy/evidence store,
  or full-receipt store.
- Authority is asserted by the authenticated integration and is not signed or
  loaded from a principal-controlled store. An action-taking agent that gains
  the integration credential or can alter the controlled backend's `authority`
  input can still grant itself permission.
- Legacy `/v1/verify` receipts remain unsigned. Complete covenant receipts and
  JWS tokens remain caller-held and are not independently timestamped; D1 keeps
  only selected receipt metadata and hashes.
- D1 metadata writes are asynchronous and best-effort. Insights can undercount,
  provide no per-integration attribution, and must not be treated as a complete
  audit ledger or adoption proof. Retention is time-based; selective deletion
  for one integration or data subject is not implemented because those
  identifiers are intentionally not stored.
- The integration can fabricate an acceptance, evidence observation,
  invalidation feed, or outcome because Vizier does not retrieve or observe any
  of them independently. Hashes prove binding and tamper evidence, not truth.
- The signal list is supplied per authorization. Absence of an invalidating
  signal does not prove that no invalidating event exists.
- Forbidden outcomes use exact effect type and optional exact target matching.
  They cannot express arbitrary semantic harm or prove that the executor reported
  every effect.
- Receipt verification trusts the configured Vizier origin and its JWKS. There
  is no transparency log, external timestamp authority, or key revocation store.
- Agent Card signing proves control of its signing key and detects card changes.
  It does not authenticate callers, principals, delegations, or receipts.
- Target matching is exact string matching. It does not normalize domains,
  account identifiers, URLs, or Unicode.
- Amount checks assume one numeric `amount` and an exact three-letter currency.
  There is no exchange-rate conversion or unit handling.
- `action.is_reversible` is supplied by the authenticated integration and is
  not independently established. Requiring review for an omitted or false value
  is a policy guardrail, not proof that a true value is correct.
- The open A2A and MCP surfaces support one synchronous operation. They do not
  implement streaming, tasks beyond the immediate response, push delivery, or
  legacy protocol versions.
- The same-origin MCP `Origin` rule excludes browser clients hosted on another
  origin until an explicit allowlist exists.
- The local gated-deploy wrapper is bypassable by any process that can invoke
  Wrangler with the user's Cloudflare credentials. It is a valid enforcement
  point only when an action-taking agent receives the wrapper capability but no
  general shell or Cloudflare credential access.
- The local MCP proxy is bypassable if the agent can reach the upstream MCP URL,
  obtain the upstream or Vizier credential, or invoke an equivalent tool through
  another transport. Its tool-name allowlist does not impose semantic argument
  constraints beyond the current Vizier policy schema; the receipt binds the
  supplied arguments but does not prove they are safe.
- The proxy supports one stateless HTTP upstream and non-streaming JSON
  responses capped at 1 MiB. It is not a multi-tenant gateway and does not
  persist per-integration usage metrics.
- Embedded callers can inject a verifier, network client, and log sink. The CLI
  uses the validating Vizier SDK, refuses redirects, and constrains destinations;
  another embedding must reproduce those controls.

## Fail-closed integration rule

The legacy caller must execute only after a valid `/v1/verify` `ALLOW` whose
receipt hash corresponds to the request. A covenant caller must additionally
verify the signed authorization, exact bindings, and expiry, then record the
reported outcome. Any other state stops or queues the action for review.

If `VIZIER_API_KEY` is missing, the authority-provenance policy forces REVIEW.
If the secret is configured, REST and MCP reject a missing or wrong credential.
A2A treats a missing credential as evaluation-only and rejects a supplied wrong
credential. In every transport, only the correct credential can reach `ALLOW`.
Action Covenant resources do not have this evaluation lane: missing enforcement
or receipt signing configuration returns an error and cannot activate or
authorize a covenant.
