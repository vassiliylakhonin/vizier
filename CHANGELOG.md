# Changelog

## Unreleased

- Add structured request-class telemetry, crawler/discovery assets, ownership metadata, canonical MCP aliases, and a non-executing capability response for `GET`/`HEAD /mcp`.
- Run independent circuit-breaker, sanctions and quorum lookups concurrently before deterministic verification to reduce I/O tail latency without changing policy results.

## 0.5.5 — 2026-09-24

- Add a reviewer-only, read-only wallet-history diagnostic for an already configured Base wallet. It uses the same bounded native-USDC collector as financial submissions and returns an explicit non-authorization result without creating a review or changing policy.
- Make Base RPC requests compatible with Cloudflare Workers and use a fixed public BlockPI endpoint after Base's public endpoints returned HTTP 429 from production. A live 45,001-block finalized native-USDC scan completed; unavailable or incomplete evidence still blocks financial reviews. The owner policy remains disabled.
- Bind DLP receipts to the scanned input and clarify the scope of playground evaluations.
- Keep playground metadata and code tabs inside the viewport on narrow screens.

## 0.5.4 — 2026-09-23

- Collect conservative finalized native-USDC history directly from the fixed public Base RPC before financial review submission. A 50-subrequest bound, 1,000-block log ranges, anchor verification and D1 trigger combine observed spending with concurrent review holds; unavailable or incomplete evidence blocks without a reservation.
- Persist the observation and anchor alongside the reservation. This remains review-queue accounting, not pending-transfer detection or wallet-wide authorization; the owner policy stays disabled.

## 0.5.3 — 2026-09-23

- Store the official address snapshot in D1 through the existing deployment credential, replacing the CI KV write that lacked permission. Retry the live check during edge propagation.

## 0.5.2 — 2026-09-23

- Require a fresh official OFAC SDN exact-address snapshot on Base native-USDC review submission, approval and claim. A scheduled sync writes the validated XML-derived snapshot to KV; absent, stale or matching data blocks. This is not comprehensive sanctions clearance or wallet-wide spend accounting.

## 0.5.1 — 2026-09-23

- Parenthesize `CASE` expressions in financial D1 triggers so remote Cloudflare migration parsing succeeds. No policy defaults or runtime contract changes.

## 0.5.0 — 2026-09-23

- Atomically reserve reviewer-configured Base native-USDC workflow budgets alongside human reviews; recheck limits at approval and consumption. No default financial policy.
- Retain claimed holds through expiry, expose reviewer cancellation before claim, and verify exact finalized Base transactions before settling or releasing reverted transfers.
- Add console controls, REST discovery, SDK reconciliation, mandatory financial audit events and extended retention for unresolved claims.
- Limits cover this queue only, not out-of-band wallet spending. See [financial reservations](docs/FINANCIAL_RESERVATIONS.md).

## 0.4.0 — 2026-09-21

- Add an explicit administrative human-review queue, separate reviewer credential, signed five-minute attestations and atomic one-time D1 claims.
- Add `/reviews`, REST discovery and SDK submission/verified-claim helpers.
- Declare the seven-day retention exception for opt-in review payloads.

## v0.3.0 — 2026-09-07

Authority can now be proved instead of asserted.

### Added

- **Delegation grants.** A request may carry `grant`: a compact JWS
  (`typ: vizier-delegation+jws`, ES256) signed by the principal, binding one
  `authority` to one agent for a bounded window. Vizier verifies it against a
  public key registered for that principal and records the result in the
  receipt. `docs/DELEGATION_GRANTS.md`.
- `VIZIER_PRINCIPAL_KEYS`: JSON mapping a principal id to one ES256 public JWK
  or an array of them, so a principal can rotate. Optional — grants are opt-in.
- `receipt.authority_provenance` (`principal_signed` | `trusted_integration` |
  `unverified`) and, for a verified grant, `receipt.grant` with `jti`, `issuer`,
  `subject`, `key_id` and `expires_at`.
- `scripts/mint-grant.mjs`: `keygen` generates a principal key pair and prints
  the public half to register; `sign` mints a grant. The private key never
  reaches the service. A test mints through this CLI and verifies through the
  kernel, so the two cannot drift.
- `GET /docs` reports `delegation.registered_principals` and
  `delegation.principal_keys_valid`, so a misconfigured registry is visible
  without sending a request through.
- 35 tests, most of them adversarial: forged signatures, an impostor reusing a
  registered `kid`, `alg: none`, unregistered principals and key ids, expiry and
  not-yet-valid windows, audience/issuer/subject mismatches, a private key
  registered by mistake, and a property check that no unverifiable grant can
  ever produce `principal_signed` provenance.

### Changed

- `verifyAction` accepts `principalKeys` and `audience`. `createReceipt` takes a
  provenance argument, kept out of `ReceiptOptions` so a caller cannot assert
  its own provenance.
- Threat model: the trust-boundary and known-limits sections now separate what a
  grant closes from what it does not — no revocation store, no way to *require*
  a grant per principal, and no proof of intent or of key possession.
- `FUTURE.md` records why principal-signed delegation left the deferred list.

### Security properties

- A grant that fails any check is `BLOCK` and never falls back to the
  caller-asserted path. Failing it open would make a forged grant strictly
  better for an attacker than sending none.
- The request's `authority` must canonicalise identically to the signed one, so
  a genuine grant beside a widened authority is `BLOCK`, not an allow at the
  larger limit.
- Claims are read before verification only to resolve the signing key.
- The decoded grant payload is complexity-bounded before it is parsed; the
  encoded token is capped at 8 KiB at the schema boundary.
- Keys are registered out of band and never fetched at decision time: the
  authorization kernel still makes no outbound request.
- An unparseable `VIZIER_PRINCIPAL_KEYS` yields an empty registry — every grant
  refused, requests without grants still served.

### Compatibility

`/v1/verify` requests without `grant` behave exactly as in v0.2.2, including
policy results and reason codes. Receipts gain `authority_provenance`; the
response contract, the SDK schema, and the OpenAPI document were updated
together, and the contract-drift test enforces that.

## v0.2.2 and earlier

See the git history and `docs/ADR-0001-ACTION-COVENANTS.md`.
