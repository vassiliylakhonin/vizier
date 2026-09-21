# Changelog

## Unreleased

## 0.3.1 — 2026-09-21

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
