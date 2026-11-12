# Changelog

## Unreleased

- Deployment proof pack: `npm run proof:deploy` (also in CI) maps 11 boundary claims to named tests (changed arguments, revoked/expired/missing grant, missing or tampered receipt JWS, hung or lost cloud response, restart and replay) and states that Cloudflare is simulated. New opt-in `requireSignedReceipt` for the Worker-version deployer (`VIZIER_REQUIRE_SIGNED_RECEIPT=1` for `serve`); the default still tolerates an unsigned receipt. Hung cloud requests are tested as aborted without retry. Docs: DEPLOY_PROOF_PACK.md, PRODUCTION_PROFILE.md; WORKER_DEPLOY_GATEWAY.md no longer says there is no revocation store (revocation by jti applies at executor and gateway; operator-driven; cannot recall a submitted operation). Production host isolation remains unverified.
- Budget idempotency (opt-in, needs D1 migration 0015 `budget_admissions`, applied by the Deploy workflow): with `VIZIER_BUDGET_IDEMPOTENCY=request_id`, a repeated `context.request_id` for the same action is counted once (a retry of an admitted request stays `ALLOW` even at the ceiling); the same id with a different agent, action type or parameters is `BLOCK` `BUDGET_REQUEST_ID_CONFLICT`. Keys are SHA-256 digests, rows pruned after 30 days. Default behaviour is unchanged. TypeScript SDK: new `guardPayment` adapter takes amount and currency from the call that reaches the executor. The server does not verify the price and counts admitted, not settled, amounts.
- No-contact demand measurement (opt-in, off unless `VIZIER_ACTIVITY_KEY` is set; D1 migration 0016 `integration_activity`): per signed-grant principal, a daily row keyed by an HMAC of the verified grant issuer with two counters. No principal, agent, request id, action, target or amount is stored; rows pruned after 35 days; `VIZIER_ACTIVITY_EXCLUDE` marks own/CI principals. `GET /v1/insights/funnel` (integration credential) returns counts only against the 3 integrations / 2 repeat threshold. Failures never change a decision. See docs/DEMAND_MEASUREMENT.md for blind spots.
- Audit chain fixes (D1 migration 0014 `audit_chain_anchor`; deployed automatically by the Deploy workflow). Reproduced first with failing tests, then fixed: (1) concurrent `storeReceipt` calls could link to the same predecessor and fork the chain; the append is now a conditional insert on the chain head with retry (up to 8 attempts; if all lose, the receipt is not stored and the failure is logged). (2) Retention pruning deleted the oldest receipts, so the first retained row failed verification with `PREV_MISMATCH` without any tampering; pruning now records the hash it cut the chain at and `GET /v1/audit/chain` starts from it. (3) Chain order is now insertion order (rowid) rather than `created_at`, so clock skew between isolates no longer breaks verification. Tests: `tests/audit-chain.test.ts`. Limits unchanged: an operator with D1 write access can still rewrite rows and the anchor; deleting the newest rows is not detectable. Prune is skew-sensitive only if a retained row was inserted before a pruned one (not tested). Docs: README R7 and THREAT_MODEL (grant revocation exists, operator-driven).
- Python SDK: `vizier_guard`, `VizierLangChainToolGuard` and `VizierCrewAIToolGuard` accept `grant=` (a string or a callable) and forward it to the service, so they can get `ALLOW` from a required-grant deployment. The grant is configuration only and is never read from tool parameters. Previously these wrappers sent no grant and could not pass a required-grant service. Tests: `packages/python-sdk/tests/test_grant_forwarding.py`. Ships with `vizier-guard` 0.3.4 (not yet published).
- Python SDK `vizier-guard` 0.3.4: opt-in `require_receipt_jws=True` on `verify()` (and `AsyncVizierClient.verify()`), matching the TypeScript `requireReceiptJws`. A response without `receipt_jws` raises `VizierError(code="RECEIPT_SIGNATURE_REQUIRED")` instead of being trusted unsigned; the option implies `request_receipt_jws=True`. A present JWS is still verified as before (`RECEIPT_SIGNATURE_INVALID` on tamper). Default behavior is unchanged. Python-only release: the npm packages and the Worker stay at 0.5.17. `check()` / `authorize`-style helpers do not take the option yet.

- Release acceptance for published clients: CI's published-package first-BLOCK step now installs npm `0.5.17` and PyPI `vizier-guard[receipts]==0.3.3` and runs the signed-receipt walkthrough (ES256 verification, tampered receipt refused, missing JWS refused via `requireReceiptJws`) plus the hash-only mode, replacing the old `0.5.16` / `0.3.2` hash-only pins. The first-BLOCK demo client now also fault-injects a stripped `receipt_jws`. Docs (README, FIRST_BLOCK, both SDK READMEs, AUTHORIZATION_QUICKSTART, TRUST_QUESTIONS, anonymous path evidence) updated to the published state, including that the Python client has no `require_receipt_jws` and tolerates an absent JWS.

## 0.5.17 — 2026-11-12

- Cumulative budget ceiling (opt-in, needs D1 migration 0013). New authority constraint `budget { id, ceiling, currency, actions }` in a principal-signed grant: Vizier sums admitted spend per (principal, budget id) in a new `budget_ledger` table, checks it before deciding, and claims the amount atomically after `ALLOW`, so concurrent calls cannot share the last headroom. New `BLOCK` reason codes: `BUDGET_CEILING_EXCEEDED`, `BUDGET_UNPRICED` (unreadable cost is refused, not counted as zero), `BUDGET_REQUIRES_GRANT`, `BUDGET_STATE_UNAVAILABLE` (no D1 or ledger error fails closed), `BUDGET_CURRENCY_CONFLICT`. A new grant with the same budget id and a higher ceiling continues the same total. The ledger records admitted, not settled, spend and does not refund failed executions. See docs/BUDGET_CEILING.md. Idea credit: OpenGeni session usage limits (Apache-2.0); independent implementation.

- SDK source: add typed TypeScript `scanNumericConsistency`, Python sync/async `scan_numeric_consistency`, and opt-in `numeric_consistency` authority constraints (including Python `check`). Scan receipts remain opaque; this does not change signed verification receipts or publish a package release.

- Numeric consistency preflight. New opt-in check `numeric_consistency: true` in authority constraints and a matching anonymous `POST /v1/numeric-consistency/scan` endpoint (text or structured parameters, optional signed clearance receipt with scope `numeric_consistency_scan_only`). The check extracts labeled numeric mentions from a text (English/Russian labels, decimal comma, markdown tables), then reports `metric_conflict` when one metric carries two different current values and `derived_value_mismatch` when a stated upside percentage does not match the value recomputed from the document's own target and current prices within the rounding tolerance implied by how the percentage was written. The "from" side of an explicit revision ("raised from $93 to $101" / "повышена с $93 до $101") is treated as superseded history, never as a current value; a conflicting value equal to a superseded one is flagged as a likely stale copy. In `/v1/verify` the new `quality.numeric_consistency` policy rule routes to `REVIEW` / `NUMERIC_INCONSISTENCY`, never `BLOCK`: which value is right is a human call. This is an internal-consistency heuristic over labeled numbers, not a fact check, and it is opt-in so existing requests are unaffected. Motivating case: a broker report whose header moved to target $101 / +13% while its metrics table still showed the old $93 / -5%.

- MCP transport: stop refusing measured external callers at the protocol boundary. `initialize` / `notifications/initialized` that mirror a revision into `params._meta` are now answered on the session profile (with the mirrored revision negotiated when it is one this endpoint answers) instead of `profile_method_mismatch`; the stateless profile accepts every published revision mirrored in `_meta` + headers, not only `2026-07-28`, instead of `unsupported_version`; and the session profile answers any dated `MCP-Protocol-Version` header, rejecting only values that name no revision at all. Telemetry had 335 stateless `unsupported_version` and 164 `profile_method_mismatch` external refusals with zero later successes. Unknown revisions are still refused with the bounded connection hint, hints still never echo caller text, and enforcement authentication is unchanged.

- Tests: pin the OAE task-detail approval/result contract captured against `812af3f` in a shared validator used by the opt-in live probe and offline regression tests. Changed field sets, types, decision/state pairs or digest linkage fail with `OAE_TASK_DETAIL_CONTRACT_DRIFT`. Replay covers the five recorded consumer outcomes; mutation tests prove drift failures. Ordinary CI remains offline and does not watch upstream OAE. The scope gate and executor remain mocks.

- Docs: record in FUTURE.md and the threat model what Vizier does not do against the per-call authorization literature: money ceiling and idempotency as policy stages, an adversarial bypass suite in CI (ScopeGate five-stage model, arXiv:2606.28679), response-side filtering beyond the DLP leak categories, and chained delegation with monotonic attenuation and argument provenance (arXiv:2611.00729, already README requirement R3). Statuses are derived from current code; nothing here is a commitment to build.

- Hash-chained audit receipts. Stored verification receipts now carry `receipt_hash` (SHA-256 over the canonical metadata row) and `prev_receipt_hash` (migration 0012), so modification, insertion, reordering, or deletion of a chained row that still has a chained successor breaks verification. `GET /v1/audit/chain` (authenticated, D1 required) recomputes the chain and reports the first broken link. The chain is best-effort single-writer: concurrent writes can fork it, which verification reports rather than hides; rows written before migration 0012 are skipped as legacy, and a silent deletion of the newest rows is not detectable without an external anchor.

- README: add an authorization-requirements coverage table mapping the seven structural requirements of arXiv:2609.15906 to what Vizier does and does not do, including chained delegation with monotonic attenuation and argument provenance (AgentCap direction) as not done.

- SDK: opt-in typed ban-account guard (`guardBanAccount`). It wraps an executor so the evaluated action (target, `is_reversible`, parameters) is derived from the actual executor call, and the executor runs only after `authorize()` establishes an ALLOW; a refusal propagates as a `VizierError` and nothing executes. Reversibility and the action type are pinned once per integration, not per call, so a call site cannot ask Vizier about one account and ban another. Defaults and callers that do not opt in are unchanged.

- SDK: opt-in `requireReceiptJws` on `verify()` and `authorize()`. A response without `receipt_jws` then throws `RECEIPT_SIGNATURE_REQUIRED` instead of being trusted unsigned, and the option implies the `X-Vizier-Receipt: jws` request header. The default behavior is unchanged. `risk_score` gains weights for `GRANT_REQUIRED`, `GRANT_POLICY_MISCONFIGURED` (0.5 each) and `IRREVERSIBLE_ACTION_REVIEW` (0.3), so a BLOCK no longer reports a zero score on those paths; the score remains diagnostic and decisions are unchanged.

- Single-use grants fail closed without D1. An enforcing transport (REST, MCP, A2A) with no D1 binding now answers `BLOCK` / `GRANT_SINGLE_USE_STATE_UNAVAILABLE` for a grant signed `single_use: true` instead of consuming it in per-isolate memory, which a restart or a second isolate could silently replay. The per-isolate memory fallback for single-use consumption is removed. Evaluation-only paths never consumed and are unchanged, reusable grants are unaffected, and the D1-backed semantics (spend at `ALLOW`, then `GRANT_ALREADY_USED`) are unchanged.

- Python SDK: `VizierClient.verify()` / `AsyncVizierClient.verify()` verify a returned `receipt_jws` against the published JWKS (ES256, signs the exact returned receipt) and raise `RECEIPT_SIGNATURE_INVALID` on failure; absence is tolerated. New `request_receipt_jws=` argument sends `X-Vizier-Receipt: jws`. Verification uses the new optional extra `vizier-guard[receipts]` (`cryptography`); a signed response without it fails closed (`RECEIPT_VERIFICATION_UNAVAILABLE`). Core install stays dependency-free. Python has no `authorize()`; this applies to `verify()`.

- Docs: add the worked example "Vizier + OAE: signed human approval by email before an agent action" and the anonymous path evidence (playground, missing-grant BLOCK, 401 without token; checked 2026-11-09).

- `/examples` no longer promises ALLOW to anonymous callers. Fields are now `expected_decision_with_valid_grant`; the allow scenario adds the anonymous required-mode outcome (BLOCK, GRANT_REQUIRED) and a top-level note. Renamed from `expected_decision`.

- SDK `authorize()` now sends `X-Vizier-Receipt: jws` and verifies a returned `receipt_jws` (ES256, `application/vizier-receipt+jwt`) against the published JWKS, checking it signs the exact returned `receipt`. Failure throws `RECEIPT_SIGNATURE_INVALID`; an absent `receipt_jws` is tolerated. `verify()` verifies it whenever it is present. `VerifyOptions.requestReceiptJws` opts `verify()` into requesting it.

- `runCovenantGatedDeploy` takes an optional `signAcceptance` callback that signs the exact draft hash (`acceptance_jws`). The gated-deploy CLI enables it with `VIZIER_ACCEPTANCE_KEY` (path to the principal's ES256 JWK). Without it, acceptance stays an integration assertion and a service with `VIZIER_REQUIRE_SIGNED_ACCEPTANCE=true` refuses activation.

- Add opt-in principal-signed covenant acceptance: `acceptance_jws` on covenant activation, verified against `VIZIER_PRINCIPAL_KEYS`, recorded as `acceptance_proof` inside the hashed covenant; `VIZIER_REQUIRE_SIGNED_ACCEPTANCE=true` makes it mandatory. `scripts/mint-grant.mjs accept` signs it. The SDK schema accepts the new optional fields and includes the proof in its covenant hash check. Unsigned acceptance and existing covenant hashes are unchanged.

- Add grant lifecycle. Revocation: `POST /v1/grants/revoke` (D1, migration 0011) and the `VIZIER_REVOKED_GRANTS` secret produce `BLOCK` / `GRANT_REVOKED` in REST, MCP and A2A. Single-use: a grant signed with `single_use: true` is consumed by its first `ALLOW` (atomic D1 insert) and later presentations return `GRANT_ALREADY_USED`. `scripts/mint-grant.mjs` and `mintDelegationGrant` accept the flag. Grants without it behave as before. Consumption happens at `ALLOW`, not on execution success.

- Add opt-in `receipt_jws` to authenticated `/v1/verify` responses (request header `X-Vizier-Receipt: jws`, receipt signing key configured; opt-in so strict-schema SDK clients are unaffected). The SDK response schema now tolerates the optional field. It is an ES256 compact JWS (`typ application/vizier-receipt+jwt`) over the exact returned receipt, verifiable with the published JWKS. The unsigned `receipt` field is unchanged; anonymous `/v1/verify/evaluate` is never signed.

- Put a runnable synthetic MCP check and its stateless request beside the public connection instructions.

- Add a runnable synthetic missing-grant example to the A2A card and public playground. The example always runs without trusted authority and cannot authorize an action.

- Add search metadata, a canonical URL and MCP connection instructions to the public authorization playground.

- Describe the A2A authorization decision record in terms of policy and delegated authority for catalog discovery.

- Classify GET/HEAD MCP discovery as HTTP metadata rather than RPC actions. Add bounded correction hints for unsupported revisions, profile/method mismatches and invalid JSON-RPC requests; preserve refusals and explicit read-only recovery.

- Move the read-only daily wallet monitor to a fixed PublicNode Base endpoint and reduce its complete finalized-day scan from 48 to nine requests. Preserve bounded retries, log/finality validation, failed observations, and disabled policies; interactive admission and outcome verification retain their existing BlockPI path.

## 0.5.16 — 2026-10-30

- Normalize npm command paths for the MCP proxy and gated deployment packages.

## 0.5.15 — 2026-10-30

- Publish the SDK `authorize` helper for principal-signed, request-bound decisions; REVIEW, BLOCK and missing or expired authority stop the caller. The helper does not execute actions or independently verify the unsigned legacy receipt.
- Add explicit anonymous evaluation metadata, privacy-bounded MCP correlation and safer connection guidance.

- Add a dependency-free Node 24 MCP connection example with explicit session/stateless profiles. Check the advertised revision, complete the corresponding read-only lifecycle and stop on errors without action calls, automatic retries, credentials or server-directed requests. Execute both profiles against the real HTTP handler in CI; server authorization and npm packages are unchanged.

## 0.5.14 — 2026-10-27

- Release the three Node packages together with the linear-time SDK URL normalization fix and Zod 4.6.7 dependency update. Pin the MCP proxy and gated deployment adapter to the corrected SDK.
- Align hosted discovery metadata, package versions and installation examples at 0.5.14. Registry test fixture isolation and URL compatibility regressions are included; Python SDK version and authorization behavior are unchanged.

## Code scanning maintenance — 2026-10-27

- Replace the SDK constructor's trailing-slash regex with a backward scan and one slice. Preserve blank-input errors and existing normalization, including internal/encoded slashes, relative inputs and surrounding whitespace. Isolate long-input regression probes in bounded child processes so a slow constructor cannot block the test runner.
- Replace the Registry test's generated JavaScript data URL with a fixed preloader receiving JSON over stdin. Preserve the dry-run publication boundary and status handling; verify code-like metadata remains data. The previous literal-encoded mock did not establish a code-injection boundary. No query suppression or alert dismissal is added; published npm packages require a separate release.

## Dependency maintenance — 2026-10-27

- Refresh Wrangler/workerd and workers-types together, regenerate Worker runtime types and update typescript-eslint. Preserve the stale-type CI gate that caught the incomplete Wrangler-only update.
- Pin Zod 4.6.7 in all Node workspaces and resolve patched Undici 7.30.1 through Wrangler 4.153.0. Allow future Zod minor-update proposals, retaining the major-update guard. Check early rejection of oversized bounded response collections and existing policy/transport contracts. Published npm tarballs are unchanged until a separate package release.
- Distinguish repeated acyclic object references from active-ancestor cycles after Zod parsing. Preserve canonical bytes and count every JSON-expanded occurrence against the existing node/depth limits; continue rejecting real cycles and excessive alias expansion.

## 0.5.12 — 2026-10-23

- Recommend a supported MCP profile/revision after a connection refusal, preserving a recognized client revision. Include complete read-only session/stateless discovery follow-ups; never automatically replay tools, weaken protocol refusal or change authority. Keep guidance free of arbitrary client strings.

## OSS Scanner preparation — 2026-10-20

- Add a source-built Docker audit environment, offline verification commands and a source-backed security threat model. Keep production releases, credentials and deployment behavior unchanged. Enrollment remains subject to maintainer approval and Anthropic review; preparation is not a completed audit or security certification.

## 0.5.11 — 2026-10-19

- Return executable, read-only tool discovery after an unknown tool name in either MCP profile. Publish the finite method inventory for each profile; never replay a tool call or weaken protocol, credential or authority checks. Verify the released standard session and stateless flows before attributing invalid probes to an outage. Node source/workspace versions advance together; existing npm 0.5.10 clients remain compatible.

## npm distribution — 2026-10-18

- Publish the three Node packages under the owned `@agenda-intelligence` npm organization: `vizier-sdk`, `vizier-mcp-proxy`, and `vizier-gated-deploy`. The unavailable `@vizier` namespace remains only in historical GitHub release archives. Update imports, exact workspace dependencies, CLI examples and release checks together; executable names and hosted API behavior are unchanged.

## 0.5.10 — 2026-10-18

- Return executable read-only connection recovery requests for both MCP profiles. Record a bounded, self-declared software family for recurring profile mismatches; preserve protocol refusal, authentication and authorization.

- Distinguish caller-asserted principals from integration assertions and signed delegation. Keep anonymous checks non-authorizing and preserve valid-grant/trusted-integration decisions. Publish action routing inside the existing policy details, preserving released SDK response validation.

- Measure the selected MCP profile and bounded header/body revision categories without retaining arbitrary client revisions or request text. Unknown protocols remain refused.

- Use provider-safe `access_mode` for content-free access categories; historical transformed authorization labels remain unknown.

- Emit bounded content-free access observations for MCP discovery, tool calls, HTTP refusals and protocol errors. Keep existing audit storage, authorization and review contracts unchanged.

## 0.5.9 — 2026-10-13

- Fix the live Cloudflare deployment response boundary: its POST can return only
  `{id}`, so confirm that ID against one exact version/percentage history row
  through a read-only GET. Keep uncertain/mismatched history unresolved and never
  repeat the deployment POST automatically.
- Return a known deployment ID with an unresolved outcome for reconciliation.
- Capture the real response shape in a regression fixture and cover missing,
  mismatched, ambiguous and unavailable history with real authorization/review
  handlers. The published example response had incorrectly suggested that the
  POST always returned the full deployment.

## 0.5.8 — 2026-10-13

- Add an operator-owned Worker version-deployment adapter with owner-signed scope,
  exact human approval, transactional claim, fixed Cloudflare endpoint and
  explicit recovery after uncertain execution outcomes.
- Ship the deployment adapter, CLI and synthetic preparation fixtures as a
  third installable GitHub Release archive alongside SDK and MCP proxy.
- Publish the integration guide and scoped paid-integration offer in the README
  and machine-readable guidance. Update onboarding links to the custom domain
  and distinguish unsigned verification receipts from signed review tokens.
- Exercise real SDK/HTTP authorization and local review storage in 44 offline
  cases; Cloudflare is simulated. No external adoption or live pilot is claimed.

## 0.5.7 — 2026-10-09

- Publish the actual signed-grant policy in both MCP discovery profiles, tool metadata and public /docs, with synthetic inputs and owner setup steps. Explain anonymous evaluation, integration credentials and principal delegation separately; invalid operator policy stays fail-closed.
- Correct registry credential guidance; an API key does not substitute for a signed principal grant. No authorization decisions, grants, receipts or enforcement rules change.

## Unreleased

- Add explicit hosted MCP and pinned stdio-bridge connection guidance, distinguish the Python helper catalog and receipt limitations, and declare the Glama maintainer. Runtime authorization and package versions are unchanged.

- Recognize an already-published registry-only revision during automatic deployment only when its complete metadata matches the source manifest, including endpoint and authorization header semantics. Keep mismatched metadata and Registry outages distinct from success.

- Move the hosted MCP Registry remote and public website metadata to vizier.agendamcp.dpdns.org. Publish a registry-only revision while keeping service/package versions, signing keys, authorization and workers.dev compatibility.

- Make playground guidance reflect required, optional or invalid signed-grant policy. Explain GRANT_REQUIRED without implying that an amount within caller-declared limits authorizes an action; preserve every policy result, decision and receipt.
- Repair a JavaScript interpolation in the LangChain Python example that prevented the initial editable preset and snippets from loading. Exercise the served browser script and anonymous strict-mode response.

- Patch development-tool dependencies: pin Miniflare's sharp to 0.35.5 and
  refresh brace-expansion 5.0.12 and source-map-js 1.2.2 in the lockfile.
  Keep Wrangler and Miniflare versions unchanged; no authorization policy change.

- Retry failed daily wallet observations at 03:47 and 04:07 UTC before the
  scheduled check; skip complete observations from today's primary window.
  Extra crons do not prune, enable financial policy or authorize spending.

- Pace scheduled finalized Base wallet-history scans in single-request batches with 2 s pauses, including bounded transient retries, after Worker requests reproduced BlockPI rate limiting. Preserve the complete day, 48-request baseline and two-call reserve; retain interactive request concurrency. Persist only fixed failure categories and safe RPC method/numeric error codes for daily monitor diagnosis.

- Publish a complete MCP outputSchema for vizier_verify_action, including policy results, authority provenance and optional signed-grant receipt fields. Validate real verification output and malformed response controls.


## 0.5.6 — 2026-09-30

- Add operator-controlled `VIZIER_SIGNED_GRANT_MODE=required` across REST/MCP/A2A verification; missing grants block, invalid configuration blocks even valid grants. Default remains optional for existing integrations.
- Prevent covenant authorization from bypassing strict mode: the legacy covenant contract has no grant field, so strict deployments block it rather than silently accepting asserted authority.
- Add protected MCP proxy grants and receipt provenance, identity, expiry and exact-request binding checks. CLI reads an operator-owned grant file for every tool call, with bounded reads and no token forwarding upstream.
- Add end-to-end signed tool-call, missing/expired/widened grant, invalid policy, transport and downgrade tests. Strict mode activation requires registered owner keys and migration of existing callers; this release does not silently activate it globally.

## Previous unreleased changes

- Clarify the anonymous A2A evaluation-only boundary on the card and add a copy-paste SendMessage example in the card extension. No enforcement decision logic changed.

- Add structured request-class telemetry, crawler/discovery assets, ownership metadata, canonical MCP aliases, and a non-executing capability response for `GET`/`HEAD /mcp`.
- Emit request telemetry as indexed JSON objects and distinguish owner synthetic runs, benchmarks, service probes, browsers, and unsigned callers.
- Refresh the Workers compatibility date to 2026-09-27 after validating the full suite against the current runtime contract.
- Run independent circuit-breaker, sanctions and quorum lookups concurrently before deterministic verification to reduce I/O tail latency without changing policy results.
- Reduce the 24-hour Base history scan from 50 to 48 external RPC requests by using BlockPI's 1,024-block public log range. Add a daily read-only Worker Cron observation and a scheduled drift check; monitoring never authorizes spending.
- Retry transient Base RPC envelope, 429, and 5xx failures using at most two spare calls across the full scan; repeated failures still block without reserving funds.
- Fetch independent Base evidence concurrently and scan log ranges in bounded batches of six, preserving the 48-request baseline and two-call retry reserve while reducing sequential RPC stages from 48 to 11.

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
