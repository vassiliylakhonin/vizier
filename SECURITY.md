# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.5.x | Yes |
| < 0.5.0 | No |

This table describes the Worker/service release line. SDKs have independent versions; the Python SDK is currently 0.3.x.

## Reporting a Vulnerability

Please do **not** open a public issue for an undisclosed vulnerability. Use [GitHub Security Advisories](https://github.com/vassiliylakhonin/vizier/security/advisories) or [vassiliylakhonin@gmail.com](mailto:vassiliylakhonin@gmail.com), the primary security contact. Include affected versions, the interface and configuration, required privileges and minimal reproduction. We aim to acknowledge receipt within 48 hours and provide an estimated remediation timeline.

## System and Scope

The owned Worker, deterministic kernel, REST/MCP/A2A transports, model proxy, grants, covenants, human review and financial reservations, API-key administration, D1/KV state, TypeScript/Python clients, private MCP proxy, deployment adapters and release/deployment tooling are in scope. Test actual route and mode behavior rather than assuming transport parity or tenant isolation from the presence of an API key.

Untrusted callers control request bodies, evidence, authority assertions and protocol metadata. Operators control service/reviewer credentials, registered principal keys, signed-grant policy and upstream/deployment scope. A caller assertion is not authenticated principal delegation. The integrating application owns action enforcement unless it uses an operator-controlled executor as the agent's sole action capability.

## Security Objectives

These are properties to assess, not a claim that every execution path already enforces every property:

1. **Authorization before execution:** The deterministic kernel must preserve BLOCK-over-REVIEW-over-ALLOW aggregation. Executors must stop on REVIEW/BLOCK, invalid authorization and failed required checks. Distinguish authorization-state failures from best-effort operational logging.
2. **Authority and request binding:** Verify registered-key grants, exact authority, subject/principal, expiry and configured mode. Unset signed-grant mode is optional and supports trusted-integration assertions; do not describe it as mandatory principal-signed authorization.
3. **Receipt integrity:** Preserve canonical request digests. Distinguish legacy hash records from ES256 attestations; verify signed issuer, audience, request hash and expiry where required.
4. **Approval and replay protection:** Bind approvals/quorum to the exact action and reject consumed or expired authorizations. Assess storage atomicity and lifetime in the actual D1, KV or process-local implementation; a status marker alone does not establish distributed exactly-once execution.
5. **Destination and credential isolation:** Restrict proxy destinations to authorized HTTPS origins, reject redirects, block prohibited literal destinations and keep integration credentials out of upstream headers. Assess DNS/network assumptions separately from hostname validation.
6. **Data isolation and privacy:** Protect administrative review payloads/tokens, financial state, tenant key/quota data, operator-only state and private signing keys. Operational audit rows are metadata-oriented; administrative reviews also persist canonical request payloads and approval tokens.
7. **Browser credentials:** Keep playground credentials transient; do not persist them in localStorage or sessionStorage.
8. **Privileged adapters:** Keep upstream/Cloudflare credentials and fixed scope operator-owned; require exact principal-signed provenance and human approval where the adapter contract requires them. Handle uncertain external acknowledgements by reconciliation rather than automatic mutation retry.

## Reportability and Assessment Context

Meaningful bypasses, cross-caller state/data access, payment or approval abuse, unintended privileged execution, credential leakage, unsafe upstream access and supply-chain failures are reportable. Calibrate severity to the additional capability, reachable asset and prerequisites. An authenticated integration's documented assertion capability is not by itself principal-key compromise; deployment administrators already possess separate platform authority.

No new finding classes or accepted risks are excluded by this policy. Differences between REST and MCP/A2A enrichment, global versus tenant-scoped state, best-effort audit persistence and quorum/DNS assumptions must remain visible review questions, not assumed guarantees or suppression authority.

See [.oss-scanner/threat_model.md](.oss-scanner/threat_model.md) for source-backed boundaries. Tests, signatures and scanner enrollment are not a security certification.
