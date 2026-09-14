# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3.0 | :x:                |

## Security Invariants

Vizier enforces the following critical security invariants across all execution paths:

1. **Fail-Closed Execution**: If any verification rule, policy evaluation, schema validation, network call, or human-in-the-loop webhook fails, errors, or times out, the proposed action is blocked (`decision: BLOCK`).
2. **Deterministic Kernel**: Policy evaluation does not use probabilistic LLM-in-the-loop decisions for authorization.
3. **Cryptographic Integrity & Tamper Evidence**: All decisions produce canonical SHA-256 request digests and optional asymmetric ES256 JWS signed receipts.
4. **Single-Use Quorum Proposals**: Quorum authorizations are strictly bound to the action hash and cannot be reused or replayed after execution (`PROPOSAL_ALREADY_CONSUMED`).
5. **SSRF & Credential Isolation**: Transparent AI proxy restricts destinations to authorized upstream origins, rejects private/link-local/cloud metadata networks, disallows HTTP redirects, and isolates client Vizier credentials from upstream providers.

## Reporting a Vulnerability

If you discover a potential security vulnerability in Vizier, please do **NOT** open a public issue.

Instead, please report security issues responsibly:
- **Maintainer**: Contact the maintainer directly via GitHub Security Advisories at [https://github.com/vassiliylakhonin/vizier/security/advisories](https://github.com/vassiliylakhonin/vizier/security/advisories) or [vassiliylakhonin@gmail.com](mailto:vassiliylakhonin@gmail.com).
- Include detailed steps to reproduce, relevant payload examples, and affected versions.
- We will acknowledge receipt of your report within 48 hours and provide an estimated timeline for remediation.
