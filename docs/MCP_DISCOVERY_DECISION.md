# MCP profile discovery and Python session negotiation

- goal: make the connection lifecycle explicit before the first POST, and prevent the Python stdio adapter from negotiating a stateless revision through initialize.
- trusted_evidence: owner-labelled live initialize matrix succeeds for ordinary session requests, while mixed protocol metadata reproduces 400 unsupported_version and 404 profile_method_mismatch. New HTTP discovery and Python negotiation regressions fail before the change. Official MCP SDK documentation separates initialize-based revisions through 2025-11-25 from stateless 2026-07-28, which starts with server/discover.
- suspected_unreliable_evidence: 311 unsigned_external initialize refusals count requests, not users or a server outage. The archive does not contain payloads or evidence that our flat inventory caused those requests.
- hidden_assumptions: publishing complete profile sequences reduces ambiguity for future integrations; an observed benefit must be checked after release. The local Python adapter is a different implementation from the hosted HTTP service.
- intended_next_action: publish the same read-only connection guide through GET /mcp and the probing document, reusing error recovery's single inventory. Correct the Python adapter's session revision set and fallback, test and release through existing CI and deployment.
- stop_or_escalate_if: mixed-profile requests become accepted, protected actions are retried, runtime authorization changes, raw client strings enter discovery, required checks fail, or absent registry credentials are treated as publication success.

Sources: https://ts.sdk.modelcontextprotocol.io/v2/protocol-versions and https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle (read 23 October 2026).
