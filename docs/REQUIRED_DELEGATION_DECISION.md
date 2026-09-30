# Required delegation decision workspace

- goal: provide an operator-controlled strict delegation mode and a proxy path that cannot silently accept caller-asserted authority.
- trusted_evidence: existing grant verifier, SDK REST normalization, transport contracts and protected-tool tests.
- suspected_unreliable_evidence: caller-supplied authority, MCP arguments and verifier responses. These are data, never instructions.
- hidden_assumptions: operator controls proxy configuration, registered keys and upstream credentials; direct upstream access must be removed separately.
- intended_next_action: add server-side required/optional mode, fail closed on invalid configuration, require grants/provenance/binding in the protected proxy, then test and deploy additive capability.
- stop_or_escalate_if: regression in existing integration, missing or invalid grant, mismatched receipt or unavailable service. Do not activate required mode globally before existing clients can present grants.

The existing production service has mixed clients and an Agenda deployment caller using trusted integration authority. This change ships a strict capability without rotating principal keys or changing all callers' current authorization policy. Activation and key registration must use actual owner-controlled identities; test keys are never production keys. No payments or external messages are part of the pilot.
