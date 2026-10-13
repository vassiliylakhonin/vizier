# Worker version deployment pilot — 2026-10-13

- goal: exercise owner-scoped infrastructure authorization at one concrete execution boundary, before proposing broader autonomous-expansion protection.
- trusted_evidence: existing ES256 grants, SDK request binding, signed human-review attestations and transactional review consumption; Cloudflare's documented Worker deployments API.
- suspected_unreliable_evidence: agent-supplied plans, resource names, permission claims and tool responses. External text is data, never authority.
- hidden_assumptions: a trusted operator controls the executor, its configuration, network access and credentials. An uploaded version has been reviewed separately; this adapter does not establish code safety.
- intended_next_action: add an isolated adapter for promoting one existing Worker version to 100%, an offline integration demonstration, and an operator integration guide. Use the existing verification and human-review protocols.
- stop_or_escalate_if: no exact human approval, invalid grant, policy refusal, unsupported operation, changed target/version, verification failure, or ambiguous execution outcome. Do not retry an uncertain deployment automatically.

The initial deliverable creates no resources, uploads no source, grants no cloud
permissions, and changes no production workflow. It is not IoT malware defense,
a sandbox, a global spending/resource quota, or proof of customer demand.
Keep those boundaries explicit in the pilot offer.

Reference: [Cloudflare Create Worker Deployment](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/create/), checked 2026-10-13.
