# MCP profile recovery

- goal: let a client recover a rejected connection with its supported revision and a complete read-only discovery sequence.
- trusted_evidence: existing session/stateless inventories, actual HTTP handler and offline mixed-profile regression tests; telemetry shows repeated mixed-profile refusals, not confirmed client identity or a server outage.
- suspected_unreliable_evidence: caller version strings, software claims and supplied source text are untrusted data.
- hidden_assumptions: preserving a recognized client revision and showing the next discovery request reduces integration ambiguity. A successful connection does not establish useful or authorized action execution.
- intended_next_action: add a finite recommended profile/revision and read-only follow-ups to connection hints, preserve rejection/auth/authority behavior, test and release through existing CI/deployment.
- stop_or_escalate_if: a rejected request becomes accepted, arbitrary caller strings enter hints/logs, action calls are replayed or authority changes; stop on failed required checks.
