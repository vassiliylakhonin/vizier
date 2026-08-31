# Validation metrics

The v0.2 product question remains whether developers put Vizier before actions
that their agents actually execute. Action Covenant completion and signed
outcomes are instrumentation, not independent demand evidence.

The primary metric is verified agent actions per day. Sign-ups and one-off curl
requests do not answer the question.

The first independent learning test is defined in [PILOT.md](PILOT.md). Its
decision uses qualified integrations, repeated machine calls on separate days,
and retention in the normal execution path. Registry probes and conformance
scores are discovery signals, not adoption metrics.

The founder-supplied problem/solution fit targets are:

- 10 independent production integrations
- at least 5 still active after 30 days
- more than 10,000 authorization calls per day
- repeated machine-generated calls
- at least 2 users willing to pay

No target has been achieved or tested. The Worker now keeps a durable,
metadata-only operational audit and exposes authenticated aggregate counts at
`GET /v1/insights`. It records decision/lifecycle metadata and hashes, not full
requests, identities, targets, evidence, effects, tokens, or secrets. Because
writes run asynchronously and may fail, these counts are not a complete ledger.
Counting unique agents, repeat use, and calls per integration still requires an
explicit authenticated integration ID before a public pilot. The store retains
30 days, so `/v1/insights` is a rolling operational window rather than a
lifetime counter.

The private MCP proxy now emits an operator-supplied integration ID with request
ID, tool name, decision, reason codes, receipt ID, outcome, and latency. It does
not persist or aggregate those events. Until an independent participant uses the
proxy in an existing action path, these fields are instrumentation capability,
not usage evidence. The Worker-level audit cannot attribute them to a particular
proxy integration.

The first internal test is 5–10 clean Git deployments routed through the full
activation, authorization, execution, and outcome lifecycle in
`npm run deploy:gated`. One bootstrap deployment and repeated deployments made
only to increase the counter do not count as product evidence. The test is
useful only if the gate remains in the normal path during actual repository
changes.

## Observed internal use

On 2026-08-09, the first gated deployment completed from Git commit `6fbf77d`.
Vizier returned `ALLOW`, and Cloudflare created Worker version
`954622cc-7251-4fa7-b820-0a5293f1066d`. This is internal dogfood. It is not an
independent integration, customer pilot, or market validation.
