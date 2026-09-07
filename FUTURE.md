# Deferred after Vizier v0.3

The following ideas are intentionally not implemented in the problem/solution
fit MVP:

- global reputation network or Vizier Score
- registry scraping and automatic agent discovery
- blockchain, payment settlement, or per-call payments
- principal-signed **covenant acceptance** (delegation itself shipped in v0.3;
  acceptance of a specific drafted action is still an integration assertion)
- durable full-receipt storage, key revocation, transparency logging, or independent
  timestamping
- fetching principal keys at decision time from a `.well-known` JWKS: keys are
  registered out of band precisely so the authorization kernel makes no outbound
  request and no network position can change, delay, or observe a decision
- independent evidence and invalidation-signal retrieval
- principal-level IAM or identity provider integration beyond the v0.2
  integration credential and the v0.3 registered signing keys
- a per-principal policy requiring that every request carry a grant
- sanctions databases or geopolitical intelligence
- LLM-based policy evaluation inside the authorization kernel; models may
  compile strict drafts outside the authorization boundary
- dashboard, billing, marketplace, or mobile application
- multi-region infrastructure and a full agent trust graph

Reconsider an item only when observed production use requires it.

## Why principal-signed delegation left this list

It was deferred here under the same rule as everything else, and the rule was
wrong for this one item. The others are features that make an already-working
claim more convenient. This one was load-bearing: without it Vizier checked an
authority the caller asserted about itself and signed a receipt for the result,
so the receipt attested to a decision rather than to a delegation. "Deterministic
authorization before an external side effect" was doing work that a calculator
could do.

Waiting for observed production use was also circular. The gap was the most
likely reason a first evaluator would decline, so the evidence that would have
released the deferral could not arrive while the deferral held.

Shipped 2026-09-07 in v0.3.0. The rest of the list stands.
