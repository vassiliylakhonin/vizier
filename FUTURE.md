# Deferred after Vizier v0.3

The following ideas are intentionally not implemented in the problem/solution
fit MVP:

- global reputation network or Vizier Score
- registry scraping and automatic agent discovery
- blockchain, payment settlement, or per-call payments
- durable full-receipt storage, key revocation, transparency logging, or independent
  timestamping
- fetching principal keys at decision time from a `.well-known` JWKS: keys are
  registered out of band precisely so the authorization kernel makes no outbound
  request and no network position can change, delay, or observe a decision
- independent evidence and invalidation-signal retrieval
- principal-level IAM or identity provider integration beyond the v0.2
  integration credential and the v0.3 registered signing keys
- a per-principal selective policy requiring grants (deployment-wide required mode shipped in v0.5.6)
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

## Principal-signed covenant acceptance

Shipped as opt-in. Add `acceptance_jws` (typ `vizier-covenant-acceptance+jws`,
ES256, payload `{iss, draft_hash, accepted_at}`) to the activation request. Vizier
verifies it against the key registered for the principal in
`VIZIER_PRINCIPAL_KEYS`, requires `iss`, draft hash and `accepted_at` to match the
request, and records `acceptance_proof` (key id and the token) inside the
covenant, so it is covered by `covenant_hash`. Set
`VIZIER_REQUIRE_SIGNED_ACCEPTANCE=true` to refuse unsigned acceptances. Without
that setting the old integration-asserted acceptance still works and nothing
changes for existing callers. Sign with
`node scripts/mint-grant.mjs accept --key principal.jwk.json --principal <id> --draft-hash <hex>`.

Limits: a signature proves the key holder accepted that draft hash, not that a
human read it. The same signed acceptance can activate the same draft more than
once, producing separate covenants.
