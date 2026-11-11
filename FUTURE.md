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

## Recorded gaps against the per-call authorization literature (2026-11-10)

Two 2026 papers define controls adjacent to Vizier. This section records, from
the current code, what is not done. It follows the rule at the top of this
file: these are documented gaps, not committed work, and each is reconsidered
only when observed production use requires it.

ScopeGate ([arXiv:2606.28679](https://arxiv.org/abs/2606.28679)) describes a
five-stage gate for agent tool calls: scope, authorization, money ceiling,
idempotency, default deny. Against that model:

- Scope, per-call authorization, and default deny are implemented: the
  evaluation kernel never returns `ALLOW` by default, and each call is checked
  against structured authority.
- Money ceiling: implemented locally and opt-in as `constraints.budget`
  (docs/BUDGET_CEILING.md), pending D1 migration 0013 and deploy. Until that
  ships, `max_amount` bounds one proposed call with an exact three-letter
  currency and no cross-call cumulative budget exists. It counts admitted
  spend at ALLOW, not settled spend. The experimental Base native-USDC review reservations add single and daily
  limits for that one workflow only, and their own documentation states they
  are not a complete wallet spending limit.
- Idempotency is not a policy stage. Execution idempotency and duplicate-effect
  prevention remain the integration's responsibility. A single-use grant is
  spent at `ALLOW`; that stops grant replay, not a duplicate executor effect.
- No adversarial bypass suite runs in CI. ScopeGate evaluates its control with
  a 48-vector static bypass suite and a 40-iteration adaptive bypass run.
  Vizier CI runs unit tests, two scripted demos, and an isolation sandbox;
  none of them systematically attempts to circumvent the decision boundary.

AgentCap ([arXiv:2611.00729](https://arxiv.org/abs/2611.00729)) delegates
authority along session-bound parent-child chains that can only attenuate, and
checks the provenance of security-sensitive arguments. Vizier grants are
single-hop: nothing is delegated onward, so there is no chain to attenuate and
no argument-provenance tracking. This is requirement R3 ("Not done") in the
README authorization-requirements table; it is restated here because it is a
deferral, not an oversight.

Response-side filtering is out of scope. DLP screening covers secret and PII
leak categories on verification-request parameters and, in the proxy, on
pre-LLM message content and post-LLM tool-call arguments. Tool outputs and
other content returned to the model are not screened, and model text responses
are not filtered beyond those leak categories. Screening tool results for
injected instructions, or enforcing output policy on model text, would be a
separate component.
