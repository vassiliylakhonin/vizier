# Budget ceiling

Status: implemented locally, opt-in, not deployed. Needs D1 migration
`0013_budget_ledger.sql` before it can run in production.

## The problem

`max_amount` bounds one proposed call. Nothing bounds the sum. An agent that is
allowed 4,000 USD per purchase and calls ten times has spent 40,000 USD, and
every call was ALLOW. FUTURE.md and THREAT_MODEL.md recorded this as "money
ceiling is not a policy stage".

## Design

The principal signs a budget inside the grant's authority:

```json
"constraints": {
  "budget": { "id": "q4-procurement", "ceiling": 10000,
              "currency": "USD", "actions": ["purchase"] }
}
```

Vizier keeps a running total per `(principal, budget id)` and refuses a call
that would take the total past the ceiling.

1. **Check before admission.** The kernel reads the ledger before it decides.
   `spent + requested > ceiling` is `BLOCK` / `BUDGET_CEILING_EXCEEDED`, with the
   ceiling, spent and requested amounts in the policy result.
2. **Claim atomically after ALLOW.** The amount is added with one conditional
   `UPDATE ... WHERE spent + amount <= ceiling`. A concurrent call that lost
   the race re-runs the kernel against the fresh ledger and gets `BLOCK`, never
   a second `ALLOW`. This is the same shape as single-use grant consumption.
3. **Unknown price is not zero.** If the call carries no readable `amount`, a
   non-number, a negative number, or a different currency, it is
   `BLOCK` / `BUDGET_UNPRICED` with `unpriced: true, coverage: "partial"`. The
   ledger is not touched, so the running total does not include that call:
   a total reported next to unpriced refusals is a partial one.
4. **A raised ceiling does not reset spending.** The ledger key is the principal
   and the budget `id`, not the grant. A new grant with the same `id` and a
   higher ceiling continues the same total. A new `id` is a new budget, and
   only the principal can sign one.
5. **Only signed authority is budgeted.** Without a verified grant, a caller
   could name a fresh budget id on every call. A budgeted request without a
   grant is `BLOCK` / `BUDGET_REQUIRES_GRANT`.
6. **Fail closed.** No D1, or a ledger read error, is
   `BLOCK` / `BUDGET_STATE_UNAVAILABLE`. A missing table is never read as zero
   spent. A currency that differs from the one the ledger first saw is
   `BUDGET_CURRENCY_CONFLICT`.
7. **Scope.** Only action types listed in `budget.actions` are counted. Other
   allowed actions are not touched by the budget.

Amounts are held as integer micro-units so addition is exact. A spend rounds up
and a ceiling rounds down, so rounding never favours the agent. The ceiling is
capped at 1,000,000,000 units. The ledger stores a SHA-256 of
`principal \n budget id`, a currency, two integers and a timestamp; no
principal, agent or action data. The ceiling is not stored. It comes from the
signed grant on each call.

Evaluation-only paths read the ledger but never claim.

If a single-use grant loses its consumption race after the budget was claimed,
the claim is released.

## Idempotency and the payment adapter (opt-in)

Set `VIZIER_BUDGET_IDEMPOTENCY=request_id` (needs migration 0015). A budgeted
request that carries `context.request_id` is then counted once: a repeat with
the same id and the same agent, action type and parameters is not added again,
and stays allowed if the first one filled the ceiling. The same id with
different content is `BLOCK` `BUDGET_REQUEST_ID_CONFLICT`. Without the option
every call counts, as before. Idempotency covers 30 days of ids. Counting
happens before the id is recorded, so a crash between the two over-counts a
retry rather than letting it through uncounted.

The TypeScript `guardPayment` adapter builds the evaluated amount and currency
from the call that reaches the executor and passes your idempotency key as the
request id. The server does not verify the price: it trusts what the
integration reports, and it does not know what was settled.

## Limits

- The ledger records what was **admitted** at ALLOW, not what the executor
  settled. A failed or cancelled execution is not refunded. A caller that
  repeats the same ALLOWed request is charged again: there is no idempotency
  stage (see FUTURE.md).
- The amount is whatever the caller puts in `parameters.amount`. Vizier checks
  it is a number in the signed currency. It cannot know the true cost of the
  call. An integration that prices from the real executor call (like the typed
  `guardBanAccount` adapter does for its parameters) is still required.
- Currency conversion is not done. One budget has one currency.
- Ledger rows are never pruned, because pruning would reset a total. They are
  small; growth is one row per budget.
- There is no read endpoint for remaining headroom yet, and no TS or Python SDK
  type for `budget`. A caller can send it as a raw authority field.
- Not an enforcement point by itself: it holds only if the integration refuses
  to execute without `ALLOW`.

## Source of the idea

The semantics (check before spending, a typed refusal, unknown cost is not
zero cost, raising a limit keeps the accounting) were prompted by the usage
limit design in the OpenGeni project's `docs/session-usage-limits.md`
(github.com/Cloudgeni-ai/opengeni, Apache-2.0). Their design bounds model
spend per session tree on Postgres. This one is written independently for
signed grants on Cloudflare D1, and no code was copied.
