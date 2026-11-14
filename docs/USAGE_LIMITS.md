# Per-window usage bounds (aggregation bounds, first step)

Authorization requirement R4 asks that cumulative use be bounded, not only
each call. Vizier already bounds one call (`max_amount`) and cumulative spend
with no time bound (`budget`). Usage bounds close the gap between them:
at most this many calls and/or this much cumulative amount per principal per
time window.

This is a first step, not the full requirement. It bounds the number and
total admitted price of calls. It is not information-flow tracking: it does
not measure what a call read, returned, or caused, and it does not relate use
back to an originating task scope.

## Constraint

`usage` sits in `authority.constraints`, inside the principal-signed grant:

```json
{
  "usage": {
    "id": "support-bot-daily",
    "window_seconds": 86400,
    "max_calls": 100,
    "max_amount": 250,
    "currency": "USD"
  }
}
```

- `id` scopes the counter; together with the principal id it forms the
  ledger key (stored only as a SHA-256 digest).
- `window_seconds` is a fixed tumbling window aligned to the Unix epoch
  (60 to 31622400). Windows are not sliding: counters reset when the window
  rolls over.
- `max_calls` and/or `max_amount` — at least one is required.
  `max_amount` requires `currency` and prices each call from
  `action.parameters.amount` and `action.parameters.currency`, like the
  budget ceiling.

## Enforcement

Counters live in D1 (`usage_ledger`, migration 0017), one row per
(usage key, window start). The check runs in the same deterministic policy
evaluation as every other constraint, and the claim after `ALLOW` is a single
atomic conditional `UPDATE`, so two concurrent calls cannot share the last
headroom. A losing race re-runs the kernel against the fresh ledger and gets
a `BLOCK` rather than a second `ALLOW`.

- A `usage` constraint without a verified grant is refused
  (`USAGE_REQUIRES_GRANT`): unsigned authority could name a fresh id on every
  call and never reach a bound.
- Without the D1 binding, or when the ledger cannot be read, the request
  fails closed (`USAGE_STATE_UNAVAILABLE`).
- A call whose cost cannot be read is refused (`USAGE_UNPRICED`) and does not
  consume from the window; unknown cost is not zero cost, so amount coverage
  is partial in the same way as the budget ceiling.
- The ledger records admitted, not settled, calls and amounts. It does not
  refund failed executions.
- Exceeded bounds are `BLOCK` with `USAGE_CALL_LIMIT_EXCEEDED` or
  `USAGE_AMOUNT_LIMIT_EXCEEDED`; the receipt records the decision like any
  other. `USAGE_CURRENCY_CONFLICT` refuses a window whose first admitted call
  used a different currency.
- A new grant with the same usage id and a higher limit continues the same
  window; a new id starts new counters.
- Expired windows are pruned by the daily scheduled handler once the window
  plus a one-day margin has passed.

Evaluation-only paths (no credential) evaluate against the same ledger but
never count into it.
