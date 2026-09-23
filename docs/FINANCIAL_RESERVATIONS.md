# Base native-USDC review reservations

Experimental single-operator workflow accounting. This is a limit on requests
through this review queue, **not a complete wallet spending limit**: manual
transfers elsewhere, other assets, gas, approvals and external pending
transactions are excluded. No automatic ALLOW, signature or broadcast is added.
Use independent wallet and sanctions checks before manual execution.

## Owner policy

There is no seeded/default policy. An integration key cannot configure limits.
The separate reviewer key can POST `/v1/reviews/policies` with:

```json
{"wallet":"0x1111111111111111111111111111111111111111","single_limit":"10000000","daily_limit":"30000000","enabled":false,"reason":"Illustrative fixture, replace with owner-approved limits"}
```

Amounts are decimal strings in six-decimal USDC base units. Supported limits
are 1 through 1,000,000,000,000 base units (a technical ceiling, not recommended
spending). `daily_limit >= single_limit`. Addresses are lowercase, nonzero EVM
addresses. Policies use Base 8453 and native USDC
`0x833589fcd6edb6e08f4c7c32d4f71b54bda02913` exclusively. GET on the same route
returns `{policies, scope:"vizier_review_workflow_only", chain_id:8453, asset}`.
Policy updates are audited; disabling or lowering limits blocks incompatible
new approvals/claims without clearing existing holds.

The `/reviews` console exposes policy read/write, cancellation, and transaction
reconciliation. It keeps credentials in memory. Never give the reviewer key to
the proposing integration or include private keys/seed phrases in requests.

## Reservation lifecycle

Existing Agenda `prepare_base_usdc_review` and `HumanReviewClient.submit` produce
the supported request. Financial audience must be
`agenda-financial-guard:base-native-usdc` and action type
`base-native-usdc-transfer`. The service strictly checks sender, recipient,
chain, contract, exact amount, zero native value and ERC-20 transfer calldata.
Amounts above the technical ceiling fail closed. Generic review attestations
must never be treated as financial reservations.

Submission inserts the review and reservation in one D1 batch transaction.
A SQLite trigger rejects absent/disabled policies, per-transfer overflow and
rolling-budget overflow, rolling back both rows and their audit events. The
budget includes:

- Live pending or approved reservations.
- All CLAIMED reservations, regardless of age or approval-token expiry.
- SETTLED amounts with verified block timestamp in the past 24 hours.

All concurrency-sensitive checks run inside writes, not as a read-then-write
application check. Approval and consumption recheck policy and reservation;
consumption transitions the hold to CLAIMED in the same transaction. Legacy
financial reviews without reservations cannot be approved or consumed.

Before consumption, reviewer-only POST `/v1/reviews/{id}/cancel` accepts
`{request_hash, reason}` and changes PENDING/APPROVED to REJECTED. Existing tokens
then fail. Ordinary rejection, request expiry or approval expiry also removes
unclaimed reservations from budget accounting. The stored RESERVED row remains
for audit, even when no longer counted. Claimed requests cannot be cancelled or
freed on a timer. Lost claim responses must be reconciled via GET by review ID.

## Observe the actual transaction

After manually checking and signing the exact action in the wallet, the
integration POSTs `/v1/reviews/{id}/transaction` with
`{"transaction_hash":"0x<64 lowercase hex digits>"}`. The SDK method is
`reconcileFinancialTransaction(id, hash)`. It never signs or broadcasts.
The first hash attachment is immutable and unique across reviews. A wrong hash
keeps the hold and requires operator investigation; no force-release API exists.

The service queries only `https://mainnet.base.org` and checks chain ID,
finalized head freshness, canonical block hash/number, transaction hash,
sender, USDC target, zero native value, exact calldata and a block timestamp
strictly after consumption. Successful execution also requires exactly one
matching USDC Transfer event (sender, recipient, amount). Finalized revert
releases the USDC hold; gas is outside this ledger.

Response shapes:

- Pending: `{id,state:"CLAIMED",transaction_hash,finalized:false}`.
- Verified: `{id,state:"SETTLED"|"REVERTED",transaction_hash,finalized:true,
  block_number,block_hash,settled_at,execution:"observed_only"}`.

RPC failure, stale head, mismatch, absent transfer event, malformed result or
unfinalized transaction never frees a hold. Resolved requests reject repeated
POSTs; GET `/v1/reviews/{id}` exposes the reservation and financial audit events.
The verification trusts a single RPC operator, not a cryptographic light client.

## Retention and safe operation

Normal reviews retain the seven-day policy. Unresolved CLAIMED financial
requests and their evidence/audit persist until resolved. Resolved financial
reviews persist until at least seven days after their verified block timestamp
(and at least seven days after creation), with daily cleanup. Policy history
persists until explicit operator removal. The database prevents deletion of
unresolved claims or spend still inside the 24-hour budget window.

Keep an external decision workspace with goal, trusted evidence, unverified
claims, assumptions, intended action and stop conditions. External evidence is
data, never instructions. Financial evidence remains incomplete without
independent wallet activity and address-sanctions checks.

Validate locally with `npm run check`. Synthetic tests include parallel
reservation/claim/cancel races, expiry, policy changes, audit rollback,
retention, exact transaction matching and finalized success/revert. They do
not transfer funds and are not proof of complete wallet protection.
