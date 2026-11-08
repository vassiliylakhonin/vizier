# OpenAgentEmail authenticated task-detail consumer fixture

This fixture implements the contract confirmed in
[OpenAgentEmail #55](https://github.com/openagentemail/openagentemail/issues/55#issuecomment-6720914852).
It reads a task-detail projection using the requester's identity token,
checks the approved action, and reserves one executor attempt in SQLite.
The API response, scope check and executor are injected test implementations.

The implementation is in
[the reference consumer](../tests/fixtures/openagentemail-handoff.ts), with
[runnable cases](../tests/openagentemail-handoff.test.ts). It reuses the
published `nested-order-v1` action and Vizier's canonical serializer from
[the first fixture](OPENAGENTEMAIL_VECTOR_PILOT.md).

## Reproduce

Use Node 24 or later, then run from the repository root.

```sh
npm ci
npm exec -- vitest run tests/openagentemail-handoff.test.ts tests/openagentemail-consumer.test.ts --reporter=verbose --silent
```

The tests use a fixed UTC clock, synthetic requester/reviewer identities,
mock HTTPS responses and a temporary on-disk SQLite database. They make no
live OAE requests. Credentials, task text and signing secrets stay outside
the ledger.

## Checked contract

The operator supplies the trusted HTTPS origin, requester, reviewer,
requester's bearer token and the task ID obtained at creation. Task-detail
reads use `GET /v1/tasks/:id`, reject redirects and HTTP errors, have a
five-second timeout and accept at most 256 KiB of response bytes.

The consumer requires the expected task ID and participants, `kind=approval`,
`state=completed` and `result.decision=approved`. Both `approval.digest` and
`result.digest`, plus the digest recomputed from the snapshot action, must
match the independently snapshotted intended action. The approved reviewer
must match the request's reviewer and the operator's configured reviewer.

As confirmed by OAE, `approval.expiresAt` is the deadline for deciding. The
consumer checks `createdAt <= decidedAt < expiresAt`. Freshness at execution
is a separate operator policy. This fixture chooses a maximum decision age
of 60 seconds and permits no future decision timestamp. It checks that age
again after awaiting the injected scope gate.

| Requested case | Expected and observed result |
| --- | --- |
| Approved | The original action reaches the mock executor once. The test clock is after `expiresAt`, with a still-fresh decision made before that deadline. |
| Rejected but completed | Stops before reservation and execution. |
| Expired | A failed task with `result.decision=expired` stops before execution. |
| Changed arguments | The intended action fails the digest comparison and obtains no reservation. |
| Duplicate delivery | Two connections racing the same task produce one executor attempt. Reopening the database preserves the reservation and blocks replay. |

Additional cases cover stale and future decisions, a decision made at the
expiry instant, each digest binding, task/participant mismatches, argument
mutation while awaiting the API or scope gate, scope refusal, response size,
HTTP errors and an uncertain execution outcome.

## Reservation and execution boundary

The store uses a primary key over `(configured origin, task ID)`, an atomic
insert with conflict refusal, WAL and `synchronous=FULL`. It records the
action digest, reviewer, decision time, claim time and attempt status.
The operator must preserve this ledger across consumer restarts and protect
it from untrusted writers. Deleting or restoring older ledger data can
remove replay evidence.

The consumer reserves before calling the executor. A returned result marks
the row `executed`. An exception marks it `uncertain`; a crash can leave it
`reserved`. Both statuses continue blocking a later attempt. An operator
must reconcile the external effect when the acknowledgement is lost. This
fixture establishes at most one attempted call while its ledger is intact.

The scope gate is a required, injected callback. The tests mock that gate
and the executor. A real integration must connect the callback to the
operator's current delegated scope and bind it to the same action snapshot.
The OAE API's authenticated projection is the trust boundary for this
example. Native Vizier human-review tokens retain their own signature and
envelope contract. Live OAE and executor integration remains a follow-up.

Local validation on 8 November 2026 passed 75 tests across the handoff,
canonical-vector, native human-review and MCP-proxy suites, plus TypeScript
checking and ESLint for the new files.
