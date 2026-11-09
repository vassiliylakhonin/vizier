# Worked example: Vizier + OAE, signed human approval by email before an agent action

An agent wants to run a consequential action, for example "pay invoice 4471 for
8,200 USD". Two separate checks must both pass before it runs:

1. **Authority (Vizier):** did the principal delegate this kind of action, within
   these limits, to this agent? Answered by a principal-signed grant and a
   Vizier `ALLOW` bound to the exact request.
2. **Human approval (OpenAgentEmail, OAE):** did a named human approve this exact
   action just now? Answered by an OAE approval task that the human decides
   by email, read back by an executor-side consumer.

Neither check replaces the other. A grant says the agent may act within limits.
The OAE approval says a person looked at this specific action and said yes.

## Flow

```text
agent -> proposes action A (exact arguments)
Vizier: authorize(A, principal-signed grant)       -> ALLOW + receipt, or stop
OAE:    create approval task for A (digest of A)   -> reviewer gets an email
human:  approves or rejects by email               -> OAE records the decision
guard:  read task detail with the requester token  -> consumer checks it
guard:  reserve one executor attempt (SQLite)      -> run A once, or refuse
```

The guard must live outside the agent's control. It holds the credentials and
runs the executor.

## Step by step

1. **Delegate.** The principal mints a short-lived grant that names the agent,
   the allowed action and its limits (`scripts/mint-grant.mjs`, see the
   [authorization quickstart](AUTHORIZATION_QUICKSTART.md)). The operator
   registers only the public key.
2. **Authorize.** The guard calls `authorize()` with the exact request and the
   grant. The SDK requires `ALLOW`, `principal_signed` provenance, matching
   identities, an unexpired grant and a receipt hash bound to the request. When
   the service returns `receipt_jws`, the SDK also verifies it against the
   published JWKS.
3. **Request approval.** The guard creates an OAE approval task whose action is
   the same canonical object (`nested-order-v1`, see
   [the vector fixture](OPENAGENTEMAIL_VECTOR_PILOT.md)). OAE emails the
   reviewer. Changing any argument changes the digest.
4. **Decide.** The reviewer approves or rejects. The requester's own token cannot
   decide: the live probe saw HTTP 403 for that, and 200 for the reviewer.
5. **Consume.** The [reference consumer](../tests/fixtures/openagentemail-handoff.ts)
   reads `GET /v1/tasks/:id` with the requester token and requires the expected
   task and participants, `state=completed`, `decision=approved`, matching
   digests, a fresh decision and the scope check. It then reserves one executor
   attempt in SQLite before calling the executor.
6. **Run once.** A duplicate, changed arguments, a rejection or an expired
   approval each end with an error code and no executor call.

## What was observed

On 9 November 2026 the [live local probe](OPENAGENTEMAIL_LIVE_PILOT.md) ran the
consumer against a real OAE API and a real local mail server:

| Case | Result |
| --- | --- |
| Changed arguments | `OAE_ACTION_MISMATCH`, no executor call |
| Approved | one call |
| Duplicate after database reopen | `OAE_APPROVAL_ALREADY_RESERVED`, count stays one |
| Rejected | `OAE_APPROVAL_NOT_GRANTED` |
| Expired | `OAE_APPROVAL_NOT_GRANTED` |

## Limits

- The scope gate and executor in the probe are mocks. No privileged operation or
  external email took part. This shows API interoperability, not a production
  deployment.
- The Vizier and OAE checks are two separate calls made by your guard. Vizier
  does not call OAE, and OAE does not call Vizier.
- An email approval proves that whoever controls that mailbox and OAE reviewer
  identity decided. It does not prove the person read the action.
- Approval consumption and the downstream effect are not atomic. An uncertain
  outcome needs reconciliation, not an automatic retry.
- No customer is running this. See [CLAIMS.md](CLAIMS.md).

Reproduce the deterministic cases with
`npm exec -- vitest run tests/openagentemail-handoff.test.ts tests/openagentemail-consumer.test.ts`.
