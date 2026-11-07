# OpenAgentEmail v1 vector consumer fixture

This offline fixture checks OpenAgentEmail's published `nested-order-v1`
action in Vizier's canonical serializer and signed human-review consumer.
It uses synthetic credentials, ephemeral ES256 keys, in-memory SQLite and a
mock executor.

## Source and reproduction

The vector is copied from OpenAgentEmail at commit
`812af3ff59167ab63d5d848f60c5cdb338534824`. Its source, equivalent input,
canonical bytes and expected digests are retained in
[the fixture](../tests/fixtures/openagentemail-nested-order-v1.json).
The upstream recipe and corpus are linked below.

- [Approval digest v1](https://github.com/openagentemail/openagentemail/blob/812af3ff59167ab63d5d848f60c5cdb338534824/docs/approval-digest.md)
- [Versioned vectors](https://github.com/openagentemail/openagentemail/blob/812af3ff59167ab63d5d848f60c5cdb338534824/packages/api/test/fixtures/approval-canonical-vectors.v1.json)
- [Pilot invitation](https://github.com/openagentemail/openagentemail/issues/55#issuecomment-6705099355)

From the Vizier repository root, with Node 24 or later, run the fixture.

```sh
npm ci
npm exec -- vitest run tests/openagentemail-consumer.test.ts --reporter=verbose
```

## Checked outcomes

| Case | Expected and observed result |
| --- | --- |
| Original action | Canonical UTF-8 JSON matches the published text. SHA-256 is `5c545d4785b95fcc5dd412b2450dfa237dd925612d40e1c21f676fd069c83603`. |
| Reordered object keys | Same action digest and same review binding. |
| `/arguments/a/x` changes from `1` to `2` | SHA-256 is `9ab054a0a91fc2f7dcdd22f67327c2891e6c9c89f5b7f9ad513b73928862528c`. The SDK rejects the original approval with `INVALID_ATTESTATION` before a consume request or mock execution. The original approval stays `APPROVED`. |
| Original action with reordered keys | The SDK verifies the local request and ES256 approval, atomically consumes it and invokes the mock executor once with those arguments. |
| Replay of consumed approval | Claim is rejected and the executor call count remains one. |

The tests use Vizier's existing `submitHumanReview` and `claimHumanReview`
methods against its local HTTP handler. The consumer snapshots its action
before awaiting verification and passes that snapshot to the mock executor.

## Interpretation

The OpenAgentEmail action digest hashes `{type, name, arguments}`. Vizier's
review request hash covers an envelope containing the action, audience,
evidence, escalation reason and expiry. The fixture checks the upstream
action digest separately and stores it in the review evidence. Each system
keeps its own hash definition.

These results establish compatibility for this one published JSON vector
and rejection at this tested consumer boundary. The approval in the execution
test is issued by Vizier's synthetic local reviewer. Cross-service verification
of an OpenAgentEmail authenticated decision remains a follow-up integration.

Local validation on 7 November 2026 passed all 48 tests in the consumer,
human-review and MCP-proxy suites, plus the test TypeScript check, ESLint for
the new test and the workspace package builds.
