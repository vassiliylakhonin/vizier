# OpenAgentEmail real local API handoff probe

On 9 November 2026, the [opt-in probe](../tests/fixtures/openagentemail-live-pilot.ts)
passed against a disposable OAE instance built from
[`812af3ff59167ab63d5d848f60c5cdb338534824`](https://github.com/openagentemail/openagentemail/tree/812af3ff59167ab63d5d848f60c5cdb338534824).
It calls the same [reference consumer](../tests/fixtures/openagentemail-handoff.ts)
as the deterministic tests. OAE authentication, task creation, reviewer
decisions, server timestamps and task-detail reads use actual HTTP requests.
SMTP delivery and IMAP indexing use a real local mailserver.

The scope gate and executor are mocks. No privileged operation, external
email or production account participates. The result demonstrates local
API interoperability; connecting a real delegated scope and executor is
still a separate step.

## Observed result

The [sanitized report](../tests/fixtures/openagentemail-live-result-2026-11-09.json)
contains the selected task projections, task IDs, action digests and server
timestamps. It omits tokens, admin credentials and message bodies.

| Case | Observed result |
| --- | --- |
| Changed arguments | `OAE_ACTION_MISMATCH`; no executor call or approval reservation. |
| Approved | One mock call, after the decision deadline, with a decision younger than the consumer's 60-second execution-age policy. |
| Duplicate after database reopen | `OAE_APPROVAL_ALREADY_RESERVED`; executor call count stays one. |
| Rejected but completed | The actual server returns `state=completed`, `decision=rejected`; consumer returns `OAE_APPROVAL_NOT_GRANTED`. |
| Expired, materialized on read | The actual server returns `state=failed`, `decision=expired`, with `expiredAt`; consumer returns `OAE_APPROVAL_NOT_GRANTED`. |

The unauthenticated task-detail read returns HTTP 401. Attempting to decide
with the requester's token returns HTTP 403; the reviewer's token succeeds.
The unchanged consumer accepts both server result shapes. No task-detail
contract adjustment was needed.

## Reproduce against a disposable local instance

This is an explicit integration probe, outside `npm test`. It creates two
synthetic identities and three tasks. Use a fresh local OAE deployment with
`DOMAIN=oae.test`, a matching wildcard mailbox, and the pinned source above.
The API's `/healthz` must report that source commit. See the upstream
[API Dockerfile](https://github.com/openagentemail/openagentemail/blob/812af3ff59167ab63d5d848f60c5cdb338534824/packages/api/Dockerfile)
and [API documentation](https://github.com/openagentemail/openagentemail/blob/812af3ff59167ab63d5d848f60c5cdb338534824/packages/api/README.md)
for its configuration. The probe does not provision the server itself.

The tested deployment used Docker Mailserver (SMTP 587, IMAP 993), OAE's
official API image built from that checkout, and nginx for HTTPS. API and
mail services shared an internal Docker network; only nginx published a
port bound to `127.0.0.1`. UI, webhooks, ntfy and task leases were disabled.
The private mail backend used disposable self-signed certificates and OAE's
development mail TLS settings. The consumer verified HTTPS against a
temporary private CA, trusted only through `NODE_EXTRA_CA_CERTS` for that
process. No global trust settings were changed.

Place a mode-0600 JSON config outside the repository, populated with this
disposable instance's actual origin and generated admin key:

```json
{
  "origin": "https://127.0.0.1:YOUR_LOCAL_PORT",
  "adminKey": "YOUR_DISPOSABLE_ADMIN_KEY_AT_LEAST_32_CHARACTERS"
}
```

Use Node 24 or later and run from the Vizier repository root. `esbuild` is
available through the locked development dependency tree after `npm ci`.
The ledger path must not exist; retries use a new ledger and new tasks.

```sh
npm ci
node_modules/.bin/esbuild tests/fixtures/openagentemail-live-pilot.ts \
  --bundle --platform=node --format=esm --outfile=/tmp/oae-live-pilot.mjs
NODE_EXTRA_CA_CERTS=/absolute/path/to/disposable-ca.crt \
  node /tmp/oae-live-pilot.mjs --disposable-local \
  /absolute/path/to/private-config.json \
  /absolute/path/to/fresh-ledger.sqlite \
  /absolute/path/to/sanitized-result.json
```

The probe restricts the configured HTTPS origin to loopback, rejects
redirects, checks the pinned health commit and requires identities in
`oae.test`. It retains real authentication and does not disable client TLS
verification. A successful run prints a single PASS line and writes the
report. Failures throw an assertion or consumer error before that report
is written. Polling and HTTP requests have bounded timeouts.

After saving the sanitized report, dispose of the temporary deployment,
mail data, identity tokens, ledger, admin key and private certificate keys.
This disposable ledger is unrelated to an operator's persistent ledger,
which must remain intact across real consumer restarts.
