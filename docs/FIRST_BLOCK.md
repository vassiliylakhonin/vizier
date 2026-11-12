# First BLOCK in TypeScript and Python

This is a disposable local demo, not a production setup. It starts the real
Worker runtime on `127.0.0.1`, uses a throwaway integration credential, and
generates a temporary receipt-signing key. It does not use your Cloudflare
account, public Vizier endpoint, production keys, or protected tool credentials.

The request deliberately has **no owner-signed grant**. With required-grant mode
on, both clients must return `BLOCK` with `GRANT_REQUIRED`. They also check the
receipt's request hash. A second request injects a client-side receipt change;
the demo must fail if either client accepts it. No purchase or other tool runs.

## Current source: signed receipts

Requirements: Node.js 24+, npm, Python 3.9+ with `venv`, and a platform supported
by Wrangler's local Worker runtime. Commands below use a POSIX shell. Run them
from the repository root; the initial installs need internet access.

```sh
git clone https://github.com/vassiliylakhonin/vizier.git
cd vizier
npm ci
python3 -m venv .venv
.venv/bin/python -m pip install -e 'packages/python-sdk[receipts]'
VIZIER_DEMO_PYTHON="$PWD/.venv/bin/python" npm run demo:first-block -- --signed
```

Expected output, after the SDK build:

```text
Disposable local Worker ready; source signed-receipt mode.
TypeScript: BLOCK (GRANT_REQUIRED), request hash verified, ES256 receipt verified
TypeScript: tampered signed receipt rejected; no tool executed
TypeScript: missing signed receipt rejected with requireReceiptJws; no tool executed
Python: BLOCK (GRANT_REQUIRED), request hash verified, ES256 receipt verified
Python: tampered signed receipt rejected; no tool executed
PASS: both clients refused the action and detected receipt tampering. Nothing deployed or executed.
```

In this mode, both clients request `receipt_jws`, verify ES256 against the local
Worker's JWKS, and reject a changed receipt ID. The demo explicitly rejects a
missing JWS too. This is stricter than the clients' normal compatibility behavior,
which permits responses without a JWS; the TypeScript SDK's opt-in
`requireReceiptJws` makes a missing JWS an error in production integrations. Installing the Python `receipts` extra is
required; without `cryptography`, signed-receipt verification fails closed.

The runner stops the Worker and removes its temporary config, signing key, and
state when it finishes, including ordinary client failures. It does not write
`.dev.vars` or alter your Wrangler deployment configuration. Do not reuse the
throwaway credential or key for a real integration.

## Published clients

As checked on 2026-11-12, npm has SDK `0.5.17` and PyPI has `vizier-guard 0.3.3`.
Both releases verify `/v1/verify` receipt JWS signatures, so the published path
runs the same `--signed` demo as current source. CI runs both modes (`--signed`
and hash-only) against exactly these published versions.

After `npm ci` in the checkout, install both published clients into separate
directories so the demo cannot silently import the source versions:

```sh
mkdir -p .wrangler/first-block-published
npm install --prefix .wrangler/first-block-published --no-save \
  @agenda-intelligence/vizier-sdk@0.5.17
python3 -m venv .wrangler/first-block-published/venv
.wrangler/first-block-published/venv/bin/python -m pip install 'vizier-guard[receipts]==0.3.3'
VIZIER_DEMO_SDK="$PWD/.wrangler/first-block-published/node_modules/@agenda-intelligence/vizier-sdk/dist/index.js" \
VIZIER_DEMO_PYTHON="$PWD/.wrangler/first-block-published/venv/bin/python" \
PYTHONPATH= node scripts/first-block.mjs --signed
```

Expected output:

```text
Disposable local Worker ready; source signed-receipt mode.
TypeScript: BLOCK (GRANT_REQUIRED), request hash verified, ES256 receipt verified
TypeScript: tampered signed receipt rejected; no tool executed
TypeScript: missing signed receipt rejected with requireReceiptJws; no tool executed
Python: BLOCK (GRANT_REQUIRED), request hash verified, ES256 receipt verified
Python: tampered signed receipt rejected; no tool executed
PASS: both clients refused the action and detected receipt tampering. Nothing deployed or executed.
```

Both published clients also check the receipt's request hash: running the same
commands without `--signed` exercises that hash-only mode, where a changed
`receipt.request_hash` must be refused. A digest binds the response to the
request; it does **not** authenticate who issued the receipt. A malicious service
could recompute a digest. Only use a service and transport you trust. The
Python client has no `require_receipt_jws` option: it verifies a returned JWS
and tolerates its absence.

## What this proves

| Check | npm 0.5.17 + PyPI 0.3.3 | Current source |
| --- | --- | --- |
| Real local `/v1/verify` returns missing-grant BLOCK | Yes | Yes |
| Client checks the request hash | Yes | Yes |
| Incorrect request hash rejected | Tested by omitting `--signed` | Tested by omitting `--signed` |
| Receipt ES256 signature and exact receipt verified | Tested with `--signed` | Tested with `--signed` |
| Changed signed receipt rejected | Tested with `--signed` | Tested with `--signed` |
| Missing signed receipt rejected | TypeScript `requireReceiptJws`, tested with `--signed`; Python tolerates absence | TypeScript `requireReceiptJws`, tested with `--signed`; Python tolerates absence |
| Production setup, ALLOW, deployment, payment, replay protection | Not tested | Not tested |

All paths use the **current local server source**, not a released server image.
These are maintainer-owned integration checks, not customer usage evidence or an
independent security audit. CI runs the source signed path and both published
modes to keep the onboarding instructions exercised. The Node client is JavaScript using the TypeScript SDK's exported API;
no TypeScript compiler is needed to run that client script.

## If it fails

- `GRANT_REQUIRED` is the intended result, not a setup error. Do not weaken the
  server's grant mode to make it disappear.
- Python `TypeError` mentioning `request_receipt_jws`: the selected interpreter
  has `vizier-guard` older than `0.3.3`. Install `vizier-guard[receipts]==0.3.3`
  or the source extra into the interpreter named by `VIZIER_DEMO_PYTHON`.
- `RECEIPT_VERIFICATION_UNAVAILABLE`: install the source Python `receipts` extra
  in the interpreter named by `VIZIER_DEMO_PYTHON`.
- Import or module errors: run `npm ci`, build the SDK with `npm run build:packages`,
  and check the selected Python environment. Do not disable receipt checks.
- Worker startup failure: confirm `node --version` is 24+ and that Wrangler can
  run on this platform. The demo uses a free loopback port and waits up to 30 seconds.
- Any unexpected ALLOW, missing signed receipt in signed mode, or accepted tamper
  causes a nonzero exit. Treat that as a failed check, not a successful demo.

## Next: a real authorization

A real ALLOW needs an operator-issued API credential, a registered principal
public key, and a matching short-lived owner-signed grant. Follow
[delegation setup](DELEGATION_GRANTS.md#setting-it-up). Keep the private signer
and tool credentials away from the agent. Stop on BLOCK, REVIEW, or verification
failure. An API key, a receipt, or a local human-review callback alone is not a grant.

For a version-bound deployment review without executing anything, see the
[deployment preparation quickstart](../README.md#optional-prepare-a-deployment-review).
The [operator guide](WORKER_DEPLOY_PILOT.md) covers separate execution controls,
approval, uncertain outcomes, and recovery.
