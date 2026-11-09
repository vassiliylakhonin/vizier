# Mass-ban guard demo (synthetic)

A disposable local demo of scoped authorization for a mass moderation action.
It answers one question: if an owner agrees that an agent may ban an exact
list of accounts, can Vizier keep the agent's executor to that list when the
agent proposes more? It uses only the existing grant, constraint and SDK
surface - no new platform code.

The scenario:

1. The owner (`community-owner`) signs a short-lived delegation grant for
   `moderation-agent-01`: action `ban_account`, constraint
   `allowed_targets` = five synthetic accounts.
2. The agent proposes a mass ban of eight accounts: the five agreed plus
   three it added itself.
3. A trusted guard sends each proposed ban to a local Vizier Worker with the
   grant. Only an established ALLOW reaches the mock executor.
4. The agent also retries one extra account beside an enlarged, unsigned
   authority (a longer `allowed_targets` than the owner signed).

Expected output:

```text
Disposable local Worker ready; grant-required mode with a registered principal key.
ALLOW fake-user-001: mock executor recorded the ban
ALLOW fake-user-002: mock executor recorded the ban
ALLOW fake-user-003: mock executor recorded the ban
ALLOW fake-user-004: mock executor recorded the ban
ALLOW fake-user-005: mock executor recorded the ban
BLOCK fake-user-006: TARGET_NOT_ALLOWED; executor not called
BLOCK fake-user-007: TARGET_NOT_ALLOWED; executor not called
BLOCK fake-user-008: TARGET_NOT_ALLOWED; executor not called
BLOCK enlarged authority for fake-user-006: GRANT_REQUIRED, GRANT_AUTHORITY_MISMATCH; executor not called
PASS: 5 authorized bans executed, 3 added accounts blocked, enlarged authority rejected. The mock executor banned exactly the agreed accounts.
```

## Run it

From the repository root of a source checkout, with Node.js 24+ and npm
installed. Dependency installation needs network access; the demo itself uses
only a disposable local Worker and needs permission to listen on localhost:

```sh
npm ci
npm run demo:mass-ban
```

Like [FIRST_BLOCK.md](FIRST_BLOCK.md), the runner starts a real local Worker
on `127.0.0.1` with a throwaway integration credential, mints a temporary
principal key in a temp dir, and removes everything when it finishes. No
account, production API key, Cloudflare account, deployment, or real platform
is involved. The grant is reusable because the disposable local Worker has no
D1 binding; a `single_use` grant fails closed without D1, by design.

## Automated regression

The `CI` workflow runs the same `npm run demo:mass-ban` command immediately
after `npm ci`, before the general checks build any packages. The command
builds the source SDK itself, so the walkthrough does not depend on a stale
or prebuilt `dist` directory. No Cloudflare credentials or production calls
are needed for this step.

The runner already contains assertions that fail the command (and CI) unless:

- all five agreed accounts return ALLOW;
- all three added accounts return BLOCK with `TARGET_NOT_ALLOWED`;
- enlarged authority returns BLOCK with `GRANT_AUTHORITY_MISMATCH`;
- the final mock execution list exactly equals the five agreed accounts, in
  order, with no extra calls or duplicates.

These are checks of actual decisions and the in-memory executor list, not
matching console output. They remain a local integration regression, not an
isolation test or a real moderation integration.

## What this proves

- A custom action type (`ban_account`) works with the existing schema: action
  types are open strings, checked against the grant's `allowed_actions`.
- `constraints.allowed_targets` binds the exact account list. Any account
  outside the signed list is `BLOCK` with `TARGET_NOT_ALLOWED`, and the guard
  never calls the executor for it.
- The request's authority must match the signed authority exactly. Enlarging
  `allowed_targets` beside the same grant is `BLOCK` with
  `GRANT_AUTHORITY_MISMATCH` - a genuine grant cannot launder a bigger claim.
- The SDK's `authorize()` enforces the guard side: it requires the
  integration credential, principal and grant, verifies the signed receipt,
  checks the receipt's grant binding and expiry, and throws instead of
  returning a non-ALLOW decision. The executor only sees authorized actions.

## What this does not prove

- **No real integration.** The executor is an in-memory mock. Wiring a real
  moderation backend (its API credentials, ban endpoint, and error handling)
  is integration work this demo does not do.
- **No fraud detection.** Nothing here decides who deserves a ban. Vizier
  bounds what the agent may do; it does not judge whether the agreed list is
  right. Choosing the list, false-positive handling and appeals stay with the
  product and its humans.
- **No mass-ban policy engine.** Rate limits, quorum, review for
  irreversible actions and session caps exist as separate constraints; this
  demo exercises only `allowed_targets`.
- **No host isolation.** The guard/executor boundary here is a function call
  in one process. Real isolation (separate UID, no direct upstream
  credential) is a deployment property covered by
  [WORKER_DEPLOY_GATEWAY.md](WORKER_DEPLOY_GATEWAY.md).
- **No production security guarantee.** This is a maintainer-owned local
  check of current source, not an audit or customer usage evidence.

These are the same limits stated in [FIRST_BLOCK.md](FIRST_BLOCK.md); the
demo extends the pattern from "block everything without a grant" to "allow
exactly the delegated list, block the rest."

The SDK ships an opt-in typed adapter for this workflow,
[`guardBanAccount`](../packages/sdk/README.md#typed-guard-account-bans-opt-in),
which builds the evaluated action from the actual executor call (target,
reversibility, parameters) instead of a separately assembled request, so the
checked values are the ones that run.
