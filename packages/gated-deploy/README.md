# @vizier/gated-deploy

Operator-owned deployment of an already uploaded version of one existing
Cloudflare Worker. Requires owner-signed scope and signed human approval of the
exact version before calling Cloudflare. Node 24+.

Install both matching GitHub Release archives; the npm scope is not published:

```sh
npm install https://github.com/vassiliylakhonin/vizier/releases/download/v0.5.8/vizier-sdk-0.5.8.tgz https://github.com/vassiliylakhonin/vizier/releases/download/v0.5.8/vizier-gated-deploy-0.5.8.tgz
npx --no-install vizier-worker-deploy prepare \
  --scope node_modules/@vizier/gated-deploy/examples/scope.json \
  --plan node_modules/@vizier/gated-deploy/examples/plan.json
```

Verify the release's `SHA256SUMS` when downloading the archives. `prepare` is
local, uses synthetic IDs and needs no credentials. `--help` lists modes.

The package exports `createWorkerVersionDeployer`,
`prepareWorkerDeploymentReview` and `workerDeploymentAuthority`. The CLI supports
`prepare`, `submit` and `execute`; the last two use the operator's trusted Vizier
instance. Execution also requires a protected Cloudflare credential, exact
approval and grant files. Keep credentials, configuration and the executor out
of the agent's control; remove direct upstream access and alternate tool routes.

Read the [operator setup and recovery guide](https://github.com/vassiliylakhonin/vizier/blob/main/docs/WORKER_DEPLOY_PILOT.md)
before using a real sandbox. No automatic retry follows an uncertain cloud
outcome. Approval consumption and cloud deployment are not atomic. API
acknowledgement is not application-health proof. The hosted MCP service exposes
verification; this installed adapter performs the bounded deployment operation.

[Assisted integration](https://github.com/vassiliylakhonin/vizier/blob/main/docs/INTEGRATION_OFFER.md)
is available by agreement. Code is MIT; no IoT defense, global resource quota,
instant revocation or customer adoption claim is made.
