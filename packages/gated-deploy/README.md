# @agenda-intelligence/vizier-gated-deploy

Operator-owned deployment of an already uploaded version of one existing
Cloudflare Worker. Requires owner-signed scope and signed human approval of the
exact version before calling Cloudflare. Node 24+.

Install the matching packages from npm:

```sh
npm install @agenda-intelligence/vizier-sdk@0.5.17 @agenda-intelligence/vizier-gated-deploy@0.5.17
npx --no-install vizier-worker-deploy prepare \
  --scope node_modules/@agenda-intelligence/vizier-gated-deploy/examples/scope.json \
  --plan node_modules/@agenda-intelligence/vizier-gated-deploy/examples/plan.json
```

`prepare` is local, uses synthetic IDs and needs no credentials. `--help` lists modes.

The package exports `createWorkerVersionDeployer`,
`prepareWorkerDeploymentReview` and `workerDeploymentAuthority`. The CLI supports
`prepare`, `submit`, `execute`, `serve` and `status`. Submit and execution modes use the operator's trusted Vizier
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

## Separate executor process

`vizier-worker-deploy serve --scope /etc/vizier-deploy/scope.json --grant /etc/vizier-deploy/grant.jws --journal /var/lib/vizier-deploy/executions.sqlite`
exposes only a bounded `POST /execute` on loopback port 8791. The agent supplies
an exact plan and approval using a separate client capability. Scope, grant,
Vizier credentials and Cloudflare credentials stay in the operator process.
Run it under a separate OS identity/container; same-user unrestricted shell
access defeats this boundary. See the [isolation and recovery guide](https://github.com/vassiliylakhonin/vizier/blob/main/docs/WORKER_DEPLOY_GATEWAY.md).

## Signed acceptance for covenant deploys

`runCovenantGatedDeploy` accepts an optional `signAcceptance` callback. When set,
the principal signs the exact covenant draft hash (`acceptance_jws`) and the
service verifies it against the registered principal key. The CLI enables this
when `VIZIER_ACCEPTANCE_KEY` points to the principal's private ES256 JWK file.
Without a signer the acceptance is the integration's own assertion, and a
service running with `VIZIER_REQUIRE_SIGNED_ACCEPTANCE=true` rejects activation
with `ACCEPTANCE_SIGNATURE_REQUIRED`. A signature proves the key holder accepted
that draft hash, not that a human read it.
