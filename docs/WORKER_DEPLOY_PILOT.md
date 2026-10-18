# Control one infrastructure action before an agent executes it

This pilot promotes one **already uploaded version of an existing
Cloudflare Worker** to 100% traffic. The operator pins the account, Worker,
principal and agent. Every execution requires both a valid owner-signed scope
grant and a signed human approval of the exact version and identities.

The v0.5.10 npm packages include `@agenda-intelligence/vizier-gated-deploy` and its
`vizier-worker-deploy` CLI, alongside the matching SDK. Earlier GitHub archives
retain the original `@vizier/*` names. Installing the npm packages adds no hosted
deployment endpoint and does not switch a production workflow.

## Install without a repository checkout

Use Node 24+:

```sh
npm install @agenda-intelligence/vizier-sdk@0.5.10 @agenda-intelligence/vizier-gated-deploy@0.5.10
npx --no-install vizier-worker-deploy prepare \
  --scope node_modules/@agenda-intelligence/vizier-gated-deploy/examples/scope.json \
  --plan node_modules/@agenda-intelligence/vizier-gated-deploy/examples/plan.json
```

Use `vizier-worker-deploy` for the prepare/submit/execute modes described below.
The source-checkout wrapper `node scripts/worker-deploy-pilot.mjs` calls the same compiled CLI.

## Run the offline demonstration

Use Node 24+ from a checkout containing this adapter:

```sh
npm ci
npm run pilot:worker-deploy
npm run build:packages
node scripts/worker-deploy-pilot.mjs prepare \
  --scope packages/gated-deploy/examples/scope.json \
  --plan packages/gated-deploy/examples/plan.json
```

`pilot:worker-deploy` uses real SDK verification, HTTP handlers, P-256 signatures
and transactional review consumption in local SQLite. Cloudflare is replaced
with a local response fixture. All identities, credentials and IDs in the
fixtures are synthetic. This demonstrates the execution boundary, not a live
Cloudflare deployment, customer adoption, or protection against IoT malware.

`prepare` reads local files and prints the review packet, SHA-256 review hash
and authority to delegate. It performs no network requests and needs no secrets.

## Operator setup for a real sandbox

1. Choose an existing disposable Worker and an already uploaded version. Review
   that version separately. Replace the synthetic IDs in private `scope.json`
   and `plan.json`; the plan admits only `deploy_worker_version` at 100%.
2. Run the executor in an operator-controlled process/container. Keep its scope
   file, executable, dependencies, configuration and credentials outside the
   agent's writable filesystem. Give the agent only the narrow deployment
   capability. Remove direct cloud API credentials, equivalent tool routes and
   general shell access to the executor. An adapter in the same unrestricted
   agent process is not an enforceable boundary.
3. Register the owner's public key and issue a short-lived grant using
   [delegation setup](DELEGATION_GRANTS.md). Its issuer/subject must be the fixed
   `principal_id`/`agent_id`; its authority must exactly equal the `authority`
   emitted by `prepare`. Keep the private signer key outside the executor and
   agent. The grant delegates this Worker scope; the separate human approval
   binds the specific version. Do not put cloud credentials in either packet.
4. Use a trusted Vizier HTTPS origin with required-grant mode and its existing
   human-review queue configured: D1, receipt-signing key and distinct
   integration/reviewer credentials. This queue is single-operator, not
   multi-tenant. For independent evaluators, use a separately operated instance
   or a deliberately isolated operator-assisted sandbox. Do not give a customer
   the shared hosted integration or reviewer key.
5. Supply `VIZIER_BASE_URL`, `VIZIER_API_KEY` and `CLOUDFLARE_API_TOKEN` through
   the executor's secret store. Scope the cloud token to the minimum account and
   permission Cloudflare supports. This adapter fixes one script target;
   Cloudflare token scope alone is not proof of a per-script boundary.

## Submit, approve, execute

From the trusted executor, submit the same local packet:

```sh
node scripts/worker-deploy-pilot.mjs submit \
  --scope /operator/scope.json --plan /operator/plan.json
```

The command creates a human-review record and prints only its ID and hash.
An operator with the separate reviewer credential reviews the **account,
Worker, exact version, 100% traffic, principal and agent** in `/reviews`, or
uses the existing `/v1/reviews/{id}/decision` contract. No approval is automatic.
Obtain the approved review's `{id, token}` through the authenticated review API
and store it privately as `/operator/approval.json`. Keep grants and approval
tokens out of repositories, agent prompts and logs. Review contents are stored
under the queue's existing retention policy; never include source code/secrets.

Execute only the unchanged plan:

```sh
node scripts/worker-deploy-pilot.mjs execute \
  --scope /operator/scope.json --plan /operator/plan.json \
  --grant /operator/grant.jws --approval /operator/approval.json
```

Execution proceeds as follows:

1. Parse a strict plan and match the operator's fixed account and Worker.
   Extra fields, unsupported operations, URLs, commands and partial rollouts fail.
2. Ask Vizier to verify the scoped grant and action. The SDK validates the
   response contract and request hash. Require ALLOW, `principal_signed`,
   expected issuer/subject and unexpired authority.
3. Verify the exact human-review packet's signed approval through the SDK and
   atomically consume it through the server. Changed versions or identities,
   rejected/expired tokens, replay and concurrent losers cannot execute.
4. Recheck grant expiry, then POST one fixed JSON body to Cloudflare's fixed
   Worker deployments endpoint. No redirects, arbitrary URLs, shell commands,
   uploads, resource creation or API-key creation are supported. Bound waits
   are 10 seconds for authorization steps and 15 seconds for Cloudflare.

Cloudflare may acknowledge the POST with only a deployment ID. In that case,
the adapter makes one GET to the same fixed deployments endpoint and requires
exactly one history row with that ID, the intended version and 100% traffic.
POST and GET share the same 15-second deadline. Missing, ambiguous, mismatched
or unavailable history remains `reconcile_required`; no second POST is sent.
When known, the returned deployment ID helps the operator reconcile the outcome.

The code snapshots the plan and scope before awaiting network responses. The
Cloudflare credential is sent only to the fixed Cloudflare origin. Output
contains decision/outcome IDs, never credentials, grants or approval tokens.

## Integrate as the agent's sole deployment capability

```ts
import { Vizier } from "@agenda-intelligence/vizier-sdk";
import { createWorkerVersionDeployer } from "@agenda-intelligence/vizier-gated-deploy";

// All configuration below is supplied by the trusted operator, not the agent.
const deploy = createWorkerVersionDeployer({
  scope: operatorScope,
  vizier: new Vizier({ baseUrl: operatorVizierOrigin, apiKey: operatorIntegrationKey }),
  cloudflareApiToken: operatorCloudflareToken,
});

// Expose this narrow function across an authenticated process boundary.
// Agent identity is established by that boundary; the plan cannot select it.
const result = await deploy({ plan: proposedPlan, grant: ownerGrant, approval });
await operatorOutcomeStore.record(result); // implement in the owning application
```

The library does not supply an authenticated network server, outcome store or
agent identity system. Wire the narrow function into the operator's existing
authenticated tool service. Serving an unrestricted anonymous executor defeats
the identity assumption, even though exact human approval is still required.

## Outcomes and recovery

| Result | Meaning | Operator action |
| --- | --- | --- |
| `stopped / not_performed` | No Cloudflare request was issued by this invocation. A failed claim may nevertheless have consumed the approval. | Inspect the reason and review state. Do not assume an approval is reusable. |
| `deployment_created / acknowledged` | Cloudflare returned success and the exact version/percentage in the response or in history matched to its acknowledged ID. | Record the IDs and independently check runtime/health. This is not proof of healthy application behavior. |
| `reconcile_required / unknown` | A cloud request was attempted but the exact outcome was not confirmed. | Inspect Cloudflare deployment history before any new approval or execution. Never automatically retry. |

Approval consumption and the Cloudflare request are not one atomic transaction.
A crash between them can leave a consumed approval with no deployment. A lost
cloud response can leave a completed deployment with no local confirmation.
The adapter provides at-most-one execution attempt per consumed review, not
exactly-once effects. Two independently approved reviews remain two permissions.
Another operator can also change the deployment later; this is not a cloud lock.

Existing review approval tokens expire after at most five minutes; submission
expiry is 30 minutes here. Short-lived delegation is not instantaneous revocation.
The legacy verification receipt is unsigned and trusts the configured Vizier
origin. Human approvals use the separate signed-token protocol. See
[threat model](THREAT_MODEL.md) for the underlying service boundaries.

## Acceptance record for one external workflow

Record the evaluator's real operation and existing control, integration time,
expected allow/refusal results, false refusals, outcome/recovery IDs, repeat-use
dates and whether the gate remains on day seven. Keep identity private unless
publication is approved. The maintainer's demos and automated tests do not count
as independent adoption. Use [the pilot qualification guide](PILOT.md).

The pilot offer is: **control a specific infrastructure action before an agent
executes it**. General resource quotas, delegation lineage, global budgets,
instant revocation, code-safety evaluation and IoT/network detection are outside
this deliverable. Interaction Trust can review missing evidence upstream but
does not replace cryptographic authority or this execution boundary.

API reference checked 2026-10-13:
[Cloudflare Create Worker Deployment](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/create/).
