# Isolated Worker deployment executor

`vizier-worker-deploy serve --scope /etc/vizier-deploy/scope.json --grant /etc/vizier-deploy/grant.jws --journal /var/lib/vizier-deploy/executions.sqlite`
starts an operator-owned HTTP executor on **127.0.0.1:8791**. It accepts only
`POST /execute`, with `Content-Type: application/json`, a separate bearer
capability and a JSON object containing `plan` and `approval: {id, token}`.
The plan format is the same as in [the pilot](WORKER_DEPLOY_PILOT.md).
The response is the existing deployment result, including `stopped` and
`reconcile_required`; HTTP 200 alone does not mean deployment succeeded.

## Boundary to deploy

Use a separate OS account or container for the executor. The agent must have
neither that account's shell nor access to its files, environment, process
memory, service manager, container socket or Cloudflare credentials. Installing
this next to an unrestricted same-user agent **does not provide isolation**.
Privileged host operators and a compromised executor are outside this boundary.

Install the package and its dependencies in an operator-owned, agent-read-only
location, such as `/opt/vizier-deploy`. Store scope, grant and environment in
`/etc/vizier-deploy`, readable only by the executor's OS account and operators.
Use the existing [operator setup](WORKER_DEPLOY_PILOT.md) to register the public
key, enable required-grant mode, mint the fixed-scope grant and obtain human
approval of the exact uploaded version. Keep signing and review-decision keys
outside the executor as well as outside the agent. The gateway cannot mint a
grant or approve a review.

The executor environment needs:

- `VIZIER_BASE_URL`: the operator's HTTPS Vizier origin;
- `VIZIER_API_KEY`: the integration credential;
- `CLOUDFLARE_API_TOKEN`: a token limited to the required account/Worker
  permissions available from the provider;
- `VIZIER_DEPLOY_CLIENT_TOKEN`: a distinct random capability, 32–256 URL-safe
  characters. Generate it with `openssl rand -hex 32` and give only this
  capability to the agent.

Example systemd unit after installing Node 24+ and the package at the fixed path:

```ini
[Unit]
Description=Vizier bounded Worker deployment executor
After=network-online.target

[Service]
User=vizier-deploy
Group=vizier-deploy
WorkingDirectory=/opt/vizier-deploy
EnvironmentFile=/etc/vizier-deploy/executor.env
ExecStart=/usr/bin/node /opt/vizier-deploy/node_modules/@agenda-intelligence/vizier-gated-deploy/dist/worker-cli.js serve --scope /etc/vizier-deploy/scope.json --grant /etc/vizier-deploy/grant.jws --journal /var/lib/vizier-deploy/executions.sqlite
NoNewPrivileges=true
StateDirectory=vizier-deploy
StateDirectoryMode=0700
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectProc=invisible
UMask=0077
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Adjust the Node installation path for the host. This unit is an operator setup
example, not a tested deployment or a substitute for OS isolation. Do not put
credentials in the agent's workspace, command arguments, logs or shared shell
startup files. Remove previously inherited Cloudflare credentials and alternate
privileged deployment tools from the agent. For stronger defense in depth,
restrict its network access to the gateway and required unprivileged services.
If the agent is on another host, use an authenticated encrypted tunnel or a
private TLS ingress; do not expose the loopback HTTP endpoint to the Internet.

## Agent request

Build `request.json` with the exact approved `plan` and the approval `id` and
`token`. No grant, scope, credentials, URL or configuration fields are accepted.

```sh
curl --fail-with-body http://127.0.0.1:8791/execute \
  -H "Authorization: Bearer $VIZIER_DEPLOY_CLIENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @request.json
```

The executor snapshots the fixed scope, loads the operator's grant on each
request, checks signed delegation, verifies the exact approval and consumes it
in Vizier before making the cloud request. Rotation uses atomic replacement of
the operator grant file. Missing or invalid replacement grants stop execution.
There is no instant grant revocation store. Operators can stop the executor to
block new requests; an already submitted Cloudflare operation may still finish.

The gateway accepts one in-flight request and returns `409 EXECUTOR_BUSY` for
another. It limits bodies to 32 KiB, rejects browser-origin requests and never
returns upstream credentials or grants. Approval replay prevention remains in
Vizier's durable atomic review consumption, including across executor restarts;
the in-memory busy flag is not the replay defense.

## Recovery and acceptance checks

A lost connection or `reconcile_required` is not permission to retry with a new
approval. Check the consumed review and Cloudflare deployment history using the
[pilot recovery procedure](WORKER_DEPLOY_PILOT.md). Approval consumption and
cloud execution are not atomic. There is no claim of exactly-once execution across SQLite and Cloudflare.

Before production, test from the actual agent OS identity:

1. The exact approved version deploys; a changed version, different Worker,
   expired grant, missing approval and unavailable verifier cause no cloud POST.
2. Replaying approval, including after gateway restart, does not deploy again.
3. A lost cloud response requires reconciliation, without an automatic POST retry.
4. The agent cannot read executor secrets, alter scope/grant/code, control the
   service or obtain a privileged shell. Direct deployment without executor
   credentials fails. Check alternate CLI, MCP and REST routes too.

The automated gateway tests exercise actual local HTTP ingress, the real
Vizier transport/SDK with a temporary SQLite review store, and a simulated
Cloudflare API. They do not establish your host's isolation or deploy a Worker.

Run the [disposable Linux sandbox](../sandbox/worker-deploy/README.md) to test
file, environment, process and API boundaries with a separate unprivileged UID.
CI runs this acceptance test without external runtime network or host mounts.

## Durable execution status

`serve` now requires `--journal FILE`; update existing service units before
upgrading. The systemd example above creates a private persistent state directory.
For other process managers, pre-create `/var/lib/vizier-deploy` owned by the
executor with mode 0700. Never use `/tmp`, an ephemeral container layer or a
network filesystem for production state. Mount durable storage into containers.
The database must be a regular, non-symlink file with no group/other permissions;
new files are created with mode 0600. Keep the directory outside agent control.
Use a separate journal per trusted Vizier deployment. Back up the database using
a SQLite-aware backup or while the executor is stopped; do not delete unresolved
records or restore an old snapshot as a retry mechanism.

The journal stores approval ID, verification receipt ID, the exact review hash,
latest state, update time and optional deployment ID. It stores no tokens,
grants, raw plan or cloud credentials. SQLite uses synchronous FULL commits,
DELETE journaling and fullfsync where supported. Durability still depends on the
filesystem and hardware honoring synchronization. This is a local recovery
record, not an append-only event history, signed audit ledger or proof of health.

After signed authorization and successful approval consumption, the executor
commits `prepared`, then `dispatching`, **before** contacting Cloudflare. A failed
write stops this invocation without sending a cloud request, although approval
may already be consumed. A failure to commit the final response returns
`reconcile_required`, even if the cloud acknowledged deployment.

Inspect a record locally as the operator (no credentials or network needed):

```sh
vizier-worker-deploy status \
  --journal /var/lib/vizier-deploy/executions.sqlite \
  --approval-id REVIEW_ID
```

| Stored state | Interpretation and next step |
| --- | --- |
| No record (`not_recorded`) | Not evidence of non-execution. Check approval, correct executor/database, legacy paths and cloud history. |
| `prepared` (`not_submitted`) | This journaled attempt did not reach cloud dispatch. Approval was consumed; reconcile it before requesting a new approval. |
| `dispatching` or `unknown` (`unknown`) | Cloud execution may have occurred. A crash immediately before POST is indistinguishable from response loss. Reconcile cloud history; never automatically redeploy. |
| `acknowledged` | Cloud acknowledged the reviewed version; the deployment ID was committed locally. This does not prove application health. |

Status is read-only, operator-local and never authorizes a retry. The journal
cannot resolve the cross-system atomicity gap or prove outcomes independently.
There is no automatic purge or operator override API in this version. Existing
programmatic adapters and `execute` can opt in with `journal` / `--journal FILE`;
unconfigured legacy callers retain their earlier non-journaled behavior.
