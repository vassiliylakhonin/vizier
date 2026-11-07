# Isolated Worker deployment executor

`vizier-worker-deploy serve --scope /etc/vizier-deploy/scope.json --grant /etc/vizier-deploy/grant.jws`
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
ExecStart=/usr/bin/node /opt/vizier-deploy/node_modules/@agenda-intelligence/vizier-gated-deploy/dist/worker-cli.js serve --scope /etc/vizier-deploy/scope.json --grant /etc/vizier-deploy/grant.jws
NoNewPrivileges=true
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
cloud execution are not atomic. There is no claim of exactly-once deployment or
a durable execution journal in this change.

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
