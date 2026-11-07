# Linux isolation acceptance test

From the repository root, with Docker running:

```sh
docker build -f sandbox/worker-deploy/Dockerfile -t vizier-worker-isolation .
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,nodev --tmpfs /app/node_modules/.vite --tmpfs /app/node_modules/.vite-temp --cap-drop ALL --cap-add SETUID --cap-add SETGID --security-opt no-new-privileges vizier-worker-isolation
```

No host directory or Docker socket is mounted and no production credentials are
used. The container has no external network at runtime. The executor/test
harness runs as container root; the adversarial child is UID/GID 65534 and gets
only the gateway capability and an exact approved operation. Root is used only
to create the separate-UID child in this disposable test container. Production
should use a dedicated unprivileged executor account.

The test checks that the child cannot read protected credentials, configuration
or executor environment, write configuration, or signal the executor. Direct
calls to the simulated cloud API fail, including with the gateway capability.
A changed version and injected credentials fail; the exact approved version
succeeds once, and approval replay fails. The normal deployment tests also run.
Vizier transport, signatures, SDK and SQLite approval consumption are real;
Cloudflare is a local authenticated simulator. This does not establish the
isolation of a production host, real Cloudflare IAM policy or application health.
