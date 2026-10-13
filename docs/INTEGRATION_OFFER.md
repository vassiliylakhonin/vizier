# Assisted integration: control one agent deployment

For a platform lead or security engineer who already operates an agent with
deployment capability. The initial engagement connects one existing Cloudflare
Worker version-deployment workflow to owner-scoped authorization and exact human
approval. This is an offer for a paid, agreed scope, not a claim that a customer
has purchased it. There is no automated checkout or self-service subscription.

## What the engagement delivers

- One pinned account/Worker and an operator-owned execution boundary.
- Owner key registration and short-lived signed scope; private signer keys stay
  with the owner. Distinct integration and human-review credentials.
- Human review of the exact uploaded version and traffic percentage.
- A verified allow and expected refusals for changed targets/versions, expired
  permissions, replay, concurrent requests and unavailable authorization.
- Recorded deployment/review IDs, recovery procedure for uncertain outcomes,
  and a handover explaining credential isolation and remaining bypass routes.

Start with an existing sandbox, a reviewed uploaded version and a named operator.
The buyer must be able to isolate credentials and remove the agent's direct
deployment route. Existing code review, Cloudflare IAM and application-health
checks remain necessary. The review queue is single-operator: use a buyer-owned
instance or an expressly isolated operator-assisted sandbox, not a shared
customer reviewer credential.

## Commercial scope

Agree the deliverables, operator responsibilities, acceptance cases and fixed
integration fee before work. Hosting, updates and ongoing support can be scoped
after the first integration. API keys and request quotas are technical access
controls, not billing or permission to act; paying for access never replaces
the owner's delegation or human approval. No payment credentials belong in an
MCP call, public issue or review packet.

The open-source packages remain MIT and can be operated independently. The
commercial work covers integration and operation. No uptime SLA, security
certification, global resource/spending cap, IoT defense or instant revocation
is included in this initial offer. Additional adapters need a separately agreed
scope. Pricing and willingness to pay have not been validated.

## Request a fit check

Use the [integration request form](https://github.com/vassiliylakhonin/vizier/issues/new?template=worker-deploy-pilot.yml).
Describe the action, existing control, concrete problem, sandbox availability
and who owns the integration. GitHub issues are public: keep names and examples
redacted and do not attach keys, tokens, internal logs or confidential code.
Private material can be discussed only through a separately agreed channel.

Record integration time, false refusals, repeat-use dates and whether the gate
remains in the normal path after seven days. A successful maintainer demo or
registry probe is not customer adoption. See [pilot criteria](PILOT.md) and
[technical setup](WORKER_DEPLOY_PILOT.md).
