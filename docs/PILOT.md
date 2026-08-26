# One-week developer pilot

Vizier is in `build-to-learn` mode. This pilot tests whether people who already
operate action-taking agents will place a deterministic authorization check in
the execution path and keep it there. It is not a launch, a production-readiness
claim, or a test of pricing.

## Gate

- **Observed:** Vizier has a deployed API, a signed A2A Agent Card, an OpenAPI
  contract, and one internal gated-deploy integration.
- **Observed:** there are no independent production integrations, paid pilots,
  or repeat-use measurements.
- **Inferred:** the likely evaluator is a founding engineer, platform lead, or
  security engineer responsible for an agent with write, deployment, messaging,
  deletion, permission, code-execution, or payment capability.
- **Unknown:** whether a recent release, incident, or review creates enough pain
  to replace the evaluator's current tool wrapper, IAM rule, allowlist, or manual
  approval step.

## Participant qualification

Recruit five developers who can describe a real agent-controlled external
action they operate or are preparing to release. Do not count general AI users,
people evaluating only a read-only chatbot, or the maintainer's own deployment.

Before showing Vizier, ask:

1. When did this agent last cause or attempt an external side effect?
2. What could have gone wrong, and what release, incident, or review made that
   risk concrete?
3. What control runs immediately before the action today?
4. Who owns the operational risk and can approve an integration?
5. What evidence would that person need before keeping a new gate in the path?

Record past behaviour and the current workaround. Do not ask whether the person
would hypothetically use or buy Vizier.

## Pilot task

Each qualified participant chooses one non-destructive test action shaped like
an action they actually operate. They must:

1. run the local quickstart and receive `ALLOW`, `REVIEW`, and `BLOCK`;
2. integrate the SDK or REST contract immediately before the selected action;
3. treat timeout, malformed responses, `REVIEW`, and `BLOCK` as stop conditions;
4. exercise at least one expected allow and one expected refusal;
5. keep the check in the normal path for seven days or explain why they removed
   it.

For a participant whose action already runs through an HTTP MCP server, the
private `@vizier/mcp-proxy` adapter may replace a custom integration. Configure
exactly one upstream endpoint and the minimum tool allowlist. The participant
must remove the agent's direct upstream route and keep the proxy, Vizier, and
upstream credentials separate. Using the proxy in a synthetic fixture proves
only contract conformance; it counts as an integration only when it gates the
participant's existing action path.

Use synthetic or redacted parameters unless the participant has explicitly
approved the data sent to the pilot deployment. Never collect API keys, payment
credentials, private signing keys, or unrestricted Cloudflare credentials.

## Evidence record

For each participant, record:

- role and organization type, without publishing identity by default;
- real action type and painful trigger;
- previous control or workaround;
- integration surface used (`SDK`, `REST`, `A2A`, or `MCP`);
- first successful refusal and first successful allow;
- dates on which repeated machine-generated calls occurred;
- whether the gate remained in the normal path on day 7;
- integration time, blockers, removals, and requested changes;
- who owns adoption and whether they approved a follow-up.

One-off curls, registry probes, maintainer dogfood, compliments, and Agenstry
scores do not count as adoption evidence.

## Decision after five conversations

- **Continue the current hypothesis** only if at least two independent
  participants complete an integration and generate repeated machine calls on
  three separate days, and at least one names a concrete owner and next adoption
  step.
- **Pivot the integration or buyer hypothesis** if the painful trigger is real
  but the existing wrapper, IAM control, or manual approval is consistently
  preferred. Preserve the reasons and test the smallest missing capability.
- **Downgrade to portfolio-only** if fewer than two participants integrate, no
  participant keeps the gate in the normal path, or the problem is repeatedly
  described as non-urgent or unowned.

Do not build billing, dashboards, a registry, durable storage, or additional
policy languages during this pilot. A requested feature becomes evidence only
when tied to a participant's blocked integration or continued use.
