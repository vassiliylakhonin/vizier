# Demand measurement without contacting users

Status: **proposal.** No instrumentation described under "Proposed" exists yet.

## Decision rule

Within 30 days: at least **3 independent integrations** that completed
install, a first successful guard (an `ALLOW` in the real action path) and a
repeat on a later calendar day, and at least **2 repeat users**. Excluded:
the maintainer's own demos, CI runs, registry probes and bots. Nothing here
has been met or tested.

## What can be measured today

| Stage | Source now | Gap |
| --- | --- | --- |
| Install | npm and PyPI download counts (include mirrors, CI and bots; not users) | No way to tie a download to a caller |
| First successful guard | `agenda_service_access` events and `/v1/insights` counts | Events carry no integration or user identity; the service uses one shared API key, so key identity cannot separate integrations |
| Repeat on another day | none | Needs a stable pseudonymous caller key |
| Exclude own/CI/bots | `owner_synthetic` / `service_probe` labels from User-Agent and client headers | Self-declared heuristics; trivially spoofed and miss own traffic without a marker |

So today the only honest statement is an aggregate upper bound. The
`/v1/insights` window is 30 days and includes internal use.

## Proposed minimal instrumentation (needs approval before building)

Only signed-grant calls get an identity, because the grant's verified issuer
(principal id) is the one caller identifier the service already validates.

1. New D1 table `integration_activity`, one row per (pseudonym, UTC day):
   `integration_hash` (HMAC-SHA-256 of the verified principal id with a
   server-only secret), `day`, `allow_count`, `block_count`. No request body,
   agent id, action, target, amount or raw principal id. Rows older than 35
   days are pruned.
2. Written only after a signed-grant decision, from the existing audit write
   path. A failed write does not affect the decision.
3. A reviewer-authenticated report `GET /v1/insights/funnel`: counts of
   hashes with a first `ALLOW`, and with `ALLOW` on at least two distinct days
   in 30. Counts only; the hashes are never returned.
4. Exclusions are a server-side deny list of hashes (maintainer principals, CI
   principals), set by the operator in a secret. Everything else counts, and
   the report shows the excluded count separately.

Trade-offs to decide:
- The pseudonym is stable per principal, so it is personal data in a loose
  sense: it links one principal's activity over days. Publish this in the
  privacy text before enabling.
- Anonymous (no-grant) traffic remains unmeasured by design.
- A single operator running several principals counts as several integrations;
  an integration is "independent" only after a human check outside the system.
- Counts show use, not value or willingness to pay.

Install-to-first-guard attribution is not possible without a user-supplied
identifier and is left out on purpose.
