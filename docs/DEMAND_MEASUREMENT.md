# Demand measurement without contacting users

Status: **implemented, off by default** (migration 0016, `VIZIER_ACTIVITY_KEY`). The owner approved this design on 2026-11-12. It has collected no data yet.

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

## Instrumentation as built

Only signed-grant calls get an identity (enforced `/v1/verify`, MCP and A2A decisions, not evaluation endpoints), because the grant's verified issuer
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

## Operating it

- Set `VIZIER_ACTIVITY_KEY` (16+ characters, server-only) to turn it on; unset means no rows are written. Set `VIZIER_ACTIVITY_EXCLUDE` to a JSON array of your own and CI principal ids. Excluded rows are reported separately.
- Read `GET /v1/insights/funnel` with the integration credential. It returns counts only, never hashes: integrations with a first `ALLOW` in the last 30 UTC days, those with `ALLOW` on two or more days, the excluded count, and whether the 3 / 2 thresholds are met. Install counts are not measured here.
- Rotating the key resets identity (old hashes no longer match). Rows are pruned after 35 days.
- Known blind spots: anonymous and unsigned traffic, principals created for each call (a fresh principal per call looks like many integrations), and the maintainer's own traffic under an id that is not on the exclude list. A passing count is a signal to check by hand, not proof of independent adoption.
