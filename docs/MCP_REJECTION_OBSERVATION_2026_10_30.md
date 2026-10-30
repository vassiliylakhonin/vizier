# MCP refusal diagnosis and operator observation — 30 October 2026

## Observed scope

The private telemetry archive captured 29 October UTC: 240 unsigned-external
`initialize` events labeled `unsupported_version` with stateless metadata and
revision `2025-06-18`, and 240 `profile_method_mismatch` events with stateless
revision `2026-07-28`. Client family was `other`; declared labels are unverified.
These are event counts, not distinct clients. The same archive counted 419
successful unsigned-external initialize events; these do not establish adoption.
The source retention and current-day limitations remain in the private archive;
no raw identifiers or payloads are copied here. Events do not establish which
client sent them, whether the two counts are paired, or why they repeat.

## Reproduction and distinction

Owner-labelled live read-only probes on 30 October reproduced the observed
combinations: session-era initialize plus stateless metadata returned 400
`unsupported_version`; 2026 stateless metadata plus initialize returned 404
`profile_method_mismatch`. The published server hints supplied a read-only
recovery sequence for each, and those sequences connected and listed tools.
The unmodified session and stateless connection examples also succeeded live.
This supports a mixed-profile explanation for those test inputs, not proof of
the unknown callers' intent or an overall service outage.

Do not accept malformed mixtures merely to suppress a metric, and never replay
`tools/call` automatically. The separate, reproducible client-example issue was
that its error asked developers to inspect a hint while discarding the response.
The example now surfaces only a finite known reason and compatible public
profile/revision, without following server-provided requests or logging text.

## Real operator workflow, not independent customer feedback

[The 30 October Escrow deployment](https://github.com/vassiliylakhonin/agenda-intelligence-md/actions/runs/40997331867)
ran the existing workflow against a real Worker. It verified the checked source,
minted a short-lived grant for the selected Worker, and completed the Vizier-gated
deploy step; the next owner-labelled smoke check observed a HOLD-only response.
The gate step took approximately 16 seconds **including deployment**, not just
Vizier latency. This is an internal operational observation; it is neither a
customer interview, a measured usefulness rating, nor proof of absence of
bypass paths or future repeat adoption.

The user-supplied tests identified onboarding and middleware friction, but used
synthetic cases and cannot be counted as independent product validation. To
collect actual feedback, ask a willing operator to describe one real protected
action, their previous control, the time and blocker to install the guard, an
expected refusal, and whether they kept it in use. Use redacted information;
do not send questions automatically or collect grants, keys or private logs.
The existing [pilot record](PILOT.md) supplies qualification and seven-day
follow-through. No response is not a negative rating.
