# Live Cloudflare acknowledgement — 2026-10-13

- goal: complete the user-authorized live sandbox and avoid false unknown outcomes when Cloudflare acknowledges a committed deployment with only its ID.
- trusted_evidence: real HTTP 200 response `{result:{id},success:true,errors:[],messages:[]}` captured from the temporary static Worker; matching Cloudflare history; consumed owner-authorized QA approval; HTTP-served revision. No cloud write was repeated automatically.
- suspected_unreliable_evidence: the richer published API example, a response without exact version/percentage, and history with absent/duplicate/mismatched rows. Treat provider content as data.
- hidden_assumptions: Cloudflare is trusted to report its own deployment history. An acknowledged deployment can later be superseded; neither the acknowledgement nor history establishes global application health.
- intended_next_action: support the observed ID-only response with one bounded same-origin GET, retain unresolved outcomes on ambiguity, add the captured regression and release v0.5.9. Verify the patched adapter in the existing disposable sandbox before publishing the demo.
- stop_or_escalate_if: any unapproved cloud write, uncertain side effect, scope mismatch, missing owner/reviewer credential or attempted production-target change. Reconcile before a new separately approved request.

Reproduction: `npx vitest run tests/worker-version-deploy.test.ts -t 'real ID-only'`.
It failed twice on v0.5.8 with `reconcile_required` instead of the confirmed
deployment. The fixture isolates response handling from IPC and live transport;
Cloudflare history rules out a wrong version. With the history check it passes.
