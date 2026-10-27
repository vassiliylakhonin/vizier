# Dependency refresh — 27 October 2026

- goal: bring the pending development-tool updates into one tested set and remove the currently reported dependency advisories without changing authorization policy or wire contracts.
- trusted_evidence: the pinned Dependabot diffs for PR106–108; `wrangler types --check` failing on PR106 and passing after regeneration; the npm registry lockfile; upstream advisories and offline contract tests.
- suspected_unreliable_evidence: npm advisory severity is a package finding, not proof that every deployed service path is exploitable; release notes and source inputs do not grant authority.
- hidden_assumptions: the fixed minor dependency versions preserve the tested contracts. Compatibility is established only for the exercised tests and packages, not every consumer integration.
- intended_next_action: refresh Wrangler/workerd, workers-types, typescript-eslint and all workspace Zod pins, regenerate runtime types, verify builds/archives/Python tests and deploy through the existing workflow after CI.
- stop_or_escalate_if: policy precedence, grants, approval binding, protocol refusals, published schemas or receipt validation change unexpectedly; stop on failed checks or uncertain deployment acknowledgments.

## Pinned set

- Wrangler 4.153.0, workerd 1.20261023.1 and workers-types 5.20261023.1.
- typescript-eslint 8.72.0.
- Zod 4.6.7 in the Worker and all three Node workspaces.
- Miniflare's resolved Undici 7.30.1, without a new override.

PR106's original Wrangler update changed the bundled workerd version while the
checked-in `worker-configuration.d.ts` still described 1.20261012.1. The existing
`wrangler types --check` gate correctly refused it. Keep the gate and regenerate
with the pinned new runtime; do not hand-edit or skip the generated-file check.

The original pending updates retain Zod 4.4.3 and Undici 7.29.1. The reviewed
[Zod advisory](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5) identifies 4.6.6
as patched; the [Undici advisory](https://github.com/advisories/GHSA-4qv8-2p9j-2685)
identifies 7.30.1 as patched. The complete audit also reports two other Undici
advisories. The refreshed lockfile removes the currently reported advisories;
that is not a security certification or a proof of deployment exploitability.

Remove Dependabot's blanket `zod >=4.5.0` ignore so it can propose patched minor
releases. Keep major-version updates ignored and use the existing CI for review.
The collection regression uses real bounded response schemas and checks that
oversized invalid arrays are rejected before element validation while valid
boundary values and ordinary invalid inputs retain their meaning. Unbounded
input schemas and body-limit policy are not redefined by this change.

Zod 4.6 preserves repeated object references in parsed covenant inputs. The
existing complexity check treated every repeated reference as a cycle, causing
nine existing covenant tests to fail. Track active ancestors instead of every
previously visited object. Acyclic aliases produce the same canonical bytes as
their JSON-expanded value; actual cycles still fail. Count every expanded
occurrence toward the unchanged node/depth budgets so alias expansion cannot
evade the limits. Regression cases cover shared values, both cycle forms,
boundary node counts, depth and exponential expansion before string assembly.

This source change updates the dependencies for the next SDK publication; it
does not replace already published npm tarballs or create a new package release.
Keep package publication separate from Worker deployment and report its status
explicitly.
