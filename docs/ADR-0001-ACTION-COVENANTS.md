# ADR-0001: Action Covenants outside the model trust boundary

- Status: accepted
- Date: 2026-08-24
- Scope: experimental v0.2

## Context

The v0.1 API evaluates one proposed action against authority supplied by an
authenticated integration. It can answer whether the action fits explicit
constraints, but it cannot represent the semantic conditions under which an
earlier human decision should remain valid or bind the eventual execution
outcome back to that decision.

A language model can translate intent and evidence into a useful structured
proposal. The same model is not a trustworthy authority source: its output can
be mistaken, manipulated, stale, or changed between approval and execution.

## Decision

Add an Action Covenant lifecycle as a separate deep module while preserving
`/v1/verify`.

1. A model, human, or deterministic system creates a strict
   `ActionCovenantDraft` outside Vizier's privileged authorization path.
2. An authenticated integration activates the draft only with an acceptance
   naming the same principal and the exact draft SHA-256 hash.
3. One covenant contains one exact action, delegated authority, evidence
   freshness requirements, shallow exact-match invalidation rules, exact
   forbidden effects, and an expiry.
4. Vizier recomputes covenant integrity and composes covenant checks with the
   existing deterministic policies. The new core defaults authority provenance
   to unauthenticated unless the caller explicitly supplies authenticated
   integration context.
5. Vizier returns a compact ES256 authorization JWS bound to issuer, covenant,
   complete request, exact action, evidence, signals, decision, rules, and a
   short execution window.
6. The executor reports an outcome only against a valid `ALLOW` receipt. Vizier
   signs a second JWS bound to the authorization token, covenant, outcome, and
   any exact forbidden-effect violations.
7. Agent Card and receipt signing use separate P-256 keys and protected JWS
   types. Public keys share the existing JWKS resource and have distinct `kid`
   values.

No model provider, dynamic expression language, evidence retrieval, policy
database, or receipt database is added to the Worker.

## Consequences

The model can contribute semantic compression without receiving authority. An
executor can prove that a particular reported outcome followed a particular
accepted and authorized action, and payload tampering becomes detectable.

The integration remains a major trust anchor. It can fabricate principal
acceptance, evidence, signals, and outcomes; signatures prove origin and binding,
not truth. Caller-held receipts are not durable audit storage or independent
timestamps. Exact-match invalidation and forbidden-effect rules deliberately
trade expressiveness for deterministic reviewability.

The first deployment needs an explicit v0.1 bootstrap path because the live
service cannot authorize through endpoints that it does not yet expose. After
that deployment, the normal gated-deploy path uses the full covenant lifecycle.
