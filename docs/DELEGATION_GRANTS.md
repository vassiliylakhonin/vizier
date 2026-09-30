# Delegation grants

## The problem this closes

Until v0.3, every Vizier decision rested on an authority the calling
application asserted about itself:

```json
{ "principal": { "id": "acme-corp" },
  "authority": { "allowed_actions": ["purchase"],
                 "constraints": { "max_amount": 10000 } } }
```

Vizier checked the proposed action against that block faithfully and signed a
receipt for the result. But nothing in the exchange showed that `acme-corp` had
ever delegated anything. Any holder of the integration credential could name any
principal and any limit, and the receipt would attest to the decision — a signed
record of an unverified claim.

That is a calculator, not a control. A delegation grant makes it a control.

## What a grant is

A compact JWS, signed by the principal, that binds one authority to one agent
for a bounded window:

```json
{
  "iss": "acme-corp",              // the principal delegating
  "sub": "procurement-agent-01",   // the agent that may act
  "jti": "grant_5f1c…",            // this grant's id
  "iat": 1757232000,
  "exp": 1757235600,
  "authority": {
    "allowed_actions": ["purchase"],
    "constraints": { "max_amount": 10000, "currency": "USD" }
  }
}
```

Header: `{"alg":"ES256","kid":"acme-2026-09","typ":"vizier-delegation+jws"}`.
The payload is serialised with RFC 8785 canonical JSON before signing.

The agent sends it as a `grant` field beside the rest of the request. Vizier
verifies it against a public key registered for `acme-corp` and, if everything
holds, the receipt carries `"authority_provenance": "principal_signed"` plus the
grant's id, key id and expiry.

## The one property worth stating plainly

**A grant that does not verify is `BLOCK`. It never degrades to the
caller-asserted path.**

Otherwise a forged grant would be strictly better for an attacker than sending
none at all: fail it open and you have built a way to launder an assertion into
an appearance of proof. Presenting a grant is an instruction to verify it.

The corollary matters for the request body: the `authority` in the request must
be byte-identical, once canonicalised, to the `authority` inside the grant. A
genuine grant travelling beside an enlarged authority is `BLOCK` with
`GRANT_AUTHORITY_MISMATCH`, not an allow at the larger limit.

## Setting it up

### 1. The principal generates a key

```bash
node scripts/mint-grant.mjs keygen --kid acme-2026-09 --out principal.jwk.json
```

The private key stays with the principal. Vizier never holds it, and there is no
endpoint that would accept it.

### 2. The operator registers the public half

`VIZIER_PRINCIPAL_KEYS` is a JSON object mapping principal id to one public JWK
or an array of them:

```json
{
  "acme-corp": [
    { "alg": "ES256", "crv": "P-256", "kid": "acme-2026-09",
      "kty": "EC", "use": "sig", "x": "…", "y": "…" }
  ]
}
```

```bash
npx wrangler secret put VIZIER_PRINCIPAL_KEYS
```

An array lets a principal rotate: register the new key alongside the old, wait
out the longest outstanding grant, then drop the old one.

`GET /docs` reports `delegation.registered_principals` and
`delegation.principal_keys_valid` so a misconfiguration is visible without
sending a request through.

### 3. The principal mints a grant

```bash
cat > grant.json <<'JSON'
{
  "iss": "acme-corp",
  "sub": "procurement-agent-01",
  "authority": {
    "allowed_actions": ["purchase"],
    "constraints": { "max_amount": 10000, "currency": "USD" }
  }
}
JSON

node scripts/mint-grant.mjs sign --key principal.jwk.json --grant grant.json --ttl 3600
```

### 4. The agent presents it

```bash
curl -sS https://vizier.vassiliy-lakhonin.workers.dev/v1/verify \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $VIZIER_API_KEY" \
  -d '{ "agent": {"id":"procurement-agent-01","owner":"acme-corp"},
        "principal": {"id":"acme-corp"},
        "action": {"type":"purchase","target":"supplier.example",
                   "parameters":{"amount":8200,"currency":"USD"}},
        "authority": {"allowed_actions":["purchase"],
                      "constraints":{"max_amount":10000,"currency":"USD"}},
        "context": {"request_id":null,"timestamp":null,"source":"rest"},
        "grant": "eyJhbGciOiJFUzI1NiIs…" }'
```

## Reason codes

| Code | Meaning |
| --- | --- |
| `GRANT_MALFORMED` | Not a compact JWS, wrong `alg`/`typ`, missing `kid`, payload fails schema, or payload too deeply nested |
| `GRANT_PRINCIPAL_UNKNOWN` | No key registered for the grant's `iss` — including when no registry is configured at all |
| `GRANT_KEY_UNKNOWN` | The principal is registered but not under this `kid` |
| `GRANT_SIGNATURE_INVALID` | The signature does not verify against the registered key |
| `GRANT_NOT_YET_VALID` | `nbf` is in the future |
| `GRANT_EXPIRED` | `exp` has passed |
| `GRANT_LIFETIME_EXCESSIVE` | `exp − iat` exceeds 365 days |
| `GRANT_ISSUER_MISMATCH` | `iss` is not the request's `principal.id`, or the request names no principal |
| `GRANT_SUBJECT_MISMATCH` | `sub` is not the request's `agent.id` |
| `GRANT_AUDIENCE_MISMATCH` | `aud` is set and is not this deployment |
| `GRANT_AUTHORITY_MISMATCH` | The request's authority differs from the signed one |

All of them produce `BLOCK`. Signature failure and the three binding mismatches
score risk 1.0, because each of them is an attempt rather than an accident.

## Deliberate limits

- **No key fetching.** Keys are registered out of band, never retrieved at
  decision time. The authorization kernel makes no outbound request, so nobody
  who controls a network path can change, delay, or observe a decision. A
  `.well-known` JWKS fetch would be more convenient and would give that away.
- **No revocation list.** `jti` and `exp` are recorded in the receipt so a
  downstream system can refuse a known-bad grant, but Vizier itself has no
  revocation store. Short TTLs are the mechanism; rotation is the fallback.
- **Clock skew** is tolerated at 60 seconds on `nbf` and `exp`.
- **A grant proves delegation, not intent.** It says the principal authorised
  this shape of action for this agent. It does not say a human looked at this
  particular action — that is what the Action Covenant lifecycle and `REVIEW`
  are for.
- **The registry fails closed but stays up.** An unparseable
  `VIZIER_PRINCIPAL_KEYS` yields an empty registry: every grant is refused,
  while requests that carry no grant keep being served. A config typo should not
  take down traffic it has nothing to do with.

## Where this sits relative to the standards

A2A gives agents a verifiable identity through signed Agent Cards and delegates
authorization elsewhere. AP2 carries pre-signed payment mandates. Neither
answers, for an arbitrary action, "who authorised this agent to do this much of
this, and can I prove it after the fact." A delegation grant plus the receipt it
produces is one deterministic, offline-checkable answer to that question. It
depends on neither protocol and composes with both.

## Mandatory server policy (v0.5.6)

Set the operator-controlled Worker binding `VIZIER_SIGNED_GRANT_MODE` to
`required` for a deployment whose callers have been migrated to grants. Unset
or `optional` preserves the existing trusted-integration path. Every other
configured value, including an empty string or typo, blocks authorization with
`GRANT_POLICY_MISCONFIGURED`. Request fields and headers cannot downgrade the
server policy. Required mode blocks missing/unverifiable grants across REST,
both MCP profiles and A2A; unknown or malformed principal key registries also
fail to verify grants. `/docs` exposes `delegation.mode` and `grant_required`.

The existing covenant authorization contract has no grant field: it is blocked
in required mode, including attempts to use it as an alternative path. Human
review attestations are a separate explicit operator-approval workflow and are
not principal delegation grants. Source screening receipts are not permission
to execute. This switch does not remove direct access to downstream tools.

Before activation, register genuine owner public keys, issue short-lived grants
for each intended agent/authority, remove the agent's direct upstream route and
keep the signing key, upstream credential and proxy configuration outside the
agent's control. Do not reuse test keys. Test allow, missing/expired grant,
changed authority/target and service timeout in that actual boundary. Existing
Agenda gated deployment currently asserts authority; migrate it before enabling
required mode globally. A grant delegates a scope, not approval of every action
inside that scope. Revocation and durable global spending remain separate.

## Protected MCP proxy

An operator-supplied `delegationGrant` automatically selects strict proxy checks;
`requireSignedGrant: true` rejects startup if no grant/provider was configured.
A provider can load rotated grants for each call. The principal must sign this
exact authority for the proxy's configured agent:

```json
{
  "iss": "platform-team",
  "sub": "coding-agent-01",
  "authority": {
    "allowed_actions": ["mcp_tool_call"],
    "constraints": {
      "allowed_targets": ["mcp://filesystem/tools/write_file"]
    }
  }
}
```

Configure matching upstream ID, allowed tools, principal and agent:

```sh
VIZIER_PROXY_UPSTREAM_ID=filesystem \
VIZIER_PROXY_AGENT_ID=coding-agent-01 \
VIZIER_PROXY_PRINCIPAL_ID=platform-team \
VIZIER_PROXY_GRANT_MODE=required \
VIZIER_PROXY_GRANT_FILE=/operator-owned/grant.jws \
npx --no-install vizier-mcp-proxy --upstream https://mcp.example/mcp --tools write_file
```

The existing API/client/upstream credentials are configured separately. Store
only the compact grant in this file, not the private signing key. The CLI reads
a regular file of at most 32 KiB per tool call; rotate it with an atomic rename
before expiry. Missing, oversized or invalid replacement files stop forwarding.
Client tool arguments cannot replace the operator grant. The grant is sent to
Vizier only and is not forwarded to the upstream tool or included in proxy logs.

Even an ALLOW must carry `principal_signed` provenance, the intended identities,
an unexpired grant and a receipt hash bound to the exact request, before strict
proxy forwarding. Legacy `/v1/verify` receipts are unsigned: this path trusts the
configured verifier over HTTPS, not an offline receipt signature. Signature and
receipt binding do not independently prove source truth or prevent direct tool
access. External executors still need idempotency to prevent duplicate effects.
