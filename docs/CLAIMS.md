# Claim ledger

Checked on 2026-08-24.

| Claim | Source | Exact support | Status |
| --- | --- | --- | --- |
| Public A2A discovery uses `/.well-known/agent-card.json`. | https://a2a-protocol.org/latest/topics/agent-discovery/ | The official discovery page names this standardized well-known URI. | supported |
| The Agent Card signature uses the A2A v1 `signatures[]` JWS shape and a protected same-origin `jku`. | https://a2a-protocol.org/latest/specification/#84-agent-card-signing | The official specification defines `AgentCardSignature`, requires `alg`, `typ`, and `kid`, permits `jku`, and verifies entries from `signatures[]`. | supported |
| The card payload is canonicalized and base64url-encoded before signing. | https://a2a-protocol.org/latest/specification/#84-agent-card-signing and local JWS tests | The official specification requires RFC 8785 canonicalization and signs `BASE64URL(protected) + "." + BASE64URL(payload)`; tests independently verify the result against the published public JWK. | supported |
| The implemented A2A JSON-RPC interface uses protocol 1.0 and `SendMessage`. | https://a2a-protocol.org/latest/specification/ | Specification v1.0.1 defines `supportedInterfaces`, JSON-RPC 2.0, PascalCase method names, and `SendMessage`. | supported |
| MCP 2026-07-28 is stateless per request and requires `server/discover`. | https://modelcontextprotocol.io/specification/2026-07-28/basic/lifecycle | The official lifecycle page removes the negotiation handshake and requires `server/discover`. | supported |
| Modern MCP Streamable HTTP validates `Origin` and mirrored request headers. | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http | The official transport page requires `Origin`, `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` validation. | supported |
| Zod 4 can emit JSON Schema 2020-12 for the MCP tool definition. | https://zod.dev/json-schema | The official Zod page documents `z.toJSONSchema()` and Draft 2020-12 as the default target. | supported |
| Vizier has production users, pilots, or revenue. | none | No evidence exists. | unsupported |
| Vizier evaluation mode cannot return `ALLOW`. | local tests | REST, A2A, and MCP tests assert `REVIEW` without authenticated authority; A2A tests also cover anonymous evaluation while `VIZIER_API_KEY` is configured and rejection of a wrong credential. | supported |
| Vizier provides a complete principal identity or delegation boundary. | none | v0.1 authenticates only the configured integration; authority is still supplied by it. | unsupported |
| The private gated-deploy tool completed one Vizier-authorized Worker deployment. | Cloudflare Worker version history, checked 2026-08-09 | Version `954622cc-7251-4fa7-b820-0a5293f1066d` carries a `Vizier ALLOW receipt` deployment message. | supported |
| A signed Agent Card authenticates Vizier callers, delegations, or receipts. | none | The signature covers only the public Agent Card. | unsupported |
| A model-produced Action Covenant draft can authorize itself. | local covenant tests | Activation rejects an acceptance from a different principal and rejects any draft changed after the accepted hash. | unsupported |
| Covenant authorization and outcome receipts are signed and bound to their inputs. | local covenant, REST, SDK, and JWS tests | Tests generate real P-256 keys, verify both compact JWS values through JWKS, recompute material hashes, and reject payload tampering. | supported |
| Vizier independently establishes that supplied evidence, signals, or outcomes are true and complete. | none | These inputs are asserted by the authenticated integration; v0.2 checks schema, freshness, exact matching, and binding only. | unsupported |
| Repository code alone establishes which API version is live. | none | Live state must be checked through the deployed `/docs` endpoint and Cloudflare deployment history. | unsupported |
