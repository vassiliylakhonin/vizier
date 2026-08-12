# Claim ledger

Checked on 2026-08-12.

| Claim | Source | Exact support | Status |
| --- | --- | --- | --- |
| Public A2A discovery uses `/.well-known/agent-card.json`. | https://a2a-protocol.org/latest/topics/agent-discovery/ | The official discovery page names this standardized well-known URI. | supported |
| The Agent Card signature is a detached JWS with an unencoded payload and a protected `jku`. | https://www.rfc-editor.org/rfc/rfc7797.html and https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.2 | RFC 7797 defines `b64: false` with `crit`; RFC 7515 defines `jku` as a protected-header URL for the verification key set. | supported |
| The card payload is canonicalized before signing. | https://www.rfc-editor.org/rfc/rfc8785.html and local JWS tests | RFC 8785 defines deterministic JSON canonicalization; tests cover nested key ordering and signature verification against the published public JWK. | supported |
| The implemented A2A JSON-RPC interface uses protocol 1.0 and `SendMessage`. | https://a2a-protocol.org/latest/specification/ | Specification v1.0.1 defines `supportedInterfaces`, JSON-RPC 2.0, PascalCase method names, and `SendMessage`. | supported |
| MCP 2026-07-28 is stateless per request and requires `server/discover`. | https://modelcontextprotocol.io/specification/2026-07-28/basic/lifecycle | The official lifecycle page removes the negotiation handshake and requires `server/discover`. | supported |
| Modern MCP Streamable HTTP validates `Origin` and mirrored request headers. | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http | The official transport page requires `Origin`, `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` validation. | supported |
| Zod 4 can emit JSON Schema 2020-12 for the MCP tool definition. | https://zod.dev/json-schema | The official Zod page documents `z.toJSONSchema()` and Draft 2020-12 as the default target. | supported |
| Vizier has production users, pilots, or revenue. | none | No evidence exists. | unsupported |
| Vizier defaults to an evaluation mode that cannot return `ALLOW`. | local tests | REST, A2A, and MCP tests assert `REVIEW` without `VIZIER_API_KEY`. | supported |
| Vizier provides a complete principal identity or delegation boundary. | none | v0.1 authenticates only the configured integration; authority is still supplied by it. | unsupported |
| The private gated-deploy tool completed one Vizier-authorized Worker deployment. | Cloudflare Worker version history, checked 2026-08-09 | Version `954622cc-7251-4fa7-b820-0a5293f1066d` carries a `Vizier ALLOW receipt` deployment message. | supported |
| A signed Agent Card authenticates Vizier callers, delegations, or receipts. | none | The signature covers only the public Agent Card. | unsupported |
