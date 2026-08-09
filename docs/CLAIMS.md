# Claim ledger

Checked on 2026-08-09.

| Claim | Source | Exact support | Status |
| --- | --- | --- | --- |
| Public A2A discovery uses `/.well-known/agent-card.json`. | https://a2a-protocol.org/latest/topics/agent-discovery/ | The official discovery page names this standardized well-known URI. | supported |
| The implemented A2A JSON-RPC interface uses protocol 1.0 and `SendMessage`. | https://a2a-protocol.org/latest/specification/ | Specification v1.0.1 defines `supportedInterfaces`, JSON-RPC 2.0, PascalCase method names, and `SendMessage`. | supported |
| MCP 2026-07-28 is stateless per request and requires `server/discover`. | https://modelcontextprotocol.io/specification/2026-07-28/basic/lifecycle | The official lifecycle page removes the negotiation handshake and requires `server/discover`. | supported |
| Modern MCP Streamable HTTP validates `Origin` and mirrored request headers. | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http | The official transport page requires `Origin`, `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` validation. | supported |
| Zod 4 can emit JSON Schema 2020-12 for the MCP tool definition. | https://zod.dev/json-schema | The official Zod page documents `z.toJSONSchema()` and Draft 2020-12 as the default target. | supported |
| Vizier has production users, pilots, or revenue. | none | No evidence exists. | unsupported |
| Vizier defaults to an evaluation mode that cannot return `ALLOW`. | local tests | REST, A2A, and MCP tests assert `REVIEW` without `VIZIER_API_KEY`. | supported |
| Vizier provides a complete principal identity or delegation boundary. | none | v0.1 authenticates only the configured integration; authority is still supplied by it. | unsupported |
