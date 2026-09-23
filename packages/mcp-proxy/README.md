# @vizier/mcp-proxy

Deterministic authorization proxy for [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers and AI agents.

Place any existing local or remote MCP server behind Vizier to enforce strict deterministic authority limits, tool allowlists, target restrictions, and tamper-proof SHA-256 audit receipts before actions execute.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

---

## ⚡ Quickstart

Install both GitHub Release archives, then run the installed proxy:

```bash
npm install https://github.com/vassiliylakhonin/vizier/releases/download/v0.5.2/vizier-sdk-0.5.2.tgz https://github.com/vassiliylakhonin/vizier/releases/download/v0.5.2/vizier-mcp-proxy-0.5.2.tgz
npx --no-install vizier-mcp-proxy \
  --upstream http://localhost:3000/mcp \
  --tools "query_db,execute_command,fetch_api" \
  --vizier https://vizier.vassiliy-lakhonin.workers.dev \
  --api-key $VIZIER_API_KEY
```

Your AI agent (Claude Desktop, Cursor, LangChain, etc.) now connects to `http://127.0.0.1:8790/mcp` instead of the raw upstream MCP server.

---

## 🛡️ How It Works

```
Agent (Claude / Cursor / Framework)
               │  JSON-RPC 2.0 (tools/call)
               ▼
   ┌───────────────────────┐
   │   @vizier/mcp-proxy   │
   └───────────┬───────────┘
               │  POST /v1/verify
               ▼
   ┌───────────────────────┐
   │  Vizier Kernel (Edge) │  ──► ALLOW / BLOCK / REVIEW
   └───────────┬───────────┘
               │
      [ If Decision == ALLOW ]
               │
               ▼
      Upstream MCP Server
```

1. **Discovery Filtering**: Responses to `tools/list` are automatically filtered to only expose the tools configured in `--tools`.
2. **Deterministic Interception**: Calls to `tools/call` are intercepted and evaluated against Vizier's deterministic policy kernel.
3. **Fail-Closed**: If Vizier returns `BLOCK` or `REVIEW`, the proxy halts execution and returns a standard JSON-RPC 2.0 error to the agent without ever calling the upstream server.
4. **Credential Isolation**: Incoming agent bearer tokens are authenticated and replaced with upstream credentials before forwarding.
5. **Loop Killer & Circuit Breaker**: Tracks tool call signatures via canonical JSON hashes in a sliding window. If an agent calls the same tool repeatedly with identical parameters, the proxy trips immediately with JSON-RPC error `-32028` (`CIRCUIT_TRIPPED:LOOP_DETECTED`), protecting against runaway LLM loops and burning API credits.

---

## 💻 Programmatic Usage

```typescript
import { createMcpEnforcementProxy } from "@vizier/mcp-proxy";
import { Vizier } from "@vizier/sdk";

const proxy = createMcpEnforcementProxy({
  integrationId: "agent-mcp-gateway",
  clientBearerToken: "your-client-token-min-16-chars",
  upstreamId: "production-db",
  upstreamUrl: "http://localhost:3000/mcp",
  allowedTools: ["read_records", "write_record"],
  agent: { id: "data-analyst-agent", owner: "acme" },
  principal: { id: "platform-team" },
  verifier: new Vizier({ apiKey: process.env.VIZIER_API_KEY! }),
  // Enable Agent Circuit Breaker & Loop Killer:
  circuitBreaker: {
    maxRepeats: 3,     // Max repeated identical calls before tripping
    windowMs: 30_000,  // Sliding window (30 seconds)
  },
});
```

---

## ⚙️ CLI Options

| Flag | Env Variable | Default | Description |
| --- | --- | --- | --- |
| `--upstream <url>` | `VIZIER_PROXY_UPSTREAM_URL` | *(required)* | Upstream MCP server URL |
| `--tools <list>` | `VIZIER_PROXY_ALLOWED_TOOLS` | *(required)* | Comma-separated list of allowed tools |
| `--vizier <url>` | `VIZIER_BASE_URL` | `https://vizier.vassiliy-lakhonin.workers.dev` | Vizier authorization kernel URL |
| `--api-key <key>` | `VIZIER_API_KEY` | *(required)* | Vizier integration API key |
| `--port <port>` | `VIZIER_PROXY_PORT` | `8790` | Proxy listen port |
| `--host <host>` | `VIZIER_PROXY_HOST` | `127.0.0.1` | Proxy listen host (`127.0.0.1` or `localhost`) |
| `--token <token>` | `VIZIER_PROXY_CLIENT_TOKEN` | *(auto-generated)* | Bearer token required from agent |
| `--upstream-token <token>`| `VIZIER_PROXY_UPSTREAM_BEARER_TOKEN` | `none` | Optional Bearer token for upstream |
| `--agent-id <id>` | `VIZIER_PROXY_AGENT_ID` | `agent` | Agent identifier for audit log |
| `--principal-id <id>` | `VIZIER_PROXY_PRINCIPAL_ID` | `principal` | Principal identifier |
| `-h, --help` | — | — | Show CLI help message |

---

## 🔒 Security

* **Loopback by default**: Listens on `127.0.0.1` to prevent unintended external exposure.
* **Payload size limit**: Enforces a strict 64 KB incoming request body ceiling (`HTTP 413`) to prevent memory exhaustion attacks.
* **No plaintext credentials in logs**: Tokens and secrets are stripped from operational event logging.

---

## 🌐 Links

* **Live Action Playground**: [https://vizier.vassiliy-lakhonin.workers.dev/playground](https://vizier.vassiliy-lakhonin.workers.dev/playground)
* **GitHub Repository**: [https://github.com/vassiliylakhonin/vizier](https://github.com/vassiliylakhonin/vizier)
