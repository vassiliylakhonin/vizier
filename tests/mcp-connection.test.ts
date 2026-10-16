import { describe, expect, it, vi } from "vitest";
import { handleHttpRequest } from "../src/transport/http";

const VERSION = "2025-11-25";
const STATELESS = "2026-07-28";
const meta = {
  "io.modelcontextprotocol/protocolVersion": STATELESS,
  "io.modelcontextprotocol/clientCapabilities": {},
};

function post(method: string, params: Record<string, unknown> = {}, headers: Record<string, string> = {}, notification = false) {
  return new Request("https://vizier.example/mcp", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", ...(!notification ? { id: 1 } : {}), method, params }),
  });
}

describe("MCP connection recovery", () => {
  it("negotiates November 2025 and accepts its subsequent notification and tool listing", async () => {
    const init = await handleHttpRequest(post("initialize", {
      protocolVersion: VERSION, capabilities: {}, clientInfo: { name: "standard-client", version: "1" },
    }));
    expect(init.status).toBe(200);
    expect(await init.json()).toMatchObject({ result: { protocolVersion: VERSION } });
    const initialized = await handleHttpRequest(post("notifications/initialized", {}, { "MCP-Protocol-Version": VERSION }, true));
    expect(initialized.status).toBe(202);
    const listed = await handleHttpRequest(post("tools/list", {}, { "MCP-Protocol-Version": VERSION }));
    expect(listed.status).toBe(200);
    expect(await listed.json()).toMatchObject({ result: { tools: [{ name: "vizier_verify_action" }] } });
    const capabilities = await handleHttpRequest(new Request("https://vizier.example/mcp"));
    expect(await capabilities.json()).toMatchObject({ supported_protocol_versions: expect.arrayContaining([VERSION]) });
  });

  it("explains a stateless initialize mismatch instead of leaving an opaque 404", async () => {
    const result = await handleHttpRequest(post("initialize", { _meta: meta }, {
      "MCP-Protocol-Version": STATELESS, "Mcp-Method": "initialize",
    }));
    expect(result.status).toBe(404);
    expect(await result.json()).toMatchObject({ error: { code: -32601, data: { connection_hint: {
      reason: "profile_method_mismatch", endpoint: "/mcp", method: "POST",
      session: { start_with: "initialize", protocol_versions: expect.arrayContaining([VERSION]) },
      stateless: { start_with: "server/discover", protocol_version: STATELESS },
    } } } });
  });

  it("gives the exact mirrored header names without accepting an incomplete stateless request", async () => {
    const response = await handleHttpRequest(post("tools/list", { _meta: meta }, { "MCP-Protocol-Version": STATELESS }));
    expect(response.status).toBe(400);
    const body = await response.json() as { error: { data: { connection_hint: {
      stateless: { protocol_version: string; params_meta: Record<string, unknown> };
    } } } };
    expect(body).toMatchObject({ error: { data: { connection_hint: {
      reason: "header_mismatch", stateless: { required_headers: ["MCP-Protocol-Version", "Mcp-Method"] },
    } } } });
    const hint = body.error.data.connection_hint;
    const recovered = await handleHttpRequest(post("tools/list", { _meta: hint.stateless.params_meta }, {
      "MCP-Protocol-Version": hint.stateless.protocol_version, "Mcp-Method": "tools/list",
    }));
    expect(recovered.status).toBe(200);
    expect(await recovered.json()).toMatchObject({ result: { tools: [{ name: "vizier_verify_action" }] } });
  });

  it("records a finite failure reason without client text and rejects unknown protocol revisions", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const response = await handleHttpRequest(post("tools/list", { private: "private-document" }, {
        "MCP-Protocol-Version": "private-client-revision", "User-Agent": "private-client-agent",
      }));
      expect(response.status).toBe(400);
      const events = log.mock.calls.map(call => typeof call[0] === "string" ? JSON.parse(call[0]) : call[0]).filter(e => e.event === "agenda_service_access");
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({ operation: "tools/list", mcp_rejection: "unsupported_version", http_status: 400 });
      expect(JSON.stringify(events)).not.toContain("private-");
    } finally { log.mockRestore(); }
  });

  it("does not weaken enforcement authentication when November 2025 is selected", async () => {
    const response = await handleHttpRequest(post("tools/call", { name: "vizier_verify_action", arguments: {} }, {
      "MCP-Protocol-Version": VERSION, Authorization: "Bearer incorrect-key",
    }), { apiKey: "configured-enforcement-key" });
    expect(response.status).toBe(401);
  });
});
