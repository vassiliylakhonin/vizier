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
  it("provides executable read-only recovery requests for both mixed-profile failures", async () => {
    for (const revision of ["2025-06-18", VERSION, STATELESS]) {
      const response = await handleHttpRequest(post("initialize", {
        _meta: { ...meta, "io.modelcontextprotocol/protocolVersion": revision },
      }, { "MCP-Protocol-Version": revision, "Mcp-Method": "initialize" }));
      expect(response.status).toBe(revision === STATELESS ? 404 : 400);
      const body = await response.json() as { error: { data: { connection_hint: {
        recovery_requests: { profile: string; headers: Record<string, string>; body: unknown }[];
      } } } };
      const requests = body.error.data.connection_hint.recovery_requests;
      expect(requests).toHaveLength(2);
      for (const recovery of requests) {
        const recovered = await handleHttpRequest(new Request("https://vizier.example/mcp", {
          method: "POST", headers: recovery.headers, body: JSON.stringify(recovery.body),
        }));
        expect(recovered.status).toBe(200);
        expect(await recovered.json()).toHaveProperty("result");
        expect(JSON.stringify(recovery)).not.toContain("tools/call");
      }
    }
  });

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

describe('bounded MCP negotiation observations', () => {
  it('records only a finite self-declared software family and does not infer owner identity', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      for (const [name, family] of [['glama-client', 'glama'], ['private-client-name', 'other']]) {
        log.mockClear();
        await handleHttpRequest(post('initialize', {protocolVersion: VERSION, capabilities: {}, clientInfo: {name, version:'private-version'}}));
        const events = log.mock.calls.map(c => {try {return JSON.parse(c[0]);} catch {return null;}}).filter(e => e?.event === 'agenda_service_access');
        expect(events).toHaveLength(1);
        expect(events[0]).toMatchObject({mcp_client_family: family, caller_kind:'unsigned_external'});
        expect(JSON.stringify(events)).not.toContain('private-');
      }
    } finally {log.mockRestore();}
  });
  it('distinguishes a mixed stateless profile from an unknown session revision without client strings', async () => {
    const log=vi.spyOn(console,'log').mockImplementation(()=>{});
    try {
      for (const [params,headers,expected] of [
        [{_meta:{...meta,'io.modelcontextprotocol/protocolVersion':VERSION}}, {'MCP-Protocol-Version':VERSION,'Mcp-Method':'tools/list'},
          {mcp_profile:'stateless',mcp_header_revision:VERSION,mcp_body_revision:VERSION}],
        [{private:'private-prompt'}, {'MCP-Protocol-Version':'private-revision'},
          {mcp_profile:'session',mcp_header_revision:'other',mcp_body_revision:'missing'}],
        [{_meta:meta}, {'MCP-Protocol-Version':VERSION,'Mcp-Method':'tools/list'},
          {mcp_profile:'stateless',mcp_header_revision:VERSION,mcp_body_revision:STATELESS}],
      ] as const) {
        log.mockClear();
        const response=await handleHttpRequest(post('tools/list',params,headers));
        expect(response.status).toBe(400);
        const rows=log.mock.calls.map(c=>typeof c[0]==='string'?JSON.parse(c[0]):c[0]).filter(e=>e.event==='agenda_service_access');
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject(expected);
        expect(JSON.stringify(rows)).not.toContain('private-');
      }
    } finally {log.mockRestore()}
  });
  it('does not infer a profile from an unreadable or origin-refused request', async()=>{
    const log=vi.spyOn(console,'log').mockImplementation(()=>{});
    try {
      await handleHttpRequest(new Request('https://vizier.example/mcp',{method:'POST',headers:{Origin:'https://foreign.example','MCP-Protocol-Version':'private-revision'},body:'private-body'}));
      const rows=log.mock.calls.map(c=>typeof c[0]==='string'?JSON.parse(c[0]):c[0]).filter(e=>e.event==='agenda_service_access');
      expect(rows[0]).toMatchObject({mcp_profile:'unmeasured',mcp_header_revision:'unmeasured',mcp_body_revision:'unmeasured'});
      expect(JSON.stringify(rows)).not.toContain('private-');
    } finally {log.mockRestore()}
  });
});
