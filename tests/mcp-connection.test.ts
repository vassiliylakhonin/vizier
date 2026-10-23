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
  it("publishes executable profile-specific connections before a failed request", async () => {
    for (const path of ["/mcp", "/.well-known/mcp-probing.json"]) {
      const document = await handleHttpRequest(new Request(`https://vizier.example${path}`));
      expect(document.status).toBe(200);
      const body = await document.json() as { connection_guide: ReturnType<typeof import("../src/transport/mcp-profiles").connectionGuide> };
      const guide = body.connection_guide;
      expect(guide).toMatchObject({ recommended_profile: "session", recommended_protocol_version: VERSION, automatic_retry: false });
      expect(guide).not.toHaveProperty("reason");
      expect(guide.recovery_requests).toHaveLength(2);
      for (const sequence of guide.recovery_requests) {
        expect(sequence.body.method).toBe(sequence.profile === "session" ? "initialize" : "server/discover");
        expect(JSON.stringify(sequence)).not.toContain("tools/call");
        for (const step of [sequence, ...sequence.follow_up_requests]) {
          const response = await handleHttpRequest(new Request(`https://vizier.example${step.endpoint}`, {
            method: step.method, headers: step.headers, body: JSON.stringify(step.body),
          }));
          expect(response.status).toBe(step.body.method === "notifications/initialized" ? 202 : 200);
          if (step.body.method === "tools/list") {
            expect(await response.json()).toMatchObject({ result: { tools: [{ name: "vizier_verify_action" }] } });
          }
        }
      }
    }
  });

  it("recommends stateless discovery for the current body revision and never echoes unknown revisions in hints",async()=>{
    for (const revision of [STATELESS,"private-client-revision"]) {
      const response=await handleHttpRequest(post("initialize",{_meta:{...meta,
        "io.modelcontextprotocol/protocolVersion":revision}},{"MCP-Protocol-Version":revision,"Mcp-Method":"initialize"}));
      const body=await response.json() as {error:{data:{connection_hint:{recommended_profile:string;
        recovery_requests:{profile:string;headers:Record<string,string>;body:unknown;
          follow_up_requests:{headers:Record<string,string>;body:unknown}[]}[]}}}};
      const hint=body.error.data.connection_hint;
      expect(hint.recommended_profile).toBe(revision===STATELESS?"stateless":"session");
      expect(JSON.stringify(hint)).not.toContain("private-");
      const recovery=hint.recovery_requests.find(r=>r.profile===hint.recommended_profile)!;
      for(const step of [recovery,...recovery.follow_up_requests]) {
        const recovered=await handleHttpRequest(new Request("https://vizier.example/mcp",{
          method:"POST",headers:step.headers,body:JSON.stringify(step.body)}));
        expect([200,202]).toContain(recovered.status);
      }
    }
  });

  it("preserves a recognized session revision and supplies its full read-only recovery sequence", async () => {
    for (const revision of ["2025-06-18", VERSION]) {
      const rejected=await handleHttpRequest(post("initialize",{_meta:{...meta,
        "io.modelcontextprotocol/protocolVersion":revision}},
        {"MCP-Protocol-Version":revision,"Mcp-Method":"initialize"}));
      expect(rejected.status).toBe(400);
      const body=await rejected.json() as {error:{data:{connection_hint:{recommended_profile:string;
        recommended_protocol_version:string;automatic_retry:boolean;recovery_requests:{profile:string;headers:Record<string,string>;
          body:unknown;follow_up_requests:{headers:Record<string,string>;body:unknown}[]}[]}}}};
      const hint=body.error.data.connection_hint;
      expect(hint.recommended_profile).toBe("session");
      expect(hint.recommended_protocol_version).toBe(revision);
      expect(hint.automatic_retry).toBe(false);
      const recovery=hint.recovery_requests.find(item=>item.profile==="session")!;
      expect(recovery.body).toMatchObject({method:"initialize",params:{protocolVersion:revision}});
      for (const step of [recovery,...recovery.follow_up_requests]) {
        const response=await handleHttpRequest(new Request("https://vizier.example/mcp",{
          method:"POST",headers:step.headers,body:JSON.stringify(step.body)}));
        expect([200,202]).toContain(response.status);
        if(response.status===200)expect(await response.json()).toHaveProperty("result");
      }
      expect(JSON.stringify(recovery)).not.toContain("tools/call");
    }
  });

  it('keeps ordinary session progress metadata in the session profile',async()=>{
    for (const method of ['initialize','tools/list']) {
      const params={...(method==='initialize'?{protocolVersion:VERSION,capabilities:{},clientInfo:{name:'standard-client',version:'1'}}:{}),
        _meta:{progressToken:'private-progress-token'}};
      const response=await handleHttpRequest(post(method,params,{'MCP-Protocol-Version':VERSION}));
      expect(response.status).toBe(200);
      expect(await response.json()).toHaveProperty('result');
    }
  });
  it('offers executable discovery, never an action replay, after an unknown tool in either profile', async () => {
    for (const profile of ['session','session-progress','stateless']) {
      const headers: Record<string,string> = profile==='stateless' ? {'MCP-Protocol-Version':STATELESS,'Mcp-Method':'tools/call','Mcp-Name':'private-unknown-tool'}
        : {'MCP-Protocol-Version':VERSION};
      const params = {name:'private-unknown-tool',arguments:{private:'private-request'},
        ...(profile==='stateless'?{_meta:meta}:profile==='session-progress'?{_meta:{progressToken:'private-progress-token'}}:{})};
      const response=await handleHttpRequest(post('tools/call',params,headers));
      const body=await response.json() as {error:{data:{tool_hint:{recovery_request:{headers:Record<string,string>;body:unknown}}}}};
      expect(body.error.data.tool_hint).toMatchObject({available_tools:['vizier_verify_action'],automatic_tool_retry:false});
      const recovery=body.error.data.tool_hint.recovery_request;
      expect(recovery.headers['MCP-Protocol-Version']).toBe(profile==='stateless'?STATELESS:VERSION);
      expect(recovery.body).toMatchObject({method:'tools/list'});
      expect(JSON.stringify(body)).not.toContain('private-');
      const listed=await handleHttpRequest(new Request('https://vizier.example/mcp',{
        method:'POST',headers:recovery.headers,body:JSON.stringify(recovery.body)}));
      expect(listed.status).toBe(200);
      expect(await listed.json()).toMatchObject({result:{tools:[{name:'vizier_verify_action'}]}});
    }
  });
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
