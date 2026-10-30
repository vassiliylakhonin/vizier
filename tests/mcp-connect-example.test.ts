import { describe, expect, it } from "vitest";
import { connectMcp } from "../examples/mcp-connect";
import { handleHttpRequest } from "../src/transport/http";

describe("copyable MCP connection example", () => {
  for (const profile of ["session", "stateless"] as const) {
    it(`executes the ${profile} lifecycle against the real HTTP handler without an action`, async () => {
      const calls: Request[] = [];
      const fetchImpl: typeof fetch = async (input, init) => {
        const request = new Request(input, init); calls.push(request.clone());
        return handleHttpRequest(request, { apiKey: "protected-action-key" });
      };
      const result = await connectMcp("https://vizier.example", profile, { fetchImpl });
      expect(result).toMatchObject({ profile, tools: ["vizier_verify_action"], discoveryOnly: true,
        authorizationGranted: false });
      const bodies = await Promise.all(calls.filter(call => call.method === "POST")
        .map(async call => await call.json() as { method: string }));
      expect(bodies.map(body => body.method)).toEqual(profile === "session"
        ? ["initialize", "notifications/initialized", "tools/list"] : ["server/discover", "tools/list"]);
      expect(calls.every(call => !call.headers.has("Authorization") && !call.headers.has("X-Client-Id"))).toBe(true);
      expect(calls.every(call => call.redirect === "error")).toBe(true);
    });
  }
  it("marks only explicit owner checks", async () => {
    const markers: (string | null)[] = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const request = new Request(input, init); markers.push(request.headers.get("X-Client-Id"));
      return handleHttpRequest(request);
    };
    await connectMcp("https://vizier.example", "stateless", { fetchImpl, ownerCheck: true });
    expect(markers).toEqual(Array(3).fill("agenda-owner-vizier-connect-example"));
  });
  it("stops on an HTTP refusal without retrying or switching profiles", async () => {
    let calls = 0;
    const fetchImpl: typeof fetch = async (input, init) => {
      calls++;
      return calls === 1 ? handleHttpRequest(new Request(input, init)) : new Response("refused", { status: 400 });
    };
    await expect(connectMcp("https://vizier.example", "session", { fetchImpl })).rejects.toThrow("No retry performed");
    expect(calls).toBe(2);
  });
  it.each([
    ["2025-06-18", "unsupported_version", "session"],
    ["2026-07-28", "profile_method_mismatch", "stateless"],
  ])("exposes a safe recovery hint for a %s mixed-profile refusal", async (revision, reason, profile) => {
    let calls = 0;
    const fetchImpl: typeof fetch = async (input, init) => {
      calls++;
      if (calls === 1) return handleHttpRequest(new Request(input, init));
      return handleHttpRequest(new Request("https://vizier.example/mcp", {
        method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream",
          "MCP-Protocol-Version": revision, "Mcp-Method": "initialize" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { _meta: {
          "io.modelcontextprotocol/protocolVersion": revision, "io.modelcontextprotocol/clientCapabilities": {},
        } } }),
      }));
    };
    await expect(connectMcp("https://vizier.example", "session", { fetchImpl })).rejects.toMatchObject({
      reason, recommendedProfile: profile, recommendedVersion: revision,
    });
    expect(calls).toBe(2);
  });
  it("does not print or follow untrusted recovery content", async () => {
    let calls = 0;
    const fetchImpl: typeof fetch = async (input, init) => {
      calls++;
      if (calls === 1) return handleHttpRequest(new Request(input, init));
      return Response.json({error:{data:{connection_hint:{reason:"private-agent-token",
        recommended_profile:"session", recommended_protocol_version:"2025-11-25",
        recovery_requests:[{endpoint:"https://foreign.example",body:{method:"tools/call"}}]}}}}, {status:400});
    };
    try { await connectMcp("https://vizier.example", "session", { fetchImpl }); throw new Error("Expected refusal"); }
    catch (error) {
      expect(String(error)).not.toContain("private-agent-token");
      expect(error).toMatchObject({reason:null, recommendedProfile:null, recommendedVersion:null});
    }
    expect(calls).toBe(2);
  });
  it("bounds a large refusal and stops without retry", async () => {
    let calls=0;
    const fetchImpl: typeof fetch=async (input,init)=>{
      calls++;
      return calls===1 ? handleHttpRequest(new Request(input,init)) : new Response("x".repeat(100_000),{status:400});
    };
    await expect(connectMcp("https://vizier.example","session",{fetchImpl})).rejects.toMatchObject({reason:null});
    expect(calls).toBe(2);
  });
  it("never follows executable content from a discovery guide", async () => {
    const urls: string[] = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const request = new Request(input, init); urls.push(request.url);
      if (request.method === "GET") return Response.json({ connection_guide: {
        stateless: { protocol_version: "2026-07-28" },
        recovery_requests: [{ endpoint: "https://foreign.example", body: { method: "tools/call" },
          headers: { Authorization: "untrusted-text" } }],
      } });
      return handleHttpRequest(request);
    };
    await connectMcp("https://vizier.example", "stateless", { fetchImpl });
    expect(urls).toEqual(["https://vizier.example/.well-known/mcp-probing.json", "https://vizier.example/mcp",
      "https://vizier.example/mcp"]);
  });
});
