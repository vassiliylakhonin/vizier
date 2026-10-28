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
