import { describe, expect, it, vi } from "vitest";

import type {
  VerificationRequest,
  VerificationResponse,
} from "../packages/sdk/src/index";
import {
  createMcpEnforcementProxy,
  MCP_PROTOCOL_VERSION,
  type McpProxyEvent,
} from "../packages/mcp-proxy/src/index";
import { Vizier } from "../packages/sdk/src/index";
import { handleHttpRequest } from "../src/transport/http";

function decision(
  value: VerificationResponse["decision"],
): VerificationResponse {
  const reasonCodes = value === "ALLOW" ? [] : ["TARGET_NOT_ALLOWED"];
  return {
    decision: value,
    risk_score: value === "ALLOW" ? 0 : 1,
    reason_codes: reasonCodes,
    explanation: "test decision",
    policy_results: [
      {
        rule_id: "target_scope",
        result: value === "ALLOW" ? "PASS" : "FAIL",
        reason_code: reasonCodes[0] ?? null,
        details: {},
      },
    ],
    receipt: {
      id: `vrf_${value.toLowerCase()}`,
      created_at: "2026-08-26T08:00:00Z",
      request_hash: "a".repeat(64),
      decision: value,
      risk_score: value === "ALLOW" ? 0 : 1,
      policy_rule_ids: ["target_scope"],
      reason_codes: reasonCodes,
    },
  };
}

function mcpBody(
  method: string,
  id: string | number,
  params: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id,
    method,
    params: {
      ...params,
      _meta: {
        "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {
          name: "proxy-test",
          version: "1.0.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
      },
    },
  };
}

function mcpRequest(body: Record<string, unknown>): Request {
  const params = body.params as Record<string, unknown>;
  const headers = new Headers({
    Accept: "application/json, text/event-stream",
    Authorization: "Bearer client-secret-that-must-not-be-forwarded",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
    "Mcp-Method": String(body.method),
  });
  if (body.method === "tools/call") {
    headers.set("Mcp-Name", String(params.name));
  }
  return new Request("http://127.0.0.1:8790/mcp", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

function proxyOptions(input: {
  verify?: (request: VerificationRequest) => Promise<VerificationResponse>;
  fetch?: typeof globalThis.fetch;
  log?: (event: McpProxyEvent) => void;
}) {
  return {
    integrationId: "pilot-acme",
    clientBearerToken: "client-secret-that-must-not-be-forwarded",
    upstreamId: "filesystem",
    upstreamUrl: "https://mcp.example/mcp",
    upstreamBearerToken: "upstream-secret",
    allowedTools: ["write_file"],
    agent: { id: "coding-agent-01", owner: "acme" },
    principal: { id: "platform-team" },
    verifier: {
      verify: input.verify ?? (async () => decision("ALLOW")),
    },
    fetch: input.fetch ?? vi.fn<typeof globalThis.fetch>(),
    log: input.log ?? vi.fn(),
    now: () => new Date("2026-08-26T08:00:00Z"),
  };
}

describe("MCP enforcement proxy", () => {
  it("filters discovery to the configured allowed tools", async () => {
    const upstreamFetch = vi.fn<typeof globalThis.fetch>(async (_url, init) => {
      const headers = new Headers(init?.headers);
      expect(headers.get("Authorization")).toBe(
        "Bearer upstream-secret",
      );
      expect(headers.has("Mcp-Name")).toBe(false);
      return Response.json({
        jsonrpc: "2.0",
        id: "list-1",
        result: {
          tools: [
            { name: "write_file", description: "Write a file" },
            { name: "delete_file", description: "Delete a file" },
          ],
        },
      });
    });
    const proxy = createMcpEnforcementProxy(
      proxyOptions({ fetch: upstreamFetch }),
    );

    const request = mcpRequest(mcpBody("tools/list", "list-1"));
    request.headers.set("Mcp-Name", "delete_file");
    const response = await proxy.handle(request);

    await expect(response.json()).resolves.toMatchObject({
      result: { tools: [{ name: "write_file" }] },
    });
    expect(upstreamFetch).toHaveBeenCalledOnce();
  });

  it("returns private proxy discovery without exposing upstream metadata", async () => {
    const upstreamFetch = vi.fn<typeof globalThis.fetch>();
    const proxy = createMcpEnforcementProxy(
      proxyOptions({ fetch: upstreamFetch }),
    );

    const response = await proxy.handle(
      mcpRequest(mcpBody("server/discover", "discover-1")),
    );

    await expect(response.json()).resolves.toMatchObject({
      id: "discover-1",
      result: {
        supportedVersions: [MCP_PROTOCOL_VERSION],
        capabilities: { tools: { listChanged: false } },
        cacheScope: "private",
      },
    });
    expect(upstreamFetch).not.toHaveBeenCalled();
  });

  it("binds exact tool arguments and forwards only after ALLOW", async () => {
    const verify = vi.fn(async (request: VerificationRequest) => {
      expect(request).toMatchObject({
        action: {
          type: "mcp_tool_call",
          target: "mcp://filesystem/tools/write_file",
          parameters: {
            tool_name: "write_file",
            arguments: { path: "notes.txt", content: "approved" },
          },
        },
        authority: {
          allowed_actions: ["mcp_tool_call"],
          constraints: {
            allowed_targets: ["mcp://filesystem/tools/write_file"],
          },
        },
        context: {
          request_id: "pilot-acme:call-1",
          timestamp: "2026-08-26T08:00:00.000Z",
          source: "mcp",
        },
      });
      return decision("ALLOW");
    });
    const upstreamFetch = vi.fn<typeof globalThis.fetch>(async (_url, init) => {
      const headers = new Headers(init?.headers);
      expect(headers.get("Authorization")).toBe("Bearer upstream-secret");
      expect(headers.get("Authorization")).not.toContain("client-secret");
      expect(JSON.parse(String(init?.body))).toMatchObject({
        method: "tools/call",
        params: {
          name: "write_file",
          arguments: { path: "notes.txt", content: "approved" },
        },
      });
      return Response.json({
        jsonrpc: "2.0",
        id: "call-1",
        result: { content: [{ type: "text", text: "written" }] },
      });
    });
    const events: McpProxyEvent[] = [];
    const proxy = createMcpEnforcementProxy(
      proxyOptions({ verify, fetch: upstreamFetch, log: (event) => events.push(event) }),
    );
    const body = mcpBody("tools/call", "call-1", {
      name: "write_file",
      arguments: { path: "notes.txt", content: "approved" },
    });

    const response = await proxy.handle(mcpRequest(body));

    await expect(response.json()).resolves.toMatchObject({
      result: { content: [{ text: "written" }] },
    });
    expect(verify).toHaveBeenCalledOnce();
    expect(upstreamFetch).toHaveBeenCalledOnce();
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      integration_id: "pilot-acme",
      tool_name: "write_file",
      outcome: "forwarded",
      decision: "ALLOW",
      receipt_id: "vrf_allow",
    });
    expect(JSON.stringify(events[0])).not.toContain("approved");
  });

  it.each(["REVIEW", "BLOCK"] as const)(
    "does not forward a %s decision",
    async (decisionValue) => {
      const upstreamFetch = vi.fn<typeof globalThis.fetch>();
      const proxy = createMcpEnforcementProxy(
        proxyOptions({
          verify: async () => decision(decisionValue),
          fetch: upstreamFetch,
        }),
      );
      const response = await proxy.handle(
        mcpRequest(
          mcpBody("tools/call", "denied-1", {
            name: "write_file",
            arguments: { path: "notes.txt" },
          }),
        ),
      );

      await expect(response.json()).resolves.toMatchObject({
        error: {
          code: -32003,
          data: { code: "VIZIER_DENIED", decision: decisionValue },
        },
      });
      expect(upstreamFetch).not.toHaveBeenCalled();
    },
  );

  it("fails closed when Vizier is unavailable", async () => {
    const upstreamFetch = vi.fn<typeof globalThis.fetch>();
    const proxy = createMcpEnforcementProxy(
      proxyOptions({
        verify: async () => {
          throw new Error("network down");
        },
        fetch: upstreamFetch,
      }),
    );

    const response = await proxy.handle(
      mcpRequest(
        mcpBody("tools/call", "unavailable-1", {
          name: "write_file",
          arguments: { path: "notes.txt", content: "blocked" },
        }),
      ),
    );

    await expect(response.json()).resolves.toMatchObject({
      error: { code: -32004, data: { code: "VIZIER_UNAVAILABLE" } },
    });
    expect(upstreamFetch).not.toHaveBeenCalled();
  });

  it("blocks a tool outside the local allowlist before verification", async () => {
    const verify = vi.fn(async () => decision("ALLOW"));
    const upstreamFetch = vi.fn<typeof globalThis.fetch>();
    const proxy = createMcpEnforcementProxy(
      proxyOptions({ verify, fetch: upstreamFetch }),
    );

    const response = await proxy.handle(
      mcpRequest(
        mcpBody("tools/call", "local-block-1", {
          name: "delete_file",
          arguments: { path: "notes.txt" },
        }),
      ),
    );

    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: -32003,
        data: { code: "TOOL_NOT_ALLOWED", decision: "BLOCK" },
      },
    });
    expect(verify).not.toHaveBeenCalled();
    expect(upstreamFetch).not.toHaveBeenCalled();
  });

  it("rejects an unauthenticated tool call before verification", async () => {
    const verify = vi.fn(async () => decision("ALLOW"));
    const upstreamFetch = vi.fn<typeof globalThis.fetch>();
    const proxy = createMcpEnforcementProxy(
      proxyOptions({ verify, fetch: upstreamFetch }),
    );
    const request = mcpRequest(
      mcpBody("tools/call", "auth-1", {
        name: "write_file",
        arguments: { path: "notes.txt", content: "blocked" },
      }),
    );
    request.headers.set("Authorization", "Bearer wrong-client-token");

    const response = await proxy.handle(request);

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: -32001 },
    });
    expect(verify).not.toHaveBeenCalled();
    expect(upstreamFetch).not.toHaveBeenCalled();
  });

  it("does not expose authenticated upstream discovery without a client token", async () => {
    const upstreamFetch = vi.fn<typeof globalThis.fetch>();
    const proxy = createMcpEnforcementProxy(
      proxyOptions({ fetch: upstreamFetch }),
    );
    const request = mcpRequest(mcpBody("tools/list", "list-auth-1"));
    request.headers.delete("Authorization");

    const response = await proxy.handle(request);

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: -32001 },
    });
    expect(upstreamFetch).not.toHaveBeenCalled();
  });

  it("does not expose an invalid upstream response after authorization", async () => {
    const proxy = createMcpEnforcementProxy(
      proxyOptions({
        fetch: vi.fn(async () => new Response("not-json", { status: 502 })),
      }),
    );

    const response = await proxy.handle(
      mcpRequest(
        mcpBody("tools/call", "upstream-1", {
          name: "write_file",
          arguments: { path: "notes.txt", content: "approved" },
        }),
      ),
    );

    await expect(response.json()).resolves.toMatchObject({
      error: { code: -32005, data: { code: "UPSTREAM_FAILED" } },
    });
  });

  it("rejects duplicate tool names at the configuration boundary", () => {
    expect(() =>
      createMcpEnforcementProxy({
        ...proxyOptions({}),
        allowedTools: ["write_file", "write_file"],
      }),
    ).toThrowError("allowedTools must contain unique tool names.");
  });

  it("rejects a non-loopback plaintext upstream", () => {
    expect(() =>
      createMcpEnforcementProxy({
        ...proxyOptions({}),
        upstreamUrl: "http://mcp.example/mcp",
      }),
    ).toThrowError("A non-loopback upstreamUrl must use https.");
  });

  it("rejects a cross-origin browser request", async () => {
    const proxy = createMcpEnforcementProxy(proxyOptions({}));
    const request = mcpRequest(mcpBody("tools/list", "origin-1"));
    request.headers.set("Origin", "https://attacker.example");

    const response = await proxy.handle(request);

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: -32020 },
    });
  });

  it("rejects structurally deep request JSON", async () => {
    const proxy = createMcpEnforcementProxy(proxyOptions({}));
    let nested: unknown = "leaf";
    for (let depth = 0; depth < 68; depth += 1) {
      nested = [nested];
    }
    const body = mcpBody("tools/list", "depth-1");
    const params = body.params as Record<string, unknown>;
    params.extra = nested;

    const response = await proxy.handle(mcpRequest(body));

    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: -32600 },
    });
  });

  it("rejects request JSON with too many aggregate values", async () => {
    const proxy = createMcpEnforcementProxy(proxyOptions({}));
    const body = mcpBody("tools/list", "nodes-1");
    const params = body.params as Record<string, unknown>;
    params.extra = Array(50_000).fill(null);

    const response = await proxy.handle(mcpRequest(body));

    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: -32600 },
    });
  });

  it("integrates with the real SDK and authorization kernel", async () => {
    const apiKey = "test-enforcement-key";
    const verifier = new Vizier({
      baseUrl: "https://vizier.example",
      apiKey,
      fetch: async (input, init) =>
        handleHttpRequest(new Request(input, init), { apiKey }),
    });
    const upstreamFetch = vi.fn<typeof globalThis.fetch>(async () =>
      Response.json({
        jsonrpc: "2.0",
        id: "integration-1",
        result: { content: [{ type: "text", text: "executed" }] },
      }),
    );
    const proxy = createMcpEnforcementProxy({
      ...proxyOptions({ fetch: upstreamFetch }),
      verifier,
    });

    const response = await proxy.handle(
      mcpRequest(
        mcpBody("tools/call", "integration-1", {
          name: "write_file",
          arguments: { path: "notes.txt", content: "approved" },
        }),
      ),
    );

    await expect(response.json()).resolves.toMatchObject({
      result: { content: [{ text: "executed" }] },
    });
    expect(upstreamFetch).toHaveBeenCalledOnce();
  });
});
