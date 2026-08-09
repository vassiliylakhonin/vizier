import { describe, expect, it, vi } from "vitest";

import { handleMcpRequest } from "../src/transport/mcp";
import { handleHttpRequest } from "../src/transport/http";

const MCP_VERSION = "2026-07-28";
const TEST_API_KEY = "test-enforcement-key";

function verificationInput(): Record<string, unknown> {
  return {
    agent: { id: "procurement-agent-01", owner: "acme-corp" },
    principal: { id: "acme-corp" },
    action: {
      type: "purchase",
      target: "supplier.example",
      parameters: { amount: 8_200, currency: "USD" },
    },
    authority: {
      allowed_actions: ["purchase"],
      constraints: { max_amount: 10_000, currency: "USD" },
    },
    context: {
      request_id: "mcp-request-01",
      timestamp: "2026-08-09T08:00:00Z",
      source: "mcp",
    },
  };
}

function requestBody(
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
        "io.modelcontextprotocol/protocolVersion": MCP_VERSION,
        "io.modelcontextprotocol/clientInfo": {
          name: "vizier-tests",
          version: "1.0.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
      },
    },
  };
}

function mcpRequest(
  body: Record<string, unknown>,
  overrides: Record<string, string> = {},
): Request {
  const params = body.params as Record<string, unknown>;
  const headers: Record<string, string> = {
    Accept: "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": MCP_VERSION,
    "Mcp-Method": String(body.method),
    Authorization: `Bearer ${TEST_API_KEY}`,
  };
  if (body.method === "tools/call" && typeof params.name === "string") {
    headers["Mcp-Name"] = params.name;
  }
  return new Request("https://vizier.example/mcp", {
    method: "POST",
    headers: { ...headers, ...overrides },
    body: JSON.stringify(body),
  });
}

describe("MCP 2026-07-28 Streamable HTTP", () => {
  it("implements mandatory stateless server discovery", async () => {
    const response = await handleMcpRequest(
      mcpRequest(requestBody("server/discover", "discover-01")),
    );
    const body = (await response.json()) as {
      id: string;
      result: {
        resultType: string;
        supportedVersions: string[];
        capabilities: { tools: { listChanged: boolean } };
      };
    };

    expect(response.status).toBe(200);
    expect(body.id).toBe("discover-01");
    expect(body.result.resultType).toBe("complete");
    expect(body.result.supportedVersions).toEqual([MCP_VERSION]);
    expect(body.result.capabilities.tools.listChanged).toBe(false);
  });

  it("lists one deterministic tool with JSON Schema 2020-12 input", async () => {
    const response = await handleMcpRequest(
      mcpRequest(requestBody("tools/list", "list-01")),
    );
    const body = (await response.json()) as {
      result: {
        tools: Array<{
          name: string;
          inputSchema: { $schema?: string; type?: string };
        }>;
      };
    };

    expect(body.result.tools).toHaveLength(1);
    expect(body.result.tools[0]?.name).toBe("vizier_verify_action");
    expect(body.result.tools[0]?.inputSchema.type).toBe("object");
    expect(body.result.tools[0]?.inputSchema.$schema).toContain("2020-12");
  });

  it("calls the verification tool and returns structured content", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const body = requestBody("tools/call", 7, {
      name: "vizier_verify_action",
      arguments: verificationInput(),
    });
    const response = await handleMcpRequest(mcpRequest(body), {
      apiKey: TEST_API_KEY,
    });
    const result = (await response.json()) as {
      id: number;
      result: {
        resultType: string;
        isError: boolean;
        structuredContent: { decision: string; receipt: { id: string } };
      };
    };

    expect(result.id).toBe(7);
    expect(result.result.resultType).toBe("complete");
    expect(result.result.isError).toBe(false);
    expect(result.result.structuredContent.decision).toBe("ALLOW");
    expect(result.result.structuredContent.receipt.id).toMatch(/^vrf_/);
  });

  it("returns REVIEW for an open tools/call evaluation", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const body = requestBody("tools/call", "evaluation-01", {
      name: "vizier_verify_action",
      arguments: verificationInput(),
    });
    const response = await handleMcpRequest(mcpRequest(body));

    await expect(response.json()).resolves.toMatchObject({
      result: { structuredContent: { decision: "REVIEW" } },
    });
  });

  it("rejects an invalid enforcement credential for tools/call", async () => {
    const body = requestBody("tools/call", "auth-01", {
      name: "vizier_verify_action",
      arguments: verificationInput(),
    });
    const response = await handleMcpRequest(
      mcpRequest(body, { Authorization: "Bearer wrong-key" }),
      { apiKey: TEST_API_KEY },
    );

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: -32001 },
    });
  });

  it.each([
    [{ "MCP-Protocol-Version": "2025-11-25" }, -32020],
    [{ "Mcp-Method": "tools/list" }, -32020],
    [{ "Mcp-Name": "wrong_tool" }, -32020],
  ] as const)("rejects mismatched mirrored headers", async (headers, code) => {
    const body = requestBody("tools/call", "header-01", {
      name: "vizier_verify_action",
      arguments: verificationInput(),
    });
    const response = await handleMcpRequest(mcpRequest(body, headers));

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ error: { code } });
  });

  it("reports supported versions when the body and header request another version", async () => {
    const body = requestBody("server/discover", "version-01");
    const params = body.params as {
      _meta: Record<string, unknown>;
    };
    params._meta["io.modelcontextprotocol/protocolVersion"] = "2099-01-01";
    const response = await handleMcpRequest(
      mcpRequest(body, { "MCP-Protocol-Version": "2099-01-01" }),
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: -32022,
        data: { supported: [MCP_VERSION], requested: "2099-01-01" },
      },
    });
  });

  it("rejects an invalid cross-origin browser request", async () => {
    const response = await handleMcpRequest(
      mcpRequest(requestBody("tools/list", "origin-01"), {
        Origin: "https://attacker.example",
      }),
    );

    expect(response.status).toBe(403);
  });

  it("uses 404 with a JSON-RPC method-not-found response", async () => {
    const response = await handleMcpRequest(
      mcpRequest(requestBody("unknown/method", "method-01")),
    );

    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toMatchObject({
      id: "method-01",
      error: { code: -32601 },
    });
  });

  it("returns 405 for GET on the single MCP endpoint", async () => {
    const response = await handleHttpRequest(
      new Request("https://vizier.example/mcp"),
    );

    expect(response.status).toBe(405);
    expect(response.headers.get("Allow")).toBe("POST");
  });
});
