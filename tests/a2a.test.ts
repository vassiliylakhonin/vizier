import { describe, expect, it, vi } from "vitest";

import { createAgentCard, handleA2aRequest } from "../src/transport/a2a";
import { handleHttpRequest } from "../src/transport/http";

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
      request_id: "a2a-request-01",
      timestamp: "2026-08-09T08:00:00Z",
      source: "a2a",
    },
  };
}

function rpcRequest(
  body: unknown,
  headers: Record<string, string> = {},
): Request {
  return new Request("https://vizier.example/a2a", {
    method: "POST",
    headers: {
      "A2A-Version": "1.0",
      Authorization: `Bearer ${TEST_API_KEY}`,
      "Content-Type": "application/json",
      ...headers,
    },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function validEnvelope(id: string | number = "rpc-01"): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id,
    method: "SendMessage",
    params: {
      message: {
        messageId: "message-01",
        role: "ROLE_USER",
        parts: [{ data: verificationInput(), mediaType: "application/json" }],
      },
    },
  };
}

describe("A2A Agent Card", () => {
  it("uses the v1.0 Agent Card shape and current discovery route", async () => {
    const card = createAgentCard("https://vizier.example");
    const response = await handleHttpRequest(
      new Request("https://vizier.example/.well-known/agent-card.json"),
    );
    const body = (await response.json()) as typeof card;

    expect(response.status).toBe(200);
    expect(body).toEqual(card);
    expect(body).toMatchObject({
      name: "Vizier",
      supportedInterfaces: [
        {
          url: "https://vizier.example/a2a",
          protocolBinding: "JSONRPC",
          protocolVersion: "1.0",
        },
      ],
      capabilities: {
        streaming: false,
        pushNotifications: false,
        extendedAgentCard: false,
      },
      securitySchemes: {
        bearerAuth: {
          httpAuthSecurityScheme: { scheme: "Bearer" },
        },
      },
      securityRequirements: [{ bearerAuth: [] }],
    });
    expect((body.skills as unknown[]).length).toBe(3);
  });
});

describe("A2A JSON-RPC binding", () => {
  it("echoes the request id and returns a completed task artifact", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const response = await handleA2aRequest(rpcRequest(validEnvelope(42)), {
      apiKey: TEST_API_KEY,
    });
    const body = (await response.json()) as {
      jsonrpc: string;
      id: number;
      result: {
        task: {
          status: { state: string };
          artifacts: Array<{ parts: Array<{ data: { decision: string } }> }>;
        };
      };
    };

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("application/json; charset=utf-8");
    expect(body.jsonrpc).toBe("2.0");
    expect(body.id).toBe(42);
    expect(body.result.task.status.state).toBe("TASK_STATE_COMPLETED");
    expect(body.result.task.artifacts[0]?.parts[0]?.data.decision).toBe("ALLOW");
  });

  it("returns REVIEW when no enforcement key is configured", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const response = await handleA2aRequest(rpcRequest(validEnvelope()));
    const body = (await response.json()) as {
      result: { task: { artifacts: Array<{ parts: Array<{ data: { decision: string } }> }> } };
    };

    expect(body.result.task.artifacts[0]?.parts[0]?.data.decision).toBe("REVIEW");
  });

  it("rejects an invalid enforcement credential", async () => {
    const response = await handleA2aRequest(
      rpcRequest(validEnvelope(), { Authorization: "Bearer wrong-key" }),
      { apiKey: TEST_API_KEY },
    );

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: -32001 },
    });
  });

  it("returns the standard method-not-found error and echoes the id", async () => {
    const envelope = { ...validEnvelope("unknown-01"), method: "UnknownMethod" };
    const response = await handleA2aRequest(rpcRequest(envelope));

    await expect(response.json()).resolves.toEqual({
      jsonrpc: "2.0",
      id: "unknown-01",
      error: { code: -32601, message: "Method not found" },
    });
  });

  it.each([
    ["{broken", -32700],
    [{ jsonrpc: "1.0", id: 1, method: "SendMessage" }, -32600],
  ] as const)("returns a valid JSON-RPC error for malformed input", async (input, code) => {
    const response = await handleA2aRequest(rpcRequest(input));
    const body = (await response.json()) as {
      jsonrpc: string;
      id: null;
      error: { code: number };
    };

    expect(body.jsonrpc).toBe("2.0");
    expect(body.id).toBeNull();
    expect(body.error.code).toBe(code);
  });

  it("returns invalid-params for a message without verification data", async () => {
    const envelope = validEnvelope("params-01");
    envelope.params = {
      message: {
        messageId: "message-01",
        role: "ROLE_USER",
        parts: [{ text: "Please verify this." }],
      },
    };
    const response = await handleA2aRequest(rpcRequest(envelope));
    const body = (await response.json()) as { id: string; error: { code: number } };

    expect(body.id).toBe("params-01");
    expect(body.error.code).toBe(-32602);
  });

  it("rejects an unsupported or omitted protocol version", async () => {
    const unsupported = await handleA2aRequest(
      rpcRequest(validEnvelope(), { "A2A-Version": "0.3" }),
    );
    const omitted = await handleA2aRequest(
      new Request("https://vizier.example/a2a", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(validEnvelope()),
      }),
    );

    await expect(unsupported.json()).resolves.toMatchObject({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32009 },
    });
    await expect(omitted.json()).resolves.toMatchObject({
      error: { code: -32009 },
    });
  });

  it("rejects non-JSON content with the A2A content-type error", async () => {
    const response = await handleA2aRequest(
      rpcRequest(validEnvelope(), { "Content-Type": "text/plain" }),
    );

    await expect(response.json()).resolves.toMatchObject({
      error: { code: -32005 },
    });
  });
});
