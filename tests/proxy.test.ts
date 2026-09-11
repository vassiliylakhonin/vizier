import { beforeAll, describe, expect, it } from "vitest";
import { webcrypto } from "node:crypto";
import { handleHttpRequest } from "../src/transport/http";
import type { TransportOptions } from "../src/transport/shared";

// In-memory KV Mock for testing
class MemoryKv {
  private readonly store = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }

  async put(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
}

async function createTestSigningKey(): Promise<string> {
  const keyPair = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const privateJwk = await webcrypto.subtle.exportKey("jwk", keyPair.privateKey);
  return JSON.stringify({
    ...privateJwk,
    alg: "ES256",
    kid: "receipt-key-1",
    use: "sig",
  });
}

describe("Transparent AI Proxy (/v1/chat/completions & /v1/models)", () => {
  let kv: any;
  let options: TransportOptions;

  beforeAll(async () => {
    kv = new MemoryKv();
    const receiptKey = await createTestSigningKey();
    options = {
      apiKey: "test-vizier-key",
      circuitBreakerKv: kv,
      receiptSigningKey: receiptKey,
    };
  });

  it("handles OPTIONS request with full CORS headers", async () => {
    const req = new Request("https://vizier.ai/v1/chat/completions", {
      method: "OPTIONS",
    });
    const res = await handleHttpRequest(req, options);
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(res.headers.get("Access-Control-Allow-Methods")).toContain("POST");
  });

  it("serves GET /v1/models with standard OpenAI model list", async () => {
    const req = new Request("https://vizier.ai/v1/models", {
      method: "GET",
    });
    const res = await handleHttpRequest(req, options);
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.object).toBe("list");
    expect(body.data.some((m: any) => m.id === "gpt-4o")).toBe(true);
    expect(body.data.some((m: any) => m.id === "claude-3-5-sonnet")).toBe(true);
  });

  it("rejects unauthorized requests with 401 when apiKey is configured", async () => {
    const req = new Request("https://vizier.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer wrong-key",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "Hello world" }],
      }),
    });
    const res = await handleHttpRequest(req, options);
    expect(res.status).toBe(401);
    const body = (await res.json()) as any;
    expect(body.error.code).toBe("invalid_api_key");
  });

  it("Pre-LLM DLP: blocks prompt containing API key with 400 SECRET_LEAK_PREVENTED", async () => {
    const req = new Request("https://vizier.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Vizier-Key": "test-vizier-key",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [
          {
            role: "user",
            content: "Here is my secret token: sk-proj-1234567890abcdef1234567890abcdef1234567890 please summarize",
          },
        ],
      }),
    });
    const res = await handleHttpRequest(req, options);
    expect(res.status).toBe(400);
    const body = (await res.json()) as any;
    expect(body.error.code).toBe("SECRET_LEAK_PREVENTED");
    expect(body.error.message).toContain("Vizier DLP Firewall");
    expect(body.error.details.findings[0].detector).toBe("openai_api_key");
  });

  it("Pre-LLM Circuit Breaker: trips on prompt repeat storm with 429 CIRCUIT_TRIPPED", async () => {
    const testKv = new MemoryKv() as any;
    const testOptions: TransportOptions = {
      ...options,
      circuitBreakerKv: testKv,
      upstreamFetch: async () =>
        new Response(
          JSON.stringify({
            id: "chatcmpl-1",
            object: "chat.completion",
            choices: [{ message: { role: "assistant", content: "I am fine" } }],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    };

    const makeCall = () =>
      handleHttpRequest(
        new Request("https://vizier.ai/v1/chat/completions", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Vizier-Key": "test-vizier-key",
            "X-Session-Id": "sess-storm-1",
          },
          body: JSON.stringify({
            model: "gpt-4o",
            messages: [{ role: "user", content: "Are you there?" }],
          }),
        }),
        testOptions,
      );

    // Call 1: OK
    const r1 = await makeCall();
    expect(r1.status).toBe(200);

    // Call 2: OK
    const r2 = await makeCall();
    expect(r2.status).toBe(200);

    // Call 3: OK
    const r3 = await makeCall();
    expect(r3.status).toBe(200);

    // Call 4: Tripped! (max_repeated_calls = 3)
    const r4 = await makeCall();
    expect(r4.status).toBe(429);
    const b4 = (await r4.json()) as any;
    expect(b4.error.code).toBe("CIRCUIT_TRIPPED");
    expect(b4.error.message).toContain("prompt repeat storm detected");
  });

  it("Post-LLM Tool Call DLP: blocks tool arguments containing secrets", async () => {
    const testOptions: TransportOptions = {
      ...options,
      upstreamFetch: async () =>
        new Response(
          JSON.stringify({
            id: "chatcmpl-tool-dlp",
            object: "chat.completion",
            choices: [
              {
                message: {
                  role: "assistant",
                  tool_calls: [
                    {
                      id: "call_1",
                      type: "function",
                      function: {
                        name: "search_web",
                        arguments: JSON.stringify({
                          query: "how to hack",
                          api_key: "ghp_1234567890abcdef1234567890abcdef1234",
                        }),
                      },
                    },
                  ],
                },
              },
            ],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    };

    const req = new Request("https://vizier.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Vizier-Key": "test-vizier-key",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "Search for info" }],
      }),
    });

    const res = await handleHttpRequest(req, testOptions);
    expect(res.status).toBe(400);
    const body = (await res.json()) as any;
    expect(body.error.code).toBe("SECRET_LEAK_PREVENTED");
    expect(body.error.message).toContain("tool call 'search_web'");
  });

  it("Post-LLM Tool Call Loop Killer: trips when agent invokes identical tool call 3 times", async () => {
    const testKv = new MemoryKv() as any;
    const testOptions: TransportOptions = {
      ...options,
      circuitBreakerKv: testKv,
      upstreamFetch: async () =>
        new Response(
          JSON.stringify({
            id: "chatcmpl-loop",
            object: "chat.completion",
            choices: [
              {
                message: {
                  role: "assistant",
                  tool_calls: [
                    {
                      id: "call_loop_1",
                      type: "function",
                      function: {
                        name: "query_database",
                        arguments: JSON.stringify({ sql: "SELECT * FROM orders WHERE status = 'pending'" }),
                      },
                    },
                  ],
                },
              },
            ],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    };

    const makeToolCall = (i: number) =>
      handleHttpRequest(
        new Request("https://vizier.ai/v1/chat/completions", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Vizier-Key": "test-vizier-key",
            "X-Session-Id": "sess-loop-agent",
          },
          body: JSON.stringify({
            model: "gpt-4o",
            messages: [{ role: "user", content: `Check orders iteration ${i}` }],
          }),
        }),
        testOptions,
      );

    // Call 1: OK
    const r1 = await makeToolCall(1);
    expect(r1.status).toBe(200);

    // Call 2: OK
    const r2 = await makeToolCall(2);
    expect(r2.status).toBe(200);

    // Call 3: OK
    const r3 = await makeToolCall(3);
    expect(r3.status).toBe(200);

    // Call 4: Tripped!
    const r4 = await makeToolCall(4);
    expect(r4.status).toBe(429);
    const b4 = (await r4.json()) as any;
    expect(b4.error.code).toBe("CIRCUIT_TRIPPED");
    expect(b4.error.message).toContain("Vizier Loop Killer tripped on tool call 'query_database'");
  });

  it("Post-LLM Quorum Gate: intercepts sensitive tool 'transfer_funds' with 403 QUORUM_REQUIRED and creates proposal", async () => {
    const testKv = new MemoryKv() as any;
    const testOptions: TransportOptions = {
      ...options,
      circuitBreakerKv: testKv,
      upstreamFetch: async () =>
        new Response(
          JSON.stringify({
            id: "chatcmpl-quorum",
            object: "chat.completion",
            choices: [
              {
                message: {
                  role: "assistant",
                  tool_calls: [
                    {
                      id: "call_funds_1",
                      type: "function",
                      function: {
                        name: "transfer_funds",
                        arguments: JSON.stringify({ recipient: "0x123", amount: 50000, currency: "USD" }),
                      },
                    },
                  ],
                },
              },
            ],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    };

    const req = new Request("https://vizier.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Vizier-Key": "test-vizier-key",
        "X-Session-Id": "sess-quorum-agent",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "Transfer $50,000 to supplier" }],
      }),
    });

    const res = await handleHttpRequest(req, testOptions);
    expect(res.status).toBe(403);
    const body = (await res.json()) as any;
    expect(body.error.code).toBe("QUORUM_REQUIRED");
    expect(body.error.message).toContain("dual-control approval (4-eyes principle)");
    expect(body.error.details.proposal_id).toMatch(/^prp_/);
    expect(body.error.details.action_type).toBe("transfer_funds");
  });

  it("Clean request passes through with X-Vizier-Status: PASSED and X-Vizier-Receipt JWS header", async () => {
    const testOptions: TransportOptions = {
      ...options,
      upstreamFetch: async () =>
        new Response(
          JSON.stringify({
            id: "chatcmpl-success",
            object: "chat.completion",
            choices: [
              {
                message: {
                  role: "assistant",
                  content: "The weather is sunny in Almaty.",
                },
              },
            ],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    };

    const req = new Request("https://vizier.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Vizier-Key": "test-vizier-key",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "What is the weather?" }],
      }),
    });

    const res = await handleHttpRequest(req, testOptions);
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Vizier-Status")).toBe("PASSED");
    expect(res.headers.get("X-Vizier-Receipt")).toBeDefined();
    expect(res.headers.get("X-Vizier-Receipt")?.split(".")).toHaveLength(3);

    const data = (await res.json()) as any;
    expect(data.choices[0].message.content).toBe("The weather is sunny in Almaty.");
  });
});
