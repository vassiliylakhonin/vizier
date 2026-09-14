import { beforeAll, describe, expect, it } from "vitest";
import { webcrypto } from "node:crypto";
import type { KVNamespace } from "@cloudflare/workers-types";
import { handleHttpRequest } from "../src/transport/http";
import type { TransportOptions } from "../src/transport/shared";
import { createQuorumProposal, recordQuorumApproval } from "../src/core/quorum";

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

interface OpenAIErrorPayload {
  readonly error: {
    readonly message: string;
    readonly type: string;
    readonly param?: string | null;
    readonly code: string;
    readonly details?: {
      readonly findings?: ReadonlyArray<{
        readonly category: string;
        readonly detector: string;
        readonly snippet_masked: string;
      }>;
      readonly proposal_id?: string;
      readonly action_type?: string;
    };
  };
}

interface OpenAIModelListPayload {
  readonly object: string;
  readonly data: ReadonlyArray<{
    readonly id: string;
    readonly object: string;
    readonly created: number;
    readonly owned_by: string;
  }>;
}

interface OpenAIChatCompletionPayload {
  readonly id: string;
  readonly object: string;
  readonly choices: ReadonlyArray<{
    readonly message: {
      readonly role: string;
      readonly content?: string;
      readonly tool_calls?: ReadonlyArray<{
        readonly id: string;
        readonly function: {
          readonly name: string;
          readonly arguments: string;
        };
      }>;
    };
  }>;
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
  let kv: KVNamespace;
  let options: TransportOptions;

  beforeAll(async () => {
    kv = new MemoryKv() as unknown as KVNamespace;
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
    const body = (await res.json()) as OpenAIModelListPayload;
    expect(body.object).toBe("list");
    expect(body.data.some((m) => m.id === "gpt-4o")).toBe(true);
    expect(body.data.some((m) => m.id === "claude-3-5-sonnet")).toBe(true);
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
    const body = (await res.json()) as OpenAIErrorPayload;
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
    const body = (await res.json()) as OpenAIErrorPayload;
    expect(body.error.code).toBe("SECRET_LEAK_PREVENTED");
    expect(body.error.message).toContain("Vizier DLP Firewall");
    expect(body.error.details?.findings?.[0]?.detector).toBe("openai_api_key");
  });

  it("Pre-LLM Circuit Breaker: trips on prompt repeat storm with 429 CIRCUIT_TRIPPED", async () => {
    const testKv = new MemoryKv() as unknown as KVNamespace;
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
    const b4 = (await r4.json()) as OpenAIErrorPayload;
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
    const body = (await res.json()) as OpenAIErrorPayload;
    expect(body.error.code).toBe("SECRET_LEAK_PREVENTED");
    expect(body.error.message).toContain("tool call 'search_web'");
  });

  it("Post-LLM Tool Call Loop Killer: trips when agent invokes identical tool call 3 times", async () => {
    const testKv = new MemoryKv() as unknown as KVNamespace;
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
    const b4 = (await r4.json()) as OpenAIErrorPayload;
    expect(b4.error.code).toBe("CIRCUIT_TRIPPED");
    expect(b4.error.message).toContain("Vizier Loop Killer tripped on tool call 'query_database'");
  });

  it("Post-LLM Quorum Gate: intercepts sensitive tool 'transfer_funds' with 403 QUORUM_REQUIRED and creates proposal", async () => {
    const testKv = new MemoryKv() as unknown as KVNamespace;
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
    const body = (await res.json()) as OpenAIErrorPayload;
    expect(body.error.code).toBe("QUORUM_REQUIRED");
    expect(body.error.message).toContain("dual-control approval (4-eyes principle)");
    expect(body.error.details?.proposal_id).toMatch(/^prp_/);
    expect(body.error.details?.action_type).toBe("transfer_funds");
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

    const data = (await res.json()) as OpenAIChatCompletionPayload;
    expect(data.choices[0]?.message?.content).toBe("The weather is sunny in Almaty.");
  });

  it("Post-LLM Sanctions Gate: blocks tool call with 403 SANCTIONS_50_RULE_VIOLATION when counterparty has >= 50% blocked ownership", async () => {
    const testOptions: TransportOptions = {
      ...options,
      upstreamFetch: async () =>
        new Response(
          JSON.stringify({
            id: "chatcmpl-sanctions-50",
            object: "chat.completion",
            choices: [
              {
                message: {
                  role: "assistant",
                  content: null,
                  tool_calls: [
                    {
                      id: "call_vendor_create",
                      type: "function",
                      function: {
                        name: "create_vendor_profile",
                        arguments: JSON.stringify({
                          counterparty: "Eurasia Import Export",
                          shareholders: [
                            { name: "Garantex Europe", percentage: 35.0 },
                            { name: "Tornado Cash", percentage: 20.0 },
                          ],
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
        messages: [{ role: "user", content: "Create vendor profile for Eurasia Import Export" }],
      }),
    });

    const res = await handleHttpRequest(req, testOptions);
    expect(res.status).toBe(403);
    const body = (await res.json()) as OpenAIErrorPayload;
    expect(body.error.code).toBe("SANCTIONS_50_RULE_VIOLATION");
    expect(body.error.message).toContain("blocked under OFAC 50% Rule");
    expect(body.error.message).toContain("55.00%");
  });

  it("Streaming Gate: blocks stream: true when tools are defined with 400 streaming_tools_unsupported", async () => {
    const req = new Request("https://vizier.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Vizier-Key": "test-vizier-key",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        stream: true,
        messages: [{ role: "user", content: "Transfer funds" }],
        tools: [
          {
            type: "function",
            function: { name: "transfer_funds", description: "Transfer funds" },
          },
        ],
      }),
    });
    const res = await handleHttpRequest(req, options);
    expect(res.status).toBe(400);
    const body = (await res.json()) as OpenAIErrorPayload;
    expect(body.error.code).toBe("streaming_tools_unsupported");
    expect(body.error.message).toContain("Streaming is not supported when tools or functions are configured");
  });

  it("Text Streaming: allows stream: true without tools and returns STREAMING_UNINSPECTED_OUTPUT header", async () => {
    const testOptions: TransportOptions = {
      ...options,
      upstreamFetch: async () =>
        new Response("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n", {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        }),
    };
    const req = new Request("https://vizier.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Vizier-Key": "test-vizier-key",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        stream: true,
        messages: [{ role: "user", content: "Hello world" }],
      }),
    });
    const res = await handleHttpRequest(req, testOptions);
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Vizier-Status")).toBe("STREAMING_UNINSPECTED_OUTPUT");
  });

  it("SSRF Gate: blocks requests with untrusted X-Upstream-Url with 400 invalid_upstream_url", async () => {
    const req = new Request("https://vizier.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Vizier-Key": "test-vizier-key",
        "X-Upstream-Url": "http://169.254.169.254/latest/meta-data",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "Hello" }],
      }),
    });
    const res = await handleHttpRequest(req, options);
    expect(res.status).toBe(400);
    const body = (await res.json()) as OpenAIErrorPayload;
    expect(body.error.code).toBe("invalid_upstream_url");
    expect(body.error.message).toContain("HTTPS");
  });

  it("Credential Isolation: never forwards Vizier Bearer token to upstream", async () => {
    let capturedUpstreamAuth: string | null = null;
    const testOptions: TransportOptions = {
      ...options,
      upstreamFetch: async (_url, init) => {
        const headers = init?.headers as Record<string, string>;
        capturedUpstreamAuth = headers?.["Authorization"] ?? null;
        return new Response(
          JSON.stringify({
            id: "chatcmpl-test",
            object: "chat.completion",
            choices: [{ message: { role: "assistant", content: "ok" } }],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      },
    };

    const req = new Request("https://vizier.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer test-vizier-key",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "Hello" }],
      }),
    });

    const res = await handleHttpRequest(req, testOptions);
    expect(res.status).toBe(200);
    expect(capturedUpstreamAuth).toBeNull();
  });

  it("Quorum Gate: blocks reuse of approved proposal on mismatched action parameters with 403 QUORUM_ACTION_MISMATCH", async () => {
    const testKv = new MemoryKv() as unknown as KVNamespace;
    const prop = await createQuorumProposal({
      kv: testKv,
      proposer: { id: "sess-quorum-agent" },
      action: {
        type: "transfer_funds",
        target: "transfer_funds",
        parameters: { recipient: "0x123", amount: 100, currency: "USD" },
      },
      constraints: { min_approvals: 1 },
    });
    await recordQuorumApproval({
      proposalId: prop.proposal_id,
      approval: {
        approver_id: "approver_alice",
        action_hash: prop.action_hash,
        decision: "APPROVE",
        notes: "Approved $100",
        timestamp: new Date().toISOString(),
      },
      kv: testKv,
    });

    const testOptions: TransportOptions = {
      ...options,
      circuitBreakerKv: testKv,
      upstreamFetch: async () =>
        new Response(
          JSON.stringify({
            id: "chatcmpl-quorum-tamper",
            object: "chat.completion",
            choices: [
              {
                message: {
                  role: "assistant",
                  tool_calls: [
                    {
                      id: "call_funds_tamper",
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
        "X-Quorum-Proposal-Id": prop.proposal_id,
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "Transfer $50,000" }],
      }),
    });

    const res = await handleHttpRequest(req, testOptions);
    expect(res.status).toBe(403);
    const body = (await res.json()) as OpenAIErrorPayload;
    expect(body.error.code).toBe("QUORUM_ACTION_MISMATCH");
    expect(body.error.message).toContain("action hash does not match current tool call");
  });

  it("Quorum Gate: allows sensitive tool execution when proposal action hash matches and is approved", async () => {
    const testKv = new MemoryKv() as unknown as KVNamespace;
    const actionPayload = { recipient: "0x123", amount: 50000, currency: "USD" };
    const prop = await createQuorumProposal({
      kv: testKv,
      proposer: { id: "sess-quorum-agent" },
      action: {
        type: "transfer_funds",
        target: "transfer_funds",
        parameters: actionPayload,
      },
      constraints: { min_approvals: 1 },
    });
    await recordQuorumApproval({
      proposalId: prop.proposal_id,
      approval: {
        approver_id: "approver_alice",
        action_hash: prop.action_hash,
        decision: "APPROVE",
        notes: "Approved $50k",
        timestamp: new Date().toISOString(),
      },
      kv: testKv,
    });

    const testOptions: TransportOptions = {
      ...options,
      circuitBreakerKv: testKv,
      upstreamFetch: async () =>
        new Response(
          JSON.stringify({
            id: "chatcmpl-quorum-approved",
            object: "chat.completion",
            choices: [
              {
                message: {
                  role: "assistant",
                  tool_calls: [
                    {
                      id: "call_funds_approved",
                      type: "function",
                      function: {
                        name: "transfer_funds",
                        arguments: JSON.stringify(actionPayload),
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
        "X-Quorum-Proposal-Id": prop.proposal_id,
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "Transfer $50,000" }],
      }),
    });

    const res = await handleHttpRequest(req, testOptions);
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Vizier-Status")).toBe("PASSED");

    // Replay attempt with the same proposal ID must fail with PROPOSAL_ALREADY_CONSUMED
    const replayReq = new Request("https://vizier.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Vizier-Key": "test-vizier-key",
        "X-Session-Id": "sess-quorum-agent",
        "X-Quorum-Proposal-Id": prop.proposal_id,
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "Transfer $50,000" }],
      }),
    });
    const replayRes = await handleHttpRequest(replayReq, testOptions);
    expect(replayRes.status).toBe(403);
    const replayErr = await replayRes.json() as { error?: { code?: string } };
    expect(replayErr.error?.code).toBe("PROPOSAL_ALREADY_CONSUMED");
  });

  it("SSRF guard: blocks private IP and cloud metadata destinations", async () => {
    let idx = 0;
    for (const host of ["169.254.169.254", "10.0.0.1", "192.168.1.1", "metadata.google.internal"]) {
      idx += 1;
      const req = new Request("https://vizier.ai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Vizier-Key": "test-vizier-key",
          "X-Session-Id": `sess-ssrf-priv-${idx}`,
          "X-Upstream-Url": `https://${host}/v1/chat/completions`,
        },
        body: JSON.stringify({
          model: "gpt-4o",
          messages: [{ role: "user", content: `Hello ${host}` }],
        }),
      });

      const res = await handleHttpRequest(req, options);
      expect(res.status).toBe(400);
      const data = (await res.json()) as { error: { message: string } };
      expect(data.error.message).toContain("prohibited");
    }
  });

  it("SSRF guard: rejects upstream HTTP redirects with 502 upstream_redirect_disallowed", async () => {
    const testOptions: TransportOptions = {
      ...options,
      upstreamFetch: async () =>
        new Response(null, {
          status: 302,
          headers: { Location: "https://attacker.evil/v1/chat/completions" },
        }),
    };

    const req = new Request("https://vizier.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Vizier-Key": "test-vizier-key",
        "X-Session-Id": "sess-redirect-guard",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "Test redirect" }],
      }),
    });

    const res = await handleHttpRequest(req, testOptions);
    expect(res.status).toBe(502);
    const err = await res.json() as { error: { code: string; message: string } };
    expect(err.error.code).toBe("upstream_redirect_disallowed");
  });

  it("Credential isolation: never forwards caller's Authorization header to upstream", async () => {
    let capturedAuth: string | null = null;
    const testOptions: TransportOptions = {
      ...options,
      upstreamFetch: async (_url, init) => {
        const headers = init?.headers as Record<string, string>;
        capturedAuth = headers?.["Authorization"] ?? null;
        return new Response(
          JSON.stringify({
            id: "chatcmpl-auth-isolation",
            object: "chat.completion",
            created: 1715367049,
            model: "gpt-4o",
            choices: [{ index: 0, message: { role: "assistant", content: "Safe" } }],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      },
    };

    // Caller authenticates with Vizier key in Authorization
    const req = new Request("https://vizier.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer test-vizier-key",
        "X-Session-Id": "sess-cred-iso-test",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "Testing credential isolation" }],
      }),
    });

    const res = await handleHttpRequest(req, testOptions);
    expect(res.status).toBe(200);
    // Upstream should NOT have received caller's Authorization header
    expect(capturedAuth).toBeNull();
  });
});
