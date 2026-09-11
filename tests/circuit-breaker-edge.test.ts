import { describe, expect, it } from "vitest";
import type { KVNamespace } from "@cloudflare/workers-types";

import { handleHttpRequest } from "../src/transport/http";

const TEST_API_KEY = "test-enforcement-key";

function createMockKv(): KVNamespace {
  const store = new Map<string, string>();
  return {
    async get(key: string) {
      return store.get(key) ?? null;
    },
    async put(key: string, value: string) {
      store.set(key, value);
    },
    async delete(key: string) {
      store.delete(key);
    },
  } as unknown as KVNamespace;
}

function verifyPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    agent: { id: "agent-007", owner: "acme" },
    principal: { id: "acme" },
    action: {
      type: "purchase",
      target: "supplier.example",
      parameters: { amount: 500, currency: "USD", item: "server" },
    },
    authority: {
      allowed_actions: ["purchase"],
      constraints: {
        max_amount: 10_000,
        currency: "USD",
        max_repeated_calls: 2,
        time_window_seconds: 30,
        cool_off_seconds: 60,
      },
    },
    context: {
      request_id: "req-01",
      session_id: "test-session-123",
      timestamp: "2026-09-11T12:00:00Z",
      source: "rest",
    },
    ...overrides,
  };
}

async function postVerify(
  body: unknown,
  kv: KVNamespace,
  apiKey: string = TEST_API_KEY,
): Promise<Response> {
  return handleHttpRequest(
    new Request("https://vizier.example/v1/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(body),
    }),
    { apiKey, circuitBreakerKv: kv },
  );
}

describe("Cloudflare Workers Edge Circuit Breaker", () => {
  it("trips and blocks repeated identical tool calls at the edge", async () => {
    const kv = createMockKv();

    // Call 1: Allowed (1st call)
    const res1 = await postVerify(verifyPayload(), kv);
    expect(res1.status).toBe(200);
    const body1 = (await res1.json()) as Record<string, unknown>;
    expect(body1).toMatchObject({ decision: "ALLOW" });

    // Call 2: Allowed (2nd call)
    const res2 = await postVerify(verifyPayload(), kv);
    expect(res2.status).toBe(200);
    const body2 = (await res2.json()) as Record<string, unknown>;
    expect(body2).toMatchObject({ decision: "ALLOW" });

    // Call 3: Tripped! (Exceeds max_repeated_calls = 2 within 30s)
    const res3 = await postVerify(verifyPayload(), kv);
    expect(res3.status).toBe(200);
    const body3 = (await res3.json()) as { decision: string; reason_codes: string[]; receipt: unknown };
    expect(body3).toMatchObject({
      decision: "BLOCK",
      reason_codes: ["CIRCUIT_TRIPPED:LOOP_DETECTED"],
    });
    expect(body3.receipt).toMatchObject({
      decision: "BLOCK",
      reason_codes: ["CIRCUIT_TRIPPED:LOOP_DETECTED"],
    });

    // Call 4: Still tripped during cool-off
    const res4 = await postVerify(verifyPayload(), kv);
    const body4 = (await res4.json()) as Record<string, unknown>;
    expect(body4).toMatchObject({
      decision: "BLOCK",
      reason_codes: ["CIRCUIT_TRIPPED:LOOP_DETECTED"],
    });
  });

  it("permits resetting a tripped session via POST /v1/circuit-breaker/reset", async () => {
    const kv = createMockKv();

    // Trip the circuit breaker
    await postVerify(verifyPayload(), kv);
    await postVerify(verifyPayload(), kv);
    const trippedRes = await postVerify(verifyPayload(), kv);
    expect(((await trippedRes.json()) as Record<string, unknown>).decision).toBe("BLOCK");

    // Reset the session
    const resetRes = await handleHttpRequest(
      new Request("https://vizier.example/v1/circuit-breaker/reset", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${TEST_API_KEY}`,
        },
        body: JSON.stringify({ session_id: "test-session-123" }),
      }),
      { apiKey: TEST_API_KEY, circuitBreakerKv: kv },
    );
    expect(resetRes.status).toBe(200);
    expect(await resetRes.json()).toMatchObject({
      status: "ok",
      session_id: "test-session-123",
    });

    // Next call is allowed again
    const afterResetRes = await postVerify(verifyPayload(), kv);
    expect(((await afterResetRes.json()) as Record<string, unknown>).decision).toBe("ALLOW");
  });

  it("requires authentication for circuit breaker reset endpoint", async () => {
    const kv = createMockKv();
    const res = await handleHttpRequest(
      new Request("https://vizier.example/v1/circuit-breaker/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: "test-session-123" }),
      }),
      { apiKey: TEST_API_KEY, circuitBreakerKv: kv },
    );
    expect(res.status).toBe(401);
  });

  it("trips session action budget when max_session_actions is reached", async () => {
    const kv = createMockKv();
    const payload = verifyPayload({
      authority: {
        allowed_actions: ["purchase"],
        constraints: {
          max_amount: 10_000,
          currency: "USD",
          max_repeated_calls: 10,
          max_session_actions: 2,
        },
      },
    });

    // Action 1: Allowed (action 1 of 2)
    const res1 = await postVerify(
      { ...payload, action: { type: "purchase", target: "s1", parameters: { amount: 100, currency: "USD", id: 1 } } },
      kv,
    );
    expect(((await res1.json()) as Record<string, unknown>).decision).toBe("ALLOW");

    // Action 2: Allowed (action 2 of 2)
    const res2 = await postVerify(
      { ...payload, action: { type: "purchase", target: "s2", parameters: { amount: 100, currency: "USD", id: 2 } } },
      kv,
    );
    expect(((await res2.json()) as Record<string, unknown>).decision).toBe("ALLOW");

    // Action 3: Budget exceeded!
    const res3 = await postVerify(
      { ...payload, action: { type: "purchase", target: "s3", parameters: { amount: 100, currency: "USD", id: 3 } } },
      kv,
    );
    const body3 = (await res3.json()) as Record<string, unknown>;
    expect(body3).toMatchObject({
      decision: "BLOCK",
      reason_codes: ["CIRCUIT_TRIPPED:BUDGET_EXCEEDED"],
    });
  });
});
