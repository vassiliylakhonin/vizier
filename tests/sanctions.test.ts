import { describe, expect, it } from "vitest";
import type { KVNamespace } from "@cloudflare/workers-types";

import { handleHttpRequest } from "../src/transport/http";
import { evaluateSanctions } from "../src/core/sanctions";
import type { VerificationRequest } from "../src/core/schemas";

const TEST_API_KEY = "test-enforcement-key";

interface VerificationResponseBody {
  readonly decision: "ALLOW" | "REVIEW" | "BLOCK";
  readonly reason_codes: string[];
  readonly policy_results?: Array<{
    readonly rule_id: string;
    readonly result: string;
    readonly reason_code?: string | null;
    readonly details?: Record<string, unknown>;
  }>;
}

interface SanctionsScreenResponseBody {
  readonly query: string;
  readonly clean: boolean;
  readonly match?: {
    readonly entity_name: string;
    readonly list: string;
    readonly matched_value: string;
  };
}

interface SanctionsEntryResponseBody {
  readonly status: string;
  readonly normalized: string;
  readonly key: string;
}

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
    agent: { id: "agent-crypto", owner: "acme" },
    principal: { id: "acme" },
    action: {
      type: "crypto_transfer",
      target: "payment_processor",
      parameters: {
        recipient_address: "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b", // OFAC Tornado Cash
        amount: 10,
        currency: "ETH",
      },
    },
    authority: {
      allowed_actions: ["crypto_transfer"],
      constraints: {
        sanctions_screening: true,
      },
    },
    context: {
      request_id: "req-sanctions-01",
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
    {
      apiKey,
      circuitBreakerKv: kv,
    },
  );
}

describe("Pre-Action Sanctions Screening & Gate", () => {
  it("evaluates built-in OFAC crypto address directly", async () => {
    const kv = createMockKv();
    const req = verifyPayload() as unknown as VerificationRequest;
    const result = await evaluateSanctions(req, kv);
    expect(result.clean).toBe(false);
    expect(result.match?.list).toBe("OFAC_SDN");
    expect(result.match?.entity_name).toContain("Tornado Cash");
  });

  it("evaluates clean transaction as clean", async () => {
    const kv = createMockKv();
    const req = verifyPayload({
      action: {
        type: "crypto_transfer",
        target: "legit_vendor",
        parameters: {
          recipient_address: "0x71c6bfb764b85770f4ac626088409617329fe24a",
          amount: 1,
        },
      },
    }) as unknown as VerificationRequest;
    const result = await evaluateSanctions(req, kv);
    expect(result.clean).toBe(true);
    expect(result.match).toBeUndefined();
  });

  it("evaluates custom blocked_entities in authority constraints", async () => {
    const kv = createMockKv();
    const req = verifyPayload({
      action: {
        type: "purchase",
        target: "rogue-supplier.com",
        parameters: { vendor: "Rogue Supplier Inc" },
      },
      authority: {
        allowed_actions: ["purchase"],
        constraints: {
          blocked_entities: ["rogue-supplier.com"],
        },
      },
    }) as unknown as VerificationRequest;
    const result = await evaluateSanctions(req, kv);
    expect(result.clean).toBe(false);
    expect(result.match?.list).toBe("CUSTOM_CONSTRAINT_BLOCKED");
  });

  it("blocks sanctioned crypto transfer at /v1/verify", async () => {
    const kv = createMockKv();
    const response = await postVerify(verifyPayload(), kv);
    expect(response.status).toBe(200);
    const body = (await response.json()) as VerificationResponseBody;
    expect(body.decision).toBe("BLOCK");
    expect(body.reason_codes).toContain("SANCTIONED_ENTITY_MATCH");
    expect(body.policy_results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          rule_id: "compliance.sanctions",
          result: "FAIL",
          reason_code: "SANCTIONED_ENTITY_MATCH",
          details: expect.objectContaining({
            list: "OFAC_SDN",
          }),
        }),
      ]),
    );
  });

  it("allows clean transaction at /v1/verify", async () => {
    const kv = createMockKv();
    const cleanPayload = verifyPayload({
      action: {
        type: "crypto_transfer",
        target: "clean_wallet",
        parameters: {
          recipient_address: "0x71c6bfb764b85770f4ac626088409617329fe24a",
          amount: 5,
        },
      },
    });
    const response = await postVerify(cleanPayload, kv);
    expect(response.status).toBe(200);
    const body = (await response.json()) as VerificationResponseBody;
    expect(body.decision).toBe("ALLOW");
    expect(body.reason_codes).toHaveLength(0);
  });

  it("serves pre-flight /v1/sanctions/screen endpoint", async () => {
    const kv = createMockKv();
    const res = await handleHttpRequest(
      new Request("https://vizier.example/v1/sanctions/screen", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: "garantex.org" }),
      }),
      { circuitBreakerKv: kv },
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as SanctionsScreenResponseBody;
    expect(data.query).toBe("garantex.org");
    expect(data.clean).toBe(false);
    expect(data.match?.entity_name).toContain("Garantex");

    // Clean query
    const cleanRes = await handleHttpRequest(
      new Request("https://vizier.example/v1/sanctions/screen", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: "stripe.com" }),
      }),
      { circuitBreakerKv: kv },
    );
    expect(cleanRes.status).toBe(200);
    const cleanData = (await cleanRes.json()) as SanctionsScreenResponseBody;
    expect(cleanData.clean).toBe(true);
  });

  it("handles operator adding custom sanctions entries at /v1/sanctions/entries", async () => {
    const kv = createMockKv();
    const authOptions = {
      apiKey: TEST_API_KEY,
      circuitBreakerKv: kv,
    };

    // Unauthenticated -> 401
    const unauthRes = await handleHttpRequest(
      new Request("https://vizier.example/v1/sanctions/entries", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          raw_value: "evil-hacker.eth",
          entity_name: "Evil Hacker Collective",
        }),
      }),
      authOptions,
    );
    expect(unauthRes.status).toBe(401);

    // Authenticated add
    const addRes = await handleHttpRequest(
      new Request("https://vizier.example/v1/sanctions/entries", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${TEST_API_KEY}`,
        },
        body: JSON.stringify({
          raw_value: "bad-vendor.io",
          entity_name: "Bad Vendor International",
          list: "INTERNAL_BLACKLIST",
        }),
      }),
      authOptions,
    );
    expect(addRes.status).toBe(200);
    const addBody = (await addRes.json()) as SanctionsEntryResponseBody;
    expect(addBody.status).toBe("ok");
    expect(addBody.normalized).toBe("bad-vendor.io");

    // Now screening bad-vendor.io returns clean: false
    const screenRes = await handleHttpRequest(
      new Request("https://vizier.example/v1/sanctions/screen", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: "bad-vendor.io" }),
      }),
      authOptions,
    );
    expect(screenRes.status).toBe(200);
    const screenBody = (await screenRes.json()) as SanctionsScreenResponseBody;
    expect(screenBody.clean).toBe(false);
    expect(screenBody.match?.entity_name).toBe("Bad Vendor International");
    expect(screenBody.match?.list).toBe("INTERNAL_BLACKLIST");
  });
});
