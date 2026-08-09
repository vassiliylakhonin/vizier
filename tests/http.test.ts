import { describe, expect, it, vi } from "vitest";

import { handleHttpRequest } from "../src/transport/http";

const TEST_API_KEY = "test-enforcement-key";

function requestBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
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
      request_id: "integration-request-01",
      timestamp: "2026-08-09T08:00:00Z",
      source: "rest",
    },
    ...overrides,
  };
}

async function postJson(
  body: unknown,
  options: { readonly apiKey?: string; readonly bearer?: string } = {},
): Promise<Response> {
  return handleHttpRequest(
    new Request("https://vizier.example/v1/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(options.bearer === undefined
          ? {}
          : { Authorization: `Bearer ${options.bearer}` }),
      },
      body: JSON.stringify(body),
    }),
    { apiKey: options.apiKey },
  );
}

describe("REST transport", () => {
  it.each([
    ["/", 200, "Vizier"],
    ["/health", 200, "ok"],
    ["/docs", 200, "v1"],
    ["/examples", 200, "AUTHORITY_LIMIT_EXCEEDED"],
  ] as const)("serves GET %s", async (path, status, expectedText) => {
    const response = await handleHttpRequest(
      new Request(`https://vizier.example${path}`),
    );

    expect(response.status).toBe(status);
    expect(response.headers.get("Content-Type")).toBe("application/json; charset=utf-8");
    expect(await response.text()).toContain(expectedText);
  });

  it("returns an ALLOW decision and receipt", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const response = await postJson(requestBody(), {
      apiKey: TEST_API_KEY,
      bearer: TEST_API_KEY,
    });
    const result = (await response.json()) as {
      decision: string;
      receipt: { id: string; request_hash: string };
    };

    expect(response.status).toBe(200);
    expect(result.decision).toBe("ALLOW");
    expect(result.receipt.id).toMatch(/^vrf_/);
    expect(result.receipt.request_hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it("downgrades open evaluation requests to REVIEW", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const response = await postJson(requestBody());

    await expect(response.json()).resolves.toMatchObject({
      decision: "REVIEW",
      reason_codes: ["AUTHORITY_SOURCE_UNTRUSTED"],
    });
  });

  it("rejects a missing token when enforcement is configured", async () => {
    const response = await postJson(requestBody(), { apiKey: TEST_API_KEY });

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "AUTHENTICATION_REQUIRED" },
    });
  });

  it("returns a structured validation error", async () => {
    const response = await postJson({ agent: { id: "incomplete" } });
    const result = (await response.json()) as {
      error: { code: string; details: unknown[] };
    };

    expect(response.status).toBe(422);
    expect(result.error.code).toBe("VALIDATION_ERROR");
    expect(result.error.details.length).toBeGreaterThan(0);
  });

  it("rejects invalid JSON and unsupported media types", async () => {
    const invalidJson = await handleHttpRequest(
      new Request("https://vizier.example/v1/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{not-json",
      }),
    );
    const wrongType = await handleHttpRequest(
      new Request("https://vizier.example/v1/verify", {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: "{}",
      }),
    );

    expect(invalidJson.status).toBe(400);
    expect(wrongType.status).toBe(415);
  });

  it("rejects bodies above the configured limit", async () => {
    const response = await postJson({ padding: "x".repeat(70_000) });

    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "PAYLOAD_TOO_LARGE" },
    });
  });

  it("rejects deeply nested JSON before recursive schema validation", async () => {
    let nested: unknown = "leaf";
    for (let index = 0; index < 40; index += 1) {
      nested = [nested];
    }
    const response = await postJson({ nested });

    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "JSON_TOO_COMPLEX" },
    });
  });

  it("returns method and route errors without leaking internals", async () => {
    const wrongMethod = await handleHttpRequest(
      new Request("https://vizier.example/v1/verify"),
    );
    const missing = await handleHttpRequest(
      new Request("https://vizier.example/missing"),
    );

    expect(wrongMethod.status).toBe(405);
    expect(wrongMethod.headers.get("Allow")).toBe("POST");
    expect(missing.status).toBe(404);
  });
});
