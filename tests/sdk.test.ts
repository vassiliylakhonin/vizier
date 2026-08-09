import { describe, expect, it, vi } from "vitest";

import {
  Vizier,
  VizierError,
  type VerificationRequest,
} from "../packages/sdk/src/index";
import { verificationRequestSchema, verifyAction } from "../src/core/index";

const input: VerificationRequest = {
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
    request_id: "sdk-request-01",
    timestamp: null,
    source: "rest",
  },
};

async function allowResponse(): Promise<unknown> {
  return verifyAction(verificationRequestSchema.parse(input), {
    createId: () => "vrf_01",
    now: () => new Date("2026-08-09T08:00:00Z"),
  });
}

describe("@vizier/sdk", () => {
  it("posts a typed request and validates the response", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      Response.json(await allowResponse()),
    );
    const vizier = new Vizier({
      baseUrl: "https://vizier.example/",
      fetch: fetchMock,
    });

    const result = await vizier.verify(input);

    expect(result.decision).toBe("ALLOW");
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      "https://vizier.example/v1/verify",
    );
  });

  it("sends the optional enforcement credential", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(Response.json(await allowResponse()));
    const vizier = new Vizier({
      baseUrl: "https://vizier.example",
      apiKey: "sdk-test-key",
      fetch: fetchMock,
    });

    await vizier.verify(input);

    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.headers).toMatchObject({
      Authorization: "Bearer sdk-test-key",
    });
  });

  it("throws a typed error for API errors", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      Response.json(
        { error: { code: "VALIDATION_ERROR", message: "Invalid request." } },
        { status: 422 },
      ),
    );
    const vizier = new Vizier({ baseUrl: "https://vizier.example", fetch: fetchMock });

    await expect(vizier.verify(input)).rejects.toMatchObject({
      name: "VizierError",
      status: 422,
      code: "VALIDATION_ERROR",
    } satisfies Partial<VizierError>);
  });

  it("rejects a successful response that violates the contract", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(Response.json({ decision: "ALLOW" }));
    const vizier = new Vizier({ baseUrl: "https://vizier.example", fetch: fetchMock });

    await expect(vizier.verify(input)).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    });
  });

  it("rejects an ALLOW response with inconsistent receipt fields", async () => {
    const valid = structuredClone(await allowResponse()) as {
      receipt: { decision: string };
    };
    valid.receipt.decision = "BLOCK";
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(Response.json(valid));
    const vizier = new Vizier({ baseUrl: "https://vizier.example", fetch: fetchMock });

    await expect(vizier.verify(input)).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    });
  });

  it("rejects a response whose receipt hash is not bound to the request", async () => {
    const valid = structuredClone(await allowResponse()) as {
      receipt: { request_hash: string };
    };
    valid.receipt.request_hash = "b".repeat(64);
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(Response.json(valid));
    const vizier = new Vizier({ baseUrl: "https://vizier.example", fetch: fetchMock });

    await expect(vizier.verify(input)).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    });
  });
});
