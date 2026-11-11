import { describe, it, expect, vi } from "vitest";
import { Vizier, VizierError, type VerificationRequest } from "../packages/sdk/src/index";

describe("numeric consistency SDK", () => {
  it("posts typed text and parameters and returns findings and opaque receipt", async () => {
    const result = { consistent: false, findings: [{ kind: "metric_conflict", label: "target_price", path: "text", detail: "different prices", mentions: [] }], mentions_count: 2, receipt: "opaque" };
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(Response.json(result));
    const signal = new AbortController().signal;
    const client = new Vizier({ baseUrl: "https://vizier.example/", apiKey: "test", fetch: fetchMock });
    const input = { text: "Target: $100", parameters: { body: "Target: $90" } };
    expect(await client.scanNumericConsistency(input, { signal })).toEqual(result);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://vizier.example/v1/numeric-consistency/scan");
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual(input);
    expect(fetchMock.mock.calls[0]?.[1]?.signal).toBe(signal);
    expect(fetchMock.mock.calls[0]?.[1]?.headers).toMatchObject({ Authorization: "Bearer test" });
  });
  it("accepts empty parameters and no receipt", async () => {
    const result = { consistent: true, findings: [], mentions_count: 0 };
    const client = new Vizier({ baseUrl: "https://vizier.example", fetch: vi.fn<typeof fetch>().mockResolvedValue(Response.json(result)) });
    expect(await client.scanNumericConsistency({ parameters: {} })).toEqual(result);
  });
  it("propagates API validation errors", async () => {
    const client = new Vizier({ baseUrl: "https://vizier.example", fetch: vi.fn<typeof fetch>().mockResolvedValue(Response.json({ error: { code: "VALIDATION_ERROR", message: "Too long" } }, { status: 422 })) });
    await expect(client.scanNumericConsistency({ text: "x" })).rejects.toMatchObject({ code: "VALIDATION_ERROR", status: 422 });
  });
  it("rejects malformed success bodies", async () => {
    const client = new Vizier({ baseUrl: "https://vizier.example", fetch: vi.fn<typeof fetch>().mockResolvedValue(Response.json({ consistent: "yes" })) });
    await expect(client.scanNumericConsistency({ text: "x" })).rejects.toBeInstanceOf(VizierError);
  });
  it("types the opt-in constraint without changing defaults", () => {
    const constraints: VerificationRequest["authority"]["constraints"] = { numeric_consistency: true };
    expect(constraints.numeric_consistency).toBe(true);
  });
});
