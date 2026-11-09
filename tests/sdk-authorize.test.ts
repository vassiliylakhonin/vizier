import { describe, expect, it, vi } from "vitest";
import { Vizier, type VerificationRequest, type VerificationResponse } from "../packages/sdk/src/index";
import { verificationRequestSchema, verifyAction } from "../src/core/index";
import { canonicalize, sha256 } from "../src/core/receipts";
import { webcrypto } from "node:crypto";
import { createJwks, signCompactJws } from "../src/crypto/jws";

async function receiptKey() {
  const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const priv = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
  return JSON.stringify({ ...priv, alg: "ES256", kid: "receipt-1", use: "sig" });
}

async function signedFetch(signingKey: string, tamper: "none" | "receipt" | "key" = "none") {
  return vi.fn<typeof fetch>().mockImplementation(async (url, init) => {
    if (String(url).endsWith("/.well-known/jwks.json")) return Response.json(createJwks(signingKey));
    const request = JSON.parse(String(init?.body)) as VerificationRequest;
    const response = await serviceResponse(request);
    const jws = await signCompactJws(
      { iss: "vizier-action-firewall", iat: 1, engine: "vizier_verify", receipt: response.receipt },
      tamper === "key" ? await receiptKey() : signingKey,
      "application/vizier-receipt+jwt",
    );
    if (tamper === "receipt") response.receipt.id = "vrf_tampered";
    return Response.json({ ...response, receipt_jws: jws });
  });
}

const input: VerificationRequest = {
  agent: { id: "agent", owner: "owner" },
  principal: { id: "owner" },
  action: { type: "purchase", target: "example", parameters: { amount: 5, currency: "USD" } },
  authority: { allowed_actions: ["purchase"], constraints: { max_amount: 10, currency: "USD" } },
  context: { request_id: "test", timestamp: null, source: "rest" },
  grant: "synthetic-grant-for-mock-only",
};

// A mock trusted service response; signature verification is the server's responsibility.
async function serviceResponse(request: VerificationRequest): Promise<VerificationResponse> {
  const noGrant = structuredClone(request);
  delete noGrant.grant;
  const response = structuredClone(await verifyAction(verificationRequestSchema.parse(noGrant))) as VerificationResponse;
  response.receipt.request_hash = await sha256(canonicalize(request));
  response.receipt.authority_provenance = "principal_signed";
  response.receipt.grant = {
    jti: "grant-test", issuer: "owner", subject: "agent", key_id: "test-key",
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  };
  return response;
}

describe("SDK authorize", () => {
  it("accepts a bound ALLOW with a valid owner delegation from the configured service", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (_url, init) => {
      const request = JSON.parse(String(init?.body)) as VerificationRequest;
      return Response.json(await serviceResponse(request));
    });
    const client = new Vizier({ baseUrl: "https://example.test", apiKey: "test", fetch: fetchMock });
    expect((await client.authorize(structuredClone(input))).decision).toBe("ALLOW");
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("rejects missing credentials or grants before contacting the service", async () => {
    const fetchMock = vi.fn<typeof fetch>();
    const noKey = new Vizier({ baseUrl: "https://example.test", fetch: fetchMock });
    const client = new Vizier({ baseUrl: "https://example.test", apiKey: "test", fetch: fetchMock });
    await expect(noKey.authorize(input)).rejects.toMatchObject({ code: "AUTHORIZATION_INPUT_REQUIRED" });
    await expect(client.authorize({ ...input, grant: undefined })).rejects.toMatchObject({ code: "AUTHORIZATION_INPUT_REQUIRED" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each(["review", "provenance", "issuer", "subject", "expired", "hash"])("rejects %s", async (scenario) => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (_url, init) => {
      const request = JSON.parse(String(init?.body)) as VerificationRequest;
      const response = await serviceResponse(request);
      if (scenario === "review") { response.decision = "REVIEW"; response.receipt.decision = "REVIEW"; }
      if (scenario === "provenance") response.receipt.authority_provenance = "trusted_integration";
      if (scenario === "issuer") response.receipt.grant!.issuer = "other";
      if (scenario === "subject") response.receipt.grant!.subject = "other";
      if (scenario === "expired") response.receipt.grant!.expires_at = "2020-01-01T00:00:00Z";
      if (scenario === "hash") response.receipt.request_hash = "a".repeat(64);
      return Response.json(response);
    });
    const client = new Vizier({ baseUrl: "https://example.test", apiKey: "test", fetch: fetchMock });
    await expect(client.authorize(structuredClone(input))).rejects.toMatchObject({
      code: scenario === "hash" ? "INVALID_RESPONSE" : "AUTHORIZATION_NOT_GRANTED",
    });
  });

  it("binds the response to a snapshot even if the caller mutates the request during fetch", async () => {
    const request = structuredClone(input);
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (_url, init) => {
      request.action.target = "changed.example";
      const sent = JSON.parse(String(init?.body)) as VerificationRequest;
      expect(sent.action.target).toBe("example");
      return Response.json(await serviceResponse(sent));
    });
    const client = new Vizier({ baseUrl: "https://example.test", apiKey: "test", fetch: fetchMock });
    expect((await client.authorize(request)).decision).toBe("ALLOW");
  });

  it("verifies receipt_jws against the published JWKS and asks for it", async () => {
    const mock = await signedFetch(await receiptKey());
    const client = new Vizier({ baseUrl: "https://example.test", apiKey: "test", fetch: mock });
    expect((await client.authorize(structuredClone(input))).decision).toBe("ALLOW");
    const verifyCall = mock.mock.calls.find(([url]) => String(url).endsWith("/v1/verify"));
    expect((verifyCall?.[1]?.headers as Record<string, string>)["X-Vizier-Receipt"]).toBe("jws");
  });

  it.each(["receipt", "key"] as const)("rejects a receipt_jws that fails verification (%s)", async (tamper) => {
    const mock = await signedFetch(await receiptKey(), tamper);
    const client = new Vizier({ baseUrl: "https://example.test", apiKey: "test", fetch: mock });
    await expect(client.authorize(structuredClone(input))).rejects.toMatchObject({ code: "RECEIPT_SIGNATURE_INVALID" });
  });
});
