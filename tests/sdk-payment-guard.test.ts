import { describe, expect, it, vi } from "vitest";
import {
  guardPayment,
  Vizier,
  VizierError,
  type VerificationRequest,
  type VerificationResponse,
} from "../packages/sdk/src/index";
import { verificationRequestSchema, verifyAction } from "../src/core/index";
import { canonicalize, sha256 } from "../src/core/receipts";

const authority = {
  allowed_actions: ["payment"],
  constraints: { allowed_targets: ["supplier.example"], max_amount: 100 },
};

const options = {
  agentId: "moderation-agent-01",
  principalId: "community-owner",
  grant: "synthetic-grant-for-mock-only",
  authority,
};

// A mock trusted service; signature verification is the server's job. It runs
// the real policy engine on the request it receives and marks the authority
// provenance as principal-signed so authorize() can establish the binding.
async function serviceResponse(
  request: VerificationRequest,
): Promise<VerificationResponse> {
  const noGrant = structuredClone(request);
  delete noGrant.grant;
  const response = structuredClone(
    await verifyAction(verificationRequestSchema.parse(noGrant)),
  ) as VerificationResponse;
  response.receipt.request_hash = await sha256(canonicalize(request));
  response.receipt.authority_provenance = "principal_signed";
  response.receipt.grant = {
    jti: "grant-test",
    issuer: "community-owner",
    subject: "moderation-agent-01",
    key_id: "test-key",
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  };
  return response;
}

function recordingFetch(received: VerificationRequest[]) {
  return vi.fn<typeof fetch>().mockImplementation(async (_url, init) => {
    const request = JSON.parse(String(init?.body)) as VerificationRequest;
    received.push(structuredClone(request));
    return Response.json(await serviceResponse(request));
  });
}

describe("SDK payment guard", () => {
  it("evaluates the amount and currency of the call that reaches the executor", async () => {
    const received: VerificationRequest[] = [];
    const client = new Vizier({ baseUrl: "https://example.test", apiKey: "test", fetch: recordingFetch(received) });
    const calls: unknown[] = [];
    const guarded = guardPayment(client, options, {
      pay(call) {
        calls.push(call);
        return "paid";
      },
    });
    await guarded.pay({ target: "supplier.example", amount: 40, currency: "USD", requestId: "pay-1" });
    expect(received).toHaveLength(1);
    expect(received[0]?.action.parameters).toMatchObject({ amount: 40, currency: "USD" });
    expect(received[0]?.context.request_id).toBe("pay-1");
    expect(calls).toEqual([{ target: "supplier.example", amount: 40, currency: "USD", requestId: "pay-1" }]);
  });

  it("does not call the executor when the call is refused", async () => {
    const received: VerificationRequest[] = [];
    const client = new Vizier({ baseUrl: "https://example.test", apiKey: "test", fetch: recordingFetch(received) });
    const pay = vi.fn();
    const guarded = guardPayment(client, options, { pay });
    await expect(guarded.pay({ target: "supplier.example", amount: 5000, currency: "USD" })).rejects.toBeInstanceOf(VizierError);
    await expect(guarded.pay({ target: "other.example", amount: 1, currency: "USD" })).rejects.toBeInstanceOf(VizierError);
    expect(pay).not.toHaveBeenCalled();
  });

  it("rejects malformed amounts before any request", async () => {
    const received: VerificationRequest[] = [];
    const client = new Vizier({ baseUrl: "https://example.test", apiKey: "test", fetch: recordingFetch(received) });
    const pay = vi.fn();
    const guarded = guardPayment(client, options, { pay });
    for (const amount of [Number.NaN, -1, Number.POSITIVE_INFINITY]) {
      await expect(guarded.pay({ target: "supplier.example", amount, currency: "USD" })).rejects.toBeInstanceOf(VizierError);
    }
    expect(received).toHaveLength(0);
    expect(pay).not.toHaveBeenCalled();
  });
});
