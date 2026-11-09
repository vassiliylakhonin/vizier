import { describe, expect, it, vi } from "vitest";
import {
  guardBanAccount,
  Vizier,
  VizierError,
  type VerificationRequest,
  type VerificationResponse,
} from "../packages/sdk/src/index";
import { verificationRequestSchema, verifyAction } from "../src/core/index";
import { canonicalize, sha256 } from "../src/core/receipts";

const authority = {
  allowed_actions: ["ban_account"],
  constraints: { allowed_targets: ["fake-user-001", "fake-user-002"] },
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

describe("SDK ban-account guard", () => {
  it("executes only after an ALLOW for the exact target and arguments that will run", async () => {
    const received: VerificationRequest[] = [];
    const client = new Vizier({
      baseUrl: "https://example.test",
      apiKey: "test",
      fetch: recordingFetch(received),
    });
    const calls: Array<[string, ...unknown[]]> = [];
    const executor = {
      ban(target: string, wave: string) {
        calls.push([target, wave]);
        return { target, wave, status: "banned" };
      },
    };
    const guarded = guardBanAccount(client, options, executor);

    const result = await guarded.ban("fake-user-001", "wave-7");

    expect(result).toEqual({ target: "fake-user-001", wave: "wave-7", status: "banned" });
    expect(calls).toEqual([["fake-user-001", "wave-7"]]);
    expect(received).toHaveLength(1);
    // The evaluated action is derived from the actual executor call:
    // same target, irreversible by default, decided by the pinned type.
    expect(received[0]!.action).toMatchObject({
      type: "ban_account",
      target: "fake-user-001",
      is_reversible: false,
    });
    expect(received[0]!.grant).toBe(options.grant);
    expect(received[0]!.principal?.id).toBe("community-owner");
    expect(received[0]!.agent.id).toBe("moderation-agent-01");
  });

  it("never calls the executor when Vizier blocks the target", async () => {
    const client = new Vizier({
      baseUrl: "https://example.test",
      apiKey: "test",
      fetch: recordingFetch([]),
    });
    const executor = { ban: vi.fn() };
    const guarded = guardBanAccount(client, options, executor);

    await expect(guarded.ban("fake-user-009")).rejects.toMatchObject({
      name: "VizierError",
      code: "AUTHORIZATION_NOT_GRANTED",
      details: { decision: "BLOCK", reason_codes: ["TARGET_NOT_ALLOWED"] },
    });
    expect(executor.ban).not.toHaveBeenCalled();
  });

  it("derives evaluated parameters from the actual call when deriveParameters is set", async () => {
    const received: VerificationRequest[] = [];
    const client = new Vizier({
      baseUrl: "https://example.test",
      apiKey: "test",
      fetch: recordingFetch(received),
    });
    const executor = { ban: (target: string, reason: string) => ({ target, reason }) };
    const guarded = guardBanAccount(
      client,
      {
        ...options,
        deriveParameters: (_target, reason: string) => ({ reason }),
      },
      executor,
    );

    await guarded.ban("fake-user-002", "coordinated-spam");

    expect(received[0]!.action.parameters).toEqual({ reason: "coordinated-spam" });
  });

  it("pins is_reversible per integration instead of per call", async () => {
    const received: VerificationRequest[] = [];
    const client = new Vizier({
      baseUrl: "https://example.test",
      apiKey: "test",
      fetch: recordingFetch(received),
    });
    const executor = { ban: (target: string) => ({ target }) };
    const guarded = guardBanAccount(
      client,
      { ...options, isReversible: true },
      executor,
    );

    await guarded.ban("fake-user-001");

    expect(received[0]!.action.is_reversible).toBe(true);
  });

  it("rejects an empty target before contacting the service", async () => {
    const fetchMock = vi.fn<typeof fetch>();
    const client = new Vizier({ baseUrl: "https://example.test", apiKey: "test", fetch: fetchMock });
    const executor = { ban: vi.fn() };
    const guarded = guardBanAccount(client, options, executor);

    await expect(guarded.ban("")).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(executor.ban).not.toHaveBeenCalled();
  });

  it("reports the established authorization receipt through onAuthorized", async () => {
    const client = new Vizier({
      baseUrl: "https://example.test",
      apiKey: "test",
      fetch: recordingFetch([]),
    });
    const executor = { ban: (target: string) => ({ target }) };
    const receipts: string[] = [];
    const guarded = guardBanAccount(
      client,
      { ...options, onAuthorized: (r) => receipts.push(r.receipt.id) },
      executor,
    );

    await guarded.ban("fake-user-001");

    expect(receipts).toHaveLength(1);
  });

  it("throws VizierError on service failure and never executes", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      Response.json({ error: { message: "down", code: "REQUEST_FAILED" } }, { status: 500 }),
    );
    const client = new Vizier({ baseUrl: "https://example.test", apiKey: "test", fetch: fetchMock });
    const executor = { ban: vi.fn() };
    const guarded = guardBanAccount(client, options, executor);

    await expect(guarded.ban("fake-user-001")).rejects.toBeInstanceOf(VizierError);
    expect(executor.ban).not.toHaveBeenCalled();
  });
});
