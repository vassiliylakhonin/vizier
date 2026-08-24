import { webcrypto } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import {
  Vizier,
  hashActionCovenantDraft,
  type ActionCovenantDraft,
} from "../packages/sdk/src/index";
import { handleHttpRequest } from "../src/transport/http";

const BASE_URL = "https://vizier.example";
const API_KEY = "sdk-covenant-key";

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
    kid: "sdk-receipt-test",
    use: "sig",
  });
}

function draft(): ActionCovenantDraft {
  const now = Date.now();
  return {
    schema_version: "0.2",
    drafted_by: { kind: "MODEL", identifier: "sdk-model-test" },
    drafted_at: new Date(now - 1_000).toISOString(),
    principal: { id: "principal-test" },
    agent: { id: "agent-test", owner: "principal-test" },
    intent: "Deploy one exact commit.",
    action: {
      type: "deploy_worker",
      target: "worker:vizier",
      parameters: { git_commit: "abc123" },
    },
    authority: {
      allowed_actions: ["deploy_worker"],
      constraints: {
        allowed_targets: ["worker:vizier"],
        allowed_sensitive_actions: ["deploy_worker"],
      },
    },
    evidence_requirements: [],
    invalidation_rules: [],
    forbidden_outcomes: [],
    expires_at: new Date(now + 3_600_000).toISOString(),
  };
}

describe("@vizier/sdk Action Covenant lifecycle", () => {
  it("validates signed authorization and outcome receipts against JWKS", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const receiptSigningKey = await createTestSigningKey();
    const fetchMock = vi.fn<typeof fetch>((input, init) => {
      const request = new Request(input, init);
      return handleHttpRequest(request, {
        apiKey: API_KEY,
        receiptSigningKey,
      });
    });
    const vizier = new Vizier({
      baseUrl: BASE_URL,
      apiKey: API_KEY,
      fetch: fetchMock,
    });
    const covenantDraft = draft();
    const covenant = await vizier.activateCovenant({
      draft: covenantDraft,
      acceptance: {
        accepted_by: covenantDraft.principal,
        accepted_at: new Date().toISOString(),
        draft_hash: await hashActionCovenantDraft(covenantDraft),
      },
    });
    const authorization = await vizier.authorizeCovenant({
      covenant,
      action: covenantDraft.action,
      evidence: [],
      signals: [],
      context: {
        request_id: "sdk-covenant-test",
        timestamp: new Date().toISOString(),
        source: "internal",
      },
    });
    const startedAt = new Date();
    const outcome = await vizier.recordOutcome({
      covenant,
      authorization_receipt: authorization.authorization_receipt,
      outcome: {
        status: "SUCCEEDED",
        started_at: startedAt.toISOString(),
        finished_at: new Date(startedAt.getTime() + 1_000).toISOString(),
        effects: [
          {
            type: "deploy_worker",
            target: "worker:vizier",
            parameters: { git_commit: "abc123" },
          },
        ],
        external_reference: "deployment-test",
      },
    });

    expect(authorization.decision).toBe("ALLOW");
    expect(outcome.payload).toMatchObject({
      authorization_receipt_id: authorization.authorization_receipt.payload.id,
      compliance: "COMPLIANT",
    });
    expect(
      fetchMock.mock.calls.filter(([input]) =>
        String(input).endsWith("/.well-known/jwks.json"),
      ),
    ).toHaveLength(2);
  });

  it("rejects a payload changed after signing", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const receiptSigningKey = await createTestSigningKey();
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const request = new Request(input, init);
      const response = await handleHttpRequest(request, {
        apiKey: API_KEY,
        receiptSigningKey,
      });
      if (new URL(request.url).pathname !== "/v1/authorizations") {
        return response;
      }
      const body = (await response.json()) as {
        authorization_receipt: { payload: { action_hash: string } };
      };
      body.authorization_receipt.payload.action_hash = "f".repeat(64);
      return Response.json(body, { status: response.status });
    });
    const vizier = new Vizier({
      baseUrl: BASE_URL,
      apiKey: API_KEY,
      fetch: fetchMock,
    });
    const covenantDraft = draft();
    const covenant = await vizier.activateCovenant({
      draft: covenantDraft,
      acceptance: {
        accepted_by: covenantDraft.principal,
        accepted_at: new Date().toISOString(),
        draft_hash: await hashActionCovenantDraft(covenantDraft),
      },
    });

    await expect(
      vizier.authorizeCovenant({
        covenant,
        action: covenantDraft.action,
        evidence: [],
        signals: [],
        context: {
          request_id: null,
          timestamp: new Date().toISOString(),
          source: "internal",
        },
      }),
    ).rejects.toMatchObject({ code: "INVALID_RESPONSE" });
  });
});
