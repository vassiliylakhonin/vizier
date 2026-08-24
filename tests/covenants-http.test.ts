import { webcrypto } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import {
  actionCovenantDraftSchema,
  hashActionCovenantDraft,
} from "../src/covenants/index";
import { handleHttpRequest } from "../src/transport/http";

const API_KEY = "covenant-enforcement-key";
const ISSUER = "https://vizier.example";

async function createTestSigningKey(kid: string): Promise<string> {
  const keyPair = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const privateJwk = await webcrypto.subtle.exportKey("jwk", keyPair.privateKey);
  return JSON.stringify({ ...privateJwk, alg: "ES256", kid, use: "sig" });
}

function createDraft() {
  const now = Date.now();
  return actionCovenantDraftSchema.parse({
    schema_version: "0.2",
    drafted_by: { kind: "MODEL", identifier: "model-test" },
    drafted_at: new Date(now - 60_000).toISOString(),
    principal: { id: "principal-test" },
    agent: { id: "agent-test", owner: "principal-test" },
    intent: "Send one exact test message.",
    action: {
      type: "send_external_message",
      target: "recipient:test",
      parameters: { body_hash: "a".repeat(64) },
    },
    authority: {
      allowed_actions: ["send_external_message"],
      constraints: {
        allowed_targets: ["recipient:test"],
        allowed_sensitive_actions: ["send_external_message"],
      },
    },
    evidence_requirements: [],
    invalidation_rules: [],
    forbidden_outcomes: [],
    expires_at: new Date(now + 3_600_000).toISOString(),
  });
}

async function post(
  path: string,
  body: unknown,
  options: {
    readonly apiKey?: string;
    readonly bearer?: string;
    readonly receiptSigningKey?: string;
  },
): Promise<Response> {
  return handleHttpRequest(
    new Request(`${ISSUER}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(options.bearer === undefined
          ? {}
          : { Authorization: `Bearer ${options.bearer}` }),
      },
      body: JSON.stringify(body),
    }),
    {
      apiKey: options.apiKey,
      receiptSigningKey: options.receiptSigningKey,
    },
  );
}

describe("Action Covenant REST resources", () => {
  it("fails closed without authenticated enforcement and a receipt key", async () => {
    const draft = createDraft();
    const body = {
      draft,
      acceptance: {
        accepted_by: draft.principal,
        accepted_at: new Date().toISOString(),
        draft_hash: await hashActionCovenantDraft(draft),
      },
    };
    const missingBearer = await post("/v1/covenants", body, {
      apiKey: API_KEY,
      receiptSigningKey: await createTestSigningKey("receipt-test"),
    });
    const evaluationOnly = await post("/v1/covenants", body, {});
    const missingSigningKey = await post("/v1/covenants", body, {
      apiKey: API_KEY,
      bearer: API_KEY,
    });
    const invalidSigningKey = await post("/v1/covenants", body, {
      apiKey: API_KEY,
      bearer: API_KEY,
      receiptSigningKey: "not-json",
    });

    expect(missingBearer.status).toBe(401);
    expect(evaluationOnly.status).toBe(503);
    expect(missingSigningKey.status).toBe(503);
    expect(invalidSigningKey.status).toBe(503);
  });

  it("activates, authorizes, and records one signed outcome", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const receiptSigningKey = await createTestSigningKey("receipt-test");
    const options = {
      apiKey: API_KEY,
      bearer: API_KEY,
      receiptSigningKey,
    };
    const draft = createDraft();
    const activation = await post(
      "/v1/covenants",
      {
        draft,
        acceptance: {
          accepted_by: draft.principal,
          accepted_at: new Date().toISOString(),
          draft_hash: await hashActionCovenantDraft(draft),
        },
      },
      options,
    );
    const covenant = (await activation.json()) as {
      id: string;
      draft: typeof draft;
      covenant_hash: string;
    };

    expect(activation.status).toBe(201);
    expect(covenant.id).toMatch(/^acv_/);
    expect(covenant.covenant_hash).toMatch(/^[a-f0-9]{64}$/);

    const authorization = await post(
      "/v1/authorizations",
      {
        covenant,
        action: draft.action,
        evidence: [],
        signals: [],
        context: {
          request_id: "http-covenant-test",
          timestamp: new Date().toISOString(),
          source: "internal",
        },
      },
      options,
    );
    const authorizationBody = (await authorization.json()) as {
      decision: string;
      authorization_receipt: {
        payload: { id: string };
        token: string;
      };
    };

    expect(authorization.status).toBe(200);
    expect(authorizationBody.decision).toBe("ALLOW");
    expect(authorizationBody.authorization_receipt.token.split(".")).toHaveLength(3);

    const startedAt = new Date();
    const outcome = await post(
      "/v1/outcomes",
      {
        covenant,
        authorization_receipt: authorizationBody.authorization_receipt,
        outcome: {
          status: "SUCCEEDED",
          started_at: startedAt.toISOString(),
          finished_at: new Date(startedAt.getTime() + 1_000).toISOString(),
          effects: [
            {
              type: "send_external_message",
              target: "recipient:test",
              parameters: { provider_id: "message-test" },
            },
          ],
          external_reference: "message-test",
        },
      },
      options,
    );
    const outcomeBody = (await outcome.json()) as {
      payload: { authorization_receipt_id: string; compliance: string };
      token: string;
    };

    expect(outcome.status).toBe(201);
    expect(outcomeBody.payload).toMatchObject({
      authorization_receipt_id: authorizationBody.authorization_receipt.payload.id,
      compliance: "COMPLIANT",
    });
    expect(outcomeBody.token.split(".")).toHaveLength(3);
  });

  it("publishes both Agent Card and receipt verification keys", async () => {
    const [agentCardSigningKey, receiptSigningKey] = await Promise.all([
      createTestSigningKey("agent-card-test"),
      createTestSigningKey("receipt-test"),
    ]);
    const response = await handleHttpRequest(
      new Request(`${ISSUER}/.well-known/jwks.json`),
      { agentCardSigningKey, receiptSigningKey },
    );
    const body = (await response.json()) as {
      keys: Array<{ kid: string; d?: string }>;
    };

    expect(body.keys.map((key) => key.kid)).toEqual([
      "agent-card-test",
      "receipt-test",
    ]);
    expect(body.keys.every((key) => key.d === undefined)).toBe(true);
  });
});
