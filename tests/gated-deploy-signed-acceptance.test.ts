import { webcrypto } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import { runCovenantGatedDeploy } from "../packages/gated-deploy/src/index";
import { parsePrincipalKeyRegistry } from "../src/core/grants";
import {
  activateActionCovenant,
  mintCovenantAcceptance,
} from "../src/covenants/index";

const NOW = new Date("2026-08-24T08:00:00.000Z");

async function keyPair(kid: string) {
  const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const priv = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
  const pub = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    signingKey: JSON.stringify({ ...priv, alg: "ES256", kid, use: "sig" }),
    publicJwk: { ...pub, alg: "ES256", kid, use: "sig" },
  };
}

describe("gated-deploy with principal-signed acceptance", () => {
  it("signs the exact draft hash and the service verifies it in required mode", async () => {
    const k = await keyPair("principal-1");
    const registry = parsePrincipalKeyRegistry(JSON.stringify({ "vassiliy-lakhonin": k.publicJwk }));
    const activate = vi.fn(async (request) =>
      activateActionCovenant(request, { now: () => NOW, principalKeys: registry, requireSignedAcceptance: true }),
    );
    const signAcceptance = vi.fn(async (input: { principalId: string; draftHash: string; acceptedAt: string }) =>
      (await mintCovenantAcceptance({ signingKey: k.signingKey, ...input, acceptedAt: new Date(input.acceptedAt) })).token,
    );
    const result = await runCovenantGatedDeploy({
      metadata: { commit: "abc123", dirty: false },
      gate: {
        activateCovenant: activate,
        authorizeCovenant: async () => ({ decision: "BLOCK", reason_codes: ["TEST_STOP"], authorization_receipt: { payload: { id: "azr_x" } } }) as never,
        recordOutcome: async () => {
          throw new Error("not reached");
        },
      },
      execute: async () => 0,
      now: () => NOW,
      signAcceptance,
    });
    expect(signAcceptance).toHaveBeenCalledOnce();
    expect(activate.mock.calls[0]?.[0].acceptance_jws).toEqual(expect.any(String));
    expect(result.status).toBe("stopped");
  });

  it("keeps the assertion path honest: unsigned acceptance fails when signing is required", async () => {
    const registry = parsePrincipalKeyRegistry(JSON.stringify({}));
    await expect(
      runCovenantGatedDeploy({
        metadata: { commit: "abc123", dirty: false },
        gate: {
          activateCovenant: (request) =>
            activateActionCovenant(request, { now: () => NOW, principalKeys: registry, requireSignedAcceptance: true }),
          authorizeCovenant: async () => {
            throw new Error("not reached");
          },
          recordOutcome: async () => {
            throw new Error("not reached");
          },
        },
        execute: async () => 0,
        now: () => NOW,
      }),
    ).rejects.toMatchObject({ code: "ACCEPTANCE_SIGNATURE_REQUIRED" });
  });
});
