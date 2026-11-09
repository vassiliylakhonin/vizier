import { webcrypto } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  activateActionCovenant,
  actionCovenantActivationRequestSchema,
  actionCovenantDraftSchema,
  authorizeActionCovenant,
  hashActionCovenantDraft,
  mintCovenantAcceptance,
} from "../src/covenants/index";
import { parsePrincipalKeyRegistry } from "../src/core/grants";

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

function draft(overrides: Record<string, unknown> = {}) {
  return actionCovenantDraftSchema.parse({
    schema_version: "0.2",
    drafted_by: { kind: "MODEL", identifier: "semantic-compiler-test" },
    drafted_at: "2026-08-24T07:59:00.000Z",
    principal: { id: "vassiliy-lakhonin" },
    agent: { id: "vizier-gated-deploy", owner: "vassiliy-lakhonin" },
    intent: "Deploy exactly the reviewed Vizier commit.",
    action: { type: "deploy_worker", target: "worker:vizier", parameters: { git_commit: "530871e", dirty_worktree: false } },
    authority: {
      allowed_actions: ["deploy_worker"],
      constraints: { allowed_targets: ["worker:vizier"], allowed_sensitive_actions: ["deploy_worker"] },
    },
    evidence_requirements: [],
    invalidation_rules: [],
    forbidden_outcomes: [],
    expires_at: "2026-08-24T08:10:00.000Z",
    ...overrides,
  });
}

async function signedRequest(signingKey: string, d = draft(), principalId = "vassiliy-lakhonin") {
  const draftHash = await hashActionCovenantDraft(d);
  const minted = await mintCovenantAcceptance({ signingKey, principalId, draftHash, acceptedAt: NOW });
  return actionCovenantActivationRequestSchema.parse({
    draft: d,
    acceptance: { accepted_by: { id: principalId }, accepted_at: minted.accepted_at, draft_hash: draftHash },
    acceptance_jws: minted.token,
  });
}

describe("principal-signed covenant acceptance", () => {
  it("activates with a verified signature and records the proof", async () => {
    const k = await keyPair("principal-1");
    const registry = parsePrincipalKeyRegistry(JSON.stringify({ "vassiliy-lakhonin": k.publicJwk }));
    const covenant = await activateActionCovenant(await signedRequest(k.signingKey), {
      now: () => NOW,
      principalKeys: registry,
      requireSignedAcceptance: true,
    });
    expect(covenant.acceptance_proof).toMatchObject({ type: "principal_signed", key_id: "principal-1" });
    expect(covenant.covenant_hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it("the proof is part of the covenant hash, so removing it fails authorization integrity", async () => {
    const k = await keyPair("principal-1");
    const registry = parsePrincipalKeyRegistry(JSON.stringify({ "vassiliy-lakhonin": k.publicJwk }));
    const covenant = await activateActionCovenant(await signedRequest(k.signingKey), { now: () => NOW, principalKeys: registry });
    const stripped = { ...covenant } as Record<string, unknown>;
    delete stripped.acceptance_proof;
    const result = await authorizeActionCovenant(
      {
        covenant: stripped as typeof covenant,
        action: covenant.draft.action,
        evidence: [],
        signals: [],
        agent: covenant.draft.agent,
        context: { request_id: "r1", timestamp: null, source: "rest" },
      } as never,
      { now: () => NOW, signingKey: k.signingKey, issuer: "https://vizier.example" },
    ).catch(() => null);
    // Either the schema or the integrity check rejects it; it must never ALLOW.
    expect(result === null || result.decision !== "ALLOW").toBe(true);
  });

  it("rejects a bad signature, unknown key, wrong draft, wrong principal", async () => {
    const k = await keyPair("principal-1");
    const other = await keyPair("principal-1");
    const registry = parsePrincipalKeyRegistry(JSON.stringify({ "vassiliy-lakhonin": k.publicJwk }));
    // Signed by a different key that claims the same kid.
    await expect(
      activateActionCovenant(await signedRequest(other.signingKey), { now: () => NOW, principalKeys: registry }),
    ).rejects.toMatchObject({ code: "ACCEPTANCE_SIGNATURE_INVALID" });
    // No registered key.
    await expect(
      activateActionCovenant(await signedRequest(k.signingKey), { now: () => NOW, principalKeys: new Map() }),
    ).rejects.toMatchObject({ code: "ACCEPTANCE_KEY_UNKNOWN" });
    // Signature over a different draft: swap the draft but keep hash+jws -> hash check fails first.
    const good = await signedRequest(k.signingKey);
    const swapped = actionCovenantActivationRequestSchema.parse({ ...good, draft: draft({ intent: "Deploy anything." }) });
    await expect(activateActionCovenant(swapped, { now: () => NOW, principalKeys: registry })).rejects.toMatchObject({
      code: "DRAFT_HASH_MISMATCH",
    });
    // JWS for another acceptance time than the request claims.
    const mismatched = actionCovenantActivationRequestSchema.parse({
      ...good,
      acceptance: { ...good.acceptance, accepted_at: "2026-08-24T08:00:30.000Z" },
    });
    await expect(activateActionCovenant(mismatched, { now: () => NOW, principalKeys: registry })).rejects.toMatchObject({
      code: "ACCEPTANCE_SIGNATURE_MISMATCH",
    });
  });

  it("required mode refuses an unsigned acceptance; default mode still accepts it", async () => {
    const d = draft();
    const unsigned = actionCovenantActivationRequestSchema.parse({
      draft: d,
      acceptance: { accepted_by: d.principal, accepted_at: NOW.toISOString(), draft_hash: await hashActionCovenantDraft(d) },
    });
    await expect(activateActionCovenant(unsigned, { now: () => NOW, requireSignedAcceptance: true })).rejects.toMatchObject({
      code: "ACCEPTANCE_SIGNATURE_REQUIRED",
    });
    const covenant = await activateActionCovenant(unsigned, { now: () => NOW });
    expect(covenant.acceptance_proof).toBeUndefined();
  });
});

describe("mint-grant accept CLI", () => {
  it("produces a signature the service verifies", async () => {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const { mkdtemp, writeFile, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const run = promisify(execFile);
    const dir = await mkdtemp(join(tmpdir(), "vizier-accept-"));
    try {
      const keyPath = join(dir, "p.jwk.json");
      const { stdout } = await run("node", ["scripts/mint-grant.mjs", "keygen", "--kid", "cli-1", "--out", keyPath]);
      const registry = parsePrincipalKeyRegistry(JSON.stringify({ "vassiliy-lakhonin": JSON.parse(stdout)["<principal-id>"] }));
      const d = draft();
      const hash = await hashActionCovenantDraft(d);
      const out = await run("node", ["scripts/mint-grant.mjs", "accept", "--key", keyPath, "--principal", "vassiliy-lakhonin", "--draft-hash", hash, "--accepted-at", NOW.toISOString()]);
      const { accepted_at, acceptance_jws } = JSON.parse(out.stdout) as { accepted_at: string; acceptance_jws: string };
      await writeFile(join(dir, "x"), "");
      const request = actionCovenantActivationRequestSchema.parse({
        draft: d,
        acceptance: { accepted_by: { id: "vassiliy-lakhonin" }, accepted_at, draft_hash: hash },
        acceptance_jws,
      });
      const covenant = await activateActionCovenant(request, { now: () => NOW, principalKeys: registry, requireSignedAcceptance: true });
      expect(covenant.acceptance_proof?.key_id).toBe("cli-1");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }, 30_000);
});
