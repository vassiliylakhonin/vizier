import { webcrypto } from "node:crypto";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { readFileSync } from "node:fs";

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { D1Database } from "@cloudflare/workers-types";

import { mintDelegationGrant } from "../src/core/grants";
import { handleHttpRequest } from "../src/transport/http";
import { resetGrantLifecycleMemory } from "../src/transport/grant-lifecycle";
import type { TransportOptions } from "../src/transport/shared";

const API_KEY = "test-enforcement-key";
const AUTHORITY = {
  allowed_actions: ["purchase"],
  constraints: { max_amount: 10_000, currency: "USD" },
};

function createD1(): D1Database {
  const mem = new DatabaseSync(":memory:");
  mem.exec(readFileSync(new URL("../migrations/0011_grant_lifecycle.sql", import.meta.url), "utf8"));
  return {
    prepare(query: string) {
      return {
        bind(...values: unknown[]) {
          const v = values as SQLInputValue[];
          return {
            async first() {
              return mem.prepare(query).get(...v) ?? null;
            },
            async run() {
              const info = mem.prepare(query).run(...v);
              return { meta: { changes: Number(info.changes) } };
            },
          };
        },
      };
    },
  } as unknown as D1Database;
}

async function keys(): Promise<{ signingKey: string; publicJwk: Record<string, unknown> }> {
  const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const priv = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
  const pub = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    signingKey: JSON.stringify({ ...priv, alg: "ES256", kid: "acme-1", use: "sig" }),
    publicJwk: { ...pub, alg: "ES256", kid: "acme-1", use: "sig" },
  };
}

function body(grant: string): Record<string, unknown> {
  return {
    agent: { id: "procurement-agent-01", owner: "acme-corp" },
    principal: { id: "acme-corp" },
    action: { type: "purchase", target: "supplier.example", parameters: { amount: 8_200, currency: "USD" } },
    authority: AUTHORITY,
    grant,
    context: { request_id: "lifecycle-01", timestamp: null, source: "rest" },
  };
}

async function post(
  path: string,
  payload: unknown,
  options: Partial<TransportOptions>,
  authed = true,
): Promise<Response> {
  return handleHttpRequest(
    new Request(`https://vizier.example${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(authed ? { Authorization: `Bearer ${API_KEY}` } : {}) },
      body: JSON.stringify(payload),
    }),
    { apiKey: API_KEY, ...options },
  );
}

interface Decision {
  decision: string;
  reason_codes: string[];
}

describe("grant lifecycle", () => {
  beforeEach(() => {
    resetGrantLifecycleMemory();
    vi.spyOn(console, "log").mockImplementation(() => undefined);
  });

  async function setup(extra: { singleUse?: boolean; jti?: string } = {}) {
    const k = await keys();
    const grant = await mintDelegationGrant({
      signingKey: k.signingKey,
      issuer: "acme-corp",
      subject: "procurement-agent-01",
      authority: AUTHORITY,
      ttlSeconds: 3600,
      jti: extra.jti ?? `grant_${crypto.randomUUID()}`,
      ...(extra.singleUse === true ? { singleUse: true } : {}),
    });
    const principalKeySource = JSON.stringify({ "acme-corp": k.publicJwk });
    return { grant, principalKeySource };
  }

  it("a normal grant stays reusable", async () => {
    const { grant, principalKeySource } = await setup();
    const opts = { principalKeySource, db: createD1() };
    for (let i = 0; i < 3; i += 1) {
      const out = (await (await post("/v1/verify", body(grant), opts)).json()) as Decision;
      expect(out.decision).toBe("ALLOW");
    }
  });

  it("single-use grant ALLOWs once, then BLOCKs with GRANT_ALREADY_USED", async () => {
    const { grant, principalKeySource } = await setup({ singleUse: true });
    const opts = { principalKeySource, db: createD1() };
    const first = (await (await post("/v1/verify", body(grant), opts)).json()) as Decision;
    const second = (await (await post("/v1/verify", body(grant), opts)).json()) as Decision;
    expect(first.decision).toBe("ALLOW");
    expect(second.decision).toBe("BLOCK");
    expect(second.reason_codes).toContain("GRANT_ALREADY_USED");
  });

  it("only one of two concurrent presentations is ALLOWed", async () => {
    const { grant, principalKeySource } = await setup({ singleUse: true });
    const opts = { principalKeySource, db: createD1() };
    const results = (await Promise.all(
      [1, 2, 3].map(async () => (await post("/v1/verify", body(grant), opts)).json()),
    )) as Decision[];
    expect(results.filter((r) => r.decision === "ALLOW")).toHaveLength(1);
    expect(results.filter((r) => r.reason_codes.includes("GRANT_ALREADY_USED"))).toHaveLength(2);
  });

  it("works without D1 using per-isolate memory", async () => {
    const { grant, principalKeySource } = await setup({ singleUse: true });
    const first = (await (await post("/v1/verify", body(grant), { principalKeySource })).json()) as Decision;
    const second = (await (await post("/v1/verify", body(grant), { principalKeySource })).json()) as Decision;
    expect([first.decision, second.decision]).toEqual(["ALLOW", "BLOCK"]);
  });

  it("evaluation never consumes a single-use grant", async () => {
    const { grant, principalKeySource } = await setup({ singleUse: true });
    const opts = { principalKeySource, db: createD1() };
    await post("/v1/verify/evaluate", body(grant), opts, false);
    await post("/v1/verify/evaluate", body(grant), opts, false);
    const real = (await (await post("/v1/verify", body(grant), opts)).json()) as Decision;
    expect(real.decision).toBe("ALLOW");
  });

  it("a BLOCKed request does not consume a single-use grant", async () => {
    const { grant, principalKeySource } = await setup({ singleUse: true });
    const opts = { principalKeySource, db: createD1() };
    const over = body(grant);
    (over.action as { parameters: { amount: number } }).parameters.amount = 99_999;
    expect(((await (await post("/v1/verify", over, opts)).json()) as Decision).decision).toBe("BLOCK");
    expect(((await (await post("/v1/verify", body(grant), opts)).json()) as Decision).decision).toBe("ALLOW");
  });

  it("revocation endpoint blocks the grant with GRANT_REVOKED", async () => {
    const { grant, principalKeySource } = await setup({ jti: "grant_to_revoke" });
    const opts = { principalKeySource, db: createD1() };
    expect(((await (await post("/v1/verify", body(grant), opts)).json()) as Decision).decision).toBe("ALLOW");
    const revoke = await post("/v1/grants/revoke", { jti: "grant_to_revoke" }, opts);
    expect(revoke.status).toBe(200);
    const after = (await (await post("/v1/verify", body(grant), opts)).json()) as Decision;
    expect(after.decision).toBe("BLOCK");
    expect(after.reason_codes).toContain("GRANT_REVOKED");
  });

  it("static VIZIER_REVOKED_GRANTS source blocks without D1", async () => {
    const { grant, principalKeySource } = await setup({ jti: "grant_static" });
    const after = (await (
      await post("/v1/verify", body(grant), { principalKeySource, revokedGrantSource: '["grant_static"]' })
    ).json()) as Decision;
    expect(after.reason_codes).toContain("GRANT_REVOKED");
  });

  it("revocation requires the integration credential and D1", async () => {
    const unauth = await post("/v1/grants/revoke", { jti: "x" }, { db: createD1() }, false);
    expect(unauth.status).toBe(401);
    const noDb = await post("/v1/grants/revoke", { jti: "x" }, {});
    expect(noDb.status).toBe(503);
  });

  it("a forged token naming a revoked id cannot probe state: signature is checked first", async () => {
    const { principalKeySource } = await setup();
    const other = await keys();
    const forged = await mintDelegationGrant({
      signingKey: other.signingKey,
      issuer: "acme-corp",
      subject: "procurement-agent-01",
      authority: AUTHORITY,
      ttlSeconds: 3600,
      jti: "grant_static",
    });
    const out = (await (
      await post("/v1/verify", body(forged), { principalKeySource, revokedGrantSource: '["grant_static"]' })
    ).json()) as Decision;
    expect(out.reason_codes).toContain("GRANT_SIGNATURE_INVALID");
    expect(out.reason_codes).not.toContain("GRANT_REVOKED");
  });
});
