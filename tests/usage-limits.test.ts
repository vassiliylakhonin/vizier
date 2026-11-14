import { webcrypto } from "node:crypto";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { readFileSync } from "node:fs";

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { D1Database } from "@cloudflare/workers-types";

import { mintDelegationGrant } from "../src/core/grants";
import { usageKey, usageWindowStart } from "../src/core/usage";
import { handleHttpRequest } from "../src/transport/http";
import { resetGrantLifecycleMemory } from "../src/transport/grant-lifecycle";
import type { TransportOptions } from "../src/transport/shared";

const API_KEY = "test-enforcement-key";

interface UsageConstraint {
  readonly id?: string;
  readonly window_seconds?: number;
  readonly max_calls?: number;
  readonly max_amount?: number;
  readonly currency?: string;
}

function usageAuthority(usage: UsageConstraint) {
  return {
    allowed_actions: ["purchase", "read_catalog"],
    constraints: {
      usage: {
        id: usage.id ?? "ops-window",
        window_seconds: usage.window_seconds ?? 86_400,
        ...(usage.max_calls === undefined ? {} : { max_calls: usage.max_calls }),
        ...(usage.max_amount === undefined
          ? {}
          : { max_amount: usage.max_amount, currency: usage.currency ?? "USD" }),
      },
    },
  };
}

function createD1(): { db: D1Database; mem: DatabaseSync } {
  const mem = new DatabaseSync(":memory:");
  for (const file of ["0011_grant_lifecycle.sql", "0017_usage_ledger.sql"]) {
    mem.exec(readFileSync(new URL(`../migrations/${file}`, import.meta.url), "utf8"));
  }
  const db = {
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
  return { db, mem };
}

async function keys() {
  const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const priv = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
  const pub = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    signingKey: JSON.stringify({ ...priv, alg: "ES256", kid: "acme-1", use: "sig" }),
    publicJwk: { ...pub, alg: "ES256", kid: "acme-1", use: "sig" },
  };
}

interface Decision {
  decision: string;
  reason_codes: string[];
  policy_results: { rule_id: string; details: Record<string, unknown> }[];
}

async function post(payload: unknown, options: Partial<TransportOptions>): Promise<Decision> {
  const res = await handleHttpRequest(
    new Request("https://vizier.example/v1/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${API_KEY}` },
      body: JSON.stringify(payload),
    }),
    { apiKey: API_KEY, ...options },
  );
  return (await res.json()) as Decision;
}

function request(
  authority: unknown,
  grant: string | undefined,
  action: { type?: string; parameters?: Record<string, unknown> } = {},
) {
  return {
    agent: { id: "procurement-agent-01", owner: "acme-corp" },
    principal: { id: "acme-corp" },
    action: {
      type: action.type ?? "purchase",
      target: "supplier.example",
      parameters: action.parameters ?? { amount: 4_000, currency: "USD" },
    },
    authority,
    ...(grant === undefined ? {} : { grant }),
    context: { request_id: `req_${crypto.randomUUID()}`, timestamp: null, source: "rest" },
  };
}

describe("per-window usage bounds", () => {
  beforeEach(() => {
    resetGrantLifecycleMemory();
    vi.spyOn(console, "log").mockImplementation(() => undefined);
  });

  async function setup(authority: unknown, extra: { singleUse?: boolean } = {}) {
    const k = await keys();
    const mint = (auth: unknown) =>
      mintDelegationGrant({
        signingKey: k.signingKey,
        issuer: "acme-corp",
        subject: "procurement-agent-01",
        authority: auth as never,
        ttlSeconds: 3600,
        jti: `grant_${crypto.randomUUID()}`,
        ...(extra.singleUse === true ? { singleUse: true } : {}),
      });
    return {
      grant: await mint(authority),
      mint,
      principalKeySource: JSON.stringify({ "acme-corp": k.publicJwk }),
    };
  }

  const ledger = (mem: DatabaseSync) =>
    (mem.prepare("SELECT calls AS c, spent_micros AS s FROM usage_ledger").get() ?? { c: 0, s: 0 }) as {
      c: number;
      s: number;
    };

  it("counts calls and refuses the one past max_calls", async () => {
    const authority = usageAuthority({ max_calls: 2 });
    const { grant, principalKeySource } = await setup(authority);
    const { db, mem } = createD1();
    const opts = { principalKeySource, db };
    const outs = [];
    for (let i = 0; i < 3; i += 1) outs.push(await post(request(authority, grant), opts));
    expect(outs.map((o) => o.decision)).toEqual(["ALLOW", "ALLOW", "BLOCK"]);
    expect(outs[2]?.reason_codes).toContain("USAGE_CALL_LIMIT_EXCEEDED");
    const rule = outs[2]?.policy_results.find((r) => r.rule_id === "authority.usage.window");
    expect(rule?.details).toMatchObject({ calls_in_window: 2, max_calls: 2 });
    // The refused call is not counted, and a calls-only bound counts no spend.
    expect(ledger(mem)).toEqual({ c: 2, s: 0 });
  });

  it("a calls-only bound does not require a price", async () => {
    const authority = usageAuthority({ max_calls: 2 });
    const { grant, principalKeySource } = await setup(authority);
    const { db, mem } = createD1();
    const opts = { principalKeySource, db };
    expect((await post(request(authority, grant, { parameters: {} }), opts)).decision).toBe("ALLOW");
    expect((await post(request(authority, grant, { parameters: {} }), opts)).decision).toBe("ALLOW");
    expect((await post(request(authority, grant, { parameters: {} }), opts)).decision).toBe("BLOCK");
    expect(ledger(mem)).toEqual({ c: 2, s: 0 });
  });

  it("sums amounts inside the window and refuses the one past max_amount", async () => {
    const authority = usageAuthority({ max_amount: 10_000 });
    const { grant, principalKeySource } = await setup(authority);
    const { db, mem } = createD1();
    const opts = { principalKeySource, db };
    const outs = [];
    for (let i = 0; i < 3; i += 1) outs.push(await post(request(authority, grant), opts));
    expect(outs.map((o) => o.decision)).toEqual(["ALLOW", "ALLOW", "BLOCK"]);
    expect(outs[2]?.reason_codes).toContain("USAGE_AMOUNT_LIMIT_EXCEEDED");
    const rule = outs[2]?.policy_results.find((r) => r.rule_id === "authority.usage.window");
    expect(rule?.details).toMatchObject({ spent_micros: 8_000_000_000, requested_micros: 4_000_000_000 });
    expect(ledger(mem)).toEqual({ c: 2, s: 8_000_000_000 });
  });

  it("refuses a call with unknown price when an amount bound is set: not zero, not counted", async () => {
    const authority = usageAuthority({ max_amount: 10_000 });
    const { grant, principalKeySource } = await setup(authority);
    const { db, mem } = createD1();
    const opts = { principalKeySource, db };
    const cases: Record<string, unknown>[] = [
      {},
      { currency: "USD" },
      { amount: "4000", currency: "USD" },
      { amount: -1, currency: "USD" },
      { amount: 100, currency: "EUR" },
      { amount: 100 },
    ];
    for (const parameters of cases) {
      const out = await post(request(authority, grant, { parameters }), opts);
      expect(out.decision).toBe("BLOCK");
      expect(out.reason_codes).toContain("USAGE_UNPRICED");
      const rule = out.policy_results.find((r) => r.rule_id === "authority.usage.window");
      expect(rule?.details).toMatchObject({ unpriced: true, coverage: "partial" });
    }
    expect(ledger(mem)).toEqual({ c: 0, s: 0 });
  });

  it("needs a signed grant: caller-asserted authority cannot name a fresh usage id", async () => {
    const authority = usageAuthority({ max_calls: 5 });
    const { principalKeySource } = await setup(authority);
    const { db } = createD1();
    const out = await post(request(authority, undefined), { principalKeySource, db });
    expect(out.decision).toBe("BLOCK");
    expect(out.reason_codes).toContain("USAGE_REQUIRES_GRANT");
  });

  it("fails closed without a durable ledger", async () => {
    const authority = usageAuthority({ max_calls: 5 });
    const { grant, principalKeySource } = await setup(authority);
    const out = await post(request(authority, grant), { principalKeySource });
    expect(out.decision).toBe("BLOCK");
    expect(out.reason_codes).toContain("USAGE_STATE_UNAVAILABLE");
  });

  it("fails closed when the ledger table is missing, instead of reading it as zero used", async () => {
    const authority = usageAuthority({ max_calls: 5 });
    const { grant, principalKeySource } = await setup(authority);
    const { db, mem } = createD1();
    mem.exec("DROP TABLE usage_ledger");
    const out = await post(request(authority, grant), { principalKeySource, db });
    expect(out.decision).toBe("BLOCK");
    expect(out.reason_codes).toContain("USAGE_STATE_UNAVAILABLE");
  });

  it("usage bounds with different ids are separate", async () => {
    const a = usageAuthority({ id: "window-a", max_calls: 1 });
    const b = usageAuthority({ id: "window-b", max_calls: 1 });
    const { grant: ga, mint, principalKeySource } = await setup(a);
    const gb = await mint(b);
    const { db } = createD1();
    const opts = { principalKeySource, db };
    expect((await post(request(a, ga), opts)).decision).toBe("ALLOW");
    expect((await post(request(a, ga), opts)).decision).toBe("BLOCK");
    expect((await post(request(b, gb), opts)).decision).toBe("ALLOW");
  });

  it("concurrent calls cannot all take the last headroom", async () => {
    const authority = usageAuthority({ max_calls: 3 });
    const { grant, principalKeySource } = await setup(authority);
    const { db, mem } = createD1();
    const opts = { principalKeySource, db };
    const outs = await Promise.all(
      [1, 2, 3, 4, 5].map(() => post(request(authority, grant), opts)),
    );
    expect(outs.filter((o) => o.decision === "ALLOW")).toHaveLength(3);
    expect(outs.filter((o) => o.reason_codes.includes("USAGE_CALL_LIMIT_EXCEEDED"))).toHaveLength(2);
    expect(ledger(mem).c).toBe(3);
  });

  it("a single-use grant that loses its race gives its usage back", async () => {
    const authority = usageAuthority({ max_calls: 2 });
    const { grant, principalKeySource } = await setup(authority, { singleUse: true });
    const { db, mem } = createD1();
    const opts = { principalKeySource, db };
    const outs = await Promise.all([1, 2, 3].map(() => post(request(authority, grant), opts)));
    expect(outs.filter((o) => o.decision === "ALLOW")).toHaveLength(1);
    expect(ledger(mem).c).toBe(1);
  });

  it("evaluation never claims usage", async () => {
    const authority = usageAuthority({ max_calls: 1 });
    const { grant, principalKeySource } = await setup(authority);
    const { db, mem } = createD1();
    const res = await handleHttpRequest(
      new Request("https://vizier.example/v1/verify/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request(authority, grant)),
      }),
      { apiKey: API_KEY, principalKeySource, db },
    );
    expect(((await res.json()) as Decision).decision).not.toBe("ALLOW");
    expect(ledger(mem)).toEqual({ c: 0, s: 0 });
  });

  it("stores no readable principal or usage id", async () => {
    const authority = usageAuthority({ max_calls: 5 });
    const { grant, principalKeySource } = await setup(authority);
    const { db, mem } = createD1();
    await post(request(authority, grant), { principalKeySource, db });
    const row = mem.prepare("SELECT * FROM usage_ledger").get() as Record<string, unknown>;
    expect(JSON.stringify(row)).not.toContain("acme-corp");
    expect(JSON.stringify(row)).not.toContain("ops-window");
    expect(row.usage_key).toBe(await usageKey("acme-corp", "ops-window"));
  });

  it("rejects a usage constraint with no bound", async () => {
    const authority = {
      allowed_actions: ["purchase"],
      constraints: { usage: { id: "empty", window_seconds: 3600 } },
    };
    const res = await handleHttpRequest(
      new Request("https://vizier.example/v1/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${API_KEY}` },
        body: JSON.stringify(request(authority, undefined)),
      }),
      { apiKey: API_KEY },
    );
    expect(res.status).toBe(422);
  });

  it("computes fixed epoch-aligned window starts", () => {
    expect(usageWindowStart(0, 60)).toBe(0);
    expect(usageWindowStart(59, 60)).toBe(0);
    expect(usageWindowStart(60, 60)).toBe(60);
    expect(usageWindowStart(86_400 + 1, 86_400)).toBe(86_400);
  });
});
