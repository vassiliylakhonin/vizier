import { webcrypto } from "node:crypto";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { readFileSync } from "node:fs";

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { D1Database } from "@cloudflare/workers-types";

import {
  amountToMicrosCeil,
  budgetKey,
  ceilingToMicrosFloor,
} from "../src/core/budget";
import { mintDelegationGrant } from "../src/core/grants";
import { handleHttpRequest } from "../src/transport/http";
import { resetGrantLifecycleMemory } from "../src/transport/grant-lifecycle";
import type { TransportOptions } from "../src/transport/shared";

const API_KEY = "test-enforcement-key";

function budgetAuthority(ceiling: number, id = "q4-procurement") {
  return {
    allowed_actions: ["purchase", "read_catalog"],
    constraints: {
      budget: { id, ceiling, currency: "USD", actions: ["purchase"] },
    },
  };
}

function createD1(): { db: D1Database; mem: DatabaseSync } {
  const mem = new DatabaseSync(":memory:");
  for (const file of ["0011_grant_lifecycle.sql", "0013_budget_ledger.sql"]) {
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
    context: { request_id: "budget-01", timestamp: null, source: "rest" },
  };
}

describe("budget ceiling", () => {
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

  const spent = (mem: DatabaseSync) =>
    (mem.prepare("SELECT spent_micros AS s, admissions AS a FROM budget_ledger").get() ?? { s: 0, a: 0 }) as {
      s: number;
      a: number;
    };

  it("sums spend across calls and refuses the one that would pass the ceiling", async () => {
    const authority = budgetAuthority(10_000);
    const { grant, principalKeySource } = await setup(authority);
    const { db, mem } = createD1();
    const opts = { principalKeySource, db };
    const outs = [];
    for (let i = 0; i < 3; i += 1) outs.push(await post(request(authority, grant), opts));
    expect(outs.map((o) => o.decision)).toEqual(["ALLOW", "ALLOW", "BLOCK"]);
    expect(outs[2]?.reason_codes).toContain("BUDGET_CEILING_EXCEEDED");
    const rule = outs[2]?.policy_results.find((r) => r.rule_id === "authority.budget.ceiling");
    expect(rule?.details).toMatchObject({ spent_micros: 8_000_000_000, requested_micros: 4_000_000_000 });
    // The refused call is not counted.
    expect(spent(mem)).toEqual({ s: 8_000_000_000, a: 2 });
  });

  it("allows a spend that lands exactly on the ceiling", async () => {
    const authority = budgetAuthority(8_000);
    const { grant, principalKeySource } = await setup(authority);
    const { db } = createD1();
    const opts = { principalKeySource, db };
    expect((await post(request(authority, grant), opts)).decision).toBe("ALLOW");
    expect((await post(request(authority, grant), opts)).decision).toBe("ALLOW");
    expect((await post(request(authority, grant, { parameters: { amount: 0.01, currency: "USD" } }), opts)).decision).toBe("BLOCK");
  });

  it("refuses a call with unknown price: not zero, not counted, coverage partial", async () => {
    const authority = budgetAuthority(10_000);
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
      expect(out.reason_codes).toContain("BUDGET_UNPRICED");
      const rule = out.policy_results.find((r) => r.rule_id === "authority.budget.ceiling");
      expect(rule?.details).toMatchObject({ unpriced: true, coverage: "partial" });
    }
    expect(spent(mem)).toEqual({ s: 0, a: 0 });
  });

  it("leaves actions outside budget.actions alone", async () => {
    const authority = budgetAuthority(1);
    const { grant, principalKeySource } = await setup(authority);
    const { db, mem } = createD1();
    const out = await post(request(authority, grant, { type: "read_catalog", parameters: {} }), { principalKeySource, db });
    expect(out.decision).toBe("ALLOW");
    expect(spent(mem)).toEqual({ s: 0, a: 0 });
  });

  it("needs a signed grant: caller-asserted authority cannot name a fresh budget id", async () => {
    const authority = budgetAuthority(10_000);
    const { principalKeySource } = await setup(authority);
    const { db } = createD1();
    const out = await post(request(authority, undefined), { principalKeySource, db });
    expect(out.decision).toBe("BLOCK");
    expect(out.reason_codes).toContain("BUDGET_REQUIRES_GRANT");
  });

  it("fails closed without a durable ledger", async () => {
    const authority = budgetAuthority(10_000);
    const { grant, principalKeySource } = await setup(authority);
    const out = await post(request(authority, grant), { principalKeySource });
    expect(out.decision).toBe("BLOCK");
    expect(out.reason_codes).toContain("BUDGET_STATE_UNAVAILABLE");
  });

  it("fails closed when the ledger table is missing, instead of reading it as zero spent", async () => {
    const authority = budgetAuthority(10_000);
    const { grant, principalKeySource } = await setup(authority);
    const { db, mem } = createD1();
    mem.exec("DROP TABLE budget_ledger");
    const out = await post(request(authority, grant), { principalKeySource, db });
    expect(out.decision).toBe("BLOCK");
    expect(out.reason_codes).toContain("BUDGET_STATE_UNAVAILABLE");
  });

  it("raising the ceiling with a new grant continues the same accounting", async () => {
    const low = budgetAuthority(8_000);
    const high = budgetAuthority(20_000);
    const { grant: lowGrant, mint, principalKeySource } = await setup(low);
    const { db, mem } = createD1();
    const opts = { principalKeySource, db };
    await post(request(low, lowGrant), opts);
    await post(request(low, lowGrant), opts);
    expect((await post(request(low, lowGrant), opts)).decision).toBe("BLOCK");

    const highGrant = await mint(high);
    expect((await post(request(high, highGrant), opts)).decision).toBe("ALLOW");
    expect(spent(mem).s).toBe(12_000_000_000);
    // 12,000 spent. 16,000 and 20,000 fit; 24,000 does not.
    expect((await post(request(high, highGrant), opts)).decision).toBe("ALLOW");
    expect((await post(request(high, highGrant), opts)).decision).toBe("ALLOW");
    expect((await post(request(high, highGrant), opts)).decision).toBe("BLOCK");
  });

  it("lowering the ceiling below what is already spent blocks everything", async () => {
    const high = budgetAuthority(20_000);
    const low = budgetAuthority(5_000);
    const { grant: highGrant, mint, principalKeySource } = await setup(high);
    const { db } = createD1();
    const opts = { principalKeySource, db };
    await post(request(high, highGrant), opts);
    await post(request(high, highGrant), opts);
    const lowGrant = await mint(low);
    expect((await post(request(low, lowGrant), opts)).decision).toBe("BLOCK");
  });

  it("budgets with different ids are separate", async () => {
    const a = budgetAuthority(4_000, "budget-a");
    const b = budgetAuthority(4_000, "budget-b");
    const { grant: ga, mint, principalKeySource } = await setup(a);
    const gb = await mint(b);
    const { db } = createD1();
    const opts = { principalKeySource, db };
    expect((await post(request(a, ga), opts)).decision).toBe("ALLOW");
    expect((await post(request(a, ga), opts)).decision).toBe("BLOCK");
    expect((await post(request(b, gb), opts)).decision).toBe("ALLOW");
  });

  it("concurrent calls cannot both take the last headroom", async () => {
    const authority = budgetAuthority(10_000);
    const { grant, principalKeySource } = await setup(authority);
    const { db, mem } = createD1();
    const opts = { principalKeySource, db };
    const outs = await Promise.all(
      [1, 2, 3, 4, 5].map(() =>
        post(request(authority, grant, { parameters: { amount: 3_000, currency: "USD" } }), opts),
      ),
    );
    expect(outs.filter((o) => o.decision === "ALLOW")).toHaveLength(3);
    expect(outs.filter((o) => o.reason_codes.includes("BUDGET_CEILING_EXCEEDED"))).toHaveLength(2);
    expect(spent(mem)).toEqual({ s: 9_000_000_000, a: 3 });
  });

  it("a single-use grant that loses its race gives its budget back", async () => {
    const authority = budgetAuthority(10_000);
    const { grant, principalKeySource } = await setup(authority, { singleUse: true });
    const { db, mem } = createD1();
    const opts = { principalKeySource, db };
    const outs = await Promise.all([1, 2, 3].map(() => post(request(authority, grant), opts)));
    expect(outs.filter((o) => o.decision === "ALLOW")).toHaveLength(1);
    expect(spent(mem)).toEqual({ s: 4_000_000_000, a: 1 });
  });

  it("evaluation never claims budget", async () => {
    const authority = budgetAuthority(10_000);
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
    expect(spent(mem)).toEqual({ s: 0, a: 0 });
  });

  it("stores no readable principal or budget id", async () => {
    const authority = budgetAuthority(10_000);
    const { grant, principalKeySource } = await setup(authority);
    const { db, mem } = createD1();
    await post(request(authority, grant), { principalKeySource, db });
    const row = mem.prepare("SELECT * FROM budget_ledger").get() as Record<string, unknown>;
    expect(JSON.stringify(row)).not.toContain("acme-corp");
    expect(JSON.stringify(row)).not.toContain("q4-procurement");
    expect(row.budget_key).toBe(await budgetKey("acme-corp", "q4-procurement"));
  });

  it("rounds spend up and ceiling down", () => {
    expect(amountToMicrosCeil(0.1 + 0.2)).toBe(300_000);
    expect(amountToMicrosCeil(0.0000001)).toBe(1);
    expect(amountToMicrosCeil(-1)).toBeNull();
    expect(amountToMicrosCeil(Number.NaN)).toBeNull();
    expect(amountToMicrosCeil(1e12)).toBeNull();
    expect(ceilingToMicrosFloor(10.0000009)).toBe(10_000_000);
  });
});
