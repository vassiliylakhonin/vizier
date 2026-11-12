import { webcrypto } from "node:crypto";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { readFileSync } from "node:fs";

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { D1Database } from "@cloudflare/workers-types";

import { getDemandFunnel } from "../src/transport/activity";
import { mintDelegationGrant } from "../src/core/grants";
import { handleHttpRequest } from "../src/transport/http";
import { resetGrantLifecycleMemory } from "../src/transport/grant-lifecycle";
import type { TransportOptions } from "../src/transport/shared";

const API_KEY = "test-enforcement-key";

function createD1(): { db: D1Database; mem: DatabaseSync } {
  const mem = new DatabaseSync(":memory:");
  for (const file of ["0011_grant_lifecycle.sql", "0013_budget_ledger.sql", "0016_integration_activity.sql"]) {
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
            async all() {
              return { results: mem.prepare(query).all(...v) };
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


const authority = { allowed_actions: ["purchase"], constraints: {} };
const KEY = "activity-hmac-key-0123456789";

async function principal(issuer: string) {
  const k = await keys();
  const grant = await mintDelegationGrant({
    signingKey: k.signingKey,
    issuer,
    subject: "procurement-agent-01",
    authority: authority as never,
    ttlSeconds: 90 * 86_400,
    jti: `grant_${crypto.randomUUID()}`,
  });
  return { issuer, grant, publicJwk: k.publicJwk };
}

function req(p: { issuer: string; grant: string }) {
  const base = request(authority, p.grant);
  return { ...base, principal: { id: p.issuer } };
}

describe("demand funnel", () => {
  beforeEach(() => {
    resetGrantLifecycleMemory();
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-11-01T10:00:00Z"));
  });

  it("counts repeat integrations on separate days, excludes own, stores no identity", async () => {
    const a = await principal("customer-a");
    const b = await principal("customer-b");
    const me = await principal("maintainer");
    const { db, mem } = createD1();
    const principalKeySource = JSON.stringify({
      "customer-a": a.publicJwk,
      "customer-b": b.publicJwk,
      maintainer: me.publicJwk,
    });
    const opts = {
      principalKeySource,
      db,
      activityKey: KEY,
      activityExcludeSource: JSON.stringify(["maintainer"]),
    };
    for (const day of ["2026-11-01", "2026-11-03"]) {
      vi.setSystemTime(new Date(`${day}T10:00:00Z`));
      expect((await post(req(a), opts)).decision).toBe("ALLOW");
    }
    vi.setSystemTime(new Date("2026-11-03T11:00:00Z"));
    await post(req(b), opts);
    await post(req(me), opts);
    await post(req(me), opts);
    const funnel = await getDemandFunnel(db, Date.now());
    expect(funnel).toMatchObject({
      integrations_with_first_allow: 2,
      repeat_integrations: 1,
      excluded_integrations: 1,
      meets_thresholds: false,
    });
    const dump = JSON.stringify(mem.prepare("SELECT * FROM integration_activity").all());
    for (const forbidden of ["customer-a", "customer-b", "maintainer", "procurement-agent-01", "supplier.example"]) {
      expect(dump).not.toContain(forbidden);
    }
    expect(JSON.stringify(funnel)).not.toMatch(/[a-f0-9]{64}/);
  });

  it("is off without a key, ignores unsigned traffic and never changes the decision", async () => {
    const a = await principal("customer-a");
    const { db, mem } = createD1();
    const principalKeySource = JSON.stringify({ "customer-a": a.publicJwk });
    await post(req(a), { principalKeySource, db });
    await post(request(authority, undefined), { principalKeySource, db, activityKey: KEY });
    expect(mem.prepare("SELECT COUNT(*) AS n FROM integration_activity").get()).toEqual({ n: 0 });
    mem.exec("DROP TABLE integration_activity");
    expect((await post(req(a), { principalKeySource, db, activityKey: KEY })).decision).toBe("ALLOW");
  });
});
