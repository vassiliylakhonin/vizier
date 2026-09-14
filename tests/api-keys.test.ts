import { describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import type { D1Database } from "@cloudflare/workers-types";
import {
  generateApiKey,
  authenticateKey,
  listApiKeys,
  revokeApiKey,
  incrementKeyUsage,
} from "../src/auth/keys";
import { handleHttpRequest } from "../src/transport/http";

function createTestD1(): D1Database {
  const mem = new DatabaseSync(":memory:");
  mem.exec(`
    CREATE TABLE IF NOT EXISTS vizier_api_keys (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      name TEXT NOT NULL,
      key_hash TEXT NOT NULL UNIQUE,
      key_prefix TEXT NOT NULL,
      tier TEXT NOT NULL DEFAULT 'developer',
      monthly_quota INTEGER NOT NULL DEFAULT 10000,
      current_usage INTEGER NOT NULL DEFAULT 0,
      period_month TEXT NOT NULL DEFAULT '',
      created_at INTEGER NOT NULL,
      revoked_at INTEGER
    );
  `);

  return {
    prepare(query: string) {
      return {
        bind(...values: unknown[]) {
          const sqlValues = values as (string | number | bigint | null | Buffer | Uint8Array)[];
          return {
            async first() {
              return mem.prepare(query).get(...sqlValues) ?? null;
            },
            async all() {
              const rows = mem.prepare(query).all(...sqlValues);
              return { results: rows };
            },
            async run() {
              const info = mem.prepare(query).run(...sqlValues);
              return { meta: { changes: Number(info.changes) } };
            },
          };
        },
      };
    },
  } as unknown as D1Database;
}

const MASTER_KEY = "master-secret-key-12345";

describe("Multi-Tenant B2B API Key Manager & Quota Engine", () => {
  it("generates a valid vz_live_ API key with default developer quota", async () => {
    const db = createTestD1();
    const created = await generateApiKey(db, {
      org_id: "org_acme",
      name: "Production Agent Key",
    });

    expect(created.key).toMatch(/^vz_live_[0-9a-f]{48}$/);
    expect(created.key_prefix).toBe(created.key.slice(0, 16));
    expect(created.org_id).toBe("org_acme");
    expect(created.tier).toBe("developer");
    expect(created.monthly_quota).toBe(10000);
  });

  it("authenticates root master key", async () => {
    const db = createTestD1();
    const auth = await authenticateKey(MASTER_KEY, { apiKey: MASTER_KEY, db });
    expect(auth.authenticated).toBe(true);
    expect(auth.is_master).toBe(true);
  });

  it("authenticates a generated tenant key and allows requests", async () => {
    const db = createTestD1();
    const created = await generateApiKey(db, {
      org_id: "org_fintech",
      name: "Trading Agent",
      tier: "team",
    });

    const auth = await authenticateKey(created.key, { apiKey: MASTER_KEY, db });
    expect(auth.authenticated).toBe(true);
    expect(auth.is_master).toBe(false);
    expect(auth.key_record?.org_id).toBe("org_fintech");
    expect(auth.key_record?.tier).toBe("team");
    expect(auth.key_record?.monthly_quota).toBe(100000);
  });

  it("rejects an invalid tenant key", async () => {
    const db = createTestD1();
    const auth = await authenticateKey("vz_live_000000000000000000000000000000000000000000000000", {
      apiKey: MASTER_KEY,
      db,
    });
    expect(auth.authenticated).toBe(false);
    expect(auth.error_code).toBe("INVALID_KEY");
  });

  it("rejects a revoked API key", async () => {
    const db = createTestD1();
    const created = await generateApiKey(db, {
      org_id: "org_corp",
      name: "Temp Key",
    });

    await revokeApiKey(db, created.id);

    const auth = await authenticateKey(created.key, { apiKey: MASTER_KEY, db });
    expect(auth.authenticated).toBe(false);
    expect(auth.error_code).toBe("KEY_REVOKED");
  });

  it("enforces monthly quota limits and blocks with QUOTA_EXCEEDED", async () => {
    const db = createTestD1();
    const created = await generateApiKey(db, {
      org_id: "org_free",
      name: "Limited Key",
      monthly_quota: 2,
    });

    // 1st use
    let auth = await authenticateKey(created.key, { apiKey: MASTER_KEY, db });
    expect(auth.authenticated).toBe(true);
    await incrementKeyUsage(db, created.id);

    // 2nd use
    auth = await authenticateKey(created.key, { apiKey: MASTER_KEY, db });
    expect(auth.authenticated).toBe(true);
    await incrementKeyUsage(db, created.id);

    // 3rd use -> Exceeded!
    auth = await authenticateKey(created.key, { apiKey: MASTER_KEY, db });
    expect(auth.authenticated).toBe(false);
    expect(auth.quota_exceeded).toBe(true);
    expect(auth.error_code).toBe("QUOTA_EXCEEDED");
  });

  it("atomically consumes quota in a single step with consumeQuota: true", async () => {
    const db = createTestD1();
    const created = await generateApiKey(db, {
      org_id: "org_atomic",
      name: "Atomic Test Key",
      monthly_quota: 2,
    });

    // 1st consumption
    const auth1 = await authenticateKey(created.key, { db, consumeQuota: true });
    expect(auth1.authenticated).toBe(true);
    expect(auth1.key_record?.current_usage).toBe(1);

    // 2nd consumption
    const auth2 = await authenticateKey(created.key, { db, consumeQuota: true });
    expect(auth2.authenticated).toBe(true);
    expect(auth2.key_record?.current_usage).toBe(2);

    // 3rd consumption -> atomically blocked!
    const auth3 = await authenticateKey(created.key, { db, consumeQuota: true });
    expect(auth3.authenticated).toBe(false);
    expect(auth3.quota_exceeded).toBe(true);
    expect(auth3.error_code).toBe("QUOTA_EXCEEDED");
  });

  it("lists and revokes keys for an organization", async () => {
    const db = createTestD1();
    const k1 = await generateApiKey(db, { org_id: "org_multi", name: "Key 1" });
    await generateApiKey(db, { org_id: "org_multi", name: "Key 2" });

    let keys = await listApiKeys(db, "org_multi");
    expect(keys).toHaveLength(2);

    const revoked = await revokeApiKey(db, k1.id, "org_multi");
    expect(revoked).toBe(true);

    keys = await listApiKeys(db, "org_multi");
    const foundK1 = keys.find((k) => k.id === k1.id);
    expect(foundK1?.revoked_at).toBeTypeOf("number");
  });
});

describe("Admin API Key Management HTTP Endpoints", () => {
  it("POST /v1/admin/keys creates a key when called with master key", async () => {
    const db = createTestD1();
    const res = await handleHttpRequest(
      new Request("https://vizier.local/v1/admin/keys", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Vizier-Key": MASTER_KEY,
        },
        body: JSON.stringify({
          org_id: "org_enterprise_1",
          name: "Primary Agent Gateway",
          tier: "enterprise",
          monthly_quota: 500000,
        }),
      }),
      { apiKey: MASTER_KEY, db },
    );

    expect(res.status).toBe(201);
    const data = (await res.json()) as { key: string; org_id: string; tier: string; monthly_quota: number };
    expect(data.key).toMatch(/^vz_live_/);
    expect(data.org_id).toBe("org_enterprise_1");
    expect(data.tier).toBe("enterprise");
    expect(data.monthly_quota).toBe(500000);
  });

  it("GET /v1/admin/keys lists keys for organization", async () => {
    const db = createTestD1();
    await generateApiKey(db, { org_id: "org_query", name: "K1" });

    const res = await handleHttpRequest(
      new Request("https://vizier.local/v1/admin/keys?org_id=org_query", {
        method: "GET",
        headers: {
          "X-Vizier-Key": MASTER_KEY,
        },
      }),
      { apiKey: MASTER_KEY, db },
    );

    expect(res.status).toBe(200);
    const data = (await res.json()) as { org_id: string; keys: Array<{ name: string }> };
    expect(data.org_id).toBe("org_query");
    expect(data.keys).toHaveLength(1);
    expect(data.keys[0]?.name).toBe("K1");
  });

  it("DELETE /v1/admin/keys/:id revokes a key", async () => {
    const db = createTestD1();
    const key = await generateApiKey(db, { org_id: "org_del", name: "To Revoke" });

    const res = await handleHttpRequest(
      new Request(`https://vizier.local/v1/admin/keys/${key.id}?org_id=org_del`, {
        method: "DELETE",
        headers: {
          "X-Vizier-Key": MASTER_KEY,
        },
      }),
      { apiKey: MASTER_KEY, db },
    );

    expect(res.status).toBe(200);
    const data = (await res.json()) as { success: boolean; revoked_id: string };
    expect(data.success).toBe(true);
    expect(data.revoked_id).toBe(key.id);
  });

  it("rejects unauthorized admin key creation requests without master key", async () => {
    const db = createTestD1();
    const res = await handleHttpRequest(
      new Request("https://vizier.local/v1/admin/keys", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Vizier-Key": "wrong-key",
        },
        body: JSON.stringify({ org_id: "hack", name: "Unauthorized" }),
      }),
      { apiKey: MASTER_KEY, db },
    );

    expect(res.status).toBe(401);
  });

  it("allows tenant key on /v1/verify and blocks when quota exceeded with 429", async () => {
    const db = createTestD1();
    const key = await generateApiKey(db, {
      org_id: "org_tenant_quota",
      name: "Quota Key",
      monthly_quota: 1,
    });

    const verifyReq = (k: string) =>
      new Request("https://vizier.local/v1/verify", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Vizier-Key": k,
        },
        body: JSON.stringify({
          agent: { id: "test-agent", owner: null },
          principal: null,
          action: { type: "test", target: "test", parameters: {} },
          authority: { allowed_actions: ["test"], constraints: {} },
          context: {
            request_id: "req_quota_1",
            timestamp: "2026-09-11T12:00:00Z",
            source: "rest",
          },
        }),
      });

    // 1st request -> Authenticated 200 OK
    const res1 = await handleHttpRequest(verifyReq(key.key), { apiKey: MASTER_KEY, db });
    expect(res1.status).toBe(200);

    // Exhaust quota
    await incrementKeyUsage(db, key.id);

    // 2nd request -> 429 QUOTA_EXCEEDED
    const res2 = await handleHttpRequest(verifyReq(key.key), { apiKey: MASTER_KEY, db });
    expect(res2.status).toBe(429);
    const err = (await res2.json()) as { error: { code: string } };
    expect(err.error.code).toBe("QUOTA_EXCEEDED");
  });

  it("resets usage counter when a new calendar month begins", async () => {
    const db = createTestD1();
    const key = await generateApiKey(db, {
      org_id: "org_rollover",
      name: "Rollover Key",
      monthly_quota: 2,
    });

    const august = new Date("2026-08-15T12:00:00Z");
    const september = new Date("2026-09-01T10:00:00Z");

    // Exhaust quota in August
    await incrementKeyUsage(db, key.id, august);
    await incrementKeyUsage(db, key.id, august);

    const authAugust = await authenticateKey(key.key, { db }, august);
    expect(authAugust.authenticated).toBe(false);
    expect(authAugust.quota_exceeded).toBe(true);

    // Roll over to September: effective usage resets to 0
    const authSeptember = await authenticateKey(key.key, { db }, september);
    expect(authSeptember.authenticated).toBe(true);
    expect(authSeptember.key_record?.current_usage).toBe(0);

    // Increment in September resets current_usage to 1 and sets period_month to 2026-09
    await incrementKeyUsage(db, key.id, september);
    const authSeptember2 = await authenticateKey(key.key, { db }, september);
    expect(authSeptember2.authenticated).toBe(true);
    expect(authSeptember2.key_record?.current_usage).toBe(1);
    expect(authSeptember2.key_record?.period_month).toBe("2026-09");
  });

  it("atomically handles high-concurrency requests without exceeding quota", async () => {
    const db = createTestD1();
    const quota = 5;
    const totalRequests = 20;
    const key = await generateApiKey(db, {
      org_id: "org_race_condition",
      name: "Race Test Key",
      monthly_quota: quota,
    });

    // Fire 20 concurrent requests simultaneously to /v1/verify
    const responses = await Promise.all(
      Array.from({ length: totalRequests }, (_, i) =>
        handleHttpRequest(
          new Request("https://vizier.local/v1/verify", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-Vizier-Key": key.key,
            },
            body: JSON.stringify({
              agent: { id: `agent-${i}`, owner: null },
              principal: null,
              action: { type: "test", target: "test", parameters: {} },
              authority: { allowed_actions: ["test"], constraints: {} },
              context: {
                request_id: `req_race_${i}`,
                timestamp: "2026-09-14T12:00:00Z",
                source: "rest",
              },
            }),
          }),
          { apiKey: MASTER_KEY, db },
        ),
      ),
    );

    const statuses = responses.map((r) => r.status);
    const successCount = statuses.filter((s) => s === 200).length;
    const quotaExceededCount = statuses.filter((s) => s === 429).length;

    expect(successCount).toBe(quota);
    expect(quotaExceededCount).toBe(totalRequests - quota);

    const row = await db
      .prepare("SELECT current_usage FROM vizier_api_keys WHERE id = ?")
      .bind(key.id)
      .first<{ current_usage: number }>();
    expect(row?.current_usage).toBe(quota);
  });
});
