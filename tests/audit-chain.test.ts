import { readFileSync, readdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

import type { D1Database } from "@cloudflare/workers-types";
import { describe, expect, it, vi } from "vitest";

import type { VerificationRequest } from "../src/core/schemas";
import type { Receipt } from "../src/core/types";
import {
  pruneAuditMetadata,
  storeReceipt,
  verifyAuditChain,
} from "../src/storage/audit";
import { handleHttpRequest } from "../src/transport/http";

const API_KEY = "audit-chain-test-enforcement-key";

function createMigratedSqlite(): DatabaseSync {
  const sqlite = new DatabaseSync(":memory:");
  const migrationsDir = new URL("../migrations/", import.meta.url);
  for (const name of readdirSync(migrationsDir)
    .filter((file) => /^\d+.*\.sql$/.test(file))
    .sort()) {
    sqlite.exec(readFileSync(new URL(name, migrationsDir), "utf8"));
  }
  return sqlite;
}

type SqlValue = null | number | bigint | string | Uint8Array;

function wrapD1(sqlite: DatabaseSync): D1Database {
  const bindRun = (statement: ReturnType<DatabaseSync["prepare"]>, values: SqlValue[]) => ({
    run: async () => ({
      success: true,
      meta: { changes: statement.run(...values).changes },
    }),
    first: async () => statement.get(...values) ?? null,
    all: async () => ({ success: true, results: statement.all(...values) }),
  });
  return {
    batch: async (statements: Array<{ run: () => Promise<unknown> }>) => {
      const results: unknown[] = [];
      for (const statement of statements) results.push(await statement.run());
      return results;
    },
    prepare: (query: string) => {
      const statement = sqlite.prepare(query);
      return {
        bind: (...values: SqlValue[]) => bindRun(statement, values),
        run: async () => ({ success: true, meta: { changes: statement.run().changes } }),
        first: async () => statement.get() ?? null,
        all: async () => ({ success: true, results: statement.all() }),
      };
    },
  } as unknown as D1Database;
}

function verificationRequest(source: string): VerificationRequest {
  return {
    agent: { id: "agent-1", owner: null },
    principal: { id: "principal-1" },
    action: { type: "purchase", target: "supplier.example", parameters: {} },
    authority: { allowed_actions: ["purchase"], constraints: {} },
    context: { request_id: null, timestamp: null, source: source as "rest" },
  };
}

function receipt(id: string, createdAt: string, decision: Receipt["decision"]): Receipt {
  return {
    id,
    created_at: createdAt,
    request_hash: `reqhash-${id}`,
    decision,
    risk_score: 0.1,
    policy_rule_ids: ["policy_allowed"],
    reason_codes: [],
    authority_provenance: "trusted_integration",
  };
}

async function storeThreeReceipts(db: D1Database): Promise<void> {
  const request = verificationRequest("rest");
  await storeReceipt(db, request, receipt("vrf_1", "2026-11-10T10:00:00.000Z", "ALLOW"));
  await storeReceipt(db, request, receipt("vrf_2", "2026-11-10T10:00:01.000Z", "REVIEW"));
  await storeReceipt(db, request, receipt("vrf_3", "2026-11-10T10:00:02.000Z", "BLOCK"));
}

describe("hash-chained audit receipt log", () => {
  it("links stored receipts and verifies the chain", async () => {
    const sqlite = createMigratedSqlite();
    const db = wrapD1(sqlite);
    await storeThreeReceipts(db);

    const rows = sqlite
      .prepare(
        "SELECT id, receipt_hash, prev_receipt_hash FROM audit_receipts ORDER BY created_at, rowid",
      )
      .all() as Array<Record<string, string>>;
    expect(rows).toHaveLength(3);
    expect(rows[0]?.prev_receipt_hash).toBe("");
    expect(rows[0]?.receipt_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(rows[1]?.prev_receipt_hash).toBe(rows[0]?.receipt_hash);
    expect(rows[2]?.prev_receipt_hash).toBe(rows[1]?.receipt_hash);

    await expect(verifyAuditChain(db)).resolves.toEqual({
      ok: true,
      checked: 3,
      legacy: 0,
      head_hash: rows[2]?.receipt_hash,
    });
  });

  it("detects modification of a stored row", async () => {
    const sqlite = createMigratedSqlite();
    const db = wrapD1(sqlite);
    await storeThreeReceipts(db);
    sqlite.prepare("UPDATE audit_receipts SET decision = 'ALLOW' WHERE id = 'vrf_2'").run();

    await expect(verifyAuditChain(db)).resolves.toEqual({
      ok: false,
      checked: 1,
      legacy: 0,
      head_hash: expect.any(String) as string,
      first_broken_id: "vrf_2",
      reason: "HASH_MISMATCH",
    });
  });

  it("detects deletion of a row that still has a chained successor", async () => {
    const sqlite = createMigratedSqlite();
    const db = wrapD1(sqlite);
    await storeThreeReceipts(db);
    sqlite.prepare("DELETE FROM audit_receipts WHERE id = 'vrf_1'").run();

    await expect(verifyAuditChain(db)).resolves.toEqual({
      ok: false,
      checked: 0,
      legacy: 0,
      head_hash: null,
      first_broken_id: "vrf_2",
      reason: "PREV_MISMATCH",
    });
  });

  it("skips pre-migration rows without a hash as legacy", async () => {
    const sqlite = createMigratedSqlite();
    const db = wrapD1(sqlite);
    sqlite
      .prepare(
        "INSERT INTO audit_receipts (id, created_at, request_hash, decision, risk_score, reason_codes, policy_rule_ids, action_type, source) VALUES ('vrf_old', '2026-11-01T00:00:00.000Z', 'legacyhash', 'ALLOW', 0, '[]', '[\"policy_allowed\"]', 'purchase', 'rest')",
      )
      .run();
    await storeReceipt(db, verificationRequest("rest"), receipt("vrf_new", "2026-11-10T10:00:00.000Z", "ALLOW"));

    await expect(verifyAuditChain(db)).resolves.toEqual({
      ok: true,
      checked: 1,
      legacy: 1,
      head_hash: expect.any(String) as string,
    });
  });

  it("serves the chain verification result to an authenticated caller", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const sqlite = createMigratedSqlite();
    const db = wrapD1(sqlite);
    await storeThreeReceipts(db);

    const response = await handleHttpRequest(
      new Request("https://vizier.example/v1/audit/chain", {
        headers: { Authorization: `Bearer ${API_KEY}` },
      }),
      { apiKey: API_KEY, db },
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      ok: true,
      checked: 3,
      legacy: 0,
      head_hash: expect.any(String) as string,
    });
  });

  it("rejects unauthenticated chain reads and reports a missing database", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const sqlite = createMigratedSqlite();
    const db = wrapD1(sqlite);

    const denied = await handleHttpRequest(
      new Request("https://vizier.example/v1/audit/chain"),
      { apiKey: API_KEY, db },
    );
    expect(denied.status).toBe(401);

    const unavailable = await handleHttpRequest(
      new Request("https://vizier.example/v1/audit/chain", {
        headers: { Authorization: `Bearer ${API_KEY}` },
      }),
      { apiKey: API_KEY },
    );
    expect(unavailable.status).toBe(503);
  });

  it("serves the chain head publicly and rate limits anonymous reads", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const sqlite = createMigratedSqlite();
    const db = wrapD1(sqlite);
    await storeThreeReceipts(db);

    // No credential: the head is public so external anchors can read it.
    const response = await handleHttpRequest(
      new Request("https://vizier.example/v1/audit/chain/head"),
      { apiKey: API_KEY, db },
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.head_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(body.chained_rows).toBe(3);
    expect(body.legacy_rows).toBe(0);
    expect(body.retention_anchor).toBeNull();
    expect(typeof body.computed_at).toBe("string");

    // The head matches what a full chain verification reports.
    const verification = await verifyAuditChain(db);
    expect(verification.head_hash).toBe(body.head_hash);

    const throttled = await handleHttpRequest(
      new Request("https://vizier.example/v1/audit/chain/head"),
      {
        apiKey: API_KEY,
        db,
        anonymousRateLimiter: {
          limit: async () => ({ success: false }),
        } as never,
      },
    );
    expect(throttled.status).toBe(429);

    const unavailable = await handleHttpRequest(
      new Request("https://vizier.example/v1/audit/chain/head"),
      { apiKey: API_KEY },
    );
    expect(unavailable.status).toBe(503);
  });

  it("keeps the chain verifiable after retention pruning removes its oldest rows", async () => {
    const sqlite = createMigratedSqlite();
    const db = wrapD1(sqlite);
    const request = verificationRequest("rest");
    await storeReceipt(db, request, receipt("vrf_old1", "2026-09-01T10:00:00.000Z", "ALLOW"));
    await storeReceipt(db, request, receipt("vrf_old2", "2026-09-01T10:00:01.000Z", "ALLOW"));
    await storeReceipt(db, request, receipt("vrf_new1", "2026-11-10T10:00:00.000Z", "ALLOW"));
    await storeReceipt(db, request, receipt("vrf_new2", "2026-11-10T10:00:01.000Z", "BLOCK"));

    const pruned = await pruneAuditMetadata(db, new Date("2026-11-12T00:00:00.000Z"));
    expect(pruned.deleted.verifications).toBe(2);

    const result = await verifyAuditChain(db);
    expect(result.ok).toBe(true);
    expect(result.checked).toBe(2);
  });

  it("still detects tampering with the retained rows after pruning", async () => {
    const sqlite = createMigratedSqlite();
    const db = wrapD1(sqlite);
    const request = verificationRequest("rest");
    await storeReceipt(db, request, receipt("vrf_old1", "2026-09-01T10:00:00.000Z", "ALLOW"));
    await storeReceipt(db, request, receipt("vrf_new1", "2026-11-10T10:00:00.000Z", "ALLOW"));
    await storeReceipt(db, request, receipt("vrf_new2", "2026-11-10T10:00:01.000Z", "BLOCK"));
    await pruneAuditMetadata(db, new Date("2026-11-12T00:00:00.000Z"));
    sqlite.prepare("UPDATE audit_receipts SET decision = 'ALLOW' WHERE id = 'vrf_new2'").run();

    await expect(verifyAuditChain(db)).resolves.toMatchObject({
      ok: false,
      first_broken_id: "vrf_new2",
      reason: "HASH_MISMATCH",
    });
  });

  it("does not fork the chain when receipts are stored concurrently", async () => {
    const sqlite = createMigratedSqlite();
    const db = wrapD1(sqlite);
    const request = verificationRequest("rest");
    await storeReceipt(db, request, receipt("vrf_seed", "2026-11-10T09:00:00.000Z", "ALLOW"));

    await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        storeReceipt(
          db,
          request,
          receipt(`vrf_c${index}`, `2026-11-10T10:00:0${index}.000Z`, "ALLOW"),
        ),
      ),
    );

    const rows = sqlite
      .prepare("SELECT prev_receipt_hash FROM audit_receipts WHERE receipt_hash != ''")
      .all() as Array<{ prev_receipt_hash: string }>;
    expect(new Set(rows.map((row) => row.prev_receipt_hash)).size).toBe(rows.length);
    await expect(verifyAuditChain(db)).resolves.toMatchObject({ ok: true, checked: 9 });
  });

  it("verifies a chain whose newest created_at was inserted before an older one", async () => {
    const sqlite = createMigratedSqlite();
    const db = wrapD1(sqlite);
    const request = verificationRequest("rest");
    await storeReceipt(db, request, receipt("vrf_a", "2026-11-10T10:00:05.000Z", "ALLOW"));
    // Clock skew between isolates: this receipt is inserted later but stamped earlier.
    await storeReceipt(db, request, receipt("vrf_b", "2026-11-10T10:00:01.000Z", "ALLOW"));
    await expect(verifyAuditChain(db)).resolves.toMatchObject({ ok: true, checked: 2 });
  });
});
