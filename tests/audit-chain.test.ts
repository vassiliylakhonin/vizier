import { readFileSync, readdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

import type { D1Database } from "@cloudflare/workers-types";
import { describe, expect, it, vi } from "vitest";

import type { VerificationRequest } from "../src/core/schemas";
import type { Receipt } from "../src/core/types";
import {
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
    await expect(response.json()).resolves.toEqual({ ok: true, checked: 3, legacy: 0 });
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
});
