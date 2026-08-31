import type { D1Database } from "@cloudflare/workers-types";
import { describe, expect, it, vi } from "vitest";

import { handleHttpRequest } from "../src/transport/http";
import { pruneAuditMetadata } from "../src/storage/audit";

const API_KEY = "audit-test-enforcement-key";

function verificationRequest(): Request {
  return new Request("https://vizier.example/v1/verify", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      agent: { id: "agent-secret-id", owner: "owner-secret-id" },
      principal: { id: "principal-secret-id" },
      action: {
        type: "purchase",
        target: "sensitive-supplier.example",
        parameters: { amount: 8_200, note: "do-not-persist" },
      },
      authority: {
        allowed_actions: ["purchase"],
        constraints: { max_amount: 10_000 },
      },
      context: {
        request_id: "audit-request-01",
        timestamp: null,
        source: "rest",
      },
    }),
  });
}

describe("metadata-only D1 audit", () => {
  it("schedules a verification write without caller payload fields", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const writes: Array<{ query: string; values: unknown[] }> = [];
    const pending: Promise<unknown>[] = [];
    const db = Object.assign(Object.create(null), {
      prepare: (query: string) => ({
        bind: (...values: unknown[]) => ({
          run: async () => {
            writes.push({ query, values });
          },
        }),
      }),
    }) as D1Database;

    const response = await handleHttpRequest(verificationRequest(), {
      apiKey: API_KEY,
      db,
      ctx: { waitUntil: (promise) => pending.push(promise) },
    });
    await Promise.all(pending);

    expect(response.status).toBe(200);
    expect(writes).toHaveLength(1);
    expect(writes[0]?.query).not.toContain("request_body");
    expect(JSON.stringify(writes)).not.toContain("do-not-persist");
    expect(JSON.stringify(writes)).not.toContain("sensitive-supplier.example");
    expect(JSON.stringify(writes)).not.toContain("principal-secret-id");
  });

  it("returns stable authenticated aggregates from one D1 batch", async () => {
    const db = Object.assign(Object.create(null), {
      prepare: (query: string) => query,
      batch: async () => [
        { results: [{ decision: "ALLOW", count: 4 }] },
        { results: [{ average: 0.25 }] },
        { results: [{ count: 1 }] },
        { results: [{ count: 7 }] },
        { results: [{ count: 3 }] },
        { results: [{ decision: "BLOCK", count: 2 }] },
        { results: [{ count: 2 }] },
        { results: [{ count: 1 }] },
      ],
    }) as D1Database;
    const response = await handleHttpRequest(
      new Request("https://vizier.example/v1/insights", {
        headers: { Authorization: `Bearer ${API_KEY}` },
      }),
      { apiKey: API_KEY, db },
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      decisions: [
        { decision: "ALLOW", count: 4 },
        { decision: "REVIEW", count: 0 },
        { decision: "BLOCK", count: 0 },
      ],
      authorization_decisions: [
        { decision: "ALLOW", count: 0 },
        { decision: "REVIEW", count: 0 },
        { decision: "BLOCK", count: 2 },
      ],
      average_risk_score: 0.25,
      failures: 1,
      totals: {
        verifications: 7,
        covenants: 3,
        authorizations: 2,
        outcomes: 1,
      },
    });
  });

  it("prunes all metadata tables at the same 30-day cutoff", async () => {
    const statements: Array<{ query: string; cutoff: unknown }> = [];
    const db = Object.assign(Object.create(null), {
      prepare: (query: string) => ({
        bind: (cutoff: unknown) => {
          statements.push({ query, cutoff });
          return { query };
        },
      }),
      batch: async () => [
        { meta: { changes: 4 } },
        { meta: { changes: 3 } },
        { meta: { changes: 2 } },
        { meta: { changes: 1 } },
      ],
    }) as D1Database;

    const result = await pruneAuditMetadata(
      db,
      new Date("2026-08-31T12:00:00.000Z"),
    );

    expect(result).toEqual({
      cutoff: "2026-08-01T12:00:00.000Z",
      deleted: {
        verifications: 1,
        covenants: 2,
        authorizations: 3,
        outcomes: 4,
      },
    });
    expect(statements.map((statement) => statement.query)).toEqual([
      "DELETE FROM outcome_receipts WHERE finished_at < ?1",
      "DELETE FROM authorization_receipts WHERE issued_at < ?1",
      "DELETE FROM action_covenants WHERE accepted_at < ?1",
      "DELETE FROM audit_receipts WHERE created_at < ?1",
    ]);
    expect(new Set(statements.map((statement) => statement.cutoff))).toEqual(
      new Set(["2026-08-01T12:00:00.000Z"]),
    );
  });

  it("rejects invalid retention configuration before querying D1", async () => {
    await expect(
      pruneAuditMetadata(
        Object.create(null) as D1Database,
        new Date("invalid"),
      ),
    ).rejects.toThrowError("Audit retention requires a valid date");
  });
});
