// Offline replay of the captured OAE contract. The live probe imports the
// same validator; npm test alone does not contact or watch upstream OAE.
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { assertOaeTaskDetailContract, type OaeContractProjection } from "./fixtures/openagentemail-contract";
import {
  consumeOaeApproval, openOaeApprovalStore, type OaeAction,
} from "./fixtures/openagentemail-handoff";

const { vector } = JSON.parse(readFileSync(
  new URL("./fixtures/openagentemail-nested-order-v1.json", import.meta.url), "utf8",
)) as { vector: { source: OaeAction; sha256: string } };

interface LiveReport {
  oae_commit: string;
  captured_at: string;
  execution_age_policy_ms: number;
  mock_executor_calls: number;
  access_controls: { unauthenticated_detail: number; requester_cannot_decide: number };
  cases: { name: string; task_id: string; outcome: string; projection?: unknown }[];
}

const report = JSON.parse(readFileSync(
  new URL("./fixtures/openagentemail-live-result-2026-11-09.json", import.meta.url), "utf8",
)) as LiveReport;

const origin = "https://oae.test";
// The pilot's sanitized projections omit from/to/createdAt; the consumer
// requires them, so the replay re-attaches the synthetic pilot participants
// and a creation time just before the recorded decision.
const syntheticRequester = "pilot-requester-b552fa39@oae.test";
const syntheticCreatedAt = "2026-11-09T04:45:24.000Z";

let directory: string;
let stores: DatabaseSync[];
let db: DatabaseSync;
let executor: ReturnType<typeof vi.fn<(action: OaeAction) => Promise<unknown>>>;
let scope: ReturnType<typeof vi.fn<(action: OaeAction) => Promise<boolean>>>;

function openStore() {
  const store = openOaeApprovalStore(join(directory, "approvals.sqlite"));
  stores.push(store);
  return store;
}

function projectionOf(caseName: string): OaeContractProjection {
  const entry = report.cases.find(item => item.name === caseName);
  expect(entry?.projection, `recorded projection for ${caseName}`).toBeDefined();
  return assertOaeTaskDetailContract(entry!.projection);
}

function consume(projection: OaeContractProjection, action: unknown, now: number, store = db) {
  const task = {
    ...projection, from: syntheticRequester, to: projection.approval.reviewer,
    createdAt: syntheticCreatedAt,
  };
  return consumeOaeApproval({
    origin, requester: syntheticRequester, reviewer: projection.approval.reviewer,
    bearerToken: "synthetic-requester-token", maxDecisionAgeMs: report.execution_age_policy_ms,
    db: store, fetch: vi.fn(async () => Response.json(task)) as unknown as typeof fetch,
    now: () => now,
    checkScope: scope, execute: executor,
  }, projection.id, action);
}

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "vizier-oae-drift-"));
  stores = [];
  db = openStore();
  executor = vi.fn(async (action: OaeAction) => ({ status: "mock_executed", action }));
  scope = vi.fn(async (action: OaeAction) =>
    action.type === vector.source.type && action.name === vector.source.name);
});

afterEach(() => {
  for (const store of stores) store.close();
  rmSync(directory, { recursive: true, force: true });
});

describe("recorded OAE task-detail contract (openagentemail 812af3f)", () => {
  it("pins the live-run provenance, outcomes and 401/403 access split", () => {
    expect(report.oae_commit).toBe("812af3ff59167ab63d5d848f60c5cdb338534824");
    expect(report.access_controls).toEqual({
      unauthenticated_detail: 401, requester_cannot_decide: 403,
    });
    expect(report.cases.map(item => [item.name, item.outcome])).toEqual([
      ["changed_arguments", "OAE_ACTION_MISMATCH"],
      ["approved_after_decision_deadline", "mock_executed_once"],
      ["duplicate_after_reopen", "OAE_APPROVAL_ALREADY_RESERVED"],
      ["rejected_but_completed", "OAE_APPROVAL_NOT_GRANTED"],
      ["expired_materialized_on_read", "OAE_APPROVAL_NOT_GRANTED"],
    ]);
  });

  it.each(["approved_after_decision_deadline", "rejected_but_completed", "expired_materialized_on_read"])(
    "keeps the result shape and status transition of %s", caseName => {
      const projection = projectionOf(caseName);
      const result = projection.result;
      expect(result, "recorded projection carries a result").toBeDefined();
      expect(projection.state).toBe(({ approved: "completed", rejected: "completed", expired: "failed" })[result!.decision]);
      expect(result!.digest).toBe(projection.approval.digest);
      expect(projection.approval.digest).toBe(vector.sha256);
    },
  );

  it.each([
    ["added result field", (task: { state: string; result?: Record<string, unknown> }) => { task.result!.extra = true; }],
    ["missing decidedAt", (task: { state: string; result?: Record<string, unknown> }) => { delete task.result!.decidedAt; }],
    ["renamed decidedAt", (task: { state: string; result?: Record<string, unknown> }) => { task.result!.decided_at = task.result!.decidedAt; delete task.result!.decidedAt; }],
    ["wrong field type", (task: { state: string; result?: Record<string, unknown> }) => { task.result!.decidedAt = 42; }],
    ["changed decision", (task: { state: string; result?: Record<string, unknown> }) => { task.result!.decision = "accepted"; }],
    ["changed state", (task: { state: string; result?: Record<string, unknown> }) => { task.state = "failed"; }],
    ["missing terminal result", (task: { state: string; result?: Record<string, unknown> }) => { delete task.result; }],
    ["changed digest", (task: { state: string; result?: Record<string, unknown> }) => { task.result!.digest = "0".repeat(64); }],
  ])("fails loudly on %s", (_name, mutate) => {
    const task = structuredClone(projectionOf("approved_after_decision_deadline"));
    mutate(task);
    expect(() => assertOaeTaskDetailContract(task)).toThrow("OAE_TASK_DETAIL_CONTRACT_DRIFT");
  });

  it("checks pending and expired shapes without inventing reviewer decisions", () => {
    const task = structuredClone(projectionOf("approved_after_decision_deadline"));
    delete task.result;
    task.state = "input-required";
    expect(assertOaeTaskDetailContract(task).result).toBeUndefined();
    const expired = projectionOf("expired_materialized_on_read");
    expect(expired.result).toHaveProperty("expiredAt");
    expect(() => assertOaeTaskDetailContract({ ...expired, result: {
      ...expired.result, reviewer: "invented@oae.test",
    } })).toThrow("OAE_TASK_DETAIL_CONTRACT_DRIFT");
    expect(() => assertOaeTaskDetailContract({ ...expired, state: "completed" }))
      .toThrow("OAE_TASK_DETAIL_CONTRACT_DRIFT");
  });

  it("reproduces the five recorded outcomes through the reference consumer", async () => {
    const approved = projectionOf("approved_after_decision_deadline");
    const rejected = projectionOf("rejected_but_completed");
    const expired = projectionOf("expired_materialized_on_read");
    const now = Date.parse(report.captured_at);

    const changed = structuredClone(vector.source);
    changed.arguments = { changed: true };
    await expect(consume(approved, changed, now)).rejects.toThrow("OAE_ACTION_MISMATCH");
    expect(executor).not.toHaveBeenCalled();
    expect(db.prepare("SELECT COUNT(*) AS n FROM oae_approval_uses").get()!.n).toBe(0);

    await expect(consume(approved, vector.source, now)).resolves.toEqual({
      status: "mock_executed", action: vector.source,
    });
    expect(executor).toHaveBeenCalledExactlyOnceWith(vector.source);
    expect(report.mock_executor_calls).toBe(1);

    db.close();
    stores.pop();
    db = openStore();
    await expect(consume(approved, vector.source, now)).rejects.toThrow("OAE_APPROVAL_ALREADY_RESERVED");
    expect(executor).toHaveBeenCalledTimes(1);

    await expect(consume(rejected, vector.source, now)).rejects.toThrow("OAE_APPROVAL_NOT_GRANTED");
    await expect(consume(expired, vector.source, now)).rejects.toThrow("OAE_APPROVAL_NOT_GRANTED");
    expect(executor).toHaveBeenCalledTimes(1);
  });
});
