import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { consumeOaeApproval, openOaeApprovalStore, type OaeAction } from "./fixtures/openagentemail-handoff";

const { vector } = JSON.parse(readFileSync(
  new URL("./fixtures/openagentemail-nested-order-v1.json", import.meta.url), "utf8",
)) as { vector: { source: OaeAction; sha256: string } };
const id = "123e4567-e89b-42d3-a456-426614174000";
const origin = "https://oae.example";
const requester = "requester@example.com";
const reviewer = "reviewer@example.com";
const createdAt = "2026-11-08T10:00:00Z";
const decidedAt = "2026-11-08T10:00:30Z";
const expiresAt = "2026-11-08T10:00:40Z";
let directory: string;
let stores: DatabaseSync[];
let db: DatabaseSync;
let now: number;
let task: ReturnType<typeof approvedTask>;
let fetcher: ReturnType<typeof vi.fn<typeof fetch>>;
let executor: ReturnType<typeof vi.fn<(action: OaeAction) => Promise<unknown>>>;
let scope: ReturnType<typeof vi.fn<(action: OaeAction) => Promise<boolean>>>;

function approvedTask() {
  return {
    id, kind: "approval", state: "completed", from: requester, to: reviewer, createdAt,
    approval: { action: structuredClone(vector.source), reviewer, expiresAt, digest: vector.sha256 },
    result: { decision: "approved", reviewer, decidedAt, digest: vector.sha256 },
  };
}

function openStore() {
  const store = openOaeApprovalStore(join(directory, "approvals.sqlite"));
  stores.push(store);
  return store;
}

function consume(action: unknown = vector.source, store = db) {
  return consumeOaeApproval({
    origin, requester, reviewer, bearerToken: "synthetic-requester-token", maxDecisionAgeMs: 60000,
    db: store, fetch: fetcher, now: () => now, checkScope: scope, execute: executor,
  }, id, action);
}

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "vizier-oae-handoff-"));
  stores = [];
  db = openStore();
  now = Date.parse("2026-11-08T10:00:45Z");
  task = approvedTask();
  fetcher = vi.fn<typeof fetch>(async (url, init) => {
    expect(String(url)).toBe(`${origin}/v1/tasks/${id}`);
    expect(init).toMatchObject({ method: "GET", redirect: "error", cache: "no-store" });
    expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer synthetic-requester-token");
    return Response.json(task);
  });
  executor = vi.fn(async (action: OaeAction) => ({ status: "mock_executed", action }));
  scope = vi.fn(async (action: OaeAction) => action.type === "tool_call" && action.name === "nested");
});

afterEach(() => {
  for (const store of stores) store.close();
  rmSync(directory, { recursive: true, force: true });
});

describe("authenticated OAE task-detail handoff fixture", () => {
  it.each(["", ":memory:"])("requires a persistent store instead of %j", path => {
    expect(() => openOaeApprovalStore(path)).toThrow("PERSISTENT_DATABASE_PATH_REQUIRED");
  });

  it("executes a fresh approved action after the request decision deadline has passed", async () => {
    expect(now).toBeGreaterThan(Date.parse(expiresAt));
    await expect(consume()).resolves.toEqual({ status: "mock_executed", action: vector.source });
    expect(executor).toHaveBeenCalledExactlyOnceWith(vector.source);
    expect(db.prepare("SELECT status FROM oae_approval_uses").get()!.status).toBe("executed");
  });

  it("rejects a completed task whose decision was rejected", async () => {
    task.result.decision = "rejected";
    await expect(consume()).rejects.toThrow("OAE_APPROVAL_NOT_GRANTED");
    expect(executor).not.toHaveBeenCalled();
  });

  it("rejects a task whose approval request expired without an approving decision", async () => {
    const expired = { ...task, state: "failed", result: { decision: "expired", digest: vector.sha256, expiredAt: expiresAt } };
    fetcher.mockResolvedValue(Response.json(expired));
    await expect(consume()).rejects.toThrow("OAE_APPROVAL_NOT_GRANTED");
    expect(executor).not.toHaveBeenCalled();
  });

  it("rejects changed intended arguments without reserving the task", async () => {
    const changed = structuredClone(vector.source);
    changed.arguments = { changed: true };
    await expect(consume(changed)).rejects.toThrow("OAE_ACTION_MISMATCH");
    expect(executor).not.toHaveBeenCalled();
    expect(db.prepare("SELECT COUNT(*) AS n FROM oae_approval_uses").get()!.n).toBe(0);
  });

  it("rejects duplicate delivery through another connection and after reopening the store", async () => {
    const other = openStore();
    const results = await Promise.allSettled([consume(), consume(vector.source, other)]);
    expect(results.map(result => result.status).sort()).toEqual(["fulfilled", "rejected"]);
    expect(executor).toHaveBeenCalledTimes(1);
    for (const store of stores) store.close();
    stores = [];
    db = openStore();
    await expect(consume()).rejects.toThrow("OAE_APPROVAL_ALREADY_RESERVED");
    expect(executor).toHaveBeenCalledTimes(1);
  });

  it("enforces the consumer age limit even for an approved task", async () => {
    now = Date.parse(decidedAt) + 60001;
    await expect(consume()).rejects.toThrow("OAE_DECISION_NOT_FRESH");
    expect(executor).not.toHaveBeenCalled();
  });

  it("rejects a decision made at the expiry instant", async () => {
    task.result.decidedAt = expiresAt;
    await expect(consume()).rejects.toThrow("OAE_DECISION_OUTSIDE_REQUEST_WINDOW");
    expect(executor).not.toHaveBeenCalled();
  });

  it.each(["snapshot", "result"])("rejects a mismatched digest in the %s", async location => {
    if (location === "snapshot") task.approval.digest = "0".repeat(64);
    else task.result.digest = "0".repeat(64);
    await expect(consume()).rejects.toThrow("OAE_ACTION_MISMATCH");
    expect(executor).not.toHaveBeenCalled();
  });

  it("rejects an unexpected reviewer", async () => {
    task.result.reviewer = "other@example.com";
    await expect(consume()).rejects.toThrow("OAE_REVIEWER_MISMATCH");
    expect(executor).not.toHaveBeenCalled();
  });

  it.each(["task", "requester", "recipient", "snapshot reviewer"])("rejects an unexpected %s", async field => {
    if (field === "task") task.id = "223e4567-e89b-42d3-a456-426614174000";
    else if (field === "requester") task.from = "other@example.com";
    else if (field === "recipient") task.to = "other@example.com";
    else task.approval.reviewer = "other@example.com";
    await expect(consume()).rejects.toThrow("OAE_PARTICIPANT_MISMATCH");
    expect(executor).not.toHaveBeenCalled();
  });

  it("keeps the intended action stable while the API read is pending", async () => {
    const action = structuredClone(vector.source);
    fetcher.mockImplementationOnce(async () => {
      action.arguments = { changed: true };
      return Response.json(task);
    });
    await expect(consume(action)).resolves.toEqual({ status: "mock_executed", action: vector.source });
  });

  it("checks freshness again when the scope gate takes too long", async () => {
    scope.mockImplementation(async () => { now = Date.parse(decidedAt) + 60001; return true; });
    await expect(consume()).rejects.toThrow("OAE_DECISION_NOT_FRESH");
    expect(executor).not.toHaveBeenCalled();
  });

  it("keeps the executed action stable when the scope callback mutates its own copy", async () => {
    scope.mockImplementation(async action => { action.arguments = { changed: true }; return true; });
    await expect(consume()).resolves.toEqual({ status: "mock_executed", action: vector.source });
  });

  it("rejects a decision dated in the future", async () => {
    now = Date.parse(decidedAt) - 1;
    await expect(consume()).rejects.toThrow("OAE_DECISION_NOT_FRESH");
    expect(executor).not.toHaveBeenCalled();
  });

  it("requires the additional operator scope gate", async () => {
    scope.mockResolvedValue(false);
    await expect(consume()).rejects.toThrow("SCOPE_DENIED");
    expect(executor).not.toHaveBeenCalled();
  });

  it("retains an uncertain execution outcome across a store reopen", async () => {
    executor.mockRejectedValue(new Error("Mock executor acknowledgement lost"));
    await expect(consume()).rejects.toThrow("EXECUTION_UNCERTAIN_RECONCILE_BEFORE_RETRY");
    expect(db.prepare("SELECT status FROM oae_approval_uses").get()!.status).toBe("uncertain");
    for (const store of stores) store.close();
    stores = [];
    db = openStore();
    await expect(consume()).rejects.toThrow("OAE_APPROVAL_ALREADY_RESERVED");
    expect(executor).toHaveBeenCalledTimes(1);
  });

  it.each([401, 403, 302, 500])("stops on HTTP %i from OAE", async status => {
    fetcher.mockResolvedValue(new Response("", { status }));
    await expect(consume()).rejects.toThrow("OAE_READ_FAILED");
    expect(executor).not.toHaveBeenCalled();
  });

  it("bounds the task-detail response body", async () => {
    fetcher.mockResolvedValue(new Response(" ".repeat(262145)));
    await expect(consume()).rejects.toThrow("OAE_RESPONSE_TOO_LARGE");
    expect(executor).not.toHaveBeenCalled();
  });
});
