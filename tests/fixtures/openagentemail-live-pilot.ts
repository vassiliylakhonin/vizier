// Opt-in probe for a disposable loopback OAE instance. Never part of npm test.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { consumeOaeApproval, openOaeApprovalStore, type OaeAction } from "./openagentemail-handoff";

const sourceCommit = "812af3ff59167ab63d5d848f60c5cdb338534824";
interface Identity { address: string; token: string; }
interface Task {
  id: string;
  kind: string;
  state: string;
  approval: { action: OaeAction; digest: string; reviewer: string; expiresAt: string };
  result?: { decision: string; digest: string; reviewer?: string; decidedAt?: string; expiredAt?: string };
}

async function main() {
  const [mode, configFile, dbFile, reportFile] = process.argv.slice(2);
  assert.ok(mode === "--disposable-local" && configFile && dbFile && reportFile,
    "Usage: pilot.mjs --disposable-local config.json fresh-ledger.sqlite report.json");
  const config = JSON.parse(readFileSync(configFile, "utf8")) as { origin: string; adminKey: string };
  const origin = new URL(config.origin);
  assert.ok(origin.protocol === "https:" && ["127.0.0.1", "[::1]", "localhost"].includes(origin.hostname));
  assert.equal(config.origin, origin.origin);
  assert.ok(typeof config.adminKey === "string" && config.adminKey.length >= 32);
  assert.ok(!existsSync(dbFile), "Use a fresh ledger path for this disposable probe");
  const { vector } = JSON.parse(readFileSync(resolve("tests/fixtures/openagentemail-nested-order-v1.json"), "utf8")) as {
    vector: { source: OaeAction; sha256: string };
  };

  const api = (path: string, token?: string, body?: unknown) => fetch(new URL(path, origin), {
    method: body === undefined ? "GET" : "POST", redirect: "error", cache: "no-store",
    signal: AbortSignal.timeout(15000),
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const read = async <T>(path: string, token?: string, body?: unknown): Promise<T> => {
    const response = await api(path, token, body);
    assert.ok(response.ok, `OAE HTTP ${response.status} on ${path}`);
    return await response.json() as T;
  };
  const health = await read<{ ok: boolean; commit: string }>("/healthz");
  assert.equal(health.ok, true);
  assert.equal(health.commit, sourceCommit);
  const suffix = randomUUID().slice(0, 8);
  const requester = await read<Identity>("/v1/identities", config.adminKey, { localpart: `pilot-requester-${suffix}` });
  const reviewer = await read<Identity>("/v1/identities", config.adminKey, { localpart: `pilot-reviewer-${suffix}` });
  assert.ok(requester.address.endsWith("@oae.test") && reviewer.address.endsWith("@oae.test"));
  assert.ok(requester.token && reviewer.token);

  const taskDetail = async (id: string, predicate: (task: Task) => boolean): Promise<Task> => {
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const response = await api(`/v1/tasks/${id}`, requester.token);
      if (response.status === 404) {
        await response.body?.cancel();
      } else {
        assert.equal(response.status, 200);
        const task = await response.json() as Task;
        if (predicate(task)) return task;
      }
      await sleep(250);
    }
    throw new Error("OAE task did not reach the expected state in the bounded polling window");
  };
  const create = async (name: string, ttlMs: number): Promise<Task> => {
    const task = await read<Task>("/v1/tasks", requester.token, {
      to: reviewer.address, subject: `Disposable Vizier pilot ${name}`, wait: false,
      body: "Synthetic approval for a mock executor in an isolated local fixture.",
      kind: "approval", approval: {
        action: vector.source, expiresAt: new Date(Date.now() + ttlMs).toISOString(),
      },
    });
    return taskDetail(task.id, row => row.state === "input-required");
  };

  let db = openOaeApprovalStore(dbFile);
  let executionCount = 0;
  const consume = (task: Task, action: unknown = vector.source) => consumeOaeApproval({
    origin: origin.origin, requester: requester.address, reviewer: reviewer.address,
    bearerToken: requester.token, maxDecisionAgeMs: 60000, db, fetch, now: Date.now,
    checkScope: async snapshot => snapshot.type === vector.source.type && snapshot.name === vector.source.name,
    execute: async snapshot => { executionCount += 1; return { status: "mock_executed", action: snapshot }; },
  }, task.id, action);
  const cases: { name: string; task_id: string; outcome: string; projection?: Task }[] = [];
  const projection = (task: Task): Task => ({
    id: task.id, kind: task.kind, state: task.state, approval: task.approval, result: task.result,
  });

  try {
    const pending = await create("approved", 12000);
    const unauthenticated = await api(`/v1/tasks/${pending.id}`);
    assert.equal(unauthenticated.status, 401);
    await unauthenticated.body?.cancel();
    const wrongActor = await api(`/v1/tasks/${pending.id}/decision`, requester.token, { decision: "approved" });
    assert.equal(wrongActor.status, 403);
    await wrongActor.body?.cancel();
    await read(`/v1/tasks/${pending.id}/decision`, reviewer.token, { decision: "approved" });
    const approved = await taskDetail(pending.id, row => row.result?.decision === "approved");
    assert.equal(approved.approval.digest, vector.sha256);

    const changed = structuredClone(vector.source);
    changed.arguments = { changed: true };
    await assert.rejects(consume(approved, changed), /OAE_ACTION_MISMATCH/);
    assert.equal(executionCount, 0);
    cases.push({ name: "changed_arguments", task_id: approved.id, outcome: "OAE_ACTION_MISMATCH" });

    await sleep(Math.max(0, Date.parse(approved.approval.expiresAt) - Date.now() + 50));
    await assert.doesNotReject(consume(approved));
    assert.equal(executionCount, 1);
    cases.push({ name: "approved_after_decision_deadline", task_id: approved.id,
      outcome: "mock_executed_once", projection: projection(approved) });

    db.close();
    db = openOaeApprovalStore(dbFile);
    await assert.rejects(consume(approved), /OAE_APPROVAL_ALREADY_RESERVED/);
    assert.equal(executionCount, 1);
    cases.push({ name: "duplicate_after_reopen", task_id: approved.id, outcome: "OAE_APPROVAL_ALREADY_RESERVED" });

    const pendingRejected = await create("rejected", 30000);
    await read(`/v1/tasks/${pendingRejected.id}/decision`, reviewer.token, { decision: "rejected" });
    const rejected = await taskDetail(pendingRejected.id, row => row.result?.decision === "rejected");
    assert.equal(rejected.state, "completed");
    await assert.rejects(consume(rejected), /OAE_APPROVAL_NOT_GRANTED/);
    cases.push({ name: "rejected_but_completed", task_id: rejected.id,
      outcome: "OAE_APPROVAL_NOT_GRANTED", projection: projection(rejected) });

    const pendingExpired = await create("expired", 8000);
    await sleep(Math.max(0, Date.parse(pendingExpired.approval.expiresAt) - Date.now() + 50));
    const expired = await taskDetail(pendingExpired.id, row => row.result?.decision === "expired");
    assert.equal(expired.state, "failed");
    await assert.rejects(consume(expired), /OAE_APPROVAL_NOT_GRANTED/);
    assert.equal(executionCount, 1);
    cases.push({ name: "expired_materialized_on_read", task_id: expired.id,
      outcome: "OAE_APPROVAL_NOT_GRANTED", projection: projection(expired) });

    writeFileSync(reportFile, JSON.stringify({
      oae_commit: health.commit, origin: origin.origin, captured_at: new Date().toISOString(),
      execution_age_policy_ms: 60000, mock_executor_calls: executionCount,
      access_controls: { unauthenticated_detail: 401, requester_cannot_decide: 403 },
      cases,
    }, null, 2) + "\n");
    console.log("PASS real local OAE API: five handoff cases, 401/403 access controls, one mock execution");
  } finally {
    db.close();
  }
}

await main();
