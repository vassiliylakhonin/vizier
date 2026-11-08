// Offline reference consumer. The tests inject the OAE API, scope gate and executor.
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { canonicalizeJson } from "../../src/crypto/jws";

const actionSchema = z.strictObject({
  type: z.string().min(1), name: z.string().min(1), arguments: z.json(),
});
const digestSchema = z.string().regex(/^[a-f0-9]{64}$/);
const timestampSchema = z.iso.datetime({ offset: true });
const decisionSchema = z.discriminatedUnion("decision", [
  z.object({
    decision: z.literal("approved"), digest: digestSchema,
    reviewer: z.email(), decidedAt: timestampSchema,
  }),
  z.object({
    decision: z.literal("rejected"), digest: digestSchema,
    reviewer: z.email(), decidedAt: timestampSchema,
  }),
  z.object({ decision: z.literal("expired"), digest: digestSchema, expiredAt: timestampSchema }),
]);
const projectionSchema = z.object({
  id: z.uuid(), from: z.email(), to: z.email(), createdAt: timestampSchema,
  kind: z.literal("approval"), state: z.string(),
  approval: z.object({
    action: actionSchema, reviewer: z.email(), expiresAt: timestampSchema, digest: digestSchema,
  }),
  result: decisionSchema.optional(),
});

export type OaeAction = z.infer<typeof actionSchema>;

interface ConsumerOptions {
  origin: string;
  requester: string;
  reviewer: string;
  bearerToken: string;
  maxDecisionAgeMs: number;
  db: DatabaseSync;
  fetch: typeof fetch;
  now: () => number;
  checkScope: (action: OaeAction) => Promise<boolean>;
  execute: (action: OaeAction) => Promise<unknown>;
}

export function openOaeApprovalStore(path: string): DatabaseSync {
  if (!path || path === ":memory:") throw new Error("PERSISTENT_DATABASE_PATH_REQUIRED");
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=FULL;
    PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS oae_approval_uses (
      origin TEXT NOT NULL,
      task_id TEXT NOT NULL,
      digest TEXT NOT NULL,
      reviewer TEXT NOT NULL,
      decided_at TEXT NOT NULL,
      claimed_at INTEGER NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('reserved','executed','uncertain')),
      PRIMARY KEY(origin, task_id)
    );
  `);
  return db;
}

function actionDigest(action: OaeAction): string {
  return createHash("sha256").update(canonicalizeJson(action), "utf8").digest("hex");
}

async function readProjection(response: Response): Promise<unknown> {
  if (!response.ok || response.redirected || !response.body) throw new Error("OAE_READ_FAILED");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 262144) throw new Error("OAE_RESPONSE_TOO_LARGE");
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
}

function requireFreshDecision(now: number, decidedAt: number, maxAge: number): void {
  const age = now - decidedAt;
  if (!Number.isFinite(age) || age < 0 || age > maxAge) throw new Error("OAE_DECISION_NOT_FRESH");
}

export async function consumeOaeApproval(
  options: ConsumerOptions, taskId: string, intendedAction: unknown,
): Promise<unknown> {
  const origin = new URL(options.origin);
  if (origin.protocol !== "https:" || options.origin !== origin.origin || !options.bearerToken ||
      !Number.isSafeInteger(options.maxDecisionAgeMs) || options.maxDecisionAgeMs <= 0) {
    throw new Error("INVALID_CONSUMER_CONFIGURATION");
  }
  const id = z.uuid().parse(taskId).toLowerCase();
  // Keep the intended action private while fetching and consulting the scope gate.
  const action = actionSchema.parse(structuredClone(intendedAction));
  const digest = actionDigest(action);
  const response = await options.fetch(new URL(`/v1/tasks/${id}`, origin), {
    method: "GET", redirect: "error", cache: "no-store", signal: AbortSignal.timeout(5000),
    headers: { Authorization: `Bearer ${options.bearerToken}`, Accept: "application/json" },
  });
  const task = projectionSchema.parse(await readProjection(response));
  const reviewer = options.reviewer.toLowerCase();
  if (task.id.toLowerCase() !== id || task.from.toLowerCase() !== options.requester.toLowerCase() ||
      task.to.toLowerCase() !== reviewer || task.approval.reviewer.toLowerCase() !== reviewer ||
      task.from.toLowerCase() === reviewer) throw new Error("OAE_PARTICIPANT_MISMATCH");
  if (task.state !== "completed" || task.result?.decision !== "approved") {
    throw new Error("OAE_APPROVAL_NOT_GRANTED");
  }
  const decision = task.result;
  if (decision.reviewer.toLowerCase() !== reviewer) throw new Error("OAE_REVIEWER_MISMATCH");
  if (task.approval.digest !== digest || decision.digest !== digest ||
      actionDigest(task.approval.action) !== digest) throw new Error("OAE_ACTION_MISMATCH");
  const decidedAt = Date.parse(decision.decidedAt);
  if (decidedAt < Date.parse(task.createdAt) || decidedAt >= Date.parse(task.approval.expiresAt)) {
    throw new Error("OAE_DECISION_OUTSIDE_REQUEST_WINDOW");
  }
  requireFreshDecision(options.now(), decidedAt, options.maxDecisionAgeMs);
  if (!await options.checkScope(structuredClone(action))) throw new Error("SCOPE_DENIED");
  const claimedAt = options.now();
  requireFreshDecision(claimedAt, decidedAt, options.maxDecisionAgeMs);
  const inserted = options.db.prepare(`
    INSERT INTO oae_approval_uses(origin,task_id,digest,reviewer,decided_at,claimed_at,status)
    VALUES(?,?,?,?,?,?,'reserved') ON CONFLICT(origin,task_id) DO NOTHING
  `).run(origin.origin, id, digest, reviewer, decision.decidedAt, claimedAt);
  if (Number(inserted.changes) !== 1) throw new Error("OAE_APPROVAL_ALREADY_RESERVED");
  try {
    const result = await options.execute(action);
    options.db.prepare("UPDATE oae_approval_uses SET status='executed' WHERE origin=? AND task_id=?")
      .run(origin.origin, id);
    return result;
  } catch {
    options.db.prepare("UPDATE oae_approval_uses SET status='uncertain' WHERE origin=? AND task_id=?")
      .run(origin.origin, id);
    throw new Error("EXECUTION_UNCERTAIN_RECONCILE_BEFORE_RETRY");
  }
}
