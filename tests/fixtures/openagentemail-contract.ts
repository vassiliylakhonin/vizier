// Selected task-detail contract captured against openagentemail 812af3f.
// Ignore unrelated top-level fields, but do not silently strip approval or
// result fields: changes there need an explicit compatibility review.
import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const timestamp = z.iso.datetime({ offset: true });
const result = z.discriminatedUnion("decision", [
  z.strictObject({
    decision: z.literal("approved"), digest, reviewer: z.email(), decidedAt: timestamp,
  }),
  z.strictObject({
    decision: z.literal("rejected"), digest, reviewer: z.email(), decidedAt: timestamp,
  }),
  z.strictObject({ decision: z.literal("expired"), digest, expiredAt: timestamp }),
]);
const projection = z.object({
  id: z.uuid(), kind: z.literal("approval"),
  state: z.enum(["input-required", "completed", "failed"]),
  approval: z.strictObject({
    action: z.strictObject({ type: z.string().min(1), name: z.string().min(1), arguments: z.json() }),
    reviewer: z.email(), expiresAt: timestamp, digest,
  }),
  result: result.optional(),
});
export type OaeContractProjection = z.infer<typeof projection>;
const stateByDecision = { approved: "completed", rejected: "completed", expired: "failed" } as const;

export function assertOaeTaskDetailContract(value: unknown): OaeContractProjection {
  const parsed = projection.safeParse(value);
  if (!parsed.success) throw new Error(`OAE_TASK_DETAIL_CONTRACT_DRIFT: ${parsed.error.message}`);
  const task = parsed.data;
  const expected = task.result ? stateByDecision[task.result.decision] : "input-required";
  if (task.state !== expected) {
    throw new Error(`OAE_TASK_DETAIL_CONTRACT_DRIFT: decision/state expected ${expected}, got ${task.state}`);
  }
  if (task.result && task.result.digest !== task.approval.digest) {
    throw new Error("OAE_TASK_DETAIL_CONTRACT_DRIFT: result/approval digest mismatch");
  }
  return task;
}
