import { constants, closeSync, fstatSync, openSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { z } from "zod";

const recordSchema = z.strictObject({
  approval_id: z.string().min(1).max(256),
  receipt_id: z.string().min(1).max(256),
  review_hash: z.string().regex(/^[a-f0-9]{64}$/),
  state: z.enum(["prepared", "dispatching", "acknowledged", "unknown"]),
  deployment_id: z.string().uuid().nullable(),
  updated_at: z.string().datetime(),
});
export type ExecutionRecord = z.infer<typeof recordSchema>;
export type ExecutionIdentity = Pick<ExecutionRecord, "approval_id" | "receipt_id" | "review_hash">;

/** All writes must commit durably before returning; errors stop execution. */
export interface ExecutionJournal {
  prepare(identity: ExecutionIdentity): void;
  dispatch(approvalId: string): void;
  finish(approvalId: string, state: "acknowledged" | "unknown", deploymentId?: string): void;
}

/** Operator-owned local SQLite file. No tokens, grants or raw plans are stored. */
export class SqliteExecutionJournal implements ExecutionJournal {
  private readonly db: DatabaseSync;

  constructor(path: string, options: { readOnly?: boolean } = {}) {
    // The parent directory must be durable, private and outside agent control.
    // Refuse symlinks, special files and files readable by other OS identities.
    const fd = openSync(path, (options.readOnly ? constants.O_RDONLY : constants.O_CREAT | constants.O_RDWR) | constants.O_NOFOLLOW, 0o600);
    try {
      const info = fstatSync(fd);
      if (!info.isFile() || (info.mode & 0o077) !== 0) throw new Error("Journal must be a private regular file");
    } finally { closeSync(fd); }
    this.db = new DatabaseSync(path, { readOnly: options.readOnly ?? false });
    try {
      this.db.exec("PRAGMA busy_timeout=5000");
      if (!options.readOnly) {
        this.db.exec("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON");
        this.db.exec(`CREATE TABLE IF NOT EXISTS worker_executions (
          approval_id TEXT PRIMARY KEY,
          receipt_id TEXT NOT NULL,
          review_hash TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('prepared','dispatching','acknowledged','unknown')),
          deployment_id TEXT,
          updated_at TEXT NOT NULL
        ) STRICT`);
      }
    } catch (error) { this.db.close(); throw error; }
  }

  prepare(identity: ExecutionIdentity): void {
    const row = recordSchema.parse({ ...identity, state: "prepared", deployment_id: null, updated_at: new Date().toISOString() });
    // Never overwrite evidence or reserve a second dispatch for the same approval.
    this.db.prepare("INSERT INTO worker_executions VALUES (?, ?, ?, ?, ?, ?)")
      .run(row.approval_id, row.receipt_id, row.review_hash, row.state, row.deployment_id, row.updated_at);
  }

  dispatch(approvalId: string): void {
    const result = this.db.prepare("UPDATE worker_executions SET state='dispatching', updated_at=? WHERE approval_id=? AND state='prepared'")
      .run(new Date().toISOString(), approvalId);
    if (result.changes !== 1) throw new Error("Invalid execution transition");
  }

  finish(approvalId: string, state: "acknowledged" | "unknown", deploymentId?: string): void {
    z.enum(["acknowledged", "unknown"]).parse(state);
    if (state === "acknowledged" || deploymentId !== undefined) z.string().uuid().parse(deploymentId);
    const result = this.db.prepare("UPDATE worker_executions SET state=?, deployment_id=?, updated_at=? WHERE approval_id=? AND state='dispatching'")
      .run(state, deploymentId ?? null, new Date().toISOString(), approvalId);
    if (result.changes !== 1) throw new Error("Invalid execution transition");
  }

  get(approvalId: string): ExecutionRecord | null {
    const row = this.db.prepare("SELECT * FROM worker_executions WHERE approval_id=?").get(approvalId);
    return row ? recordSchema.parse(row) : null;
  }

  close(): void { this.db.close(); }
}
