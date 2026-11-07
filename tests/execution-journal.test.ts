import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { SqliteExecutionJournal } from "../packages/gated-deploy/src/execution-journal";

let directory: string;
let path: string;
beforeEach(() => { directory = mkdtempSync(join(tmpdir(), "vizier-journal-")); path = join(directory, "journal.sqlite"); });
afterEach(() => { rmSync(directory, { recursive: true, force: true }); });
const identity = { approval_id: "approval", receipt_id: "receipt", review_hash: "a".repeat(64) };

it.each(["prepared", "dispatching"])("recovers %s after abrupt process exit without closing SQLite", state => {
  const module = new URL("../packages/gated-deploy/src/execution-journal.ts", import.meta.url).href;
  const program = `import { SqliteExecutionJournal } from ${JSON.stringify(module)};
    const journal = new SqliteExecutionJournal(process.argv[1]);
    journal.prepare(${JSON.stringify(identity)});
    ${state === "dispatching" ? 'journal.dispatch("approval");' : ""}
    process.exit(0);`;
  execFileSync(process.execPath, ["--input-type=module", "-e", program, path], { stdio: "pipe" });
  const journal = new SqliteExecutionJournal(path, { readOnly: true });
  try {
    expect(journal.get("approval")?.state).toBe(state);
    expect(() => journal.dispatch("approval")).toThrow();
  } finally { journal.close(); }
});

it("refuses duplicate approvals and invalid state transitions", () => {
  const journal = new SqliteExecutionJournal(path);
  try {
    journal.prepare(identity);
    expect(() => journal.prepare({ ...identity, review_hash: "b".repeat(64) })).toThrow();
    expect(() => journal.finish("approval", "unknown")).toThrow();
    journal.dispatch("approval");
    expect(() => journal.dispatch("approval")).toThrow();
    expect(() => journal.finish("approval", "acknowledged")).toThrow();
    journal.finish("approval", "unknown");
    expect(() => journal.dispatch("approval")).toThrow();
    expect(journal.get("approval")?.review_hash).toBe(identity.review_hash);
  } finally { journal.close(); }
});

it("refuses a symlink or a journal readable by another OS identity", () => {
  new SqliteExecutionJournal(path).close();
  symlinkSync(path, join(directory, "alias"));
  expect(() => new SqliteExecutionJournal(join(directory, "alias"))).toThrow();
  chmodSync(path, 0o644);
  expect(() => new SqliteExecutionJournal(path)).toThrow();
});
