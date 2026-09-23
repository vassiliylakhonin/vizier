import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

const migrationsUrl = new URL("../migrations/", import.meta.url);
const migrations = readdirSync(migrationsUrl)
  .filter((name) => /^\d+.*\.sql$/.test(name))
  .sort();

assert.ok(migrations.length > 0, "At least one D1 migration is required.");

const db = new DatabaseSync(":memory:");
db.exec(readFileSync(new URL(migrations[0], migrationsUrl), "utf8"));

// Seed the payload-bearing v1 schema so the hardening migration proves that it
// removes existing sensitive columns and preserves only operational rows.
db.exec(`
  INSERT INTO audit_receipts VALUES (
    'vrf_old', '2026-08-01T00:00:00.000Z', 'hash', 'ALLOW', 0,
    '[]', '["rule"]', '{"secret":"must-disappear"}'
  );
  INSERT INTO action_covenants VALUES (
    'cov_old', '2026-08-01T00:00:00.000Z', '2026-08-01T00:01:00.000Z',
    'principal-secret', 'agent-secret', 'deploy_worker', 'target-secret',
    '2026-08-01T00:05:00.000Z', 'draft-hash'
  );
  INSERT INTO outcome_receipts VALUES (
    'out_old', 'azr_old', 'COMPLIANT', 'SUCCEEDED',
    '2026-08-01T00:02:00.000Z', '2026-08-01T00:03:00.000Z',
    '[{"secret":"must-disappear"}]'
  );
`);

const financialSql = readFileSync(new URL("0007_financial_reservations.sql", migrationsUrl), "utf8");
assert.equal((financialSql.match(/SELECT \(CASE WHEN/g) ?? []).length, 2,
  "D1 remote migration parser requires parenthesized CASE in triggers");
for (const migration of migrations.slice(1)) {
  db.exec(readFileSync(new URL(migration, migrationsUrl), "utf8"));
}

function columns(table) {
  return db
    .prepare(`PRAGMA table_info(${table})`)
    .all()
    .map((row) => row.name);
}

assert.deepEqual(columns("audit_receipts"), [
  "id",
  "created_at",
  "request_hash",
  "decision",
  "risk_score",
  "reason_codes",
  "policy_rule_ids",
  "action_type",
  "source",
]);
assert.deepEqual(columns("action_covenants"), [
  "id",
  "drafted_at",
  "accepted_at",
  "action_type",
  "expires_at",
  "draft_hash",
  "covenant_hash",
]);
assert.deepEqual(columns("outcome_receipts"), [
  "id",
  "authorization_receipt_id",
  "covenant_id",
  "issued_at",
  "compliance",
  "status",
  "started_at",
  "finished_at",
  "outcome_hash",
]);
assert.equal(
  db.prepare("SELECT COUNT(*) AS count FROM audit_receipts").get().count,
  1,
);
assert.equal(
  db.prepare("SELECT COUNT(*) AS count FROM action_covenants").get().count,
  1,
);
assert.equal(
  db.prepare("SELECT COUNT(*) AS count FROM outcome_receipts").get().count,
  1,
);

const schemaSql = db
  .prepare("SELECT GROUP_CONCAT(sql, ' ') AS sql FROM sqlite_master")
  .get().sql;
assert.equal(schemaSql.includes("request_body"), false);
assert.equal(schemaSql.includes("effects"), false);
assert.equal(schemaSql.includes("principal_id"), false);
assert.equal(schemaSql.includes("agent_id"), false);

console.log(`checked ${migrations.length} D1 migrations in order`);
