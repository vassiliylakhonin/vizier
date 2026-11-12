-- Idempotent budget admissions. Used only when the operator sets
-- VIZIER_BUDGET_IDEMPOTENCY=request_id. One row per (budget, request id):
-- the same request id with the same action is counted once. Both keys are
-- SHA-256 digests, so the table holds no principal, agent, request id or
-- action data. Rows are pruned after 30 days; a retry after that is counted
-- as a new spend.
CREATE TABLE budget_admissions (
  budget_key TEXT NOT NULL,
  request_key TEXT NOT NULL,
  action_hash TEXT NOT NULL,
  amount_micros INTEGER NOT NULL CHECK (amount_micros >= 0),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (budget_key, request_key)
);
CREATE INDEX budget_admissions_created ON budget_admissions (created_at);
