-- Cumulative budget ceiling ledger. One row per (principal, budget id), keyed
-- by a SHA-256 of "principal id \n budget id", so the table holds no principal,
-- agent or action data. Amounts are integer micro-units of one currency.
-- Rows are never pruned: deleting a row would reset the accounting, and a
-- grant with a higher ceiling must continue the same spend, not restart it.
-- The ceiling itself is not stored: it comes from the principal-signed grant
-- on every call.
CREATE TABLE budget_ledger (
  budget_key TEXT PRIMARY KEY,
  currency TEXT NOT NULL,
  spent_micros INTEGER NOT NULL DEFAULT 0 CHECK (spent_micros >= 0),
  admissions INTEGER NOT NULL DEFAULT 0 CHECK (admissions >= 0),
  updated_at INTEGER NOT NULL
);
