-- Per-principal aggregate usage bounds over fixed tumbling windows
-- (authorization requirement R4, first step). One row per (usage scope,
-- window start), keyed by a SHA-256 of "principal id \n usage id", so the
-- table holds no principal, agent or action data. Amounts are integer
-- micro-units of one currency. Windows are fixed and aligned to the Unix
-- epoch: a new window starts with zeroed counters, and the window length is
-- stored so pruning never has to know it. Rows are pruned once their window
-- plus a one-day margin has passed; deleting a row inside its live window
-- would reset the accounting, so retention only removes expired windows.
CREATE TABLE usage_ledger (
  usage_key TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  window_seconds INTEGER NOT NULL,
  calls INTEGER NOT NULL DEFAULT 0 CHECK (calls >= 0),
  spent_micros INTEGER NOT NULL DEFAULT 0 CHECK (spent_micros >= 0),
  currency TEXT,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (usage_key, window_start)
);
CREATE INDEX usage_ledger_updated ON usage_ledger (updated_at);
