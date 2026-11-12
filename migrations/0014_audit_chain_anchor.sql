-- Retention anchor for the audit receipt chain. Pruning removes the oldest
-- receipts, so the first retained chained row links to a hash that no longer
-- exists. Before each prune the hash of the newest row about to be deleted is
-- recorded here, and chain verification starts from it instead of from the
-- empty genesis value. One row; replaced on each prune that removes chained
-- receipts. A party with D1 write access can still edit this row.

CREATE TABLE IF NOT EXISTS audit_chain_anchor (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  pruned_through_id TEXT NOT NULL,
  pruned_through_hash TEXT NOT NULL,
  anchored_at TEXT NOT NULL
);
