CREATE TABLE IF NOT EXISTS audit_receipts (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  decision TEXT NOT NULL,
  risk_score REAL NOT NULL,
  reason_codes TEXT NOT NULL,
  policy_rule_ids TEXT NOT NULL,
  request_body TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS action_covenants (
  id TEXT PRIMARY KEY,
  drafted_at TEXT NOT NULL,
  accepted_at TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  target TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  draft_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outcome_receipts (
  id TEXT PRIMARY KEY,
  authorization_receipt_id TEXT NOT NULL,
  compliance TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  effects TEXT NOT NULL
);
