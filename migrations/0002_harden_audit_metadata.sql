-- Replace payload-bearing audit tables with a metadata-only operational log.
-- Action parameters, evidence, signals, outcome effects, principal IDs, agent
-- IDs, targets, JWS tokens, and signing material are intentionally excluded.

CREATE TABLE audit_receipts_hardened (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'REVIEW', 'BLOCK')),
  risk_score REAL NOT NULL CHECK (risk_score >= 0 AND risk_score <= 1),
  reason_codes TEXT NOT NULL,
  policy_rule_ids TEXT NOT NULL,
  action_type TEXT NOT NULL,
  source TEXT NOT NULL
);

INSERT INTO audit_receipts_hardened (
  id, created_at, request_hash, decision, risk_score, reason_codes,
  policy_rule_ids, action_type, source
)
SELECT
  id, created_at, request_hash, decision, risk_score, reason_codes,
  policy_rule_ids, 'unknown', 'unknown'
FROM audit_receipts;

DROP TABLE audit_receipts;
ALTER TABLE audit_receipts_hardened RENAME TO audit_receipts;

CREATE TABLE action_covenants_hardened (
  id TEXT PRIMARY KEY,
  drafted_at TEXT NOT NULL,
  accepted_at TEXT NOT NULL,
  action_type TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  draft_hash TEXT NOT NULL,
  covenant_hash TEXT NOT NULL
);

INSERT INTO action_covenants_hardened (
  id, drafted_at, accepted_at, action_type, expires_at, draft_hash,
  covenant_hash
)
SELECT
  id, drafted_at, accepted_at, action_type, expires_at, draft_hash,
  'unknown'
FROM action_covenants;

DROP TABLE action_covenants;
ALTER TABLE action_covenants_hardened RENAME TO action_covenants;

CREATE TABLE authorization_receipts (
  id TEXT PRIMARY KEY,
  covenant_id TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'REVIEW', 'BLOCK')),
  risk_score REAL NOT NULL CHECK (risk_score >= 0 AND risk_score <= 1),
  reason_codes TEXT NOT NULL,
  policy_rule_ids TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  action_hash TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  signals_hash TEXT NOT NULL
);

CREATE TABLE outcome_receipts_hardened (
  id TEXT PRIMARY KEY,
  authorization_receipt_id TEXT NOT NULL,
  covenant_id TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  compliance TEXT NOT NULL CHECK (compliance IN ('COMPLIANT', 'VIOLATION')),
  status TEXT NOT NULL CHECK (status IN ('SUCCEEDED', 'FAILED', 'PARTIAL')),
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  outcome_hash TEXT NOT NULL
);

INSERT INTO outcome_receipts_hardened (
  id, authorization_receipt_id, covenant_id, issued_at, compliance, status,
  started_at, finished_at, outcome_hash
)
SELECT
  id, authorization_receipt_id, 'unknown', finished_at, compliance, status,
  started_at, finished_at, 'unknown'
FROM outcome_receipts;

DROP TABLE outcome_receipts;
ALTER TABLE outcome_receipts_hardened RENAME TO outcome_receipts;

CREATE INDEX audit_receipts_created_at_idx
  ON audit_receipts (created_at);
CREATE INDEX audit_receipts_decision_idx
  ON audit_receipts (decision);
CREATE INDEX action_covenants_accepted_at_idx
  ON action_covenants (accepted_at);
CREATE INDEX authorization_receipts_issued_at_idx
  ON authorization_receipts (issued_at);
CREATE INDEX authorization_receipts_decision_idx
  ON authorization_receipts (decision);
CREATE INDEX outcome_receipts_finished_at_idx
  ON outcome_receipts (finished_at);
CREATE INDEX outcome_receipts_compliance_status_idx
  ON outcome_receipts (compliance, status);
