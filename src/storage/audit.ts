import type { Receipt, VerificationRequest } from "../core/types";
import type { ActionCovenant, SignedOutcomeReceipt } from "../covenants/types";
import type { VerificationRequest as VerificationRequestSchema } from "../core/schemas";

export async function storeReceipt(
  db: any,
  request: VerificationRequestSchema,
  receipt: Receipt
): Promise<void> {
  const stmt = db.prepare(
    "INSERT INTO audit_receipts (id, created_at, request_hash, decision, risk_score, reason_codes, policy_rule_ids, request_body) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
  );
  await stmt.bind(
    receipt.id,
    receipt.created_at,
    receipt.request_hash,
    receipt.decision,
    receipt.risk_score,
    JSON.stringify(receipt.reason_codes),
    JSON.stringify(receipt.policy_rule_ids),
    JSON.stringify(request)
  ).run();
}

export async function storeCovenant(
  db: any,
  covenant: ActionCovenant
): Promise<void> {
  const stmt = db.prepare(
    "INSERT INTO action_covenants (id, drafted_at, accepted_at, principal_id, agent_id, action_type, target, expires_at, draft_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
  );
  await stmt.bind(
    covenant.id,
    covenant.draft.drafted_at,
    covenant.acceptance.accepted_at,
    covenant.draft.principal.id,
    covenant.draft.agent.id,
    covenant.draft.action.type,
    covenant.draft.action.target,
    covenant.draft.expires_at,
    covenant.acceptance.draft_hash
  ).run();
}

export async function storeOutcome(
  db: any,
  receipt: SignedOutcomeReceipt
): Promise<void> {
  const stmt = db.prepare(
    "INSERT INTO outcome_receipts (id, authorization_receipt_id, compliance, status, started_at, finished_at, effects) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
  );
  await stmt.bind(
    receipt.payload.id,
    receipt.payload.authorization_receipt_id,
    receipt.payload.compliance,
    receipt.payload.outcome.status,
    receipt.payload.outcome.started_at,
    receipt.payload.outcome.finished_at,
    JSON.stringify(receipt.payload.outcome.effects)
  ).run();
}
