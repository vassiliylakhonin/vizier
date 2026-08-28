import type { Receipt } from "../core/types";
import type { ActionCovenant, SignedOutcomeReceipt, ExecutionOutcome } from "../covenants/schemas";
import type { VerificationRequest } from "../core/schemas";
import type { D1Database } from "@cloudflare/workers-types";

export async function storeReceipt(
  db: D1Database,
  request: VerificationRequest,
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
  db: D1Database,
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
  db: D1Database,
  receipt: SignedOutcomeReceipt,
  outcome: ExecutionOutcome
): Promise<void> {
  const stmt = db.prepare(
    "INSERT INTO outcome_receipts (id, authorization_receipt_id, compliance, status, started_at, finished_at, effects) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
  );
  await stmt.bind(
    receipt.payload.id,
    receipt.payload.authorization_receipt_id,
    receipt.payload.compliance,
    outcome.status,
    outcome.started_at,
    outcome.finished_at,
    JSON.stringify(outcome.effects)
  ).run();
}

export async function getInsights(db: D1Database): Promise<Record<string, unknown>> {
  const stmt1 = db.prepare("SELECT decision, COUNT(*) as count FROM audit_receipts GROUP BY decision");
  const { results: decisionCounts } = await stmt1.all();
  
  const stmt2 = db.prepare("SELECT AVG(risk_score) as avg_risk FROM audit_receipts");
  const { results: riskAvg } = await stmt2.all();
  
  const stmt3 = db.prepare("SELECT COUNT(*) as total_failures FROM outcome_receipts WHERE compliance = 'VIOLATION' OR status = 'FAILED'");
  const { results: failures } = await stmt3.all();

  return {
    decisions: decisionCounts,
    average_risk_score: riskAvg[0]?.avg_risk ?? 0,
    failures: failures[0]?.total_failures ?? 0,
  };
}
