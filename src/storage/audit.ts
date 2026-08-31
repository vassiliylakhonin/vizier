import type { D1Database } from "@cloudflare/workers-types";

import type { VerificationRequest } from "../core/schemas";
import type { Decision, Receipt } from "../core/types";
import type {
  ActionCovenant,
  ExecutionOutcome,
  SignedAuthorizationReceipt,
  SignedOutcomeReceipt,
} from "../covenants/schemas";

export interface DecisionCount {
  readonly decision: Decision;
  readonly count: number;
}

export interface AuditInsights {
  readonly decisions: readonly DecisionCount[];
  readonly authorization_decisions: readonly DecisionCount[];
  readonly average_risk_score: number;
  readonly failures: number;
  readonly totals: {
    readonly verifications: number;
    readonly covenants: number;
    readonly authorizations: number;
    readonly outcomes: number;
  };
}

export const AUDIT_RETENTION_DAYS = 30;

export interface AuditPruneResult {
  readonly cutoff: string;
  readonly deleted: {
    readonly verifications: number;
    readonly covenants: number;
    readonly authorizations: number;
    readonly outcomes: number;
  };
}

export async function storeReceipt(
  db: D1Database,
  request: VerificationRequest,
  receipt: Receipt,
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO audit_receipts (id, created_at, request_hash, decision, risk_score, reason_codes, policy_rule_ids, action_type, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(
      receipt.id,
      receipt.created_at,
      receipt.request_hash,
      receipt.decision,
      receipt.risk_score,
      JSON.stringify(receipt.reason_codes),
      JSON.stringify(receipt.policy_rule_ids),
      request.action.type,
      request.context.source,
    )
    .run();
}

export async function storeCovenant(
  db: D1Database,
  covenant: ActionCovenant,
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO action_covenants (id, drafted_at, accepted_at, action_type, expires_at, draft_hash, covenant_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(
      covenant.id,
      covenant.draft.drafted_at,
      covenant.acceptance.accepted_at,
      covenant.draft.action.type,
      covenant.draft.expires_at,
      covenant.acceptance.draft_hash,
      covenant.covenant_hash,
    )
    .run();
}

export async function storeAuthorization(
  db: D1Database,
  receipt: SignedAuthorizationReceipt,
): Promise<void> {
  const payload = receipt.payload;
  await db
    .prepare(
      "INSERT INTO authorization_receipts (id, covenant_id, issued_at, expires_at, decision, risk_score, reason_codes, policy_rule_ids, request_hash, action_hash, evidence_hash, signals_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )
    .bind(
      payload.id,
      payload.covenant_id,
      payload.issued_at,
      payload.expires_at,
      payload.decision,
      payload.risk_score,
      JSON.stringify(payload.reason_codes),
      JSON.stringify(payload.policy_rule_ids),
      payload.request_hash,
      payload.action_hash,
      payload.evidence_hash,
      payload.signals_hash,
    )
    .run();
}

export async function storeOutcome(
  db: D1Database,
  receipt: SignedOutcomeReceipt,
  outcome: ExecutionOutcome,
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO outcome_receipts (id, authorization_receipt_id, covenant_id, issued_at, compliance, status, started_at, finished_at, outcome_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(
      receipt.payload.id,
      receipt.payload.authorization_receipt_id,
      receipt.payload.covenant_id,
      receipt.payload.issued_at,
      receipt.payload.compliance,
      outcome.status,
      outcome.started_at,
      outcome.finished_at,
      receipt.payload.outcome_hash,
    )
    .run();
}

const DECISIONS = ["ALLOW", "REVIEW", "BLOCK"] as const;

function numericValue(
  row: Readonly<Record<string, unknown>> | undefined,
  key: string,
): number {
  const value = row?.[key];
  const number = typeof value === "number" ? value : Number(value ?? 0);
  return Number.isFinite(number) && number >= 0 ? number : 0;
}

function decisionCounts(
  rows: readonly Readonly<Record<string, unknown>>[],
): readonly DecisionCount[] {
  const counts = new Map(
    rows.flatMap((row) =>
      typeof row.decision === "string"
        ? [[row.decision, numericValue(row, "count")] as const]
        : [],
    ),
  );
  return DECISIONS.map((decision) => ({
    decision,
    count: counts.get(decision) ?? 0,
  }));
}

function resultAt<T>(results: readonly T[], index: number): T {
  const result = results[index];
  if (result === undefined) {
    throw new Error("D1 returned an incomplete audit batch.");
  }
  return result;
}

export async function getInsights(db: D1Database): Promise<AuditInsights> {
  const results = await db.batch<Record<string, unknown>>([
    db.prepare(
      "SELECT decision, COUNT(*) AS count FROM audit_receipts GROUP BY decision",
    ),
    db.prepare("SELECT AVG(risk_score) AS average FROM audit_receipts"),
    db.prepare(
      "SELECT COUNT(*) AS count FROM outcome_receipts WHERE compliance = 'VIOLATION' OR status = 'FAILED'",
    ),
    db.prepare("SELECT COUNT(*) AS count FROM audit_receipts"),
    db.prepare("SELECT COUNT(*) AS count FROM action_covenants"),
    db.prepare(
      "SELECT decision, COUNT(*) AS count FROM authorization_receipts GROUP BY decision",
    ),
    db.prepare("SELECT COUNT(*) AS count FROM authorization_receipts"),
    db.prepare("SELECT COUNT(*) AS count FROM outcome_receipts"),
  ]);
  const verificationDecisions = resultAt(results, 0);
  const averageRisk = resultAt(results, 1);
  const failures = resultAt(results, 2);
  const verificationTotal = resultAt(results, 3);
  const covenantTotal = resultAt(results, 4);
  const authorizationDecisions = resultAt(results, 5);
  const authorizationTotal = resultAt(results, 6);
  const outcomeTotal = resultAt(results, 7);

  return {
    decisions: decisionCounts(verificationDecisions.results),
    authorization_decisions: decisionCounts(authorizationDecisions.results),
    average_risk_score: numericValue(averageRisk.results[0], "average"),
    failures: numericValue(failures.results[0], "count"),
    totals: {
      verifications: numericValue(verificationTotal.results[0], "count"),
      covenants: numericValue(covenantTotal.results[0], "count"),
      authorizations: numericValue(authorizationTotal.results[0], "count"),
      outcomes: numericValue(outcomeTotal.results[0], "count"),
    },
  };
}

export async function pruneAuditMetadata(
  db: D1Database,
  now: Date,
  retentionDays = AUDIT_RETENTION_DAYS,
): Promise<AuditPruneResult> {
  if (
    !Number.isInteger(retentionDays) ||
    retentionDays < 1 ||
    retentionDays > 3_650 ||
    !Number.isFinite(now.getTime())
  ) {
    throw new TypeError("Audit retention requires a valid date and 1-3650 days.");
  }
  const cutoff = new Date(
    now.getTime() - retentionDays * 24 * 60 * 60 * 1_000,
  ).toISOString();
  const results = await db.batch([
    db.prepare("DELETE FROM outcome_receipts WHERE finished_at < ?1").bind(cutoff),
    db.prepare("DELETE FROM authorization_receipts WHERE issued_at < ?1").bind(cutoff),
    db.prepare("DELETE FROM action_covenants WHERE accepted_at < ?1").bind(cutoff),
    db.prepare("DELETE FROM audit_receipts WHERE created_at < ?1").bind(cutoff),
  ]);

  return {
    cutoff,
    deleted: {
      outcomes: resultAt(results, 0).meta.changes,
      authorizations: resultAt(results, 1).meta.changes,
      covenants: resultAt(results, 2).meta.changes,
      verifications: resultAt(results, 3).meta.changes,
    },
  };
}
