import type { D1Database } from "@cloudflare/workers-types";

import { canonicalize, sha256 } from "../core/receipts";
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

export const ANONYMOUS_SURFACES = ["mcp", "a2a"] as const;
export const ANONYMOUS_OUTCOMES = ["served", "throttled"] as const;

export type AnonymousSurface = (typeof ANONYMOUS_SURFACES)[number];
export type AnonymousOutcome = (typeof ANONYMOUS_OUTCOMES)[number];

export interface AnonymousCallCount {
  readonly surface: AnonymousSurface;
  readonly outcome: AnonymousOutcome;
  readonly count: number;
}

export interface AuditInsights {
  readonly decisions: readonly DecisionCount[];
  readonly authorization_decisions: readonly DecisionCount[];
  readonly anonymous_calls: readonly AnonymousCallCount[];
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
    readonly anonymous_days: number;
  };
}

/**
 * The exact metadata a stored verification receipt is hashed over. The hash
 * covers the same columns the audit insert writes plus the previous chain
 * link, so any later change to a stored row invalidates its hash.
 */
export interface ChainedReceiptRow {
  readonly id: string;
  readonly created_at: string;
  readonly request_hash: string;
  readonly decision: Decision;
  readonly risk_score: number;
  readonly reason_codes: string;
  readonly policy_rule_ids: string;
  readonly action_type: string;
  readonly source: string;
  readonly prev_receipt_hash: string;
}

export async function auditReceiptHash(row: ChainedReceiptRow): Promise<string> {
  return sha256(canonicalize({ ...row }));
}

export type AuditChainBreakReason = "PREV_MISMATCH" | "HASH_MISMATCH";

export interface AuditChainVerification {
  readonly ok: boolean;
  /** Chained rows whose hash and link verified, in order, up to the first break. */
  readonly checked: number;
  /** Rows written before migration 0012; they carry no hash and are skipped. */
  readonly legacy: number;
  readonly first_broken_id?: string;
  readonly reason?: AuditChainBreakReason;
}

export async function storeReceipt(
  db: D1Database,
  request: VerificationRequest,
  receipt: Receipt,
): Promise<void> {
  const reasonCodes = JSON.stringify(receipt.reason_codes);
  const policyRuleIds = JSON.stringify(receipt.policy_rule_ids);
  const actionType = request.action.type;
  const source = request.context.source;
  const latest = await db
    .prepare(
      "SELECT receipt_hash FROM audit_receipts WHERE receipt_hash != '' ORDER BY created_at DESC, rowid DESC LIMIT 1",
    )
    .first<{ receipt_hash: string }>();
  const row: ChainedReceiptRow = {
    id: receipt.id,
    created_at: receipt.created_at,
    request_hash: receipt.request_hash,
    decision: receipt.decision,
    risk_score: receipt.risk_score,
    reason_codes: reasonCodes,
    policy_rule_ids: policyRuleIds,
    action_type: actionType,
    source,
    prev_receipt_hash: latest?.receipt_hash ?? "",
  };
  const receiptHash = await auditReceiptHash(row);
  await db
    .prepare(
      "INSERT INTO audit_receipts (id, created_at, request_hash, decision, risk_score, reason_codes, policy_rule_ids, action_type, source, receipt_hash, prev_receipt_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )
    .bind(
      row.id,
      row.created_at,
      row.request_hash,
      row.decision,
      row.risk_score,
      row.reason_codes,
      row.policy_rule_ids,
      row.action_type,
      row.source,
      receiptHash,
      row.prev_receipt_hash,
    )
    .run();
}

/**
 * Recomputes the audit receipt chain over every stored row, oldest first.
 * Detects modification, insertion, reordering, and deletion of any chained
 * row that still has a chained successor; a silent deletion of the newest
 * rows is not detectable without an external anchor, and rows written before
 * migration 0012 carry no hash and are skipped as legacy. Writers are
 * best-effort: two concurrent writes can fork the chain by linking to the
 * same predecessor, and verification reports the fork at the second link
 * rather than hiding it.
 */
export async function verifyAuditChain(
  db: D1Database,
): Promise<AuditChainVerification> {
  const result = await db
    .prepare(
      "SELECT id, created_at, request_hash, decision, risk_score, reason_codes, policy_rule_ids, action_type, source, receipt_hash, prev_receipt_hash FROM audit_receipts ORDER BY created_at, rowid",
    )
    .all<ChainedReceiptRow & { readonly receipt_hash: string }>();
  let checked = 0;
  let legacy = 0;
  let expectedPrev = "";
  for (const row of result.results) {
    if (row.receipt_hash === "") {
      legacy += 1;
      continue;
    }
    if (row.prev_receipt_hash !== expectedPrev) {
      return {
        ok: false,
        checked,
        legacy,
        first_broken_id: row.id,
        reason: "PREV_MISMATCH",
      };
    }
    const { receipt_hash, ...fields } = row;
    if ((await auditReceiptHash(fields)) !== receipt_hash) {
      return {
        ok: false,
        checked,
        legacy,
        first_broken_id: row.id,
        reason: "HASH_MISMATCH",
      };
    }
    expectedPrev = row.receipt_hash;
    checked += 1;
  }
  return { ok: true, checked, legacy };
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

// The counter is bumped in place rather than appended to, so an anonymous call
// costs one bounded write and never a row. The day is the UTC calendar day, so
// the retention sweep can drop whole days by string comparison like every other
// table here.
export async function recordAnonymousCall(
  db: D1Database,
  surface: AnonymousSurface,
  outcome: AnonymousOutcome,
  now: Date,
): Promise<void> {
  const day = now.toISOString().slice(0, 10);
  await db
    .prepare(
      "INSERT INTO anonymous_call_counts (day, surface, outcome, calls) VALUES (?1, ?2, ?3, 1) ON CONFLICT (day, surface, outcome) DO UPDATE SET calls = calls + 1",
    )
    .bind(day, surface, outcome)
    .run();
}

function anonymousCounts(
  rows: readonly Readonly<Record<string, unknown>>[],
): readonly AnonymousCallCount[] {
  const counts = new Map(
    rows.flatMap((row) =>
      typeof row.surface === "string" && typeof row.outcome === "string"
        ? [[`${row.surface}:${row.outcome}`, numericValue(row, "count")] as const]
        : [],
    ),
  );
  return ANONYMOUS_SURFACES.flatMap((surface) =>
    ANONYMOUS_OUTCOMES.map((outcome) => ({
      surface,
      outcome,
      count: counts.get(`${surface}:${outcome}`) ?? 0,
    })),
  );
}

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
    db.prepare(
      "SELECT surface, outcome, SUM(calls) AS count FROM anonymous_call_counts GROUP BY surface, outcome",
    ),
  ]);
  const verificationDecisions = resultAt(results, 0);
  const averageRisk = resultAt(results, 1);
  const failures = resultAt(results, 2);
  const verificationTotal = resultAt(results, 3);
  const covenantTotal = resultAt(results, 4);
  const authorizationDecisions = resultAt(results, 5);
  const authorizationTotal = resultAt(results, 6);
  const outcomeTotal = resultAt(results, 7);
  const anonymousCalls = resultAt(results, 8);

  return {
    decisions: decisionCounts(verificationDecisions.results),
    authorization_decisions: decisionCounts(authorizationDecisions.results),
    anonymous_calls: anonymousCounts(anonymousCalls.results),
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
    db
      .prepare("DELETE FROM anonymous_call_counts WHERE day < ?1")
      .bind(cutoff.slice(0, 10)),
  ]);

  return {
    cutoff,
    deleted: {
      outcomes: resultAt(results, 0).meta.changes,
      authorizations: resultAt(results, 1).meta.changes,
      covenants: resultAt(results, 2).meta.changes,
      verifications: resultAt(results, 3).meta.changes,
      anonymous_days: resultAt(results, 4).meta.changes,
    },
  };
}
