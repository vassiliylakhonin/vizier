import type { PolicyResult } from "./types";

export const RISK_WEIGHTS = Object.freeze({
  AUTHORITY_SOURCE_UNTRUSTED: 0.5,
  PRINCIPAL_UNVERIFIED: 0.2,
  SENSITIVE_ACTION_REVIEW: 0.3,
  AMOUNT_UNVERIFIED: 0.3,
  CURRENCY_UNVERIFIED: 0.3,
  ACTION_NOT_DELEGATED: 0.5,
  AUTHORITY_LIMIT_EXCEEDED: 0.5,
  TARGET_BLOCKED: 0.3,
  TARGET_NOT_ALLOWED: 0.3,
  COVENANT_INTEGRITY_INVALID: 1,
  COVENANT_EXPIRED: 1,
  ACTION_COVENANT_MISMATCH: 1,
  EVIDENCE_MISSING: 0.4,
  EVIDENCE_TYPE_MISMATCH: 0.4,
  EVIDENCE_STALE: 0.4,
  EVIDENCE_FROM_FUTURE: 0.4,
  COVENANT_INVALIDATED: 1,
  GRANT_MALFORMED: 0.5,
  GRANT_PRINCIPAL_UNKNOWN: 0.5,
  GRANT_KEY_UNKNOWN: 0.5,
  GRANT_SIGNATURE_INVALID: 1,
  GRANT_NOT_YET_VALID: 0.5,
  GRANT_EXPIRED: 0.5,
  GRANT_LIFETIME_EXCESSIVE: 0.5,
  GRANT_ISSUER_MISMATCH: 1,
  GRANT_SUBJECT_MISMATCH: 1,
  GRANT_AUDIENCE_MISMATCH: 1,
  GRANT_AUTHORITY_MISMATCH: 1,
} as const);

export function calculateRiskScore(results: readonly PolicyResult[]): number {
  const reasonCodes = new Set(
    results.flatMap((item) => (item.reason_code === null ? [] : [item.reason_code])),
  );
  let score = 0;
  for (const code of reasonCodes) {
    score += RISK_WEIGHTS[code as keyof typeof RISK_WEIGHTS] ?? 0;
  }
  return Math.min(1, Number(score.toFixed(2)));
}
