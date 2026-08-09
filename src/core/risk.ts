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
