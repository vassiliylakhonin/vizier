import type { VerificationRequest } from "./schemas";
import type { Decision, PolicyResult, Receipt } from "./types";
import { assertJsonComplexity } from "./json-complexity";

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function canonicalize(value: unknown): string {
  assertJsonComplexity(value);
  return canonicalizeValidated(value);
}

function canonicalizeValidated(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeValidated(item)).join(",")}]`;
  }
  if (isPlainObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalizeValidated(value[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("Value is not canonicalizable JSON");
}

export async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export interface ReceiptOptions {
  readonly now?: () => Date;
  readonly createId?: () => string;
}

export async function createReceipt(
  request: VerificationRequest,
  decision: Decision,
  riskScore: number,
  policyResults: readonly PolicyResult[],
  options: ReceiptOptions = {},
): Promise<Receipt> {
  const now = options.now ?? (() => new Date());
  const createId = options.createId ?? (() => `vrf_${crypto.randomUUID()}`);
  const reasonCodes = policyResults.flatMap((item) =>
    item.reason_code === null ? [] : [item.reason_code],
  );

  return Object.freeze({
    id: createId(),
    created_at: now().toISOString(),
    request_hash: await sha256(canonicalize(request)),
    decision,
    risk_score: riskScore,
    policy_rule_ids: Object.freeze(policyResults.map((item) => item.rule_id)),
    reason_codes: Object.freeze(reasonCodes),
  });
}
