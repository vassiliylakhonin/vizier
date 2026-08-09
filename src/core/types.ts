export type Decision = "ALLOW" | "REVIEW" | "BLOCK";

export type PolicyResultStatus = "PASS" | "REVIEW" | "FAIL";

export interface PolicyResult {
  readonly rule_id: string;
  readonly result: PolicyResultStatus;
  readonly reason_code: string | null;
  readonly details: Readonly<Record<string, unknown>>;
}

export interface Receipt {
  readonly id: string;
  readonly created_at: string;
  readonly request_hash: string;
  readonly decision: Decision;
  readonly risk_score: number;
  readonly policy_rule_ids: readonly string[];
  readonly reason_codes: readonly string[];
}

export interface VerificationResponse {
  readonly decision: Decision;
  readonly risk_score: number;
  readonly reason_codes: readonly string[];
  readonly explanation: string;
  readonly policy_results: readonly PolicyResult[];
  readonly receipt: Receipt;
}

