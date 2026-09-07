export type Decision = "ALLOW" | "REVIEW" | "BLOCK";

export type PolicyResultStatus = "PASS" | "REVIEW" | "FAIL";

export interface PolicyResult {
  readonly rule_id: string;
  readonly result: PolicyResultStatus;
  readonly reason_code: string | null;
  readonly details: Readonly<Record<string, unknown>>;
}

/** Where the authority Vizier evaluated actually came from. */
export type AuthorityProvenance =
  /** A delegation grant signed by the principal, verified against a registered key. */
  | "principal_signed"
  /** Asserted by the calling application over the authenticated boundary. */
  | "trusted_integration"
  /** Asserted by an unauthenticated caller; never sufficient for ALLOW. */
  | "unverified";

/** The verified delegation grant a decision rested on, recorded in the receipt. */
export interface ReceiptGrant {
  readonly jti: string;
  readonly issuer: string;
  readonly subject: string;
  readonly key_id: string;
  readonly expires_at: string;
}

export interface Receipt {
  readonly id: string;
  readonly created_at: string;
  readonly request_hash: string;
  readonly decision: Decision;
  readonly risk_score: number;
  readonly policy_rule_ids: readonly string[];
  readonly reason_codes: readonly string[];
  readonly authority_provenance: AuthorityProvenance;
  readonly grant?: ReceiptGrant;
}

export interface VerificationResponse {
  readonly decision: Decision;
  readonly risk_score: number;
  readonly reason_codes: readonly string[];
  readonly explanation: string;
  readonly policy_results: readonly PolicyResult[];
  readonly receipt: Receipt;
}
