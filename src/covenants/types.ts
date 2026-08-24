import type { Decision, PolicyResult } from "../core/types";
import type { SignedAuthorizationReceipt } from "./schemas";

export interface ActionCovenantAuthorizationResponse {
  readonly decision: Decision;
  readonly risk_score: number;
  readonly reason_codes: readonly string[];
  readonly explanation: string;
  readonly policy_results: readonly PolicyResult[];
  readonly authorization_receipt: SignedAuthorizationReceipt;
}
