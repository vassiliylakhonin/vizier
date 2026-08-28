export { verificationRequestSchema } from "./schemas";
export type { VerificationRequest } from "./schemas";
export { DEFAULT_SENSITIVE_ACTIONS, evaluatePolicies } from "./policies";
export type { PolicyEvaluator, PolicyOptions } from "./policies";
export { aggregateDecision } from "./decision";
export { RISK_WEIGHTS, calculateRiskScore } from "./risk";
export { canonicalize, createReceipt, sha256 } from "./receipts";
export {
  assertJsonComplexity,
  JsonComplexityError,
  MAX_JSON_DEPTH,
  MAX_JSON_NODES,
} from "./json-complexity";
export { verifyAction } from "./verify";
export type {
  Decision,
  PolicyResult,
  Receipt,
  VerificationResponse,
} from "./types";
