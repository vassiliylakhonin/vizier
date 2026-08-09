import { aggregateDecision } from "./decision";
import { evaluatePolicies, type PolicyOptions } from "./policies";
import { createReceipt, type ReceiptOptions } from "./receipts";
import { calculateRiskScore } from "./risk";
import type { VerificationRequest } from "./schemas";
import type { Decision, VerificationResponse } from "./types";

export interface VerificationOptions extends PolicyOptions, ReceiptOptions {}

const EXPLANATIONS: Readonly<Record<Decision, string>> = Object.freeze({
  ALLOW: "The proposed action is within the supplied delegated authority and constraints.",
  REVIEW: "The proposed action requires human review because authority or risk could not be resolved automatically.",
  BLOCK: "The proposed action violates the supplied delegated authority or constraints.",
});

export async function verifyAction(
  request: VerificationRequest,
  options: VerificationOptions = {},
): Promise<VerificationResponse> {
  const policyResults = evaluatePolicies(request, options);
  const decision = aggregateDecision(policyResults);
  const riskScore = calculateRiskScore(policyResults);
  const reasonCodes = Object.freeze(
    policyResults.flatMap((item) =>
      item.reason_code === null ? [] : [item.reason_code],
    ),
  );
  const receipt = await createReceipt(
    request,
    decision,
    riskScore,
    policyResults,
    options,
  );

  return Object.freeze({
    decision,
    risk_score: riskScore,
    reason_codes: reasonCodes,
    explanation: EXPLANATIONS[decision],
    policy_results: policyResults,
    receipt,
  });
}
