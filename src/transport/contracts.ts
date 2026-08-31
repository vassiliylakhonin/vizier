import { z } from "zod";

import { jsonValueSchema } from "../core/schemas";
import { signedAuthorizationReceiptSchema } from "../covenants/schemas";

const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const timestampSchema = z.iso.datetime({ offset: true });
const decisionSchema = z.enum(["ALLOW", "REVIEW", "BLOCK"]);

const policyResultSchema = z.strictObject({
  rule_id: z.string().trim().min(1).max(512),
  result: z.enum(["PASS", "REVIEW", "FAIL"]),
  reason_code: z.string().trim().min(1).max(128).nullable(),
  details: z.record(z.string(), jsonValueSchema),
});

const receiptSchema = z.strictObject({
  id: z.string().trim().min(1).max(256),
  created_at: timestampSchema,
  request_hash: hashSchema,
  decision: decisionSchema,
  risk_score: z.number().finite().min(0).max(1),
  policy_rule_ids: z.array(z.string().trim().min(1).max(512)).min(1).max(100),
  reason_codes: z.array(z.string().trim().min(1).max(128)).max(100),
});

export const verificationResponseContractSchema = z.strictObject({
  decision: decisionSchema,
  risk_score: z.number().finite().min(0).max(1),
  reason_codes: z.array(z.string().trim().min(1).max(128)).max(100),
  explanation: z.string().trim().min(1).max(4_096),
  policy_results: z.array(policyResultSchema).min(1).max(100),
  receipt: receiptSchema,
});

export const actionCovenantAuthorizationResponseContractSchema = z.strictObject({
  decision: decisionSchema,
  risk_score: z.number().finite().min(0).max(1),
  reason_codes: z.array(z.string().trim().min(1).max(128)).max(100),
  explanation: z.string().trim().min(1).max(4_096),
  policy_results: z.array(policyResultSchema).min(1).max(100),
  authorization_receipt: signedAuthorizationReceiptSchema,
});

const decisionCountSchema = z.strictObject({
  decision: decisionSchema,
  count: z.number().int().nonnegative(),
});

export const auditInsightsContractSchema = z.strictObject({
  decisions: z.array(decisionCountSchema).length(3),
  authorization_decisions: z.array(decisionCountSchema).length(3),
  average_risk_score: z.number().finite().min(0).max(1),
  failures: z.number().int().nonnegative(),
  totals: z.strictObject({
    verifications: z.number().int().nonnegative(),
    covenants: z.number().int().nonnegative(),
    authorizations: z.number().int().nonnegative(),
    outcomes: z.number().int().nonnegative(),
  }),
});

export const apiErrorContractSchema = z.strictObject({
  error: z.strictObject({
    code: z.string().trim().min(1).max(128),
    message: z.string().trim().min(1).max(4_096),
    details: z.unknown().optional(),
  }),
});
