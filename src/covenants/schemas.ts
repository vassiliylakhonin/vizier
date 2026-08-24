import { z } from "zod";

import {
  actionSchema,
  agentSchema,
  authoritySchema,
  contextSchema,
  identifierSchema,
  jsonPrimitiveSchema,
  jsonValueSchema,
  principalSchema,
  targetSchema,
} from "../core/schemas";

const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const timestampSchema = z.iso.datetime({ offset: true });
const policyRuleIdSchema = z.string().trim().min(1).max(512);
const reasonCodeSchema = z.string().trim().min(1).max(128);

function uniqueIds<T extends { readonly id: string }>(values: readonly T[]): boolean {
  return new Set(values.map((value) => value.id)).size === values.length;
}

export const evidenceRequirementSchema = z.strictObject({
  id: identifierSchema,
  evidence_type: identifierSchema,
  description: z.string().trim().min(1).max(1_024),
  max_age_seconds: z.number().int().min(1).max(31_536_000),
});

const shallowAttributesSchema = z
  .record(z.string().trim().min(1).max(256), jsonPrimitiveSchema)
  .refine((value) => Object.keys(value).length <= 32, {
    message: "Attributes cannot contain more than 32 keys",
  });

export const invalidationRuleSchema = z.strictObject({
  id: identifierSchema,
  signal_type: identifierSchema,
  match: shallowAttributesSchema,
  reason: z.string().trim().min(1).max(1_024),
});

export const forbiddenOutcomeSchema = z.strictObject({
  id: identifierSchema,
  effect_type: identifierSchema,
  target: targetSchema.optional(),
  reason: z.string().trim().min(1).max(1_024),
});

export const actionCovenantDraftSchema = z
  .strictObject({
    schema_version: z.literal("0.2"),
    drafted_by: z.strictObject({
      kind: z.enum(["MODEL", "HUMAN", "SYSTEM"]),
      identifier: identifierSchema,
    }),
    drafted_at: timestampSchema,
    principal: principalSchema,
    agent: agentSchema,
    intent: z.string().trim().min(1).max(4_096),
    action: actionSchema,
    authority: authoritySchema,
    evidence_requirements: z
      .array(evidenceRequirementSchema)
      .max(32)
      .refine(uniqueIds, { message: "Evidence requirement ids must be unique" }),
    invalidation_rules: z
      .array(invalidationRuleSchema)
      .max(32)
      .refine(uniqueIds, { message: "Invalidation rule ids must be unique" }),
    forbidden_outcomes: z
      .array(forbiddenOutcomeSchema)
      .max(32)
      .refine(uniqueIds, { message: "Forbidden outcome ids must be unique" }),
    expires_at: timestampSchema,
  })
  .refine(
    (value) => Date.parse(value.expires_at) > Date.parse(value.drafted_at),
    {
      path: ["expires_at"],
      message: "expires_at must be after drafted_at",
    },
  );

export const covenantAcceptanceSchema = z.strictObject({
  accepted_by: principalSchema,
  accepted_at: timestampSchema,
  draft_hash: hashSchema,
});

export const actionCovenantActivationRequestSchema = z.strictObject({
  draft: actionCovenantDraftSchema,
  acceptance: covenantAcceptanceSchema,
});

export const actionCovenantSchema = z.strictObject({
  id: identifierSchema,
  version: z.literal(1),
  status: z.literal("ACTIVE"),
  activated_at: timestampSchema,
  draft: actionCovenantDraftSchema,
  acceptance: covenantAcceptanceSchema,
  covenant_hash: hashSchema,
});

export const evidenceObservationSchema = z.strictObject({
  requirement_id: identifierSchema,
  evidence_type: identifierSchema,
  source: identifierSchema,
  observed_at: timestampSchema,
  content_hash: hashSchema,
});

export const signalObservationSchema = z.strictObject({
  signal_type: identifierSchema,
  source: identifierSchema,
  observed_at: timestampSchema,
  attributes: shallowAttributesSchema,
});

export const actionCovenantAuthorizationRequestSchema = z.strictObject({
  covenant: actionCovenantSchema,
  action: actionSchema,
  evidence: z
    .array(evidenceObservationSchema)
    .max(32)
    .refine(
      (values) =>
        new Set(values.map((value) => value.requirement_id)).size === values.length,
      { message: "Evidence observations must have unique requirement ids" },
    ),
  signals: z.array(signalObservationSchema).max(64),
  context: contextSchema,
});

export const authorizationReceiptPayloadSchema = z.strictObject({
  type: z.literal("ACTION_AUTHORIZATION"),
  version: z.literal(1),
  id: identifierSchema,
  issuer: z.string().url().max(2_048),
  issued_at: timestampSchema,
  expires_at: timestampSchema,
  covenant_id: identifierSchema,
  covenant_hash: hashSchema,
  request_hash: hashSchema,
  action_hash: hashSchema,
  evidence_hash: hashSchema,
  signals_hash: hashSchema,
  decision: z.enum(["ALLOW", "REVIEW", "BLOCK"]),
  risk_score: z.number().finite().min(0).max(1),
  policy_rule_ids: z.array(policyRuleIdSchema).min(1).max(100),
  reason_codes: z.array(reasonCodeSchema).max(100),
});

export const signedAuthorizationReceiptSchema = z.strictObject({
  payload: authorizationReceiptPayloadSchema,
  token: z.string().min(1).max(32_768),
});

export const executionEffectSchema = z.strictObject({
  type: identifierSchema,
  target: targetSchema,
  parameters: z.record(z.string().max(256), jsonValueSchema),
});

export const executionOutcomeSchema = z
  .strictObject({
    status: z.enum(["SUCCEEDED", "FAILED", "PARTIAL"]),
    started_at: timestampSchema,
    finished_at: timestampSchema,
    effects: z.array(executionEffectSchema).max(64),
    external_reference: z.string().trim().min(1).max(2_048).nullable(),
  })
  .refine(
    (value) => Date.parse(value.finished_at) >= Date.parse(value.started_at),
    {
      path: ["finished_at"],
      message: "finished_at must not be before started_at",
    },
  );

export const outcomeRecordingRequestSchema = z.strictObject({
  covenant: actionCovenantSchema,
  authorization_receipt: signedAuthorizationReceiptSchema,
  outcome: executionOutcomeSchema,
});

export const outcomeReceiptPayloadSchema = z.strictObject({
  type: z.literal("OUTCOME_RECEIPT"),
  version: z.literal(1),
  id: identifierSchema,
  issuer: z.string().url().max(2_048),
  issued_at: timestampSchema,
  authorization_receipt_id: identifierSchema,
  authorization_token_hash: hashSchema,
  covenant_id: identifierSchema,
  covenant_hash: hashSchema,
  outcome_hash: hashSchema,
  compliance: z.enum(["COMPLIANT", "VIOLATION"]),
  violation_codes: z.array(z.string().trim().min(1).max(512)).max(32),
});

export const signedOutcomeReceiptSchema = z.strictObject({
  payload: outcomeReceiptPayloadSchema,
  token: z.string().min(1).max(32_768),
});

export type ActionCovenantDraft = z.infer<typeof actionCovenantDraftSchema>;
export type CovenantAcceptance = z.infer<typeof covenantAcceptanceSchema>;
export type ActionCovenantActivationRequest = z.infer<
  typeof actionCovenantActivationRequestSchema
>;
export type ActionCovenant = z.infer<typeof actionCovenantSchema>;
export type EvidenceObservation = z.infer<typeof evidenceObservationSchema>;
export type SignalObservation = z.infer<typeof signalObservationSchema>;
export type ActionCovenantAuthorizationRequest = z.infer<
  typeof actionCovenantAuthorizationRequestSchema
>;
export type AuthorizationReceiptPayload = z.infer<
  typeof authorizationReceiptPayloadSchema
>;
export type SignedAuthorizationReceipt = z.infer<
  typeof signedAuthorizationReceiptSchema
>;
export type ExecutionOutcome = z.infer<typeof executionOutcomeSchema>;
export type OutcomeRecordingRequest = z.infer<typeof outcomeRecordingRequestSchema>;
export type OutcomeReceiptPayload = z.infer<typeof outcomeReceiptPayloadSchema>;
export type SignedOutcomeReceipt = z.infer<typeof signedOutcomeReceiptSchema>;
