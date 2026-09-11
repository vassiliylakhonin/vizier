import { z } from "zod";

export const identifierSchema = z.string().trim().min(1).max(256);
export const actionTypeSchema = z.string().trim().min(1).max(128);
export const targetSchema = z.string().trim().min(1).max(2_048);

export const jsonPrimitiveSchema = z.union([
  z.string(),
  z.number().finite(),
  z.boolean(),
  z.null(),
]);

type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    jsonPrimitiveSchema,
    z.array(jsonValueSchema),
    z.record(z.string(), jsonValueSchema),
  ]),
);

export const stringSetSchema = z
  .array(z.string().trim().min(1).max(2_048))
  .refine((values) => new Set(values).size === values.length, {
    message: "Values must be unique",
  });

export const agentSchema = z.strictObject({
  id: identifierSchema,
  owner: identifierSchema.nullable(),
});

export const principalSchema = z.strictObject({
  id: identifierSchema,
});

export const actionSchema = z.strictObject({
  type: actionTypeSchema,
  target: targetSchema,
  parameters: z.record(z.string(), jsonValueSchema),
  is_reversible: z.boolean().optional(),
});

export const authoritySchema = z.strictObject({
  allowed_actions: z
    .array(actionTypeSchema)
    .refine((values) => new Set(values).size === values.length, {
      message: "Actions must be unique",
    }),
  constraints: z.strictObject({
    max_amount: z.number().finite().nonnegative().optional(),
    currency: z.string().regex(/^[A-Z]{3}$/).optional(),
    allowed_targets: stringSetSchema.optional(),
    blocked_targets: stringSetSchema.optional(),
    allowed_sensitive_actions: z.array(actionTypeSchema).optional(),
    require_review_for_irreversible: z.boolean().optional(),
    max_repeated_calls: z.number().int().min(1).max(100).optional(),
    time_window_seconds: z.number().min(1).max(3600).optional(),
    max_session_actions: z.number().int().min(1).max(10000).optional(),
    cool_off_seconds: z.number().min(1).max(86400).optional(),
    sanctions_screening: z.boolean().optional(),
    blocked_entities: stringSetSchema.optional(),
    dlp_screening: z.boolean().optional(),
    allowed_dlp_categories: stringSetSchema.optional(),
    quorum: z
      .strictObject({
        min_approvals: z.number().int().min(1).max(10),
        allowed_approvers: stringSetSchema.optional(),
        require_distinct_owners: z.boolean().optional(),
        max_age_seconds: z.number().int().min(1).max(86400).optional(),
      })
      .optional(),
  }),
});

export const quorumConstraintsSchema = z.strictObject({
  min_approvals: z.number().int().min(1).max(10),
  allowed_approvers: stringSetSchema.optional(),
  require_distinct_owners: z.boolean().optional(),
  max_age_seconds: z.number().int().min(1).max(86400).optional(),
});

export type QuorumConstraints = z.infer<typeof quorumConstraintsSchema>;

export const quorumApprovalSchema = z.strictObject({
  approver_id: identifierSchema,
  approver_owner: identifierSchema.optional(),
  action_hash: z.string().regex(/^[a-f0-9]{64}$/),
  timestamp: z.iso.datetime({ offset: true }),
  decision: z.enum(["APPROVE", "REJECT"]).default("APPROVE"),
  grant_token: z.string().optional(),
  signature: z.string().optional(),
  notes: z.string().max(1024).optional(),
});

export type QuorumApproval = z.infer<typeof quorumApprovalSchema>;

/** Bound on the encoded delegation grant, checked before anything is decoded. */
export const MAX_GRANT_TOKEN_CHARS = 8_192;

/** A compact JWS signed by the principal. See `src/core/grants.ts`. */
export const delegationGrantTokenSchema = z
  .string()
  .trim()
  .min(1)
  .max(MAX_GRANT_TOKEN_CHARS);

export const contextSchema = z.strictObject({
  request_id: identifierSchema.nullable(),
  session_id: identifierSchema.optional(),
  timestamp: z.iso.datetime({ offset: true }).nullable(),
  source: z.enum(["a2a", "mcp", "rest", "internal", "unknown"]),
  proposal_id: z.string().regex(/^prp_[0-9a-zA-Z_-]+$/).optional(),
  approvals: z.array(quorumApprovalSchema).optional(),
});

export const verificationRequestSchema = z.strictObject({
  agent: agentSchema,
  principal: principalSchema.nullable(),
  action: actionSchema,
  authority: authoritySchema,
  context: contextSchema,
  /**
   * Optional principal-signed proof of the `authority` above. When present it
   * is verified, and it must match this request or the decision is BLOCK.
   * When absent, behaviour is unchanged: the authority is caller-asserted.
   */
  grant: delegationGrantTokenSchema.optional(),
});

export type VerificationRequest = z.infer<typeof verificationRequestSchema>;
