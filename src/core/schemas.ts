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
    z.array(jsonValueSchema).max(1_000),
    z.record(z.string().max(256), jsonValueSchema),
  ]),
);

export const stringSetSchema = z
  .array(z.string().trim().min(1).max(2_048))
  .max(100)
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
  parameters: z.record(z.string().max(256), jsonValueSchema),
});

export const authoritySchema = z.strictObject({
  allowed_actions: z
    .array(actionTypeSchema)
    .max(100)
    .refine((values) => new Set(values).size === values.length, {
      message: "Actions must be unique",
    }),
  constraints: z.strictObject({
    max_amount: z.number().finite().nonnegative().optional(),
    currency: z.string().regex(/^[A-Z]{3}$/).optional(),
    allowed_targets: stringSetSchema.optional(),
    blocked_targets: stringSetSchema.optional(),
    allowed_sensitive_actions: z.array(actionTypeSchema).max(100).optional(),
  }),
});

export const contextSchema = z.strictObject({
  request_id: identifierSchema.nullable(),
  timestamp: z.iso.datetime({ offset: true }).nullable(),
  source: z.enum(["a2a", "mcp", "rest", "internal", "unknown"]),
});

export const verificationRequestSchema = z.strictObject({
  agent: agentSchema,
  principal: principalSchema.nullable(),
  action: actionSchema,
  authority: authoritySchema,
  context: contextSchema,
});

export type VerificationRequest = z.infer<typeof verificationRequestSchema>;
