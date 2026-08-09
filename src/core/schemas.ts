import { z } from "zod";

const identifierSchema = z.string().trim().min(1).max(256);
const actionTypeSchema = z.string().trim().min(1).max(128);
const targetSchema = z.string().trim().min(1).max(2_048);

const jsonPrimitiveSchema = z.union([
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

const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    jsonPrimitiveSchema,
    z.array(jsonValueSchema).max(1_000),
    z.record(z.string().max(256), jsonValueSchema),
  ]),
);

const stringSetSchema = z
  .array(z.string().trim().min(1).max(2_048))
  .max(100)
  .refine((values) => new Set(values).size === values.length, {
    message: "Values must be unique",
  });

export const verificationRequestSchema = z.strictObject({
  agent: z.strictObject({
    id: identifierSchema,
    owner: identifierSchema.nullable(),
  }),
  principal: z
    .strictObject({
      id: identifierSchema,
    })
    .nullable(),
  action: z.strictObject({
    type: actionTypeSchema,
    target: targetSchema,
    parameters: z.record(z.string().max(256), jsonValueSchema),
  }),
  authority: z.strictObject({
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
  }),
  context: z.strictObject({
    request_id: identifierSchema.nullable(),
    timestamp: z.iso.datetime({ offset: true }).nullable(),
    source: z.enum(["a2a", "mcp", "rest", "internal", "unknown"]),
  }),
});

export type VerificationRequest = z.infer<typeof verificationRequestSchema>;
