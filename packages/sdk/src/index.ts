import { z } from "zod";

export type Decision = "ALLOW" | "REVIEW" | "BLOCK";
export type Source = "a2a" | "mcp" | "rest" | "internal" | "unknown";

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface VerificationRequest {
  agent: { id: string; owner: string | null };
  principal: { id: string } | null;
  action: {
    type: string;
    target: string;
    parameters: Record<string, JsonValue>;
    is_reversible?: boolean;
  };
  authority: {
    allowed_actions: string[];
    constraints: {
      max_amount?: number;
      currency?: string;
      allowed_targets?: string[];
      blocked_targets?: string[];
      allowed_sensitive_actions?: string[];
      require_review_for_irreversible?: boolean;
    };
  };
  context: {
    request_id: string | null;
    timestamp: string | null;
    source: Source;
  };
}

export interface PolicyResult {
  rule_id: string;
  result: "PASS" | "REVIEW" | "FAIL";
  reason_code: string | null;
  details: Record<string, unknown>;
}

export interface VerificationResponse {
  decision: Decision;
  risk_score: number;
  reason_codes: string[];
  explanation: string;
  policy_results: PolicyResult[];
  receipt: {
    id: string;
    created_at: string;
    request_hash: string;
    decision: Decision;
    risk_score: number;
    policy_rule_ids: string[];
    reason_codes: string[];
  };
}

export type DraftAuthorKind = "MODEL" | "HUMAN" | "SYSTEM";

export interface ActionCovenantDraft {
  schema_version: "0.2";
  drafted_by: { kind: DraftAuthorKind; identifier: string };
  drafted_at: string;
  principal: { id: string };
  agent: { id: string; owner: string | null };
  intent: string;
  action: VerificationRequest["action"];
  authority: VerificationRequest["authority"];
  evidence_requirements: Array<{
    id: string;
    evidence_type: string;
    description: string;
    max_age_seconds: number;
  }>;
  invalidation_rules: Array<{
    id: string;
    signal_type: string;
    match: Record<string, string | number | boolean | null>;
    reason: string;
  }>;
  forbidden_outcomes: Array<{
    id: string;
    effect_type: string;
    target?: string;
    reason: string;
  }>;
  expires_at: string;
}

export interface CovenantAcceptance {
  accepted_by: { id: string };
  accepted_at: string;
  draft_hash: string;
}

export interface ActionCovenantActivationRequest {
  draft: ActionCovenantDraft;
  acceptance: CovenantAcceptance;
}

export interface ActionCovenant {
  id: string;
  version: 1;
  status: "ACTIVE";
  activated_at: string;
  draft: ActionCovenantDraft;
  acceptance: CovenantAcceptance;
  covenant_hash: string;
}

export interface EvidenceObservation {
  requirement_id: string;
  evidence_type: string;
  source: string;
  observed_at: string;
  content_hash: string;
}

export interface SignalObservation {
  signal_type: string;
  source: string;
  observed_at: string;
  attributes: Record<string, string | number | boolean | null>;
}

export interface ActionCovenantAuthorizationRequest {
  covenant: ActionCovenant;
  action: VerificationRequest["action"];
  evidence: EvidenceObservation[];
  signals: SignalObservation[];
  context: VerificationRequest["context"];
}

export interface AuthorizationReceiptPayload {
  type: "ACTION_AUTHORIZATION";
  version: 1;
  id: string;
  issuer: string;
  issued_at: string;
  expires_at: string;
  covenant_id: string;
  covenant_hash: string;
  request_hash: string;
  action_hash: string;
  evidence_hash: string;
  signals_hash: string;
  decision: Decision;
  risk_score: number;
  policy_rule_ids: string[];
  reason_codes: string[];
}

export interface SignedAuthorizationReceipt {
  payload: AuthorizationReceiptPayload;
  token: string;
}

export interface ActionCovenantAuthorizationResponse {
  decision: Decision;
  risk_score: number;
  reason_codes: string[];
  explanation: string;
  policy_results: PolicyResult[];
  authorization_receipt: SignedAuthorizationReceipt;
}

export interface ExecutionOutcome {
  status: "SUCCEEDED" | "FAILED" | "PARTIAL";
  started_at: string;
  finished_at: string;
  effects: Array<{
    type: string;
    target: string;
    parameters: Record<string, JsonValue>;
  }>;
  external_reference: string | null;
}

export interface OutcomeRecordingRequest {
  covenant: ActionCovenant;
  authorization_receipt: SignedAuthorizationReceipt;
  outcome: ExecutionOutcome;
}

export interface OutcomeReceiptPayload {
  type: "OUTCOME_RECEIPT";
  version: 1;
  id: string;
  issuer: string;
  issued_at: string;
  authorization_receipt_id: string;
  authorization_token_hash: string;
  covenant_id: string;
  covenant_hash: string;
  outcome_hash: string;
  compliance: "COMPLIANT" | "VIOLATION";
  violation_codes: string[];
}

export interface SignedOutcomeReceipt {
  payload: OutcomeReceiptPayload;
  token: string;
}

export interface VizierOptions {
  baseUrl: string;
  apiKey?: string;
  fetch?: typeof globalThis.fetch;
}

export interface VerifyOptions {
  signal?: AbortSignal;
}

export class VizierError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = "VizierError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const decisionSchema = z.enum(["ALLOW", "REVIEW", "BLOCK"]);
const reasonCodeSchema = z.string().min(1).max(128);
const policyResultSchema = z.strictObject({
  rule_id: z.string().min(1).max(512),
  result: z.enum(["PASS", "REVIEW", "FAIL"]),
  reason_code: reasonCodeSchema.nullable(),
  details: z.record(z.string(), z.unknown()),
});
const verificationResponseSchema = z.strictObject({
  decision: decisionSchema,
  risk_score: z.number().finite().min(0).max(1),
  reason_codes: z.array(reasonCodeSchema).max(100),
  explanation: z.string().min(1).max(2_048),
  policy_results: z.array(policyResultSchema).min(1).max(100),
  receipt: z.strictObject({
    id: z.string().min(1).max(256),
    created_at: z.iso.datetime({ offset: true }),
    request_hash: z.string().regex(/^[a-f0-9]{64}$/),
    decision: decisionSchema,
    risk_score: z.number().finite().min(0).max(1),
    policy_rule_ids: z.array(z.string().min(1).max(256)).min(1).max(100),
    reason_codes: z.array(reasonCodeSchema).max(100),
  }),
});

const identifierSchema = z.string().trim().min(1).max(256);
const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const timestampSchema = z.iso.datetime({ offset: true });
const jsonPrimitiveSchema = z.union([
  z.string(),
  z.number().finite(),
  z.boolean(),
  z.null(),
]);
const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    jsonPrimitiveSchema,
    z.array(jsonValueSchema),
    z.record(z.string(), jsonValueSchema),
  ]),
);
const actionSchema = z.strictObject({
  type: z.string().trim().min(1).max(128),
  target: z.string().trim().min(1).max(2_048),
  parameters: z.record(z.string(), jsonValueSchema),
  is_reversible: z.boolean().optional(),
});
const authoritySchema = z.strictObject({
  allowed_actions: z.array(z.string().trim().min(1).max(128)),
  constraints: z.strictObject({
    max_amount: z.number().finite().nonnegative().optional(),
    currency: z.string().regex(/^[A-Z]{3}$/).optional(),
    allowed_targets: z.array(z.string().trim().min(1).max(2_048)).optional(),
    blocked_targets: z.array(z.string().trim().min(1).max(2_048)).optional(),
    allowed_sensitive_actions: z.array(z.string().trim().min(1).max(128)).optional(),
    require_review_for_irreversible: z.boolean().optional(),
  }),
});
const actionCovenantDraftSchema = z.strictObject({
  schema_version: z.literal("0.2"),
  drafted_by: z.strictObject({
    kind: z.enum(["MODEL", "HUMAN", "SYSTEM"]),
    identifier: identifierSchema,
  }),
  drafted_at: timestampSchema,
  principal: z.strictObject({ id: identifierSchema }),
  agent: z.strictObject({ id: identifierSchema, owner: identifierSchema.nullable() }),
  intent: z.string().trim().min(1).max(4_096),
  action: actionSchema,
  authority: authoritySchema,
  evidence_requirements: z
    .array(
      z.strictObject({
        id: identifierSchema,
        evidence_type: identifierSchema,
        description: z.string().trim().min(1).max(1_024),
        max_age_seconds: z.number().int().min(1).max(31_536_000),
      }),
    )
    .max(32),
  invalidation_rules: z
    .array(
      z.strictObject({
        id: identifierSchema,
        signal_type: identifierSchema,
        match: z.record(z.string().trim().min(1).max(256), jsonPrimitiveSchema),
        reason: z.string().trim().min(1).max(1_024),
      }),
    )
    .max(32),
  forbidden_outcomes: z
    .array(
      z.strictObject({
        id: identifierSchema,
        effect_type: identifierSchema,
        target: z.string().trim().min(1).max(2_048).optional(),
        reason: z.string().trim().min(1).max(1_024),
      }),
    )
    .max(32),
  expires_at: timestampSchema,
});
const covenantAcceptanceSchema = z.strictObject({
  accepted_by: z.strictObject({ id: identifierSchema }),
  accepted_at: timestampSchema,
  draft_hash: hashSchema,
});
const actionCovenantSchema = z.strictObject({
  id: identifierSchema,
  version: z.literal(1),
  status: z.literal("ACTIVE"),
  activated_at: timestampSchema,
  draft: actionCovenantDraftSchema,
  acceptance: covenantAcceptanceSchema,
  covenant_hash: hashSchema,
});
const authorizationReceiptPayloadSchema = z.strictObject({
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
  decision: decisionSchema,
  risk_score: z.number().finite().min(0).max(1),
  policy_rule_ids: z.array(z.string().trim().min(1).max(512)).min(1).max(100),
  reason_codes: z.array(reasonCodeSchema).max(100),
});
const signedAuthorizationReceiptSchema = z.strictObject({
  payload: authorizationReceiptPayloadSchema,
  token: z.string().min(1).max(32_768),
});
const actionCovenantAuthorizationResponseSchema = z.strictObject({
  decision: decisionSchema,
  risk_score: z.number().finite().min(0).max(1),
  reason_codes: z.array(reasonCodeSchema).max(100),
  explanation: z.string().min(1).max(2_048),
  policy_results: z.array(policyResultSchema).min(1).max(100),
  authorization_receipt: signedAuthorizationReceiptSchema,
});
const outcomeReceiptPayloadSchema = z.strictObject({
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
const signedOutcomeReceiptSchema = z.strictObject({
  payload: outcomeReceiptPayloadSchema,
  token: z.string().min(1).max(32_768),
});
const jwksSchema = z.strictObject({
  keys: z.array(
    z.strictObject({
      alg: z.literal("ES256"),
      crv: z.literal("P-256"),
      kid: identifierSchema,
      kty: z.literal("EC"),
      use: z.literal("sig"),
      x: z.string().min(1),
      y: z.string().min(1),
    }),
  ),
});

function equalStrings(left: readonly string[], right: readonly string[]): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("Request is not canonicalizable JSON");
}

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export async function hashCanonicalJson(value: unknown): Promise<string> {
  return sha256(canonicalize(value));
}

export async function hashActionCovenantDraft(
  draft: ActionCovenantDraft,
): Promise<string> {
  return hashCanonicalJson(draft);
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 8_192) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8_192));
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error("Invalid base64url value.");
  }
  const standard = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(standard.padEnd(Math.ceil(standard.length / 4) * 4, "="));
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function verifyCompactJws(
  token: string,
  payload: unknown,
  expectedType: string,
  jwks: z.infer<typeof jwksSchema>,
): Promise<boolean> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return false;
    }
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    if (
      encodedHeader === undefined ||
      encodedPayload === undefined ||
      encodedSignature === undefined
    ) {
      return false;
    }
    const header = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(
        base64urlDecode(encodedHeader),
      ),
    ) as unknown;
    if (
      !isRecord(header) ||
      header.alg !== "ES256" ||
      header.typ !== expectedType ||
      typeof header.kid !== "string"
    ) {
      return false;
    }
    const key = jwks.keys.find((candidate) => candidate.kid === header.kid);
    if (key === undefined) {
      return false;
    }
    const expectedPayload = base64urlEncode(
      new TextEncoder().encode(canonicalize(payload)),
    );
    if (encodedPayload !== expectedPayload) {
      return false;
    }
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      key,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      cryptoKey,
      base64urlDecode(encodedSignature),
      new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`),
    );
  } catch {
    return false;
  }
}

async function parseVerificationResponse(
  value: unknown,
  request: VerificationRequest,
): Promise<VerificationResponse | null> {
  const parsed = verificationResponseSchema.safeParse(value);
  if (!parsed.success) {
    return null;
  }
  const response = parsed.data;
  const policyRuleIds = response.policy_results.map((item) => item.rule_id);
  const policyReasonCodes = response.policy_results.flatMap((item) =>
    item.reason_code === null ? [] : [item.reason_code],
  );
  if (
    response.receipt.decision !== response.decision ||
    response.receipt.risk_score !== response.risk_score ||
    !equalStrings(response.receipt.reason_codes, response.reason_codes) ||
    !equalStrings(response.reason_codes, policyReasonCodes) ||
    !equalStrings(response.receipt.policy_rule_ids, policyRuleIds)
  ) {
    return null;
  }
  const expectedHash = await sha256(canonicalize(request));
  return response.receipt.request_hash === expectedHash ? response : null;
}

export class Vizier {
  readonly #baseUrl: string;
  readonly #apiKey: string | undefined;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: VizierOptions) {
    if (!options.baseUrl.trim()) {
      throw new TypeError("baseUrl is required");
    }
    this.#baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.#apiKey = options.apiKey;
    this.#fetch = options.fetch ?? globalThis.fetch;
  }

  async #postJson(
    path: string,
    body: unknown,
    options: VerifyOptions,
  ): Promise<{ readonly body: unknown; readonly status: number }> {
    const response = await this.#fetch(`${this.#baseUrl}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(this.#apiKey === undefined
          ? {}
          : { Authorization: `Bearer ${this.#apiKey}` }),
      },
      body: JSON.stringify(body),
      signal: options.signal,
    });
    let responseBody: unknown;
    try {
      responseBody = await response.json();
    } catch {
      throw new VizierError(
        "Vizier returned a non-JSON response.",
        response.status,
        "INVALID_RESPONSE",
      );
    }
    if (!response.ok) {
      const error =
        isRecord(responseBody) && isRecord(responseBody.error)
          ? responseBody.error
          : {};
      throw new VizierError(
        typeof error.message === "string"
          ? error.message
          : "Vizier request failed.",
        response.status,
        typeof error.code === "string" ? error.code : "REQUEST_FAILED",
        error.details,
      );
    }
    return { body: responseBody, status: response.status };
  }

  async #fetchJwks(options: VerifyOptions): Promise<z.infer<typeof jwksSchema>> {
    const response = await this.#fetch(
      `${this.#baseUrl}/.well-known/jwks.json`,
      { signal: options.signal },
    );
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new VizierError(
        "Vizier returned a non-JSON JWKS response.",
        response.status,
        "INVALID_RESPONSE",
      );
    }
    const parsed = jwksSchema.safeParse(body);
    if (!response.ok || !parsed.success) {
      throw new VizierError(
        "Vizier returned an invalid JWKS contract.",
        response.status,
        "INVALID_RESPONSE",
      );
    }
    return parsed.data;
  }

  #issuer(): string {
    try {
      return new URL(this.#baseUrl).origin;
    } catch {
      throw new VizierError(
        "baseUrl must be an absolute URL for signed receipts.",
        0,
        "INVALID_CONFIGURATION",
      );
    }
  }

  async verify(
    request: VerificationRequest,
    options: VerifyOptions = {},
  ): Promise<VerificationResponse> {
    const normalizedRequest: VerificationRequest = {
      ...request,
      context: { ...request.context, source: "rest" },
    };
    const response = await this.#fetch(`${this.#baseUrl}/v1/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(this.#apiKey === undefined
          ? {}
          : { Authorization: `Bearer ${this.#apiKey}` }),
      },
      body: JSON.stringify(normalizedRequest),
      signal: options.signal,
    });

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new VizierError(
        "Vizier returned a non-JSON response.",
        response.status,
        "INVALID_RESPONSE",
      );
    }

    if (!response.ok) {
      const error = isRecord(body) && isRecord(body.error) ? body.error : {};
      throw new VizierError(
        typeof error.message === "string" ? error.message : "Vizier request failed.",
        response.status,
        typeof error.code === "string" ? error.code : "REQUEST_FAILED",
        error.details,
      );
    }
    const verifiedBody = await parseVerificationResponse(body, normalizedRequest);
    if (verifiedBody === null) {
      throw new VizierError(
        "Vizier returned an invalid response contract.",
        response.status,
        "INVALID_RESPONSE",
      );
    }
    return verifiedBody;
  }

  async activateCovenant(
    request: ActionCovenantActivationRequest,
    options: VerifyOptions = {},
  ): Promise<ActionCovenant> {
    const { body, status } = await this.#postJson(
      "/v1/covenants",
      request,
      options,
    );
    const parsed = actionCovenantSchema.safeParse(body);
    if (!parsed.success) {
      throw new VizierError(
        "Vizier returned an invalid Action Covenant contract.",
        status,
        "INVALID_RESPONSE",
      );
    }
    const covenant = parsed.data;
    const hashInput = {
      id: covenant.id,
      version: covenant.version,
      status: covenant.status,
      activated_at: covenant.activated_at,
      draft: covenant.draft,
      acceptance: covenant.acceptance,
    };
    const [expectedCovenantHash, requestDraftHash, responseDraftHash] =
      await Promise.all([
        hashCanonicalJson(hashInput),
        hashActionCovenantDraft(request.draft),
        hashActionCovenantDraft(covenant.draft),
      ]);
    if (
      covenant.covenant_hash !== expectedCovenantHash ||
      request.acceptance.draft_hash !== requestDraftHash ||
      covenant.acceptance.draft_hash !== responseDraftHash ||
      requestDraftHash !== responseDraftHash ||
      canonicalize(covenant.acceptance) !== canonicalize(request.acceptance)
    ) {
      throw new VizierError(
        "Vizier returned an Action Covenant not bound to the accepted draft.",
        status,
        "INVALID_RESPONSE",
      );
    }
    return covenant;
  }

  async authorizeCovenant(
    request: ActionCovenantAuthorizationRequest,
    options: VerifyOptions = {},
  ): Promise<ActionCovenantAuthorizationResponse> {
    const normalizedRequest: ActionCovenantAuthorizationRequest = {
      ...request,
      context: { ...request.context, source: "rest" },
    };
    const { body, status } = await this.#postJson(
      "/v1/authorizations",
      normalizedRequest,
      options,
    );
    const parsed = actionCovenantAuthorizationResponseSchema.safeParse(body);
    if (!parsed.success) {
      throw new VizierError(
        "Vizier returned an invalid authorization contract.",
        status,
        "INVALID_RESPONSE",
      );
    }
    const response = parsed.data;
    const receipt = response.authorization_receipt;
    const policyRuleIds = response.policy_results.map((item) => item.rule_id);
    const policyReasonCodes = response.policy_results.flatMap((item) =>
      item.reason_code === null ? [] : [item.reason_code],
    );
    const [requestHash, actionHash, evidenceHash, signalsHash] = await Promise.all([
      hashCanonicalJson(normalizedRequest),
      hashCanonicalJson(normalizedRequest.action),
      hashCanonicalJson(normalizedRequest.evidence),
      hashCanonicalJson(normalizedRequest.signals),
    ]);
    const payload = receipt.payload;
    const fieldsAreBound =
      payload.issuer === this.#issuer() &&
      payload.covenant_id === normalizedRequest.covenant.id &&
      payload.covenant_hash === normalizedRequest.covenant.covenant_hash &&
      payload.request_hash === requestHash &&
      payload.action_hash === actionHash &&
      payload.evidence_hash === evidenceHash &&
      payload.signals_hash === signalsHash &&
      payload.decision === response.decision &&
      payload.risk_score === response.risk_score &&
      equalStrings(payload.policy_rule_ids, policyRuleIds) &&
      equalStrings(payload.reason_codes, response.reason_codes) &&
      equalStrings(response.reason_codes, policyReasonCodes);
    const signatureIsValid = fieldsAreBound
      ? await verifyCompactJws(
          receipt.token,
          receipt.payload,
          "VIZIER-ACTION-AUTHORIZATION+JWS",
          await this.#fetchJwks(options),
        )
      : false;
    const usableAllow =
      response.decision !== "ALLOW" ||
      Date.parse(payload.expires_at) > Date.now();
    if (!fieldsAreBound || !signatureIsValid || !usableAllow) {
      throw new VizierError(
        "Vizier returned an authorization receipt that is invalid or not bound to the request.",
        status,
        "INVALID_RESPONSE",
      );
    }
    return response;
  }

  async recordOutcome(
    request: OutcomeRecordingRequest,
    options: VerifyOptions = {},
  ): Promise<SignedOutcomeReceipt> {
    const { body, status } = await this.#postJson(
      "/v1/outcomes",
      request,
      options,
    );
    const parsed = signedOutcomeReceiptSchema.safeParse(body);
    if (!parsed.success) {
      throw new VizierError(
        "Vizier returned an invalid outcome receipt contract.",
        status,
        "INVALID_RESPONSE",
      );
    }
    const receipt = parsed.data;
    const [authorizationTokenHash, outcomeHash] = await Promise.all([
      sha256(request.authorization_receipt.token),
      hashCanonicalJson(request.outcome),
    ]);
    const payload = receipt.payload;
    const fieldsAreBound =
      payload.issuer === this.#issuer() &&
      payload.authorization_receipt_id ===
        request.authorization_receipt.payload.id &&
      payload.authorization_token_hash === authorizationTokenHash &&
      payload.covenant_id === request.covenant.id &&
      payload.covenant_hash === request.covenant.covenant_hash &&
      payload.outcome_hash === outcomeHash;
    const signatureIsValid = fieldsAreBound
      ? await verifyCompactJws(
          receipt.token,
          receipt.payload,
          "VIZIER-OUTCOME-RECEIPT+JWS",
          await this.#fetchJwks(options),
        )
      : false;
    if (!fieldsAreBound || !signatureIsValid) {
      throw new VizierError(
        "Vizier returned an outcome receipt that is invalid or not bound to the execution.",
        status,
        "INVALID_RESPONSE",
      );
    }
    return receipt;
  }
}
