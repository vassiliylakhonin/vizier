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
  };
  authority: {
    allowed_actions: string[];
    constraints: {
      max_amount?: number;
      currency?: string;
      allowed_targets?: string[];
      blocked_targets?: string[];
      allowed_sensitive_actions?: string[];
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
  rule_id: z.string().min(1).max(256),
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
}
import { z } from "zod";
