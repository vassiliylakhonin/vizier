import { z } from "zod";
import {
  actionSchema,
  addCustomSanctionsEntry,
  agentSchema,
  computeActionHash,
  consumeQuorumProposal,
  createQuorumProposal,
  evaluateDlp,
  evaluateEdgeCircuitBreaker,
  evaluateQuorum,
  evaluateSanctions,
  evaluateSanctions50Rule,
  getQuorumProposal,
  identifierSchema,
  quorumApprovalSchema,
  quorumConstraintsSchema,
  recordQuorumApproval,
  resetEdgeCircuitBreaker,
  scanDlpParameters,
  scanDlpText,
  verificationRequestSchema,
  verifyAction,
  type DlpEvaluationResult,
  type DlpFinding,
  type EdgeCircuitBreakerResult,
  type QuorumEvaluationResult,
  type SanctionsEvaluationResult,
  type Shareholder,
  type VerificationRequest,
} from "../core/index";
import { publicJwkFromPrivate, signCompactJws } from "../crypto/jws";
import {
  activateActionCovenant,
  ActionCovenantError,
  actionCovenantActivationRequestSchema,
  actionCovenantAuthorizationRequestSchema,
  authorizeActionCovenant,
  outcomeRecordingRequestSchema,
  recordActionOutcome,
} from "../covenants/index";
import {
  jsonResponse,
  readLimitedJson,
  type TransportOptions,
  TransportRequestError,
  principalKeysMisconfigured,
  resolvePrincipalKeys,
} from "./shared";
import { createAgentCard, handleA2aRequest } from "./a2a";
import {
  createAiCatalog,
  createMcpServerManifest,
  createVizierAgentsTxt,
  createVizierLlmsTxt,
} from "./catalog";
import { handleMcpRequest } from "./mcp";
import { authorizeEnforcement } from "./auth";
import { generateApiKey, listApiKeys, revokeApiKey } from "../auth/keys";
import { createJwks, maybeSignAgentCard } from "./jws";
import { SERVICE_VERSION } from "../version";
import { createOpenApiDocument } from "./openapi";
import { createPlaygroundHtml } from "./playground";
import { createConsoleHtml } from "../console/index";
import { handleChatCompletions, handleModels } from "../proxy/index";
import {
  getInsights,
  storeAuthorization,
  storeCovenant,
  storeOutcome,
  storeReceipt,
  recordAnonymousCall,
  type AnonymousSurface,
} from "../storage/audit";

interface ApiErrorBody {
  readonly error: {
    readonly code: string;
    readonly message: string;
    readonly details?: unknown;
  };
}

function errorResponse(error: TransportRequestError): Response {
  const body: ApiErrorBody = {
    error: {
      code: error.code,
      message: error.message,
      ...(error.details === undefined ? {} : { details: error.details }),
    },
  };
  return jsonResponse(body, error.status);
}

function validationDetails(error: {
  readonly issues: readonly {
    readonly code: string;
    readonly path: readonly PropertyKey[];
    readonly message: string;
  }[];
}): readonly Readonly<Record<string, unknown>>[] {
  return error.issues.map((issue) => ({
    code: issue.code,
    path: issue.path.map(String),
    message: issue.message,
  }));
}

function persistAuditMetadata(
  options: TransportOptions,
  event: string,
  identifiers: Readonly<Record<string, string>>,
  write: (db: NonNullable<TransportOptions["db"]>) => Promise<void>,
): void {
  const { db, ctx } = options;
  if (db === undefined || ctx === undefined) {
    return;
  }
  ctx.waitUntil(
    write(db).catch((error: unknown) => {
      console.error(
        JSON.stringify({
          event,
          ...identifiers,
          error: error instanceof Error ? error.name : "UnknownError",
        }),
      );
    }),
  );
}

async function requireAuthenticatedIntegration(
  request: Request,
  options: TransportOptions,
  resourceName: string,
): Promise<void> {
  const authorization = await authorizeEnforcement(request, options.apiKey, { db: options.db });
  if (authorization === "quota_exceeded") {
    throw new TransportRequestError(
      429,
      "QUOTA_EXCEEDED",
      `Monthly API quota exceeded for this API key.`,
    );
  }
  if (authorization === "denied") {
    throw new TransportRequestError(
      401,
      "AUTHENTICATION_REQUIRED",
      `A valid Bearer token or X-Vizier-Key is required for ${resourceName}.`,
    );
  }
  if (authorization === "evaluation") {
    throw new TransportRequestError(
      503,
      "ENFORCEMENT_UNAVAILABLE",
      `${resourceName} requires configured enforcement.`,
    );
  }
}

async function requireCovenantEnforcement(
  request: Request,
  options: TransportOptions,
): Promise<string> {
  await requireAuthenticatedIntegration(
    request,
    options,
    "Action Covenant resources",
  );
  if (
    options.receiptSigningKey === undefined ||
    options.receiptSigningKey.length === 0
  ) {
    throw new TransportRequestError(
      503,
      "RECEIPT_SIGNING_UNAVAILABLE",
      "Action Covenant resources require a receipt signing key.",
    );
  }
  try {
    publicJwkFromPrivate(options.receiptSigningKey);
  } catch {
    throw new TransportRequestError(
      503,
      "RECEIPT_SIGNING_INVALID",
      "The configured receipt signing key is invalid.",
    );
  }
  return options.receiptSigningKey;
}

interface PipelineExecutionParams {
  readonly request: Request;
  readonly options: TransportOptions;
  readonly isEvaluation: boolean;
  readonly trustedAuthority: boolean;
}

interface PipelineExecutionResult {
  readonly normalizedRequest: VerificationRequest;
  readonly result: Awaited<ReturnType<typeof verifyAction>>;
  readonly startedAt: number;
}

async function executeVerificationPipeline(
  params: PipelineExecutionParams,
): Promise<PipelineExecutionResult> {
  const startedAt = performance.now();
  const parsedJson = await readLimitedJson(params.request);
  const parsed = verificationRequestSchema.safeParse(parsedJson);
  if (!parsed.success) {
    throw new TransportRequestError(
      422,
      "VALIDATION_ERROR",
      "Verification request failed schema validation.",
      validationDetails(parsed.error),
    );
  }

  const normalizedRequest = {
    ...parsed.data,
    context: { ...parsed.data.context, source: "rest" as const },
  };

  let circuitBreakerResult: EdgeCircuitBreakerResult | undefined;
  // In evaluation mode, DO NOT pass circuitBreakerKv to prevent unauthenticated clients
  // from mutating, budgeting, or tripping production session state.
  if (!params.isEvaluation && params.options.circuitBreakerKv !== undefined) {
    circuitBreakerResult = await evaluateEdgeCircuitBreaker(
      params.options.circuitBreakerKv,
      normalizedRequest,
    );
  }

  let sanctionsResult: SanctionsEvaluationResult | undefined;
  if (normalizedRequest.authority.constraints.sanctions_screening !== false) {
    sanctionsResult = await evaluateSanctions(
      normalizedRequest,
      params.options.circuitBreakerKv,
    );
  }

  let dlpResult: DlpEvaluationResult | undefined;
  if (normalizedRequest.authority.constraints.dlp_screening !== false) {
    dlpResult = evaluateDlp(normalizedRequest);
  }

  let quorumResult: QuorumEvaluationResult | undefined;
  if (normalizedRequest.authority.constraints.quorum !== undefined) {
    quorumResult = await evaluateQuorum(
      normalizedRequest,
      params.options.circuitBreakerKv,
    );
  }

  const result = await verifyAction(normalizedRequest, {
    trustedAuthority: params.trustedAuthority,
    principalKeys: resolvePrincipalKeys(params.options),
    circuitBreaker: circuitBreakerResult,
    sanctions: sanctionsResult,
    dlp: dlpResult,
    quorum: quorumResult,
  });

  return { normalizedRequest, result, startedAt };
}

async function handleVerify(
  request: Request,
  options: TransportOptions,
): Promise<Response> {
  const authorization = await authorizeEnforcement(request, options.apiKey, { db: options.db });
  if (authorization === "quota_exceeded") {
    throw new TransportRequestError(
      429,
      "QUOTA_EXCEEDED",
      "Monthly API quota exceeded for this API key.",
    );
  }
  if (authorization === "denied") {
    throw new TransportRequestError(
      401,
      "AUTHENTICATION_REQUIRED",
      "A valid Bearer token or X-Vizier-Key is required for enforcement mode.",
    );
  }

  const { normalizedRequest, result, startedAt } = await executeVerificationPipeline({
    request,
    options,
    isEvaluation: false,
    trustedAuthority: authorization === "authenticated",
  });

  if (
    result.decision === "ALLOW" &&
    normalizedRequest.authority.constraints.quorum !== undefined &&
    normalizedRequest.context.proposal_id
  ) {
    const actionHash = await computeActionHash(normalizedRequest.action);
    const consumed = await consumeQuorumProposal(
      normalizedRequest.context.proposal_id,
      options.circuitBreakerKv,
      actionHash,
    );
    if (!consumed) {
      throw new TransportRequestError(
        403,
        "PROPOSAL_ALREADY_CONSUMED",
        "Quorum proposal has already been consumed, expired, or action hash does not match.",
      );
    }
  }

  const requestId =
    normalizedRequest.context.request_id ?? `req_${crypto.randomUUID()}`;
  console.log(
    JSON.stringify({
      event: "vizier.verification.completed",
      request_id: requestId,
      receipt_id: result.receipt.id,
      decision: result.decision,
      reason_codes: result.reason_codes,
      latency_ms: Number((performance.now() - startedAt).toFixed(2)),
    }),
  );
  persistAuditMetadata(
    options,
    "vizier.audit.receipt.failed",
    { receipt_id: result.receipt.id },
    (db) => storeReceipt(db, normalizedRequest, result.receipt),
  );
  return jsonResponse(result);
}

async function handleVerifyEvaluate(
  request: Request,
  options: TransportOptions,
): Promise<Response> {
  const { normalizedRequest, result, startedAt } = await executeVerificationPipeline({
    request,
    options,
    isEvaluation: true,
    trustedAuthority: false,
  });

  const requestId =
    normalizedRequest.context.request_id ?? `req_${crypto.randomUUID()}`;
  console.log(
    JSON.stringify({
      event: "vizier.verification.evaluated",
      request_id: requestId,
      receipt_id: result.receipt.id,
      decision: result.decision,
      reason_codes: result.reason_codes,
      latency_ms: Number((performance.now() - startedAt).toFixed(2)),
    }),
  );
  return jsonResponse(result);
}

const resetCircuitBreakerSchema = z.strictObject({
  session_id: identifierSchema,
});

async function handleCircuitBreakerReset(
  request: Request,
  options: TransportOptions,
): Promise<Response> {
  await requireAuthenticatedIntegration(request, options, "circuit breaker reset");
  if (options.circuitBreakerKv === undefined) {
    throw new TransportRequestError(
      503,
      "CIRCUIT_BREAKER_UNAVAILABLE",
      "Circuit breaker KV storage is not configured on this Worker.",
    );
  }
  const parsedJson = await readLimitedJson(request);
  const parsed = resetCircuitBreakerSchema.safeParse(parsedJson);
  if (!parsed.success) {
    throw new TransportRequestError(
      422,
      "VALIDATION_ERROR",
      "Reset request failed schema validation.",
      validationDetails(parsed.error),
    );
  }
  await resetEdgeCircuitBreaker(options.circuitBreakerKv, parsed.data.session_id);
  console.log(
    JSON.stringify({
      event: "vizier.circuit_breaker.reset",
      session_id: parsed.data.session_id,
    }),
  );
  return jsonResponse({
    status: "ok",
    session_id: parsed.data.session_id,
    message: `Circuit breaker reset for session '${parsed.data.session_id}'.`,
  });
}

const sanctionsScreenRequestSchema = z.strictObject({
  query: z.string().trim().min(1).max(2048),
  type: z.enum(["domain", "crypto_address", "entity_name", "iban"]).optional(),
});

async function handleSanctionsScreen(
  request: Request,
  options: TransportOptions,
): Promise<Response> {
  const parsedJson = await readLimitedJson(request);
  const parsed = sanctionsScreenRequestSchema.safeParse(parsedJson);
  if (!parsed.success) {
    throw new TransportRequestError(
      422,
      "VALIDATION_ERROR",
      "Sanctions screening request failed schema validation.",
      validationDetails(parsed.error),
    );
  }
  const query = parsed.data.query;
  const dummyRequest = {
    agent: { id: "screening", owner: null },
    principal: null,
    action: {
      type: "screen",
      target: query,
      parameters: { counterparty: query },
    },
    authority: {
      allowed_actions: ["screen"],
      constraints: {},
    },
    context: {
      request_id: null,
      timestamp: null,
      source: "rest" as const,
    },
  };
  const result = await evaluateSanctions(dummyRequest, options.circuitBreakerKv);
  return jsonResponse({
    query,
    clean: result.clean,
    ...(result.match === undefined ? {} : { match: result.match }),
    ...(result.rule50_result === undefined ? {} : { rule50_result: result.rule50_result }),
  });
}

const shareholderSchema: z.ZodType<Shareholder> = z.lazy(() =>
  z.strictObject({
    name: z.string().trim().min(1).max(512),
    percentage: z.number().min(0).max(100),
    lei: z.string().trim().max(32).optional(),
    country: z.string().trim().max(16).optional(),
    shareholders: z.array(shareholderSchema).optional(),
  })
);

const screenEntity50RuleSchema = z.strictObject({
  entity_name: z.string().trim().min(1).max(512),
  country: z.string().trim().max(16).optional(),
  jurisdiction: z.string().trim().max(16).optional(),
  lei: z.string().trim().max(32).optional(),
  registration_number: z.string().trim().max(64).optional(),
  shareholders: z.array(shareholderSchema).optional().default([]),
  threshold_percentage: z.number().min(0.1).max(100).optional(),
});

async function handleSanctionsScreenEntity(
  request: Request,
  options: TransportOptions,
): Promise<Response> {
  const parsedJson = await readLimitedJson(request);
  const parsed = screenEntity50RuleSchema.safeParse(parsedJson);
  if (!parsed.success) {
    throw new TransportRequestError(
      422,
      "VALIDATION_ERROR",
      "Entity sanctions 50% rule request failed schema validation.",
      validationDetails(parsed.error),
    );
  }
  const result = await evaluateSanctions50Rule(
    parsed.data,
    options.circuitBreakerKv,
  );
  let receiptToken: string | null = null;
  if (options.receiptSigningKey) {
    try {
      const receiptPayload = {
        iss: "vizier-action-firewall",
        sub: result.entity_name,
        iat: Math.floor(Date.now() / 1000),
        engine: "vizier_ofac_50_rule",
        clean: result.clean,
        violation: result.violation,
        aggregate_blocked_percentage: result.aggregate_blocked_percentage,
        threshold_percentage: result.threshold_percentage,
        reason_codes: result.reason_codes,
      };
      receiptToken = await signCompactJws(
        receiptPayload,
        options.receiptSigningKey,
        "application/vizier-receipt+jwt",
      );
    } catch (jwsErr) {
      console.error("Failed to sign clearance receipt in screen-entity:", jwsErr);
    }
  }
  return jsonResponse({
    entity_name: result.entity_name,
    clean: result.clean,
    violation: result.violation,
    aggregate_blocked_percentage: result.aggregate_blocked_percentage,
    threshold_percentage: result.threshold_percentage,
    blocked_shareholders: result.blocked_shareholders,
    reason_codes: result.reason_codes,
    explanation: result.explanation,
    ...(receiptToken ? { receipt: receiptToken } : {}),
    ...(result.direct_match === undefined ? {} : { direct_match: result.direct_match }),
  });
}

const addSanctionsEntrySchema = z.strictObject({
  raw_value: z.string().trim().min(1).max(2048),
  entity_name: z.string().trim().min(1).max(512),
  list: z.string().trim().min(1).max(128).optional(),
  type: z.enum(["domain", "crypto_address", "entity_name", "iban"]).optional(),
  details: z.record(z.string(), z.unknown()).optional(),
});

async function handleSanctionsEntry(
  request: Request,
  options: TransportOptions,
): Promise<Response> {
  await requireAuthenticatedIntegration(request, options, "sanctions entry management");
  if (options.circuitBreakerKv === undefined) {
    throw new TransportRequestError(
      503,
      "STORAGE_UNAVAILABLE",
      "KV storage is not configured on this Worker.",
    );
  }
  const parsedJson = await readLimitedJson(request);
  const parsed = addSanctionsEntrySchema.safeParse(parsedJson);
  if (!parsed.success) {
    throw new TransportRequestError(
      422,
      "VALIDATION_ERROR",
      "Add sanctions entry request failed schema validation.",
      validationDetails(parsed.error),
    );
  }
  const added = await addCustomSanctionsEntry(options.circuitBreakerKv, parsed.data);
  console.log(
    JSON.stringify({
      event: "vizier.sanctions.entry_added",
      entity_name: parsed.data.entity_name,
      normalized: added.normalized,
      key: added.key,
    }),
  );
  return jsonResponse({
    status: "ok",
    key: added.key,
    normalized: added.normalized,
    entity_name: parsed.data.entity_name,
  });
}

const dlpScanRequestSchema = z
  .strictObject({
    text: z.string().max(65536).optional(),
    parameters: z.record(z.string(), z.unknown()).optional(),
    allowed_categories: z.array(z.string()).optional(),
  })
  .refine((data) => data.text !== undefined || data.parameters !== undefined, {
    message: "Either text or parameters must be provided.",
  });

async function handleDlpScan(
  request: Request,
  options?: TransportOptions,
): Promise<Response> {
  const parsedJson = await readLimitedJson(request);
  const parsed = dlpScanRequestSchema.safeParse(parsedJson);
  if (!parsed.success) {
    throw new TransportRequestError(
      422,
      "VALIDATION_ERROR",
      "DLP scan request failed schema validation.",
      validationDetails(parsed.error),
    );
  }
  const allowedCategories = new Set(
    (parsed.data.allowed_categories ?? []).map((c) => c.toLowerCase()),
  );
  const findings: DlpFinding[] = [];
  if (parsed.data.text !== undefined) {
    findings.push(...scanDlpText(parsed.data.text, "text", allowedCategories));
  }
  if (parsed.data.parameters !== undefined) {
    findings.push(...scanDlpParameters(parsed.data.parameters, allowedCategories, "parameters"));
  }
  const clean = findings.length === 0;
  let receiptToken: string | null = null;
  if (options?.receiptSigningKey) {
    try {
      const receiptPayload = {
        iss: "vizier-action-firewall",
        sub: "dlp-scan",
        iat: Math.floor(Date.now() / 1000),
        engine: "vizier_dlp_firewall",
        clean,
        findings_count: findings.length,
        categories: Array.from(new Set(findings.map((f) => f.category))),
      };
      receiptToken = await signCompactJws(
        receiptPayload,
        options.receiptSigningKey,
        "application/vizier-receipt+jwt",
      );
    } catch (jwsErr) {
      console.error("Failed to sign clearance receipt in dlp-scan:", jwsErr);
    }
  }
  return jsonResponse({
    clean,
    findings,
    total_leaks_prevented: findings.length,
    ...(receiptToken ? { receipt: receiptToken } : {}),
  });
}

const quorumProposeRequestSchema = z.strictObject({
  proposer: agentSchema,
  action: actionSchema,
  constraints: quorumConstraintsSchema,
  ttl_seconds: z.number().int().min(60).max(86400).optional(),
});

const quorumApproveRequestSchema = z.strictObject({
  proposal_id: z.string().regex(/^prp_[0-9a-zA-Z_-]+$/),
  approval: quorumApprovalSchema,
});

async function handleQuorumPropose(
  request: Request,
  options: TransportOptions,
): Promise<Response> {
  await requireAuthenticatedIntegration(request, options, "quorum proposal creation");
  const parsedJson = await readLimitedJson(request);
  const parsed = quorumProposeRequestSchema.safeParse(parsedJson);
  if (!parsed.success) {
    throw new TransportRequestError(
      422,
      "VALIDATION_ERROR",
      "Quorum propose request failed schema validation.",
      validationDetails(parsed.error),
    );
  }
  const proposal = await createQuorumProposal({
    kv: options.circuitBreakerKv,
    proposer: parsed.data.proposer,
    action: parsed.data.action,
    constraints: parsed.data.constraints,
    ttlSeconds: parsed.data.ttl_seconds,
  });
  return jsonResponse(proposal, 201);
}

async function handleQuorumApprove(
  request: Request,
  options: TransportOptions,
): Promise<Response> {
  await requireAuthenticatedIntegration(request, options, "quorum approval");
  const parsedJson = await readLimitedJson(request);
  const parsed = quorumApproveRequestSchema.safeParse(parsedJson);
  if (!parsed.success) {
    throw new TransportRequestError(
      422,
      "VALIDATION_ERROR",
      "Quorum approve request failed schema validation.",
      validationDetails(parsed.error),
    );
  }
  try {
    const updated = await recordQuorumApproval({
      kv: options.circuitBreakerKv,
      proposalId: parsed.data.proposal_id,
      approval: parsed.data.approval,
    });
    return jsonResponse(updated);
  } catch (err) {
    throw new TransportRequestError(
      400,
      "QUORUM_APPROVAL_FAILED",
      err instanceof Error ? err.message : String(err),
    );
  }
}

async function handleQuorumGet(
  proposalId: string,
  request: Request,
  options: TransportOptions,
): Promise<Response> {
  await requireAuthenticatedIntegration(request, options, "quorum proposal lookup");
  const proposal = await getQuorumProposal(proposalId, options.circuitBreakerKv);
  if (!proposal) {
    throw new TransportRequestError(
      404,
      "PROPOSAL_NOT_FOUND",
      `Quorum proposal '${proposalId}' was not found or has expired.`,
    );
  }
  return jsonResponse(proposal);
}

async function handleCovenantActivation(
  request: Request,
  options: TransportOptions,
): Promise<Response> {
  await requireCovenantEnforcement(request, options);
  const parsed = actionCovenantActivationRequestSchema.safeParse(
    await readLimitedJson(request),
  );
  if (!parsed.success) {
    throw new TransportRequestError(
      422,
      "VALIDATION_ERROR",
      "Action Covenant activation failed schema validation.",
      validationDetails(parsed.error),
    );
  }
  const covenant = await activateActionCovenant(parsed.data);
  console.log(
    JSON.stringify({
      event: "vizier.covenant.activated",
      covenant_id: covenant.id,
      principal_id: covenant.draft.principal.id,
      expires_at: covenant.draft.expires_at,
    }),
  );
  persistAuditMetadata(
    options,
    "vizier.audit.covenant.failed",
    { covenant_id: covenant.id },
    (db) => storeCovenant(db, covenant),
  );
  return jsonResponse(covenant, 201);
}

async function handleCovenantAuthorization(
  request: Request,
  options: TransportOptions,
  issuer: string,
): Promise<Response> {
  const signingKey = await requireCovenantEnforcement(request, options);
  const parsed = actionCovenantAuthorizationRequestSchema.safeParse(
    await readLimitedJson(request),
  );
  if (!parsed.success) {
    throw new TransportRequestError(
      422,
      "VALIDATION_ERROR",
      "Action Covenant authorization failed schema validation.",
      validationDetails(parsed.error),
    );
  }
  const normalizedRequest = {
    ...parsed.data,
    context: { ...parsed.data.context, source: "rest" as const },
  };
  const result = await authorizeActionCovenant(normalizedRequest, {
    signingKey,
    issuer,
    trustedAuthority: true,
  });
  console.log(
    JSON.stringify({
      event: "vizier.covenant.authorization.completed",
      covenant_id: normalizedRequest.covenant.id,
      receipt_id: result.authorization_receipt.payload.id,
      decision: result.decision,
      reason_codes: result.reason_codes,
    }),
  );
  persistAuditMetadata(
    options,
    "vizier.audit.authorization.failed",
    { receipt_id: result.authorization_receipt.payload.id },
    (db) => storeAuthorization(db, result.authorization_receipt),
  );
  return jsonResponse(result);
}

async function handleOutcomeRecording(
  request: Request,
  options: TransportOptions,
  issuer: string,
): Promise<Response> {
  const signingKey = await requireCovenantEnforcement(request, options);
  const parsed = outcomeRecordingRequestSchema.safeParse(
    await readLimitedJson(request),
  );
  if (!parsed.success) {
    throw new TransportRequestError(
      422,
      "VALIDATION_ERROR",
      "Outcome recording failed schema validation.",
      validationDetails(parsed.error),
    );
  }
  const result = await recordActionOutcome(parsed.data, {
    signingKey,
    issuer,
  });
  console.log(
    JSON.stringify({
      event: "vizier.covenant.outcome.recorded",
      covenant_id: parsed.data.covenant.id,
      receipt_id: result.payload.id,
      authorization_receipt_id: result.payload.authorization_receipt_id,
      compliance: result.payload.compliance,
    }),
  );
  persistAuditMetadata(
    options,
    "vizier.audit.outcome.failed",
    { receipt_id: result.payload.id },
    (db) => storeOutcome(db, result, parsed.data.outcome),
  );
  return jsonResponse(result, 201);
}

async function handleInsights(
  request: Request,
  options: TransportOptions,
): Promise<Response> {
  await requireAuthenticatedIntegration(request, options, "Audit insights");
  if (options.db === undefined) {
    throw new TransportRequestError(
      503,
      "INSIGHTS_UNAVAILABLE",
      "Audit insights require a configured database.",
    );
  }
  return jsonResponse(await getInsights(options.db));
}

const createApiKeyRequestSchema = z.strictObject({
  org_id: z.string().trim().min(1).max(128),
  name: z.string().trim().min(1).max(128),
  tier: z.enum(["developer", "team", "enterprise"]).optional(),
  monthly_quota: z.number().int().min(1).max(100_000_000).optional(),
});

async function requireMasterKey(
  request: Request,
  options: TransportOptions,
  action: string,
): Promise<void> {
  const token =
    request.headers.get("X-Vizier-Key") ||
    (request.headers.get("Authorization")?.replace(/^Bearer\s+/i, ""));
  if (!token || !options.apiKey || token.trim() !== options.apiKey.trim()) {
    throw new TransportRequestError(
      401,
      "UNAUTHORIZED",
      `Master API key required to ${action}.`,
    );
  }
  if (!options.db) {
    throw new TransportRequestError(
      503,
      "DATABASE_UNAVAILABLE",
      `Database is required to ${action}.`,
    );
  }
}

async function handleAdminCreateKey(
  request: Request,
  options: TransportOptions,
): Promise<Response> {
  await requireMasterKey(request, options, "create tenant API keys");
  const parsedJson = await readLimitedJson(request);
  const parsed = createApiKeyRequestSchema.safeParse(parsedJson);
  if (!parsed.success) {
    throw new TransportRequestError(
      422,
      "VALIDATION_ERROR",
      "API key creation failed schema validation.",
      validationDetails(parsed.error),
    );
  }
  const generated = await generateApiKey(options.db!, parsed.data);
  return jsonResponse(generated, 201);
}

async function handleAdminListKeys(
  request: Request,
  options: TransportOptions,
  url: URL,
): Promise<Response> {
  await requireMasterKey(request, options, "list tenant API keys");
  const orgId = url.searchParams.get("org_id") || "default";
  const keys = await listApiKeys(options.db!, orgId);
  return jsonResponse({ org_id: orgId, keys });
}

async function handleAdminRevokeKey(
  request: Request,
  options: TransportOptions,
  keyId: string,
  url: URL,
): Promise<Response> {
  await requireMasterKey(request, options, "revoke tenant API keys");
  const orgId = url.searchParams.get("org_id") ?? undefined;
  const revoked = await revokeApiKey(options.db!, keyId, orgId);
  if (!revoked) {
    throw new TransportRequestError(
      404,
      "KEY_NOT_FOUND",
      `API key '${keyId}' not found or already revoked.`,
    );
  }
  return jsonResponse({ success: true, revoked_id: keyId });
}

function rootDocument(): Response {
  return jsonResponse({
    name: "Vizier",
    version: SERVICE_VERSION,
    tagline: "Every agent. Every action. Verified.",
    description: "Deterministic authorization checks for actions proposed by AI agents.",
    limitations: [
      "Not a factuality verifier.",
      "No live source retrieval.",
      "REVIEW requires a human decision before the external action.",
    ],
    docs: "/docs",
    console: "/console",
    playground: "/playground",
    openapi: "/openapi.json",
    ai_catalog: "/.well-known/ai-catalog.json",
    health: "/health",
    verify: "/v1/verify",
    covenants: "/v1/covenants",
    authorizations: "/v1/authorizations",
    outcomes: "/v1/outcomes",
    insights: "/v1/insights",
    a2a: "/.well-known/agent-card.json",
    mcp: "/mcp",
    mcp_manifest: "/.well-known/mcp.json",
  });
}

function docsDocument(options: TransportOptions): Response {
  return jsonResponse({
    api_version: `v${SERVICE_VERSION}`,
    endpoints: {
      verify: "POST /v1/verify",
      activate_covenant: "POST /v1/covenants",
      authorize_covenant_action: "POST /v1/authorizations",
      record_outcome: "POST /v1/outcomes",
      audit_insights: "GET /v1/insights",
    },
    content_type: "application/json",
    request_schema: {
      agent: { id: "string", owner: "string | null" },
      principal: "{ id: string } | null",
      action: {
        type: "string",
        target: "string",
        parameters: "JSON object",
        is_reversible: "boolean (optional; supplied assertion)",
      },
      authority: {
        allowed_actions: ["string"],
        constraints: {
          max_amount: "number (optional)",
          currency: "ISO 4217 code (optional)",
          allowed_targets: ["string (optional)"],
          blocked_targets: ["string (optional)"],
          allowed_sensitive_actions: ["string (optional)"],
          require_review_for_irreversible: "boolean (optional)",
        },
      },
      context: {
        request_id: "string | null",
        timestamp: "ISO-8601 | null",
        source: "a2a | mcp | rest | internal | unknown",
      },
      grant:
        "compact JWS signed by the principal, binding this exact authority to this agent (optional)",
    },
    decisions: ["ALLOW", "REVIEW", "BLOCK"],
    enforcement: {
      evaluation_mode: "No VIZIER_API_KEY: REVIEW or BLOCK only",
      authenticated_mode:
        "VIZIER_API_KEY configured: Bearer credential required for verification",
      covenant_mode:
        "VIZIER_API_KEY and RECEIPT_SIGNING_KEY configured: authenticated lifecycle with ES256 receipts",
      insights_mode:
        "VIZIER_API_KEY and D1 configured: authenticated metadata-only operational counts",
      delegation_mode:
        "VIZIER_PRINCIPAL_KEYS configured: a principal-signed grant is verified against a registered key, and the receipt records it",
    },
    delegation: {
      grant_field: "grant",
      grant_media_type: "compact JWS, typ vizier-delegation+jws, alg ES256",
      registered_principals: resolvePrincipalKeys(options).size,
      principal_keys_configured:
        options.principalKeySource !== undefined &&
        options.principalKeySource.trim().length > 0,
      principal_keys_valid: !principalKeysMisconfigured(options),
      authority_provenance: ["principal_signed", "trusted_integration", "unverified"],
      note: "Without a grant the authority is whatever the caller asserts. A grant that does not verify is BLOCK, never a downgrade to the caller-asserted path.",
    },
    machine_contracts: {
      openapi_3_1: "/openapi.json",
      openapi_well_known_alias: "/.well-known/openapi.json",
      ai_catalog: "/.well-known/ai-catalog.json",
      agent_card: "/.well-known/agent-card.json",
      mcp_server_manifest: "/.well-known/mcp.json",
      receipt_keys: "/.well-known/jwks.json",
    },
    examples: "/examples",
  });
}

function examplesDocument(): Response {
  return jsonResponse({
    allow: {
      description: "Purchase 8,200 USD under a 10,000 USD limit.",
      file: "examples/allow.json",
      expected_decision: "ALLOW",
    },
    block: {
      description: "Purchase 18,000 USD under a 10,000 USD limit.",
      file: "examples/block.json",
      expected_decision: "BLOCK",
      expected_reason: "AUTHORITY_LIMIT_EXCEEDED",
    },
    review: {
      description: "External message without explicit sensitive-action authority.",
      file: "examples/review.json",
      expected_decision: "REVIEW",
      expected_reason: "SENSITIVE_ACTION_REVIEW",
    },
  });
}

// Two endpoints answer without a credential: evaluation-only A2A since v0.2,
// and evaluation-only MCP since the registry listing made /mcp discoverable by
// design. Both run the full deterministic kernel on every call and neither
// writes to the audit store, so the exposure is CPU rather than storage, and
// nothing in this Worker bounded it before 2026-09-02.
//
// The check runs the credential comparison itself rather than looking for an
// Authorization header, so a caller cannot leave the budget by attaching a
// wrong token. Authenticated integrations are bounded by credential issuance
// instead and are never counted here.
//
// The same pass records the call. Neither surface writes a receipt, so before
// this the only trace of anonymous traffic was a Worker log line and nothing
// could answer how much of it there was. The counter is bumped in place: one
// bounded write, no row per call, and nothing about the caller.
async function gateAnonymousCall(
  request: Request,
  options: TransportOptions,
  surface: AnonymousSurface,
): Promise<"authenticated" | "served" | "throttled"> {
  const authorization = await authorizeEnforcement(request, options.apiKey, {
    allowMissingCredentialForEvaluation: true,
  });
  if (authorization === "authenticated") {
    return "authenticated";
  }

  const limiter = options.anonymousRateLimiter;
  const throttled =
    limiter !== undefined &&
    !(
      await limiter.limit({
        key: request.headers.get("CF-Connecting-IP") ?? "unattributed",
      })
    ).success;
  const outcome = throttled ? "throttled" : "served";

  persistAuditMetadata(
    options,
    "vizier.audit.anonymous_call.failed",
    { surface, outcome },
    (db) => recordAnonymousCall(db, surface, outcome, new Date()),
  );
  return outcome;
}

// Both endpoints behind this gate speak JSON-RPC 2.0, and the body has not been
// read yet, so the error carries a null id.
function rateLimitedResponse(): Response {
  return jsonResponse(
    {
      jsonrpc: "2.0",
      id: null,
      error: {
        code: -32029,
        message:
          "Anonymous request rate limit exceeded. Retry in 60 seconds, or use an integration credential.",
      },
    },
    429,
    { "Retry-After": "60" },
  );
}

export async function handleHttpRequest(
  request: Request,
  options: TransportOptions = {},
): Promise<Response> {
  const url = new URL(request.url);
  try {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Vizier-Key, X-Upstream-Key, X-Upstream-Url, X-Session-Id, X-Quorum-Proposal-Id, X-Quorum-Actions",
        },
      });
    }
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/playground")) {
      const accept = request.headers.get("accept") ?? "";
      if (url.pathname === "/playground" || accept.includes("text/html")) {
        return new Response(createPlaygroundHtml(url.origin), {
          status: 200,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }
      return rootDocument();
    }
    if (request.method === "GET" && (url.pathname === "/console" || url.pathname === "/dashboard")) {
      return new Response(createConsoleHtml(url.origin), {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    if (request.method === "GET" && url.pathname === "/health") {
      return jsonResponse({ status: "ok" });
    }
    if (request.method === "GET" && url.pathname === "/docs") {
      return docsDocument(options);
    }
    if (request.method === "GET" && url.pathname === "/examples") {
      return examplesDocument();
    }
    if (
      request.method === "GET" &&
      (url.pathname === "/openapi.json" ||
        url.pathname === "/.well-known/openapi.json")
    ) {
      return jsonResponse(createOpenApiDocument(url.origin), 200, {
        "Cache-Control": "public, max-age=300",
      });
    }
    if (
      request.method === "GET" &&
      (url.pathname === "/.well-known/ai-catalog.json" ||
        url.pathname === "/.well-known/ard.json")
    ) {
      return jsonResponse(createAiCatalog(url.origin), 200, {
        "Cache-Control": "public, max-age=300",
      });
    }
    if (
      request.method === "GET" &&
      (url.pathname === "/llms.txt" || url.pathname === "/.well-known/llms.txt")
    ) {
      return new Response(createVizierLlmsTxt(url.origin), {
        status: 200,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "public, max-age=300",
        },
      });
    }
    if (
      request.method === "GET" &&
      (url.pathname === "/agents.txt" || url.pathname === "/.well-known/agents.txt")
    ) {
      return new Response(createVizierAgentsTxt(url.origin), {
        status: 200,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "public, max-age=300",
        },
      });
    }
    if (
      request.method === "GET" &&
      url.pathname === "/.well-known/mcp.json"
    ) {
      return jsonResponse(createMcpServerManifest(url.origin), 200, {
        "Cache-Control": "public, max-age=300",
      });
    }
    if (
      request.method === "GET" &&
      url.pathname === "/.well-known/agent-card.json"
    ) {
      const card = await maybeSignAgentCard(
        createAgentCard(url.origin),
        options.agentCardSigningKey,
      );
      return jsonResponse(card, 200, {
        "Cache-Control": "public, max-age=300",
      });
    }
    if (
      request.method === "GET" &&
      url.pathname === "/.well-known/jwks.json"
    ) {
      return jsonResponse(
        createJwks(
          options.agentCardSigningKey,
          options.receiptSigningKey,
        ),
        200,
        {
        "Cache-Control": "public, max-age=3600",
        },
      );
    }
    // The agent card names /a2a, but a caller who copies the base URL or
    // assumes the common A2A path used to get a bare 404. Measured 2026-08-18:
    // every sibling Worker of this account answers SendMessage on "/", so the
    // 404 read as "this agent is down" rather than "wrong path".
    if (
      request.method === "POST" &&
      (url.pathname === "/a2a" ||
        url.pathname === "/" ||
        url.pathname === "/message/send")
    ) {
      if ((await gateAnonymousCall(request, options, "a2a")) === "throttled") {
        return rateLimitedResponse();
      }
      return await handleA2aRequest(request, options);
    }
    if (request.method === "POST" && url.pathname === "/mcp") {
      if ((await gateAnonymousCall(request, options, "mcp")) === "throttled") {
        return rateLimitedResponse();
      }
      return await handleMcpRequest(request, options);
    }
    if (url.pathname === "/mcp") {
      return jsonResponse(
        {
          error: {
            code: "METHOD_NOT_ALLOWED",
            message: "Use POST for this endpoint.",
          },
        },
        405,
        { Allow: "POST" },
      );
    }
    if (
      request.method === "POST" &&
      (url.pathname === "/v1/verify/evaluate" || url.pathname === "/playground/evaluate")
    ) {
      const limiter = options.anonymousRateLimiter;
      if (
        limiter !== undefined &&
        !(
          await limiter.limit({
            key: request.headers.get("CF-Connecting-IP") ?? "unattributed",
          })
        ).success
      ) {
        return jsonResponse(
          {
            error: {
              code: "RATE_LIMITED",
              message: "Evaluation rate limit exceeded. Please retry in 60 seconds or provide an API key.",
            },
          },
          429,
        );
      }
      return await handleVerifyEvaluate(request, options);
    }
    if (request.method === "POST" && url.pathname === "/v1/verify") {
      return await handleVerify(request, options);
    }
    if (request.method === "POST" && url.pathname === "/v1/circuit-breaker/reset") {
      return await handleCircuitBreakerReset(request, options);
    }
    if (request.method === "POST" && url.pathname === "/v1/sanctions/screen") {
      return await handleSanctionsScreen(request, options);
    }
    if (request.method === "POST" && url.pathname === "/v1/sanctions/screen-entity") {
      return await handleSanctionsScreenEntity(request, options);
    }
    if (request.method === "POST" && url.pathname === "/v1/sanctions/entries") {
      return await handleSanctionsEntry(request, options);
    }
    if (request.method === "POST" && url.pathname === "/v1/dlp/scan") {
      return await handleDlpScan(request, options);
    }
    if (request.method === "POST" && url.pathname === "/v1/quorum/propose") {
      return await handleQuorumPropose(request, options);
    }
    if (request.method === "POST" && url.pathname === "/v1/quorum/approve") {
      return await handleQuorumApprove(request, options);
    }
    if (request.method === "GET" && url.pathname.startsWith("/v1/quorum/proposals/")) {
      const proposalId = url.pathname.slice("/v1/quorum/proposals/".length);
      return await handleQuorumGet(proposalId, request, options);
    }
    if (request.method === "POST" && url.pathname === "/v1/covenants") {
      return await handleCovenantActivation(request, options);
    }
    if (request.method === "POST" && url.pathname === "/v1/authorizations") {
      return await handleCovenantAuthorization(request, options, url.origin);
    }
    if (request.method === "POST" && url.pathname === "/v1/outcomes") {
      return await handleOutcomeRecording(request, options, url.origin);
    }
    if (request.method === "GET" && url.pathname === "/v1/insights") {
      return await handleInsights(request, options);
    }
    if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
      return await handleChatCompletions(request, options);
    }
    if (request.method === "GET" && url.pathname === "/v1/models") {
      return await handleModels();
    }
    if (request.method === "POST" && url.pathname === "/v1/admin/keys") {
      return await handleAdminCreateKey(request, options);
    }
    if (request.method === "GET" && url.pathname === "/v1/admin/keys") {
      return await handleAdminListKeys(request, options, url);
    }
    if (request.method === "DELETE" && url.pathname.startsWith("/v1/admin/keys/")) {
      const keyId = url.pathname.slice("/v1/admin/keys/".length);
      return await handleAdminRevokeKey(request, options, keyId, url);
    }
    if (url.pathname === "/v1/chat/completions") {
      return jsonResponse(
        {
          error: {
            code: "METHOD_NOT_ALLOWED",
            message: "Use POST for this endpoint.",
          },
        },
        405,
        { Allow: "POST" },
      );
    }
    if (url.pathname === "/v1/models") {
      return jsonResponse(
        {
          error: {
            code: "METHOD_NOT_ALLOWED",
            message: "Use GET for this endpoint.",
          },
        },
        405,
        { Allow: "GET" },
      );
    }
    if (url.pathname === "/v1/verify") {
      return jsonResponse(
        {
          error: {
            code: "METHOD_NOT_ALLOWED",
            message: "Use POST for this endpoint.",
          },
        },
        405,
        { Allow: "POST" },
      );
    }
    if (
      url.pathname === "/v1/circuit-breaker/reset" ||
      url.pathname === "/v1/sanctions/screen" ||
      url.pathname === "/v1/sanctions/screen-entity" ||
      url.pathname === "/v1/sanctions/entries" ||
      url.pathname === "/v1/dlp/scan" ||
      url.pathname === "/v1/quorum/propose" ||
      url.pathname === "/v1/quorum/approve" ||
      url.pathname === "/v1/covenants" ||
      url.pathname === "/v1/authorizations" ||
      url.pathname === "/v1/outcomes"
    ) {
      return jsonResponse(
        {
          error: {
            code: "METHOD_NOT_ALLOWED",
            message: "Use POST for this endpoint.",
          },
        },
        405,
        { Allow: "POST" },
      );
    }
    if (url.pathname.startsWith("/v1/quorum/proposals/")) {
      return jsonResponse(
        {
          error: {
            code: "METHOD_NOT_ALLOWED",
            message: "Use GET for this endpoint.",
          },
        },
        405,
        { Allow: "GET" },
      );
    }
    if (url.pathname === "/v1/insights") {
      return jsonResponse(
        {
          error: {
            code: "METHOD_NOT_ALLOWED",
            message: "Use GET for this endpoint.",
          },
        },
        405,
        { Allow: "GET" },
      );
    }
    return jsonResponse(
      {
        error: {
          code: "NOT_FOUND",
          message: "Route not found.",
          data: {
            routes: {
              "GET /": "service index",
              "GET /docs": "field reference for a verification request",
              "GET /openapi.json": "OpenAPI 3.1 contract for all REST resources",
              "GET /.well-known/openapi.json": "well-known alias for the OpenAPI contract",
              "GET /.well-known/ai-catalog.json": "machine discovery catalog",
              "GET /examples": "worked ALLOW, REVIEW and BLOCK examples",
              "GET /health": "liveness",
              "GET /.well-known/agent-card.json": "A2A agent card",
              "POST /a2a": "A2A SendMessage (also accepted on / and /message/send)",
              "GET /.well-known/mcp.json": "MCP server manifest (registry server.json)",
              "POST /mcp": "MCP JSON-RPC",
              "POST /v1/verify": "REST verification",
              "POST /v1/circuit-breaker/reset": "operator reset for tripped agent circuit breaker",
              "POST /v1/sanctions/screen": "pre-action sanctions screening query",
              "POST /v1/sanctions/screen-entity": "OFAC 50% Rule and aggregated beneficial ownership screening",
              "POST /v1/sanctions/entries": "operator ingestion of custom sanctions entries",
              "POST /v1/dlp/scan": "pre-flight PII and secret leak scan",
              "POST /v1/covenants": "activate an accepted Action Covenant",
              "POST /v1/authorizations": "authorize an exact covenant action",
              "POST /v1/outcomes": "bind an execution outcome to an authorization",
              "GET /v1/insights": "authenticated metadata-only audit counts",
            },
            contact: "vassiliy.lakhonin@gmail.com",
          },
        },
      },
      404,
    );
  } catch (error) {
    if (error instanceof TransportRequestError) {
      return errorResponse(error);
    }
    if (error instanceof ActionCovenantError) {
      return errorResponse(
        new TransportRequestError(422, error.code, error.message),
      );
    }
    console.error(
      JSON.stringify({
        event: "vizier.request.failed",
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
    return errorResponse(
      new TransportRequestError(
        500,
        "INTERNAL_ERROR",
        "The request could not be processed.",
      ),
    );
  }
}
