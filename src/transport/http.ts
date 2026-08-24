import { verificationRequestSchema, verifyAction } from "../core/index";
import { publicJwkFromPrivate } from "../crypto/jws";
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
} from "./shared";
import { createAgentCard, handleA2aRequest } from "./a2a";
import { handleMcpRequest } from "./mcp";
import { authorizeEnforcement } from "./auth";
import { createJwks, maybeSignAgentCard } from "./jws";

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

async function requireCovenantEnforcement(
  request: Request,
  options: TransportOptions,
): Promise<string> {
  const authorization = await authorizeEnforcement(request, options.apiKey);
  if (authorization === "denied") {
    throw new TransportRequestError(
      401,
      "AUTHENTICATION_REQUIRED",
      "A valid Bearer token is required for Action Covenant resources.",
    );
  }
  if (authorization === "evaluation") {
    throw new TransportRequestError(
      503,
      "ENFORCEMENT_UNAVAILABLE",
      "Action Covenant resources require configured enforcement.",
    );
  }
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

async function handleVerify(
  request: Request,
  options: TransportOptions,
): Promise<Response> {
  const startedAt = performance.now();
  const authorization = await authorizeEnforcement(request, options.apiKey);
  if (authorization === "denied") {
    throw new TransportRequestError(
      401,
      "AUTHENTICATION_REQUIRED",
      "A valid Bearer token is required for enforcement mode.",
    );
  }
  const parsedJson = await readLimitedJson(request);
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
  const result = await verifyAction(normalizedRequest, {
    trustedAuthority: authorization === "authenticated",
  });
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
  return jsonResponse(result);
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
  return jsonResponse(result, 201);
}

function rootDocument(): Response {
  return jsonResponse({
    name: "Vizier",
    tagline: "Every agent. Every action. Verified.",
    description: "Deterministic authorization checks for actions proposed by AI agents.",
    limitations: [
      "Not a factuality verifier.",
      "No live source retrieval.",
      "REVIEW requires a human decision before the external action.",
    ],
    docs: "/docs",
    health: "/health",
    verify: "/v1/verify",
    covenants: "/v1/covenants",
    authorizations: "/v1/authorizations",
    outcomes: "/v1/outcomes",
    a2a: "/.well-known/agent-card.json",
    mcp: "/mcp",
  });
}

function docsDocument(): Response {
  return jsonResponse({
    api_version: "v0.2",
    endpoints: {
      verify: "POST /v1/verify",
      activate_covenant: "POST /v1/covenants",
      authorize_covenant_action: "POST /v1/authorizations",
      record_outcome: "POST /v1/outcomes",
    },
    content_type: "application/json",
    request_schema: {
      agent: { id: "string", owner: "string | null" },
      principal: "{ id: string } | null",
      action: { type: "string", target: "string", parameters: "JSON object" },
      authority: {
        allowed_actions: ["string"],
        constraints: {
          max_amount: "number (optional)",
          currency: "ISO 4217 code (optional)",
          allowed_targets: ["string (optional)"],
          blocked_targets: ["string (optional)"],
          allowed_sensitive_actions: ["string (optional)"],
        },
      },
      context: {
        request_id: "string | null",
        timestamp: "ISO-8601 | null",
        source: "a2a | mcp | rest | internal | unknown",
      },
    },
    decisions: ["ALLOW", "REVIEW", "BLOCK"],
    enforcement: {
      evaluation_mode: "No VIZIER_API_KEY: REVIEW or BLOCK only",
      authenticated_mode:
        "VIZIER_API_KEY configured: Bearer credential required for verification",
      covenant_mode:
        "VIZIER_API_KEY and RECEIPT_SIGNING_KEY configured: authenticated lifecycle with ES256 receipts",
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

export async function handleHttpRequest(
  request: Request,
  options: TransportOptions = {},
): Promise<Response> {
  const url = new URL(request.url);
  try {
    if (request.method === "GET" && url.pathname === "/") {
      return rootDocument();
    }
    if (request.method === "GET" && url.pathname === "/health") {
      return jsonResponse({ status: "ok" });
    }
    if (request.method === "GET" && url.pathname === "/docs") {
      return docsDocument();
    }
    if (request.method === "GET" && url.pathname === "/examples") {
      return examplesDocument();
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
      return await handleA2aRequest(request, options);
    }
    if (request.method === "POST" && url.pathname === "/mcp") {
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
    if (request.method === "POST" && url.pathname === "/v1/verify") {
      return await handleVerify(request, options);
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
    return jsonResponse(
      {
        error: {
          code: "NOT_FOUND",
          message: "Route not found.",
          data: {
            routes: {
              "GET /": "service index",
              "GET /docs": "field reference for a verification request",
              "GET /examples": "worked ALLOW, REVIEW and BLOCK examples",
              "GET /health": "liveness",
              "GET /.well-known/agent-card.json": "A2A agent card",
              "POST /a2a": "A2A SendMessage (also accepted on / and /message/send)",
              "POST /mcp": "MCP JSON-RPC",
              "POST /v1/verify": "REST verification",
              "POST /v1/covenants": "activate an accepted Action Covenant",
              "POST /v1/authorizations": "authorize an exact covenant action",
              "POST /v1/outcomes": "bind an execution outcome to an authorization",
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
