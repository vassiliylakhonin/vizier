import { verificationRequestSchema, verifyAction } from "../core/index";
import {
  jsonResponse,
  readLimitedJson,
  type TransportOptions,
  TransportRequestError,
} from "./shared";
import { createAgentCard, handleA2aRequest } from "./a2a";
import { handleMcpRequest } from "./mcp";
import { authorizeEnforcement } from "./auth";

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
    const details = parsed.error.issues.map((issue) => ({
      code: issue.code,
      path: issue.path.map(String),
      message: issue.message,
    }));
    throw new TransportRequestError(
      422,
      "VALIDATION_ERROR",
      "Verification request failed schema validation.",
      details,
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
    a2a: "/.well-known/agent-card.json",
    mcp: "/mcp",
  });
}

function docsDocument(): Response {
  return jsonResponse({
    api_version: "v1",
    endpoint: "POST /v1/verify",
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
      return jsonResponse(createAgentCard(url.origin));
    }
    if (request.method === "POST" && url.pathname === "/a2a") {
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
    return jsonResponse(
      { error: { code: "NOT_FOUND", message: "Route not found." } },
      404,
    );
  } catch (error) {
    if (error instanceof TransportRequestError) {
      return errorResponse(error);
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
