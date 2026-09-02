import { z } from "zod";

import { verificationRequestSchema, verifyAction } from "../core/index";
import {
  jsonResponse,
  readLimitedJson,
  type TransportOptions,
  TransportRequestError,
} from "./shared";
import { authorizeEnforcement } from "./auth";
import { SERVICE_VERSION } from "../version";

const MCP_PROTOCOL_VERSION = "2026-07-28";

// Revisions that predate the stateless 2026-07-28 handshake. Shipping clients
// (Claude Code, Cursor, the MCP Inspector) still open a session with
// `initialize` and negotiate one of these. Measured 2026-09-02 against the
// deployed Worker: a standard `initialize` was rejected with -32600 because the
// stateless schema requires the 2026-07-28 `_meta` block, so the endpoint was
// unreachable from every off-the-shelf client. Both profiles are served from
// the same handler; the request body selects which one applies.
const SESSION_PROTOCOL_VERSIONS = Object.freeze([
  "2025-06-18",
  "2025-03-26",
  "2024-11-05",
]);
const DEFAULT_SESSION_PROTOCOL_VERSION = "2025-06-18";

const SERVER_INFO = Object.freeze({
  name: "vizier",
  title: "Vizier",
  version: SERVICE_VERSION,
  description: "Deterministic authorization checks for actions proposed by AI agents.",
});
const SERVER_INSTRUCTIONS =
  "Call vizier_verify_action immediately before an AI agent executes an external action.";

const requestMetaSchema = z.looseObject({
  "io.modelcontextprotocol/protocolVersion": z.string(),
  "io.modelcontextprotocol/clientInfo": z
    .looseObject({ name: z.string(), version: z.string() })
    .optional(),
  "io.modelcontextprotocol/clientCapabilities": z.record(z.string(), z.unknown()),
});

const requestSchema = z.strictObject({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string(), z.number().finite()]),
  method: z.string().min(1),
  params: z.looseObject({ _meta: requestMetaSchema }),
});

// Session-profile messages carry no `_meta` contract, and notifications carry
// no `id` at all.
const sessionMessageSchema = z.strictObject({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string(), z.number().finite()]).optional(),
  method: z.string().min(1),
  params: z.looseObject({}).optional(),
});

type McpRequest = z.infer<typeof requestSchema>;
type SessionMessage = z.infer<typeof sessionMessageSchema>;

const toolInputSchema = z.toJSONSchema(verificationRequestSchema, {
  target: "draft-2020-12",
  unrepresentable: "any",
});

const verifyTool = Object.freeze({
  name: "vizier_verify_action",
  title: "Verify Agent Action",
  description:
    "Evaluate whether an AI agent should be allowed to perform a proposed action.",
  inputSchema: toolInputSchema,
  annotations: {
    title: "Verify Agent Action",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
});

function responseMeta(): Readonly<Record<string, unknown>> {
  return { "io.modelcontextprotocol/serverInfo": SERVER_INFO };
}

function mcpError(
  id: string | number | undefined,
  code: number,
  message: string,
  status: number,
  data?: unknown,
): Response {
  return jsonResponse(
    {
      jsonrpc: "2.0",
      ...(id === undefined ? {} : { id }),
      error: { code, message, ...(data === undefined ? {} : { data }) },
    },
    status,
  );
}

function mcpResult(id: string | number, result: Record<string, unknown>): Response {
  return jsonResponse({
    jsonrpc: "2.0",
    id,
    result: {
      ...result,
      resultType: "complete",
      _meta: responseMeta(),
    },
  });
}

function sessionResult(
  id: string | number,
  result: Record<string, unknown>,
): Response {
  return jsonResponse({ jsonrpc: "2.0", id, result });
}

function acceptsMcpResponse(request: Request): boolean {
  const accepted = request.headers
    .get("Accept")
    ?.split(",")
    .map((value) => value.trim().split(";", 1)[0]);
  return (
    accepted?.includes("application/json") === true &&
    accepted.includes("text/event-stream")
  );
}

// Session clients are told to send both media types, but several send only
// `application/json`. Refuse only a client that can accept neither.
function acceptsSessionResponse(request: Request): boolean {
  const header = request.headers.get("Accept");
  if (header === null) {
    return true;
  }
  const accepted = header.split(",").map((value) => value.trim().split(";", 1)[0]);
  return (
    accepted.includes("application/json") ||
    accepted.includes("text/event-stream") ||
    accepted.includes("*/*") ||
    accepted.includes("application/*")
  );
}

function validateOrigin(request: Request): boolean {
  const origin = request.headers.get("Origin");
  return origin === null || origin === new URL(request.url).origin;
}

// The stateless profile is selected by the request itself: only 2026-07-28
// carries the protocol version inside `params._meta`.
function usesStatelessProfile(input: unknown): boolean {
  if (typeof input !== "object" || input === null) {
    return false;
  }
  const params = (input as { params?: unknown }).params;
  if (typeof params !== "object" || params === null) {
    return false;
  }
  const meta = (params as { _meta?: unknown })._meta;
  if (typeof meta !== "object" || meta === null) {
    return false;
  }
  return (
    typeof (meta as Record<string, unknown>)[
      "io.modelcontextprotocol/protocolVersion"
    ] === "string"
  );
}

function validateHeaders(request: Request, body: McpRequest): Response | null {
  const headerVersion = request.headers.get("MCP-Protocol-Version");
  const bodyVersion = body.params._meta["io.modelcontextprotocol/protocolVersion"];
  const headerMethod = request.headers.get("Mcp-Method");
  if (
    headerVersion === null ||
    headerVersion !== bodyVersion ||
    headerMethod === null ||
    headerMethod !== body.method
  ) {
    return mcpError(
      body.id,
      -32020,
      "Required MCP headers are missing or do not match the request body.",
      400,
    );
  }

  if (bodyVersion !== MCP_PROTOCOL_VERSION) {
    return mcpError(
      body.id,
      -32022,
      "The requested MCP protocol version is not supported.",
      400,
      { supported: [MCP_PROTOCOL_VERSION], requested: bodyVersion },
    );
  }

  if (body.method === "tools/call") {
    const name = body.params.name;
    const headerName = request.headers.get("Mcp-Name");
    if (typeof name !== "string" || headerName !== name) {
      return mcpError(
        body.id,
        -32020,
        "Mcp-Name is missing or does not match params.name.",
        400,
      );
    }
  }
  return null;
}

type ToolOutcome =
  | {
      readonly kind: "error";
      readonly code: number;
      readonly status: number;
      readonly message: string;
      readonly data?: unknown;
    }
  | { readonly kind: "result"; readonly result: Record<string, unknown> };

// One verification path for both profiles: authorization, argument validation,
// and the decision are identical; only the JSON-RPC envelope differs.
async function runVerifyTool(
  request: Request,
  params: Record<string, unknown>,
  options: TransportOptions,
  requestId: string,
): Promise<ToolOutcome> {
  // Same boundary as A2A: an anonymous caller gets an evaluation-only decision
  // that cannot return ALLOW, a supplied credential that is wrong is rejected.
  // Without this a client that found the server in a registry could list the
  // tool and never call it.
  const authorization = await authorizeEnforcement(request, options.apiKey, {
    allowMissingCredentialForEvaluation: true,
  });
  if (authorization === "denied") {
    return {
      kind: "error",
      code: -32001,
      status: 401,
      message: "The supplied Bearer token is not valid for enforcement mode.",
    };
  }
  if (params.name !== verifyTool.name) {
    return { kind: "error", code: -32602, status: 200, message: "Unknown tool name." };
  }
  const parsed = verificationRequestSchema.safeParse(params.arguments);
  if (!parsed.success) {
    return {
      kind: "error",
      code: -32602,
      status: 200,
      message: "Tool arguments failed validation.",
      data: {
        issues: parsed.error.issues.map((issue) => ({
          code: issue.code,
          path: issue.path.map(String),
          message: issue.message,
        })),
      },
    };
  }

  const normalizedRequest = {
    ...parsed.data,
    context: { ...parsed.data.context, source: "mcp" as const },
  };
  const result = await verifyAction(normalizedRequest, {
    trustedAuthority: authorization === "authenticated",
  });
  console.log(
    JSON.stringify({
      event: "vizier.mcp.completed",
      request_id: normalizedRequest.context.request_id ?? requestId,
      receipt_id: result.receipt.id,
      decision: result.decision,
      reason_codes: result.reason_codes,
    }),
  );
  return {
    kind: "result",
    result: {
      content: [{ type: "text", text: JSON.stringify(result) }],
      structuredContent: result,
      isError: false,
    },
  };
}

async function callVerifyTool(
  request: Request,
  body: McpRequest,
  options: TransportOptions,
): Promise<Response> {
  const outcome = await runVerifyTool(
    request,
    body.params,
    options,
    String(body.id),
  );
  return outcome.kind === "error"
    ? mcpError(body.id, outcome.code, outcome.message, outcome.status, outcome.data)
    : mcpResult(body.id, outcome.result);
}

async function handleStatelessRequest(
  request: Request,
  input: unknown,
  options: TransportOptions,
): Promise<Response> {
  if (!acceptsMcpResponse(request)) {
    return mcpError(
      undefined,
      -32020,
      "Accept must include application/json and text/event-stream.",
      400,
    );
  }

  const parsed = requestSchema.safeParse(input);
  if (!parsed.success) {
    return mcpError(undefined, -32600, "Invalid MCP request.", 400);
  }
  const headerError = validateHeaders(request, parsed.data);
  if (headerError !== null) {
    return headerError;
  }

  switch (parsed.data.method) {
    case "server/discover":
      return mcpResult(parsed.data.id, {
        supportedVersions: [MCP_PROTOCOL_VERSION],
        capabilities: { tools: { listChanged: false } },
        instructions: SERVER_INSTRUCTIONS,
        ttlMs: 300_000,
        cacheScope: "public",
      });
    case "tools/list":
      return mcpResult(parsed.data.id, {
        tools: [verifyTool],
        ttlMs: 300_000,
        cacheScope: "public",
      });
    case "tools/call":
      return callVerifyTool(request, parsed.data, options);
    default:
      return mcpError(parsed.data.id, -32601, "Method not found.", 404);
  }
}

function negotiateSessionVersion(params: Record<string, unknown> | undefined): string {
  const requested = params?.protocolVersion;
  return typeof requested === "string" &&
    SESSION_PROTOCOL_VERSIONS.includes(requested)
    ? requested
    : DEFAULT_SESSION_PROTOCOL_VERSION;
}

async function handleSessionRequest(
  request: Request,
  input: unknown,
  options: TransportOptions,
): Promise<Response> {
  if (!acceptsSessionResponse(request)) {
    return mcpError(
      undefined,
      -32020,
      "Accept must include application/json or text/event-stream.",
      400,
    );
  }

  const parsed = sessionMessageSchema.safeParse(input);
  if (!parsed.success) {
    return mcpError(undefined, -32600, "Invalid MCP request.", 400);
  }
  const message: SessionMessage = parsed.data;

  // The header is absent on `initialize` and carries the negotiated revision
  // afterwards. Reject only a revision this endpoint cannot answer.
  const headerVersion = request.headers.get("MCP-Protocol-Version");
  if (
    headerVersion !== null &&
    headerVersion !== MCP_PROTOCOL_VERSION &&
    !SESSION_PROTOCOL_VERSIONS.includes(headerVersion)
  ) {
    return mcpError(
      message.id,
      -32022,
      "The requested MCP protocol version is not supported.",
      400,
      {
        supported: [MCP_PROTOCOL_VERSION, ...SESSION_PROTOCOL_VERSIONS],
        requested: headerVersion,
      },
    );
  }

  // Notifications and responses carry no id and get no JSON-RPC reply.
  if (message.id === undefined) {
    return new Response(null, { status: 202 });
  }

  switch (message.method) {
    case "initialize":
      return sessionResult(message.id, {
        protocolVersion: negotiateSessionVersion(message.params),
        capabilities: { tools: { listChanged: false } },
        serverInfo: {
          name: SERVER_INFO.name,
          title: SERVER_INFO.title,
          version: SERVER_INFO.version,
        },
        instructions: SERVER_INSTRUCTIONS,
      });
    case "ping":
      return sessionResult(message.id, {});
    case "tools/list":
      return sessionResult(message.id, { tools: [verifyTool] });
    case "tools/call": {
      const outcome = await runVerifyTool(
        request,
        message.params ?? {},
        options,
        String(message.id),
      );
      return outcome.kind === "error"
        ? mcpError(
            message.id,
            outcome.code,
            outcome.message,
            outcome.status,
            outcome.data,
          )
        : sessionResult(message.id, outcome.result);
    }
    default:
      return mcpError(message.id, -32601, "Method not found.", 200);
  }
}

export async function handleMcpRequest(
  request: Request,
  options: TransportOptions = {},
): Promise<Response> {
  if (!validateOrigin(request)) {
    return mcpError(
      undefined,
      -32020,
      "Origin is not allowed for this MCP endpoint.",
      403,
    );
  }

  let input: unknown;
  try {
    input = await readLimitedJson(request);
  } catch (error) {
    if (error instanceof TransportRequestError) {
      const code = error.code === "INVALID_JSON" ? -32700 : -32600;
      return mcpError(undefined, code, error.message, error.status);
    }
    return mcpError(undefined, -32603, "Internal error.", 500);
  }

  return usesStatelessProfile(input)
    ? handleStatelessRequest(request, input, options)
    : handleSessionRequest(request, input, options);
}
