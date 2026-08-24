import { z } from "zod";

import { verificationRequestSchema, verifyAction } from "../core/index";
import {
  jsonResponse,
  readLimitedJson,
  type TransportOptions,
  TransportRequestError,
} from "./shared";
import { authorizeEnforcement } from "./auth";

const MCP_PROTOCOL_VERSION = "2026-07-28";
const SERVER_INFO = Object.freeze({
  name: "vizier",
  title: "Vizier",
  version: "0.2.0",
  description: "Deterministic authorization checks for actions proposed by AI agents.",
});

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

type McpRequest = z.infer<typeof requestSchema>;

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

function validateOrigin(request: Request): boolean {
  const origin = request.headers.get("Origin");
  return origin === null || origin === new URL(request.url).origin;
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

async function callVerifyTool(
  request: Request,
  body: McpRequest,
  options: TransportOptions,
): Promise<Response> {
  const authorization = await authorizeEnforcement(request, options.apiKey);
  if (authorization === "denied") {
    return mcpError(
      body.id,
      -32001,
      "A valid Bearer token is required for enforcement mode.",
      401,
    );
  }
  if (body.params.name !== verifyTool.name) {
    return mcpError(body.id, -32602, "Unknown tool name.", 200);
  }
  const parsed = verificationRequestSchema.safeParse(body.params.arguments);
  if (!parsed.success) {
    return mcpError(body.id, -32602, "Tool arguments failed validation.", 200, {
      issues: parsed.error.issues.map((issue) => ({
        code: issue.code,
        path: issue.path.map(String),
        message: issue.message,
      })),
    });
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
      request_id: normalizedRequest.context.request_id ?? String(body.id),
      receipt_id: result.receipt.id,
      decision: result.decision,
      reason_codes: result.reason_codes,
    }),
  );
  return mcpResult(body.id, {
    content: [{ type: "text", text: JSON.stringify(result) }],
    structuredContent: result,
    isError: false,
  });
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
  if (!acceptsMcpResponse(request)) {
    return mcpError(
      undefined,
      -32020,
      "Accept must include application/json and text/event-stream.",
      400,
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
        instructions:
          "Call vizier_verify_action immediately before an AI agent executes an external action.",
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
