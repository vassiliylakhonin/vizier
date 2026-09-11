import { z } from "zod";

import {
  hashCanonicalJson,
  type JsonValue,
  type VerificationRequest,
  type VerificationResponse,
} from "@vizier/sdk";

export const MCP_PROTOCOL_VERSION = "2026-07-28";
export const MCP_PROXY_ACTION_TYPE = "mcp_tool_call";

const MAX_BODY_BYTES = 1024 * 1024;
const MAX_JSON_DEPTH = 64;
const MAX_JSON_VALUES = 50_000;
const DEFAULT_TIMEOUT_MS = 5_000;

const identifierSchema = z.string().trim().min(1).max(256);
const stableIdSchema = z
  .string()
  .trim()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/);
const toolNameSchema = z.string().trim().min(1).max(256);
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
const jsonObjectSchema = z.record(z.string(), jsonValueSchema);
const requestMetaSchema = z.looseObject({
  "io.modelcontextprotocol/protocolVersion": z.string(),
  "io.modelcontextprotocol/clientInfo": z
    .looseObject({ name: z.string(), version: z.string() })
    .optional(),
  "io.modelcontextprotocol/clientCapabilities": z.record(z.string(), z.unknown()),
});
const mcpRequestSchema = z.strictObject({
  jsonrpc: z.literal("2.0"),
  id: z.union([
    z.string().min(1).max(128),
    z.number().int().safe(),
  ]),
  method: z.string().min(1),
  params: z.looseObject({ _meta: requestMetaSchema }),
});
const mcpResponseSchema = z.looseObject({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string(), z.number().finite()]),
});
const toolsListResultSchema = z.looseObject({
  tools: z.array(z.looseObject({ name: toolNameSchema })),
});

type McpRequest = z.infer<typeof mcpRequestSchema>;

export interface McpProxyVerifier {
  verify(
    request: VerificationRequest,
    options?: { readonly signal?: AbortSignal },
  ): Promise<VerificationResponse>;
}

export interface McpProxyEvent {
  readonly event: "vizier.mcp_proxy.completed";
  readonly integration_id: string;
  readonly request_id: string;
  readonly tool_name: string;
  readonly outcome:
    | "forwarded"
    | "denied"
    | "verification_unavailable"
    | "upstream_failed"
    | "circuit_tripped";
  readonly decision?: VerificationResponse["decision"];
  readonly reason_codes?: readonly string[];
  readonly receipt_id?: string;
  readonly duration_ms: number;
}

export interface McpEnforcementProxyOptions {
  readonly integrationId: string;
  readonly clientBearerToken: string;
  readonly upstreamId: string;
  readonly upstreamUrl: string;
  readonly upstreamBearerToken?: string;
  readonly allowedTools: readonly string[];
  readonly agent: { readonly id: string; readonly owner: string | null };
  readonly principal: { readonly id: string };
  readonly verifier: McpProxyVerifier;
  readonly fetch?: typeof globalThis.fetch;
  readonly verificationTimeoutMs?: number;
  readonly upstreamTimeoutMs?: number;
  readonly now?: () => Date;
  readonly log?: (event: McpProxyEvent) => void;
  readonly circuitBreaker?: {
    readonly maxRepeats?: number;
    readonly windowMs?: number;
  };
}

interface NormalizedOptions {
  readonly integrationId: string;
  readonly clientBearerToken: string;
  readonly upstreamId: string;
  readonly upstreamUrl: string;
  readonly upstreamBearerToken?: string;
  readonly allowedTools: ReadonlySet<string>;
  readonly allowedTargets: readonly string[];
  readonly agent: { readonly id: string; readonly owner: string | null };
  readonly principal: { readonly id: string };
  readonly verifier: McpProxyVerifier;
  readonly fetch: typeof globalThis.fetch;
  readonly verificationTimeoutMs: number;
  readonly upstreamTimeoutMs: number;
  readonly now: () => Date;
  readonly log: (event: McpProxyEvent) => void;
  readonly circuitBreaker?: {
    readonly maxRepeats: number;
    readonly windowMs: number;
  };
  readonly callHistory: {
    entries: { timestamp: number; signature: string }[];
  };
}

function targetFor(upstreamId: string, toolName: string): string {
  return `mcp://${upstreamId}/tools/${encodeURIComponent(toolName)}`;
}

function boundedTimeout(value: number | undefined, name: string): number {
  const parsed = z.number().int().min(100).max(60_000).safeParse(
    value ?? DEFAULT_TIMEOUT_MS,
  );
  if (!parsed.success) {
    throw new TypeError(`${name} must be an integer between 100 and 60000.`);
  }
  return parsed.data;
}

function boundedCircuitBreaker(circuitBreaker?: {
  readonly maxRepeats?: number;
  readonly windowMs?: number;
}): { readonly maxRepeats: number; readonly windowMs: number } | undefined {
  if (circuitBreaker === undefined) {
    return undefined;
  }
  const maxRepeats = z
    .number()
    .int()
    .min(1)
    .max(1_000)
    .safeParse(circuitBreaker.maxRepeats ?? 4);
  if (!maxRepeats.success) {
    throw new TypeError(
      "circuitBreaker.maxRepeats must be an integer between 1 and 1000.",
    );
  }
  const windowMs = z
    .number()
    .int()
    .min(100)
    .max(300_000)
    .safeParse(circuitBreaker.windowMs ?? 30_000);
  if (!windowMs.success) {
    throw new TypeError(
      "circuitBreaker.windowMs must be an integer between 100 and 300000.",
    );
  }
  return { maxRepeats: maxRepeats.data, windowMs: windowMs.data };
}

function normalizeOptions(options: McpEnforcementProxyOptions): NormalizedOptions {
  const integrationId = stableIdSchema.parse(options.integrationId);
  const upstreamId = stableIdSchema.parse(options.upstreamId);
  const upstream = new URL(options.upstreamUrl);
  if (upstream.protocol !== "http:" && upstream.protocol !== "https:") {
    throw new TypeError("upstreamUrl must use http or https.");
  }
  if (upstream.username !== "" || upstream.password !== "") {
    throw new TypeError("upstreamUrl must not contain credentials.");
  }
  if (upstream.protocol === "http:" && !isLoopbackHostname(upstream.hostname)) {
    throw new TypeError("A non-loopback upstreamUrl must use https.");
  }
  const allowedTools = z.array(toolNameSchema).min(1).parse(options.allowedTools);
  if (new Set(allowedTools).size !== allowedTools.length) {
    throw new TypeError("allowedTools must contain unique tool names.");
  }
  return {
    integrationId,
    clientBearerToken: z.string().min(16).max(4_096).parse(options.clientBearerToken),
    upstreamId,
    upstreamUrl: upstream.toString(),
    ...(options.upstreamBearerToken === undefined
      ? {}
      : {
          upstreamBearerToken: z
            .string()
            .min(1)
            .max(4_096)
            .parse(options.upstreamBearerToken),
        }),
    allowedTools: new Set(allowedTools),
    allowedTargets: allowedTools.map((name) => targetFor(upstreamId, name)),
    agent: {
      id: identifierSchema.parse(options.agent.id),
      owner:
        options.agent.owner === null
          ? null
          : identifierSchema.parse(options.agent.owner),
    },
    principal: { id: identifierSchema.parse(options.principal.id) },
    verifier: options.verifier,
    fetch: options.fetch ?? globalThis.fetch,
    verificationTimeoutMs: boundedTimeout(
      options.verificationTimeoutMs,
      "verificationTimeoutMs",
    ),
    upstreamTimeoutMs: boundedTimeout(options.upstreamTimeoutMs, "upstreamTimeoutMs"),
    now: options.now ?? (() => new Date()),
    log: options.log ?? ((event) => console.log(JSON.stringify(event))),
    circuitBreaker: boundedCircuitBreaker(options.circuitBreaker),
    callHistory: { entries: [] },
  };
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function bearerToken(request: Request): string | null {
  const value = request.headers.get("Authorization");
  if (value === null || !value.startsWith("Bearer ")) {
    return null;
  }
  const token = value.slice("Bearer ".length);
  return token.length > 0 ? token : null;
}

async function digest(value: string): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
  );
}

async function secretsEqual(left: string, right: string): Promise<boolean> {
  const [leftDigest, rightDigest] = await Promise.all([digest(left), digest(right)]);
  let difference = 0;
  for (let index = 0; index < leftDigest.length; index += 1) {
    difference |= leftDigest[index]! ^ rightDigest[index]!;
  }
  return difference === 0;
}

async function authorizeClient(
  request: Request,
  expectedToken: string,
): Promise<boolean> {
  const token = bearerToken(request);
  return token !== null && secretsEqual(token, expectedToken);
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function assertJsonComplexity(value: unknown): void {
  const stack: Array<{ readonly depth: number; readonly value: unknown }> = [
    { depth: 0, value },
  ];
  let values = 0;
  while (stack.length > 0) {
    const current = stack.pop()!;
    values += 1;
    if (values > MAX_JSON_VALUES || current.depth > MAX_JSON_DEPTH) {
      throw new RangeError("JSON exceeds the structural complexity limit.");
    }
    if (Array.isArray(current.value)) {
      for (const item of current.value) {
        stack.push({ depth: current.depth + 1, value: item });
      }
    } else if (typeof current.value === "object" && current.value !== null) {
      for (const item of Object.values(current.value)) {
        stack.push({ depth: current.depth + 1, value: item });
      }
    }
  }
}

async function readLimitedText(
  body: ReadableStream<Uint8Array> | null,
  declaredLength: string | null,
): Promise<string> {
  if (declaredLength !== null && Number(declaredLength) > MAX_BODY_BYTES) {
    throw new RangeError("JSON body is too large.");
  }
  if (body === null) {
    throw new SyntaxError("Request body must contain JSON.");
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      totalBytes += value.byteLength;
      if (totalBytes > MAX_BODY_BYTES) {
        await reader.cancel("body size limit exceeded");
        throw new RangeError("JSON body is too large.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const joined = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(joined);
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

async function readBody(request: Request): Promise<{
  readonly body: McpRequest;
  readonly serialized: string;
}> {
  const contentType = request.headers.get("Content-Type")?.split(";", 1)[0]?.trim();
  if (contentType !== "application/json") {
    throw new TypeError("Content-Type must be application/json.");
  }
  const serialized = await readLimitedText(
    request.body,
    request.headers.get("Content-Length"),
  );
  let input: unknown;
  try {
    input = JSON.parse(serialized) as unknown;
  } catch {
    throw new SyntaxError("Request body contains invalid JSON.");
  }
  assertJsonComplexity(input);
  const parsed = mcpRequestSchema.safeParse(input);
  if (!parsed.success) {
    throw new TypeError("Invalid MCP request.");
  }
  return { body: parsed.data, serialized };
}

function validateProtocol(request: Request, body: McpRequest): Response | null {
  const accepted = request.headers
    .get("Accept")
    ?.split(",")
    .map((value) => value.trim().split(";", 1)[0]);
  if (
    accepted?.includes("application/json") !== true ||
    !accepted.includes("text/event-stream")
  ) {
    return mcpError(
      body.id,
      -32020,
      "Accept must include application/json and text/event-stream.",
      400,
    );
  }
  const version = body.params._meta["io.modelcontextprotocol/protocolVersion"];
  if (
    version !== MCP_PROTOCOL_VERSION ||
    request.headers.get("MCP-Protocol-Version") !== version ||
    request.headers.get("Mcp-Method") !== body.method
  ) {
    return mcpError(
      body.id,
      -32020,
      "Required MCP headers are missing or do not match the request body.",
      400,
    );
  }
  if (
    body.method === "tools/call" &&
    (typeof body.params.name !== "string" ||
      request.headers.get("Mcp-Name") !== body.params.name)
  ) {
    return mcpError(
      body.id,
      -32020,
      "Mcp-Name is missing or does not match params.name.",
      400,
    );
  }
  return null;
}

async function parseUpstreamResponse(
  response: Response,
  requestId: string | number,
): Promise<Record<string, unknown>> {
  const declaredLength = response.headers.get("Content-Length");
  const contentType = response.headers.get("Content-Type")?.split(";", 1)[0]?.trim();
  if (contentType !== "application/json") {
    throw new Error("Upstream MCP server returned an unsupported media type.");
  }
  const text = await readLimitedText(response.body, declaredLength);
  let input: unknown;
  try {
    input = JSON.parse(text) as unknown;
  } catch {
    throw new Error("Upstream MCP server returned invalid JSON.");
  }
  assertJsonComplexity(input);
  const parsed = mcpResponseSchema.safeParse(input);
  if (!response.ok || !parsed.success || parsed.data.id !== requestId) {
    throw new Error("Upstream MCP server returned an invalid response contract.");
  }
  return parsed.data;
}

function upstreamHeaders(
  request: Request,
  body: McpRequest,
  options: NormalizedOptions,
): Headers {
  const headers = new Headers({
    Accept: "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": request.headers.get("MCP-Protocol-Version") ?? "",
    "Mcp-Method": request.headers.get("Mcp-Method") ?? "",
  });
  if (body.method === "tools/call" && typeof body.params.name === "string") {
    headers.set("Mcp-Name", body.params.name);
  }
  if (options.upstreamBearerToken !== undefined) {
    headers.set("Authorization", `Bearer ${options.upstreamBearerToken}`);
  }
  return headers;
}

async function forward(
  request: Request,
  body: McpRequest,
  serialized: string,
  options: NormalizedOptions,
): Promise<Record<string, unknown>> {
  const response = await options.fetch(options.upstreamUrl, {
    method: "POST",
    headers: upstreamHeaders(request, body, options),
    body: serialized,
    redirect: "error",
    signal: AbortSignal.timeout(options.upstreamTimeoutMs),
  });
  return parseUpstreamResponse(response, body.id);
}

function filterTools(
  response: Record<string, unknown>,
  allowedTools: ReadonlySet<string>,
): Record<string, unknown> {
  const result = toolsListResultSchema.safeParse(response.result);
  if (!result.success) {
    throw new Error("Upstream MCP tools/list response is invalid.");
  }
  return {
    ...response,
    result: {
      ...result.data,
      tools: result.data.tools.filter((tool) => allowedTools.has(tool.name)),
    },
  };
}

function discoveryResponse(body: McpRequest): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id: body.id,
    result: {
      supportedVersions: [MCP_PROTOCOL_VERSION],
      capabilities: { tools: { listChanged: false } },
      instructions:
        "Only tools returned by tools/list are available through this Vizier enforcement proxy.",
      ttlMs: 300_000,
      cacheScope: "private",
    },
  };
}

function verificationRequest(
  body: McpRequest,
  toolName: string,
  argumentsValue: Record<string, JsonValue>,
  options: NormalizedOptions,
): VerificationRequest {
  return {
    agent: options.agent,
    principal: options.principal,
    action: {
      type: MCP_PROXY_ACTION_TYPE,
      target: targetFor(options.upstreamId, toolName),
      parameters: { tool_name: toolName, arguments: argumentsValue },
    },
    authority: {
      allowed_actions: [MCP_PROXY_ACTION_TYPE],
      constraints: { allowed_targets: [...options.allowedTargets] },
    },
    context: {
      request_id: `${options.integrationId}:${String(body.id)}`,
      timestamp: options.now().toISOString(),
      source: "mcp",
    },
  };
}

async function handleToolCall(
  request: Request,
  body: McpRequest,
  serialized: string,
  options: NormalizedOptions,
): Promise<Response> {
  const startedAt = performance.now();
  const toolName = toolNameSchema.safeParse(body.params.name);
  const argumentsValue = jsonObjectSchema.safeParse(body.params.arguments);
  if (!toolName.success || !argumentsValue.success) {
    return mcpError(
      body.id,
      -32602,
      "Tool name or arguments failed validation.",
      200,
    );
  }
  const requestId = `${options.integrationId}:${String(body.id)}`;
  if (!options.allowedTools.has(toolName.data)) {
    options.log({
      event: "vizier.mcp_proxy.completed",
      integration_id: options.integrationId,
      request_id: requestId,
      tool_name: toolName.data,
      outcome: "denied",
      decision: "BLOCK",
      reason_codes: ["TARGET_NOT_ALLOWED"],
      duration_ms: Math.round(performance.now() - startedAt),
    });
    return mcpError(
      body.id,
      -32003,
      "Tool call is outside the proxy allowlist.",
      200,
      {
        code: "TOOL_NOT_ALLOWED",
        decision: "BLOCK",
        reason_codes: ["TARGET_NOT_ALLOWED"],
      },
    );
  }
  if (options.circuitBreaker !== undefined) {
    const signature = `${toolName.data}:${await hashCanonicalJson(argumentsValue.data)}`;
    const nowMs = options.now().getTime();
    const cutoff = nowMs - options.circuitBreaker.windowMs;
    options.callHistory.entries = options.callHistory.entries.filter(
      (entry) => entry.timestamp >= cutoff,
    );
    const repeats = options.callHistory.entries.filter(
      (entry) => entry.signature === signature,
    ).length;

    if (repeats >= options.circuitBreaker.maxRepeats) {
      options.log({
        event: "vizier.mcp_proxy.completed",
        integration_id: options.integrationId,
        request_id: requestId,
        tool_name: toolName.data,
        outcome: "circuit_tripped",
        decision: "BLOCK",
        reason_codes: ["CIRCUIT_TRIPPED:LOOP_DETECTED"],
        duration_ms: Math.round(performance.now() - startedAt),
      });
      return mcpError(
        body.id,
        -32028,
        "Circuit breaker tripped: potential tool loop detected.",
        200,
        {
          code: "CIRCUIT_TRIPPED",
          decision: "BLOCK",
          reason_codes: ["CIRCUIT_TRIPPED:LOOP_DETECTED"],
        },
      );
    }
    options.callHistory.entries.push({ timestamp: nowMs, signature });
  }
  let decision: VerificationResponse;
  try {
    decision = await options.verifier.verify(
      verificationRequest(body, toolName.data, argumentsValue.data, options),
      { signal: AbortSignal.timeout(options.verificationTimeoutMs) },
    );
  } catch {
    options.log({
      event: "vizier.mcp_proxy.completed",
      integration_id: options.integrationId,
      request_id: requestId,
      tool_name: toolName.data,
      outcome: "verification_unavailable",
      duration_ms: Math.round(performance.now() - startedAt),
    });
    return mcpError(
      body.id,
      -32004,
      "Authorization service is unavailable; tool call was not forwarded.",
      200,
      { code: "VIZIER_UNAVAILABLE" },
    );
  }
  if (decision.decision !== "ALLOW") {
    options.log({
      event: "vizier.mcp_proxy.completed",
      integration_id: options.integrationId,
      request_id: requestId,
      tool_name: toolName.data,
      outcome: "denied",
      decision: decision.decision,
      reason_codes: decision.reason_codes,
      receipt_id: decision.receipt.id,
      duration_ms: Math.round(performance.now() - startedAt),
    });
    return mcpError(
      body.id,
      -32003,
      "Tool call was not authorized by Vizier.",
      200,
      {
        code: "VIZIER_DENIED",
        decision: decision.decision,
        reason_codes: decision.reason_codes,
        receipt_id: decision.receipt.id,
      },
    );
  }
  try {
    const upstreamResponse = await forward(request, body, serialized, options);
    options.log({
      event: "vizier.mcp_proxy.completed",
      integration_id: options.integrationId,
      request_id: requestId,
      tool_name: toolName.data,
      outcome: "forwarded",
      decision: decision.decision,
      reason_codes: decision.reason_codes,
      receipt_id: decision.receipt.id,
      duration_ms: Math.round(performance.now() - startedAt),
    });
    return jsonResponse(upstreamResponse);
  } catch {
    options.log({
      event: "vizier.mcp_proxy.completed",
      integration_id: options.integrationId,
      request_id: requestId,
      tool_name: toolName.data,
      outcome: "upstream_failed",
      decision: decision.decision,
      reason_codes: decision.reason_codes,
      receipt_id: decision.receipt.id,
      duration_ms: Math.round(performance.now() - startedAt),
    });
    return mcpError(
      body.id,
      -32005,
      "Authorized upstream tool call failed.",
      200,
      { code: "UPSTREAM_FAILED", receipt_id: decision.receipt.id },
    );
  }
}

export function createMcpEnforcementProxy(
  inputOptions: McpEnforcementProxyOptions,
): { readonly handle: (request: Request) => Promise<Response> } {
  const options = normalizeOptions(inputOptions);
  return {
    async handle(request: Request): Promise<Response> {
      const origin = request.headers.get("Origin");
      if (origin !== null && origin !== new URL(request.url).origin) {
        return mcpError(
          undefined,
          -32020,
          "Origin is not allowed for this MCP endpoint.",
          403,
        );
      }
      if (request.method !== "POST") {
        return mcpError(undefined, -32600, "Only POST is supported.", 405);
      }
      if (!(await authorizeClient(request, options.clientBearerToken))) {
        return mcpError(
          undefined,
          -32001,
          "A valid proxy Bearer token is required.",
          401,
        );
      }
      let parsed: { readonly body: McpRequest; readonly serialized: string };
      try {
        parsed = await readBody(request);
      } catch (error) {
        if (error instanceof RangeError) {
          return mcpError(undefined, -32600, error.message, 413);
        }
        if (error instanceof SyntaxError) {
          return mcpError(undefined, -32700, error.message, 400);
        }
        return mcpError(
          undefined,
          -32600,
          error instanceof Error ? error.message : "Invalid MCP request.",
          400,
        );
      }
      const protocolError = validateProtocol(request, parsed.body);
      if (protocolError !== null) {
        return protocolError;
      }
      if (parsed.body.method === "tools/call") {
        return handleToolCall(
          request,
          parsed.body,
          parsed.serialized,
          options,
        );
      }
      if (
        parsed.body.method !== "server/discover" &&
        parsed.body.method !== "tools/list"
      ) {
        return mcpError(parsed.body.id, -32601, "Method not found.", 404);
      }
      if (parsed.body.method === "server/discover") {
        return jsonResponse(discoveryResponse(parsed.body));
      }
      try {
        const response = await forward(
          request,
          parsed.body,
          parsed.serialized,
          options,
        );
        return jsonResponse(
          filterTools(response, options.allowedTools),
        );
      } catch {
        return mcpError(
          parsed.body.id,
          -32005,
          "Upstream MCP server is unavailable.",
          200,
          { code: "UPSTREAM_FAILED" },
        );
      }
    },
  };
}
