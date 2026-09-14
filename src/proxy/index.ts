import {
  evaluateEdgeCircuitBreaker,
} from "../core/circuit-breaker";
import {
  scanDlpParameters,
  scanDlpText,
} from "../core/dlp";
import {
  computeActionHash,
  consumeQuorumProposal,
  createQuorumProposal,
  getQuorumProposal,
} from "../core/quorum";
import { evaluateSanctions } from "../core/sanctions";
import { DEFAULT_SENSITIVE_ACTIONS } from "../core/policies";
import { sha256 } from "../core/receipts";
import { signCompactJws } from "../crypto/jws";
import {
  jsonResponse,
  readLimitedJson,
  type TransportOptions,
  TransportRequestError,
} from "../transport/shared";
import { authorizeEnforcement } from "../transport/auth";
import type { VerificationRequest } from "../core/schemas";

export interface ProxyMessage {
  role: string;
  content?: string | null | Array<{ type: string; text?: string }>;
  name?: string;
  tool_calls?: Array<{
    id: string;
    type: string;
    function: {
      name: string;
      arguments: string;
    };
  }>;
}

export interface ProxyChatCompletionRequest {
  model: string;
  messages: ProxyMessage[];
  tools?: Array<{
    type: "function";
    function: {
      name: string;
      description?: string;
      parameters?: Record<string, unknown>;
    };
  }>;
  stream?: boolean;
  user?: string;
  temperature?: number;
  max_tokens?: number;
  [key: string]: unknown;
}

interface OpenAIErrorResponse {
  error: {
    message: string;
    type: string;
    param?: string | null;
    code: string;
    details?: unknown;
  };
}

function openAiError(
  message: string,
  code: string,
  status: number,
  type = "invalid_request_error",
  param: string | null = null,
  details?: unknown,
): Response {
  const body: OpenAIErrorResponse = {
    error: {
      message,
      type,
      param,
      code,
      ...(details !== undefined ? { details } : {}),
    },
  };
  return jsonResponse(body, status, {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  });
}

function extractTextFromContent(
  content: string | null | Array<{ type: string; text?: string }> | undefined,
): string {
  if (!content) return "";
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .filter((part) => part.type === "text" && typeof part.text === "string")
      .map((part) => part.text)
      .join("\n");
  }
  return "";
}

/**
 * Validates Vizier authentication.
 * Supports root master key (VIZIER_API_KEY) and tenant keys (vz_live_...).
 */
async function checkProxyAuth(
  request: Request,
  options: TransportOptions,
): Promise<{ ok: boolean; status: number; code: string; message: string }> {
  if (!options.apiKey || options.apiKey.length === 0) {
    return { ok: true, status: 200, code: "", message: "" };
  }
  const auth = await authorizeEnforcement(request, options.apiKey, { db: options.db });
  if (auth === "authenticated" || auth === "evaluation") {
    return { ok: true, status: 200, code: "", message: "" };
  }
  if (auth === "quota_exceeded") {
    return {
      ok: false,
      status: 429,
      code: "QUOTA_EXCEEDED",
      message: "Vizier Proxy: Monthly API quota exceeded for this API key. Upgrade your tier to proceed.",
    };
  }
  return {
    ok: false,
    status: 401,
    code: "invalid_api_key",
    message: "Unauthorized: Invalid or missing Vizier API key. Provide it via 'Authorization: Bearer <key>' or 'X-Vizier-Key' header.",
  };
}

interface UpstreamResolution {
  readonly upstreamUrl?: string;
  readonly upstreamAuthHeader?: string | null;
  readonly error?: string;
}

function isPrivateOrMetadataHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host === "0.0.0.0" ||
    host === "169.254.169.254" ||
    host === "metadata.google.internal" ||
    host === "instance-data" ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".arpa")
  ) {
    return true;
  }

  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = host.match(ipv4Regex);
  if (match) {
    const o1 = parseInt(match[1]!, 10);
    const o2 = parseInt(match[2]!, 10);
    if (o1 === 10) return true;
    if (o1 === 127) return true;
    if (o1 === 169 && o2 === 254) return true;
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return true;
    if (o1 === 192 && o2 === 168) return true;
    if (o1 === 0) return true;
  }

  if (host.startsWith("fe80:") || host.startsWith("fc00:") || host.startsWith("fd")) {
    return true;
  }

  return false;
}

function resolveUpstream(
  request: Request,
  options: TransportOptions,
): UpstreamResolution {
  const defaultAllowedOrigins = ["https://api.openai.com"];
  const allowedOrigins = new Set<string>([
    ...defaultAllowedOrigins,
    ...(options.allowedUpstreamOrigins ?? []),
  ]);
  if (options.upstreamUrl) {
    try {
      allowedOrigins.add(new URL(options.upstreamUrl).origin);
    } catch {
      // ignore invalid options.upstreamUrl for set population
    }
  }

  const rawUpstreamUrl =
    request.headers.get("X-Upstream-Url") ||
    options.upstreamUrl ||
    "https://api.openai.com/v1/chat/completions";

  let parsed: URL;
  try {
    parsed = new URL(rawUpstreamUrl);
  } catch {
    return { error: "Invalid upstream URL specified in X-Upstream-Url or configuration." };
  }

  if (parsed.username || parsed.password) {
    return { error: "Upstream URL must not contain credentials." };
  }

  const isLocalhost = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  const isHttps = parsed.protocol === "https:";

  if (!isHttps && !isLocalhost) {
    return { error: "A non-loopback upstream URL must use HTTPS protocol." };
  }

  const isTestEnv =
    (globalThis as { process?: { env?: { NODE_ENV?: string } } }).process?.env?.NODE_ENV === "test";

  if (isPrivateOrMetadataHost(parsed.hostname) && !(isLocalhost && isTestEnv)) {
    return { error: `Access to private or metadata network host '${parsed.hostname}' is prohibited.` };
  }

  const originAllowed =
    allowedOrigins.has(parsed.origin) ||
    (isLocalhost && (isTestEnv || allowedOrigins.has(parsed.origin)));

  if (!originAllowed) {
    return {
      error: `Untrusted upstream origin '${parsed.origin}'. Upstream must match authorized origins.`,
    };
  }

  let upstreamAuthHeader: string | null = null;
  const upstreamKey = request.headers.get("X-Upstream-Key");
  if (upstreamKey) {
    upstreamAuthHeader = `Bearer ${upstreamKey}`;
  }

  return { upstreamUrl: parsed.toString(), upstreamAuthHeader };
}

/**
 * Handles GET /v1/models - standard OpenAI model catalog.
 */
export async function handleModels(): Promise<Response> {
  const models = [
    { id: "gpt-4o", object: "model", created: 1715367049, owned_by: "openai" },
    { id: "gpt-4o-mini", object: "model", created: 1721297054, owned_by: "openai" },
    { id: "o1-preview", object: "model", created: 1726100000, owned_by: "openai" },
    { id: "claude-3-5-sonnet", object: "model", created: 1718928000, owned_by: "anthropic" },
    { id: "deepseek-chat", object: "model", created: 1720000000, owned_by: "deepseek" },
  ];

  return jsonResponse(
    { object: "list", data: models },
    200,
    {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    },
  );
}

/**
 * Handles POST /v1/chat/completions - Transparent AI Proxy with Vizier Guardrails.
 */
export async function handleChatCompletions(
  request: Request,
  options: TransportOptions,
): Promise<Response> {
  const startedAt = performance.now();

  // 1. Authentication
  const authCheck = await checkProxyAuth(request, options);
  if (!authCheck.ok) {
    return openAiError(
      authCheck.message,
      authCheck.code,
      authCheck.status,
      "authentication_error",
    );
  }

  // 2. Parse request body
  let rawBody: unknown;
  try {
    rawBody = await readLimitedJson(request);
  } catch (err: unknown) {
    if (err instanceof TransportRequestError) {
      return openAiError(err.message, err.code, err.status);
    }
    return openAiError("Invalid JSON in request body.", "invalid_payload", 400);
  }

  if (typeof rawBody !== "object" || rawBody === null) {
    return openAiError("Request body must be a JSON object.", "invalid_payload", 400);
  }

  const payload = rawBody as ProxyChatCompletionRequest;
  if (!payload.messages || !Array.isArray(payload.messages) || payload.messages.length === 0) {
    return openAiError("Field 'messages' must be a non-empty array.", "missing_required_field", 400, "invalid_request_error", "messages");
  }

  const sessionId =
    request.headers.get("X-Session-Id") ||
    (typeof payload.user === "string" ? payload.user : null) ||
    "session_default";

  // 3. Pre-LLM Guardrail: DLP & Secret Leak Firewall on outgoing prompt
  for (let i = 0; i < payload.messages.length; i++) {
    const msg = payload.messages[i]!;
    const textContent = extractTextFromContent(msg.content);
    if (textContent.length > 0) {
      const dlpFindings = scanDlpText(textContent, `messages[${i}].content`);
      if (dlpFindings.length > 0) {
        const primaryFinding = dlpFindings[0]!;
        console.warn(
          JSON.stringify({
            event: "vizier.proxy.dlp_blocked",
            session_id: sessionId,
            message_index: i,
            detector: primaryFinding.detector,
            snippet: primaryFinding.snippet_masked,
          }),
        );
        return openAiError(
          `Vizier DLP Firewall: outgoing message blocked due to detected secret/PII leak (${primaryFinding.category}: ${primaryFinding.detector}, masked: ${primaryFinding.snippet_masked}).`,
          "SECRET_LEAK_PREVENTED",
          400,
          "vizier_dlp_violation",
          `messages[${i}].content`,
          { findings: dlpFindings },
        );
      }
    }
  }

  // 4. Pre-LLM Guardrail: Circuit Breaker on prompt repeat storms
  if (options.circuitBreakerKv !== undefined) {
    const lastMessage = payload.messages[payload.messages.length - 1];
    const lastPromptText = extractTextFromContent(lastMessage?.content);
    if (lastPromptText.length > 0) {
      const promptHash = await sha256(lastPromptText);
      const promptVerificationRequest: VerificationRequest = {
        agent: { id: sessionId, owner: null },
        principal: null,
        action: {
          type: "prompt_submit",
          target: typeof payload.model === "string" ? payload.model : "unknown_model",
          parameters: { prompt_hash: promptHash },
        },
        authority: {
          allowed_actions: ["prompt_submit"],
          constraints: {
            max_repeated_calls: 3,
            time_window_seconds: 30,
            cool_off_seconds: 60,
          },
        },
        context: {
          request_id: `req_${crypto.randomUUID()}`,
          session_id: sessionId,
          timestamp: new Date().toISOString(),
          source: "rest",
        },
      };

      const cbResult = await evaluateEdgeCircuitBreaker(
        options.circuitBreakerKv,
        promptVerificationRequest,
      );

      if (cbResult.tripped) {
        console.warn(
          JSON.stringify({
            event: "vizier.proxy.prompt_circuit_breaker_tripped",
            session_id: sessionId,
            reason: cbResult.reasonCode,
          }),
        );
        return openAiError(
          `Vizier Circuit Breaker tripped: prompt repeat storm detected for session '${sessionId}'. ${cbResult.message ?? ""}`,
          "CIRCUIT_TRIPPED",
          429,
          "vizier_circuit_breaker_tripped",
          null,
          cbResult.details,
        );
      }
    }
  }

  // 5. Forward request to upstream
  const upstreamResolution = resolveUpstream(request, options);
  if (upstreamResolution.error) {
    return openAiError(upstreamResolution.error, "invalid_upstream_url", 400);
  }
  const upstreamUrl = upstreamResolution.upstreamUrl!;
  const upstreamAuthHeader = upstreamResolution.upstreamAuthHeader;

  // Fail-closed: do not allow streaming tool calls to bypass post-LLM guardrails
  if (
    payload.stream === true &&
    ((Array.isArray(payload.tools) && payload.tools.length > 0) ||
      (Array.isArray(payload.functions) && payload.functions.length > 0))
  ) {
    return openAiError(
      "Streaming is not supported when tools or functions are configured. Vizier guardrails require complete post-LLM tool call inspection. Please set 'stream: false' to use tools with guardrails.",
      "streaming_tools_unsupported",
      400,
    );
  }

  const upstreamHeaders: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (upstreamAuthHeader) {
    upstreamHeaders["Authorization"] = upstreamAuthHeader;
  }

  const fetchFn = options.upstreamFetch ?? fetch;
  let upstreamResponse: Response;
  try {
    upstreamResponse = await fetchFn(upstreamUrl, {
      method: "POST",
      headers: upstreamHeaders,
      body: JSON.stringify(payload),
      redirect: "manual",
    });
  } catch (fetchErr: unknown) {
    console.error(
      JSON.stringify({
        event: "vizier.proxy.upstream_fetch_error",
        error: fetchErr instanceof Error ? fetchErr.message : "Unknown error",
        url: upstreamUrl,
      }),
    );
    return openAiError(
      `Vizier Proxy failed to connect to upstream LLM: ${fetchErr instanceof Error ? fetchErr.message : "Connection failed"}`,
      "upstream_connection_failed",
      502,
      "api_connection_error",
    );
  }

  if (upstreamResponse.status >= 300 && upstreamResponse.status < 400) {
    return openAiError(
      "Upstream returned an HTTP redirect, which is disallowed for security reasons.",
      "upstream_redirect_disallowed",
      502,
      "api_connection_error",
    );
  }

  if (!upstreamResponse.ok) {
    // Forward upstream error directly
    const errorBody = await upstreamResponse.text();
    return new Response(errorBody, {
      status: upstreamResponse.status,
      headers: {
        "Content-Type": upstreamResponse.headers.get("Content-Type") || "application/json",
        "Access-Control-Allow-Origin": "*",
        "X-Vizier-Proxy": "passthrough_error",
      },
    });
  }

  // 6. Inspect response (Post-LLM Tool Call Guardrails)
  // If streaming is requested for pure text/completion (no tools), return pass-through with security headers
  if (payload.stream === true) {
    return new Response(upstreamResponse.body, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*",
        "X-Vizier-Status": "STREAMING_UNINSPECTED_OUTPUT",
        "X-Vizier-Guardrails": "DLP,CircuitBreaker",
      },
    });
  }

interface ChatCompletionResponse {
  readonly id?: string;
  readonly object?: string;
  readonly choices?: readonly {
    readonly message?: {
      readonly role?: string;
      readonly content?: string | null;
      readonly tool_calls?: readonly {
        readonly id?: string;
        readonly type?: string;
        readonly function?: {
          readonly name?: string;
          readonly arguments?: string;
        };
      }[];
    };
  }[];
  readonly [key: string]: unknown;
}

  // Non-streaming JSON response inspection
  let responseData: ChatCompletionResponse;
  try {
    responseData = (await upstreamResponse.json()) as ChatCompletionResponse;
  } catch {
    return openAiError("Upstream returned non-JSON response.", "invalid_upstream_response", 502);
  }

  const choices = responseData.choices;
  if (Array.isArray(choices) && choices.length > 0) {
    for (const choice of choices) {
      const toolCalls = choice?.message?.tool_calls;
      if (Array.isArray(toolCalls) && toolCalls.length > 0) {
        for (let tIdx = 0; tIdx < toolCalls.length; tIdx++) {
          const toolCall = toolCalls[tIdx];
          const fnName = toolCall?.function?.name || "unknown_tool";
          const rawArgs = toolCall?.function?.arguments || "{}";

          let parsedArgs: Record<string, unknown>;
          try {
            parsedArgs = JSON.parse(rawArgs) as Record<string, unknown>;
          } catch {
            parsedArgs = { raw: rawArgs };
          }

          // A. Post-LLM DLP on tool arguments
          const argDlpFindings = scanDlpParameters(
            parsedArgs,
            new Set(),
            `tool_calls[${tIdx}].arguments`,
          );
          if (argDlpFindings.length > 0) {
            const firstLeak = argDlpFindings[0]!;
            console.warn(
              JSON.stringify({
                event: "vizier.proxy.tool_call_dlp_blocked",
                session_id: sessionId,
                tool_name: fnName,
                detector: firstLeak.detector,
                snippet: firstLeak.snippet_masked,
              }),
            );
            return openAiError(
              `Vizier DLP Firewall: tool call '${fnName}' arguments blocked due to secret leak (${firstLeak.category}: ${firstLeak.detector}, masked: ${firstLeak.snippet_masked}).`,
              "SECRET_LEAK_PREVENTED",
              400,
              "vizier_dlp_violation",
              `tool_calls[${tIdx}].function.arguments`,
              { findings: argDlpFindings },
            );
          }

          // B. Post-LLM Circuit Breaker & Loop Killer on tool calls
          if (options.circuitBreakerKv !== undefined) {
            const toolVerifyRequest: VerificationRequest = {
              agent: { id: sessionId, owner: null },
              principal: null,
              action: {
                type: fnName,
                target: fnName,
                parameters: parsedArgs as VerificationRequest["action"]["parameters"],
              },
              authority: {
                allowed_actions: [fnName],
                constraints: {
                  max_repeated_calls: 3,
                  time_window_seconds: 30,
                  cool_off_seconds: 60,
                },
              },
              context: {
                request_id: `req_${crypto.randomUUID()}`,
                session_id: sessionId,
                timestamp: new Date().toISOString(),
                source: "rest",
              },
            };

            const toolCbRes = await evaluateEdgeCircuitBreaker(
              options.circuitBreakerKv,
              toolVerifyRequest,
            );

            if (toolCbRes.tripped) {
              console.warn(
                JSON.stringify({
                  event: "vizier.proxy.tool_circuit_breaker_tripped",
                  session_id: sessionId,
                  tool_name: fnName,
                  reason: toolCbRes.reasonCode,
                }),
              );
              return openAiError(
                `Vizier Loop Killer tripped on tool call '${fnName}': potential infinite loop detected. ${toolCbRes.message ?? ""}`,
                "CIRCUIT_TRIPPED",
                429,
                "vizier_circuit_breaker_tripped",
                `tool_calls[${tIdx}]`,
                toolCbRes.details,
              );
            }
          }

          // C. Post-LLM Sanctions & OFAC 50% Rule screening on tool calls
          const dummySanctionsReq: VerificationRequest = {
            agent: { id: sessionId, owner: null },
            principal: null,
            action: {
              type: fnName,
              target: fnName,
              parameters: parsedArgs as VerificationRequest["action"]["parameters"],
            },
            authority: {
              allowed_actions: [fnName],
              constraints: {},
            },
            context: {
              request_id: `req_${crypto.randomUUID()}`,
              session_id: sessionId,
              timestamp: new Date().toISOString(),
              source: "rest",
            },
          };

          const sanctionsRes = await evaluateSanctions(
            dummySanctionsReq,
            options.circuitBreakerKv,
          );

          if (!sanctionsRes.clean && sanctionsRes.match) {
            const is50Rule = sanctionsRes.rule50_result !== undefined;
            const errCode = is50Rule ? "SANCTIONS_50_RULE_VIOLATION" : "SANCTIONED_ENTITY_MATCH";
            const errMsg = is50Rule
              ? sanctionsRes.rule50_result!.explanation
              : `Vizier Sanctions Gate: tool call '${fnName}' matched sanctioned entity '${sanctionsRes.match.entity_name}' (${sanctionsRes.match.list}).`;

            console.warn(
              JSON.stringify({
                event: "vizier.proxy.sanctions_blocked",
                session_id: sessionId,
                tool_name: fnName,
                code: errCode,
                match: sanctionsRes.match,
              }),
            );

            return openAiError(
              errMsg,
              errCode,
              403,
              "vizier_sanctions_violation",
              `tool_calls[${tIdx}].function.arguments`,
              {
                match: sanctionsRes.match,
                ...(sanctionsRes.rule50_result ? { rule50_result: sanctionsRes.rule50_result } : {}),
              },
            );
          }

          // D. Post-LLM Quorum Gate (4-Eyes Principle) on sensitive tools
          const customQuorumActions = request.headers
            .get("X-Quorum-Actions")
            ?.split(",")
            .map((s) => s.trim())
            .filter(Boolean) || [];

          const isSensitive =
            (DEFAULT_SENSITIVE_ACTIONS as readonly string[]).includes(fnName) ||
            customQuorumActions.includes(fnName);

          if (isSensitive) {
            const suppliedProposalId = request.headers.get("X-Quorum-Proposal-Id");
            let quorumApproved = false;

            const currentAction: VerificationRequest["action"] = {
              type: fnName,
              target: fnName,
              parameters: parsedArgs as VerificationRequest["action"]["parameters"],
            };
            const currentActionHash = await computeActionHash(currentAction);

            if (suppliedProposalId && options.circuitBreakerKv !== undefined) {
              const prop = await getQuorumProposal(
                suppliedProposalId,
                options.circuitBreakerKv,
              );

              if (prop === null) {
                return openAiError(
                  `Vizier Quorum Gate: proposal '${suppliedProposalId}' not found.`,
                  "PROPOSAL_NOT_FOUND",
                  403,
                  "vizier_proposal_not_found",
                  `tool_calls[${tIdx}]`,
                  { proposal_id: suppliedProposalId },
                );
              }

              if (prop.status === "CONSUMED") {
                return openAiError(
                  `Vizier Quorum Gate: proposal '${suppliedProposalId}' has already been executed. Dual-control proposals are single-use and cannot be replayed.`,
                  "PROPOSAL_ALREADY_CONSUMED",
                  403,
                  "vizier_proposal_already_consumed",
                  `tool_calls[${tIdx}]`,
                  { proposal_id: suppliedProposalId },
                );
              }

              if (prop.status === "EXPIRED" || Date.parse(prop.expires_at) < Date.now()) {
                return openAiError(
                  `Vizier Quorum Gate: proposal '${suppliedProposalId}' has expired.`,
                  "PROPOSAL_EXPIRED",
                  403,
                  "vizier_proposal_expired",
                  `tool_calls[${tIdx}]`,
                  { proposal_id: suppliedProposalId, expires_at: prop.expires_at },
                );
              }

              if (prop.action_hash !== currentActionHash) {
                return openAiError(
                  `Vizier Quorum Gate: proposal '${suppliedProposalId}' action hash does not match current tool call. Dual-control approval cannot be reused across different actions or parameters.`,
                  "QUORUM_ACTION_MISMATCH",
                  403,
                  "vizier_quorum_action_mismatch",
                  `tool_calls[${tIdx}]`,
                  {
                    proposal_id: suppliedProposalId,
                    expected_action_hash: currentActionHash,
                    proposal_action_hash: prop.action_hash,
                  },
                );
              }

              if (prop.status === "APPROVED") {
                quorumApproved = true;
                await consumeQuorumProposal(suppliedProposalId, options.circuitBreakerKv);
              }
            }

            if (!quorumApproved) {
              // Auto-create proposal in KV if KV is available
              let createdProposalId = `prp_${crypto.randomUUID().slice(0, 12)}`;
              if (options.circuitBreakerKv !== undefined) {
                const newProp = await createQuorumProposal({
                  kv: options.circuitBreakerKv,
                  proposer: { id: sessionId, owner: null },
                  action: {
                    type: fnName,
                    target: fnName,
                    parameters: parsedArgs as VerificationRequest["action"]["parameters"],
                  },
                  constraints: {
                    min_approvals: 2,
                  },
                });
                createdProposalId = newProp.proposal_id;
              }

              console.warn(
                JSON.stringify({
                  event: "vizier.proxy.quorum_required",
                  session_id: sessionId,
                  tool_name: fnName,
                  proposal_id: createdProposalId,
                }),
              );

              return openAiError(
                `Vizier Quorum Gate: sensitive tool '${fnName}' requires dual-control approval (4-eyes principle). Proposal created: ${createdProposalId}`,
                "QUORUM_REQUIRED",
                403,
                "vizier_quorum_required",
                `tool_calls[${tIdx}]`,
                {
                  proposal_id: createdProposalId,
                  action_type: fnName,
                  required_approvals: 2,
                  status: "PROPOSED",
                  approve_endpoint: "/v1/quorum/approve",
                },
              );
            }
          }
        }
      }
    }
  }

  // 7. Mint cryptographic JWS receipt if signing key configured
  let receiptToken: string | undefined;
  if (options.receiptSigningKey) {
    try {
      const receiptPayload = {
        iss: "vizier.ai",
        sub: sessionId,
        aud: "transparent-ai-proxy",
        iat: Math.floor(Date.now() / 1000),
        decision: "ALLOW",
        model: payload.model,
        guardrails: ["DLP", "CIRCUIT_BREAKER", "QUORUM"],
      };
      receiptToken = await signCompactJws(
        receiptPayload,
        options.receiptSigningKey,
        "application/vizier-receipt+jwt",
      );
    } catch (jwsErr) {
      console.error("Failed to sign receipt in proxy:", jwsErr);
    }
  }

  const latencyMs = (performance.now() - startedAt).toFixed(2);
  const responseHeaders: Record<string, string> = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "X-Vizier-Status": "PASSED",
    "X-Vizier-Guardrails": "DLP,CircuitBreaker,Quorum",
    "X-Vizier-Latency-Ms": latencyMs,
  };
  if (receiptToken) {
    responseHeaders["X-Vizier-Receipt"] = receiptToken;
  }

  return new Response(JSON.stringify(responseData), {
    status: 200,
    headers: responseHeaders,
  });
}
