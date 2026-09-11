import {
  evaluateEdgeCircuitBreaker,
  type EdgeCircuitBreakerResult,
} from "../core/circuit-breaker";
import {
  scanDlpParameters,
  scanDlpText,
  type DlpFinding,
} from "../core/dlp";
import {
  createQuorumProposal,
  getQuorumProposal,
} from "../core/quorum";
import { DEFAULT_SENSITIVE_ACTIONS } from "../core/policies";
import { sha256 } from "../core/receipts";
import { signCompactJws } from "../crypto/jws";
import {
  jsonResponse,
  readLimitedJson,
  type TransportOptions,
  TransportRequestError,
} from "../transport/shared";
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
 * Returns true if authenticated or if no apiKey is configured.
 */
function isVizierAuthenticated(
  request: Request,
  options: TransportOptions,
): boolean {
  if (!options.apiKey || options.apiKey.length === 0) {
    return true;
  }
  const vizierHeader = request.headers.get("X-Vizier-Key");
  if (vizierHeader && vizierHeader === options.apiKey) {
    return true;
  }
  const authHeader = request.headers.get("Authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice("Bearer ".length).trim();
    if (token === options.apiKey) {
      return true;
    }
  }
  return false;
}

/**
 * Resolves the upstream authorization header and target URL.
 */
function resolveUpstream(
  request: Request,
  options: TransportOptions,
): { upstreamUrl: string; upstreamAuthHeader: string | null } {
  const upstreamUrl =
    request.headers.get("X-Upstream-Url") ||
    options.upstreamUrl ||
    "https://api.openai.com/v1/chat/completions";

  let upstreamAuthHeader: string | null = null;
  const upstreamKey = request.headers.get("X-Upstream-Key");
  if (upstreamKey) {
    upstreamAuthHeader = `Bearer ${upstreamKey}`;
  } else {
    const authHeader = request.headers.get("Authorization");
    // If the Authorization header is NOT the Vizier API key, forward it to upstream
    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.slice("Bearer ".length).trim();
      if (!options.apiKey || token !== options.apiKey) {
        upstreamAuthHeader = authHeader;
      }
    }
  }

  return { upstreamUrl, upstreamAuthHeader };
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
  if (!isVizierAuthenticated(request, options)) {
    return openAiError(
      "Unauthorized: Invalid or missing Vizier API key. Provide it via 'Authorization: Bearer <key>' or 'X-Vizier-Key' header.",
      "invalid_api_key",
      401,
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
  const { upstreamUrl, upstreamAuthHeader } = resolveUpstream(request, options);
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
  // If streaming is requested, return pass-through with security headers
  if (payload.stream === true) {
    return new Response(upstreamResponse.body, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*",
        "X-Vizier-Status": "STREAMING_PASSED",
        "X-Vizier-Guardrails": "DLP,CircuitBreaker",
      },
    });
  }

  // Non-streaming JSON response inspection
  let responseData: any;
  try {
    responseData = await upstreamResponse.json();
  } catch {
    return openAiError("Upstream returned non-JSON response.", "invalid_upstream_response", 502);
  }

  const choices = responseData?.choices;
  if (Array.isArray(choices) && choices.length > 0) {
    for (const choice of choices) {
      const toolCalls = choice?.message?.tool_calls;
      if (Array.isArray(toolCalls) && toolCalls.length > 0) {
        for (let tIdx = 0; tIdx < toolCalls.length; tIdx++) {
          const toolCall = toolCalls[tIdx];
          const fnName = toolCall?.function?.name || "unknown_tool";
          const rawArgs = toolCall?.function?.arguments || "{}";

          let parsedArgs: Record<string, unknown> = {};
          try {
            parsedArgs = JSON.parse(rawArgs);
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
                parameters: parsedArgs,
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

          // C. Post-LLM Quorum Gate (4-Eyes Principle) on sensitive tools
          const customQuorumActions = request.headers
            .get("X-Quorum-Actions")
            ?.split(",")
            .map((s) => s.trim())
            .filter(Boolean) || [];

          const isSensitive =
            DEFAULT_SENSITIVE_ACTIONS.includes(fnName as any) ||
            customQuorumActions.includes(fnName);

          if (isSensitive) {
            const suppliedProposalId = request.headers.get("X-Quorum-Proposal-Id");
            let quorumApproved = false;

            if (suppliedProposalId && options.circuitBreakerKv !== undefined) {
              const prop = await getQuorumProposal(
                suppliedProposalId,
                options.circuitBreakerKv,
              );
              if (prop !== null && prop.status === "APPROVED") {
                quorumApproved = true;
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
                    parameters: parsedArgs as any,
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
