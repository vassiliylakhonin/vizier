import { z } from "zod";

import { verificationRequestSchema, verifyAction } from "../core/index";
import {
  jsonResponse,
  readLimitedJson,
  type TransportOptions,
  TransportRequestError,
  resolvePrincipalKeys,
} from "./shared";
import { authorizeEnforcement } from "./auth";
import { SERVICE_VERSION } from "../version";

const A2A_PROTOCOL_VERSION = "1.0";

const jsonRpcIdSchema = z.union([z.string(), z.number().finite()]);

const jsonRpcRequestSchema = z.strictObject({
  jsonrpc: z.literal("2.0"),
  id: jsonRpcIdSchema,
  method: z.string().min(1),
  params: z.unknown().optional(),
});

const partSchema = z
  .strictObject({
    // Клиенты v0.x и большинство JSON-RPC-библиотек помечают Part полем
    // kind ("text" | "data" | "file"). Содержания оно не несёт — какое поле
    // заполнено, видно и так, — но strictObject без него отклоняет запрос
    // целиком. Принимается и игнорируется.
    kind: z.string().optional(),
    text: z.string().optional(),
    raw: z.string().optional(),
    url: z.url().optional(),
    data: z.unknown().optional(),
    metadata: z.record(z.string(), z.unknown()).optional(),
    filename: z.string().optional(),
    mediaType: z.string().optional(),
  })
  .refine(
    (part) =>
      [part.text, part.raw, part.url, part.data].filter((value) => value !== undefined)
        .length === 1,
    { message: "A Part must contain exactly one content field." },
  );

const sendMessageParamsSchema = z.strictObject({
  tenant: z.string().optional(),
  message: z.strictObject({
    messageId: z.string().min(1),
    contextId: z.string().min(1).optional(),
    taskId: z.string().min(1).optional(),
    // В protobuf-представлении A2A роль пишется ROLE_USER, в JSON-RPC —
    // "user". Спецификация допускает оба, клиенты шлют то одно, то другое, и
    // отвергать половину из-за написания — это отказ по орфографии, а не по
    // смыслу. Нормализуется к ROLE_USER, чтобы ниже по коду написание было одно.
    role: z
      .union([z.literal("ROLE_USER"), z.literal("user")])
      .transform(() => "ROLE_USER" as const),
    parts: z.array(partSchema).min(1),
    metadata: z.record(z.string(), z.unknown()).optional(),
    extensions: z.array(z.url()).optional(),
    referenceTaskIds: z.array(z.string()).optional(),
  }),
  configuration: z.record(z.string(), z.unknown()).optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

type JsonRpcId = z.infer<typeof jsonRpcIdSchema> | null;

function jsonRpcError(
  id: JsonRpcId,
  code: number,
  message: string,
  status = 200,
  data?: unknown,
): Response {
  return jsonResponse(
    {
      jsonrpc: "2.0",
      id,
      error: { code, message, ...(data === undefined ? {} : { data }) },
    },
    status,
  );
}

// Measured 2026-08-18 against the deployed Worker: a caller who sent a
// plain-language message to /a2a got `-32602 A JSON data Part is required.`
// and nothing else — no field list, no example, no address for a human. A
// refusal that names no remedy is a dead end at the first call, so every
// refusal below carries this guidance in the JSON-RPC error `data`.
const REQUEST_GUIDANCE = Object.freeze({
  what_this_endpoint_does:
    "Evaluates one proposed agent action against the authority you supply and returns ALLOW, REVIEW, or BLOCK with a signed receipt.",
  how_to_send:
    "POST a JSON-RPC 2.0 SendMessage request with header `A2A-Version: 1.0`. The verification request goes in a message part as `data` — a text part is not read.",
  required_fields: [
    "agent — { id, owner }",
    "action — { type, target, parameters }",
    "authority — { allowed_actions[], constraints }",
    "context — { request_id, timestamp, source }",
    "principal — { id } (optional)",
  ],
  example_request: {
    jsonrpc: "2.0",
    id: "1",
    method: "SendMessage",
    params: {
      message: {
        messageId: "message-1",
        role: "ROLE_USER",
        parts: [
          {
            data: {
              agent: { id: "procurement-agent-01", owner: "acme-corp" },
              principal: { id: "acme-corp" },
              action: {
                type: "purchase",
                target: "supplier.example",
                parameters: { amount: 8200, currency: "USD" },
              },
              authority: {
                allowed_actions: ["purchase"],
                constraints: {
                  max_amount: 10000,
                  currency: "USD",
                  allowed_targets: ["supplier.example"],
                },
              },
              context: {
                request_id: "allow-example-01",
                timestamp: null,
                source: "a2a",
              },
            },
          },
        ],
      },
    },
  },
  decisions: ["ALLOW", "REVIEW", "BLOCK"],
  other_routes: {
    field_reference: "GET /docs",
    worked_examples: "GET /examples",
    agent_card: "GET /.well-known/agent-card.json",
    rest_equivalent: "POST /v1/verify",
  },
  boundary:
    "Deterministic policy evaluation only. Not a factuality verifier, no live source retrieval; REVIEW means a human decides before the action.",
  contact: "vassiliy.lakhonin@gmail.com",
});

export function createAgentCard(origin: string): Readonly<Record<string, unknown>> {
  return Object.freeze({
    name: "Vizier",
    description:
      "Evaluates proposed agent actions against supplied authority and deterministic policy. Not a factuality verifier; no live source retrieval. REVIEW requires a human decision before the external action.",
    provider: {
      organization: "Vassiliy Lakhonin",
      url: "https://github.com/vassiliylakhonin",
    },
    supportedInterfaces: [
      {
        url: `${origin}/a2a`,
        protocolBinding: "JSONRPC",
        protocolVersion: A2A_PROTOCOL_VERSION,
      },
    ],
    version: SERVICE_VERSION,
    documentationUrl: `${origin}/docs`,
    capabilities: {
      streaming: false,
      pushNotifications: false,
      extendedAgentCard: false,
      extensions: [
        {
          uri: "https://vizier.dev/extensions/security-posture/v1",
          description: "Vizier Security Posture and Data Retention",
          required: false,
          params: {
            zero_retention_guarantee: false,
            prompt_retention: "none",
            payload_persistence: "ephemeral_verification; reviews_7_days; financial_claims_until_resolved_plus_7_days",
            dlp_sanitization: "real_time",
            context_isolation_verified: true,
            eval_framework_safe: true,
            data_handling: [
              "No payment credentials accepted.",
              "Verification payloads remain ephemeral. Explicit /v1/reviews submissions persist for seven days; unresolved financial claims persist until reconciled, then at least seven more days; policy audits persist until operator removal; do not submit secrets or confidential documents.",
              "Audit ledger stores cryptographic action hashes and signed clearance receipts only."
            ]
          }
        }
      ],
    },
    securitySchemes: {
      bearerAuth: {
        httpAuthSecurityScheme: {
          scheme: "Bearer",
          description:
            "Integration credential required for enforcement results. Anonymous A2A calls are evaluation-only and cannot return ALLOW.",
        },
      },
    },
    // A2A v1 SecurityRequirement is a single `schemes` map of scheme name to
    // StringList, not a bare map of name to scopes. An independent conformance
    // scan on 2026-08-23 rejected the card on exactly this: the bare form puts
    // `bearerAuth` where the schema allows only `schemes`. First entry empty:
    // anonymous evaluation is allowed.
    securityRequirements: [{ schemes: {} }, { schemes: { bearerAuth: { list: [] } } }],
    defaultInputModes: ["application/json"],
    defaultOutputModes: ["application/json"],
    skills: [
      {
        id: "verify_agent_action",
        name: "Verify Agent Action",
        description:
          "Evaluate whether a proposed agent action is allowed by delegated authority, policy, target, and context.",
        tags: ["authorization", "policy", "agent-actions"],
        examples: [
          "Verify a procurement action against an amount limit and target allowlist.",
        ],
        inputModes: ["application/json"],
        outputModes: ["application/json"],
      },
      {
        id: "evaluate_delegated_authority",
        name: "Evaluate Delegated Authority",
        description:
          "Determine whether an agent has sufficient delegated authority for a requested action.",
        tags: ["delegation", "authority", "least-privilege"],
        inputModes: ["application/json"],
        outputModes: ["application/json"],
      },
      {
        id: "generate_verification_receipt",
        name: "Generate Verification Receipt",
        description:
          "Return an auditable machine-readable receipt for an authorization decision.",
        tags: ["receipt", "audit", "verification"],
        inputModes: ["application/json"],
        outputModes: ["application/json"],
      },
      {
        id: "activate_action_covenant",
        name: "Activate Action Covenant",
        description:
          "Through authenticated REST, activate one exact-action covenant after the integration supplies principal acceptance bound to the draft hash.",
        tags: ["action-covenant", "acceptance", "rest"],
        examples: [
          "Activate a deployment covenant accepted by the principal for one exact target and parameter set.",
        ],
        inputModes: ["application/json"],
        outputModes: ["application/json"],
      },
      {
        id: "authorize_covenant_action",
        name: "Authorize Covenant Action",
        description:
          "Through authenticated REST, authorize an exact action against an active covenant, supplied evidence, and invalidation signals, returning a signed authorization receipt.",
        tags: ["action-covenant", "authorization", "signed-receipt", "rest"],
        examples: [
          "Authorize the exact deployment action bound to an active covenant before execution.",
        ],
        inputModes: ["application/json"],
        outputModes: ["application/json"],
      },
      {
        id: "record_action_outcome",
        name: "Record Action Outcome",
        description:
          "Through authenticated REST, bind a caller-reported execution outcome to a valid ALLOW receipt and return a signed outcome receipt. Not independent execution proof.",
        tags: ["action-covenant", "reported-outcome", "signed-receipt", "rest"],
        examples: [
          "Record the reported result of an authorized deployment and bind it to the authorization receipt.",
        ],
        inputModes: ["application/json"],
        outputModes: ["application/json"],
      },
    ],
  });
}

export async function handleA2aRequest(
  request: Request,
  options: TransportOptions = {},
): Promise<Response> {
  // Отсутствие заголовка — это «версию не назвали», а не «назвали 0.3».
  // Подставлять сюда легаси-строку, которую следующая же строка отвергает,
  // значит закрыть эндпоинт для всех, кто не знает про необязательный
  // заголовок, — то есть почти для всех. Замерено 2026-08-23 независимым
  // сканером a2a-scorecard: проверка C020 «отвечает ли агент на
  // спеко-корректный SendMessage по адресу, который объявляет его же
  // карточка» провалена именно здесь, и агент попал в публичные 63%
  // неотвечающих. Явно названная неподдерживаемая версия по-прежнему
  // отвергается — меняется только умолчание.
  const requestedVersion = request.headers.get("A2A-Version") ?? A2A_PROTOCOL_VERSION;
  if (requestedVersion !== A2A_PROTOCOL_VERSION) {
    return jsonRpcError(
      null,
      -32009,
      `A2A protocol version ${requestedVersion} is not supported; use ${A2A_PROTOCOL_VERSION}.`,
    );
  }

  const authorization = await authorizeEnforcement(request, options.apiKey, {
    allowMissingCredentialForEvaluation: true,
  });
  if (authorization === "denied") {
    return jsonRpcError(
      null,
      -32001,
      "A valid Bearer token is required for enforcement mode.",
      401,
    );
  }

  let input: unknown;
  try {
    input = await readLimitedJson(request);
  } catch (error) {
    if (error instanceof TransportRequestError) {
      if (error.code === "UNSUPPORTED_MEDIA_TYPE") {
        return jsonRpcError(null, -32005, "Content type not supported.");
      }
      if (error.code === "INVALID_JSON") {
        return jsonRpcError(null, -32700, "Invalid JSON payload");
      }
      return jsonRpcError(null, -32600, "Request payload validation error", error.status);
    }
    return jsonRpcError(null, -32603, "Internal error");
  }

  const envelope = jsonRpcRequestSchema.safeParse(input);
  if (!envelope.success) {
    return jsonRpcError(null, -32600, "Request payload validation error");
  }
  const { id, method, params } = envelope.data;
  // Карточка объявляет привязку JSONRPC версии 1.0, а каноническое имя метода
  // в этой привязке — message/send; SendMessage приходит из gRPC-имени того же
  // вызова. Обслуживаются оба: клиент, читающий карточку буквально, шлёт
  // первое, сканеры и старые клиенты — второе.
  if (method !== "SendMessage" && method !== "message/send") {
    return jsonRpcError(id, -32601, "Method not found", 200, REQUEST_GUIDANCE);
  }

  const sendMessage = sendMessageParamsSchema.safeParse(params);
  if (!sendMessage.success) {
    return jsonRpcError(id, -32602, "Invalid parameters", 200, REQUEST_GUIDANCE);
  }

  const dataPart = sendMessage.data.message.parts.find(
    (part) => part.data !== undefined,
  );
  if (dataPart?.data === undefined) {
    // Сообщение без data-части — это не сломанный протокол, а собеседник,
    // который ещё не знает, чего от него хотят: так выглядят и пробы
    // каталогов, и первый заход человека. Ответ уровня протокола (-32602)
    // здесь не по адресу — запрос сформирован верно, — и всякий, кто читает
    // ответ как A2A-сообщение, видит только ошибку. Поэтому тем же
    // руководством отвечаем в виде обычного Message: оно и машиночитаемо, и
    // попадает в диалог, а не в транспортный слой.
    return jsonResponse({
      jsonrpc: "2.0",
      id,
      result: {
        message: {
          messageId: `message_${crypto.randomUUID()}`,
          contextId: sendMessage.data.message.contextId ?? `ctx_${crypto.randomUUID()}`,
          role: "ROLE_AGENT",
          parts: [
            {
              text:
                "Vizier evaluates one proposed agent action against the authority you supply and returns ALLOW, REVIEW or BLOCK with a signed receipt. " +
                "Send the verification request as a JSON object in a `data` part of the message; a text part is not read. " +
                "The required fields, a worked example and an address for questions are in the data part of this reply.",
            },
            { data: REQUEST_GUIDANCE, mediaType: "application/json" },
          ],
          metadata: { skillId: "verify_agent_action", guidance: true },
        },
      },
    });
  }
  const verification = verificationRequestSchema.safeParse(dataPart.data);
  if (!verification.success) {
    return jsonRpcError(id, -32602, "Verification request is invalid.", 200, {
      ...REQUEST_GUIDANCE,
      validation_errors: verification.error.issues.map((issue) => ({
        code: issue.code,
        path: issue.path.map(String),
        message: issue.message,
      })),
    });
  }

  const normalizedRequest = {
    ...verification.data,
    context: { ...verification.data.context, source: "a2a" as const },
  };
  const result = await verifyAction(normalizedRequest, {
    trustedAuthority: authorization === "authenticated",
    principalKeys: resolvePrincipalKeys(options),
  });
  const contextId =
    sendMessage.data.message.contextId ?? `ctx_${crypto.randomUUID()}`;
  const taskId = `task_${crypto.randomUUID()}`;
  const createdAt = new Date().toISOString();

  console.log(
    JSON.stringify({
      event: "vizier.a2a.completed",
      request_id: normalizedRequest.context.request_id ?? String(id),
      receipt_id: result.receipt.id,
      decision: result.decision,
      reason_codes: result.reason_codes,
    }),
  );

  return jsonResponse({
    jsonrpc: "2.0",
    id,
    result: {
      task: {
        id: taskId,
        contextId,
        status: {
          state: "TASK_STATE_COMPLETED",
          timestamp: createdAt,
        },
        artifacts: [
          {
            artifactId: `artifact_${crypto.randomUUID()}`,
            name: "verification-decision",
            description: "Vizier authorization decision and audit receipt.",
            parts: [{ data: result, mediaType: "application/json" }],
          },
        ],
        history: [sendMessage.data.message],
        metadata: { skillId: "verify_agent_action" },
      },
    },
  });
}
