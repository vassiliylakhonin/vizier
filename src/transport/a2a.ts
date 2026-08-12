import { z } from "zod";

import { verificationRequestSchema, verifyAction } from "../core/index";
import {
  jsonResponse,
  readLimitedJson,
  type TransportOptions,
  TransportRequestError,
} from "./shared";
import { authorizeEnforcement } from "./auth";

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
    role: z.literal("ROLE_USER"),
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
): Response {
  return jsonResponse({ jsonrpc: "2.0", id, error: { code, message } }, status);
}

export function createAgentCard(origin: string): Readonly<Record<string, unknown>> {
  return Object.freeze({
    name: "Vizier",
    description:
      "Evaluates proposed agent actions against supplied authority and deterministic policy. Not a factuality verifier; no live source retrieval. REVIEW requires a human decision before the external action.",
    provider: {
      organization: "Vassiliy Lakhonin",
      url: "https://vassiliylakhonin.github.io/",
    },
    supportedInterfaces: [
      {
        url: `${origin}/a2a`,
        protocolBinding: "JSONRPC",
        protocolVersion: A2A_PROTOCOL_VERSION,
      },
    ],
    version: "0.1.0",
    documentationUrl: `${origin}/docs`,
    capabilities: {
      streaming: false,
      pushNotifications: false,
      extendedAgentCard: false,
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
    securityRequirements: [{}, { bearerAuth: [] }],
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
    ],
  });
}

export async function handleA2aRequest(
  request: Request,
  options: TransportOptions = {},
): Promise<Response> {
  const requestedVersion = request.headers.get("A2A-Version") || "0.3";
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
  if (method !== "SendMessage") {
    return jsonRpcError(id, -32601, "Method not found");
  }

  const sendMessage = sendMessageParamsSchema.safeParse(params);
  if (!sendMessage.success) {
    return jsonRpcError(id, -32602, "Invalid parameters");
  }

  const dataPart = sendMessage.data.message.parts.find(
    (part) => part.data !== undefined,
  );
  if (dataPart?.data === undefined) {
    return jsonRpcError(id, -32602, "A JSON data Part is required.");
  }
  const verification = verificationRequestSchema.safeParse(dataPart.data);
  if (!verification.success) {
    return jsonRpcError(id, -32602, "Verification request is invalid.");
  }

  const normalizedRequest = {
    ...verification.data,
    context: { ...verification.data.context, source: "a2a" as const },
  };
  const result = await verifyAction(normalizedRequest, {
    trustedAuthority: authorization === "authenticated",
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
