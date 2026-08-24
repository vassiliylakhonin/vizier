import { z, type ZodType } from "zod";

import {
  actionCovenantActivationRequestSchema,
  actionCovenantAuthorizationRequestSchema,
  actionCovenantSchema,
  authorizationReceiptPayloadSchema,
  covenantAcceptanceSchema,
  evidenceObservationSchema,
  executionOutcomeSchema,
  outcomeReceiptPayloadSchema,
  outcomeRecordingRequestSchema,
  signalObservationSchema,
  signedAuthorizationReceiptSchema,
  signedOutcomeReceiptSchema,
} from "../covenants/schemas";
import {
  actionSchema,
  agentSchema,
  authoritySchema,
  contextSchema,
  jsonValueSchema,
  principalSchema,
  verificationRequestSchema,
} from "../core/schemas";
import {
  actionCovenantAuthorizationResponseContractSchema,
  apiErrorContractSchema,
  verificationResponseContractSchema,
} from "./contracts";

const registry = z.registry<{ id: string }>();
const schemas: ReadonlyArray<readonly [string, ZodType]> = [
  ["JsonValue", jsonValueSchema],
  ["Agent", agentSchema],
  ["Principal", principalSchema],
  ["Action", actionSchema],
  ["Authority", authoritySchema],
  ["RequestContext", contextSchema],
  ["VerificationRequest", verificationRequestSchema],
  ["VerificationResponse", verificationResponseContractSchema],
  ["CovenantAcceptance", covenantAcceptanceSchema],
  ["ActionCovenantActivationRequest", actionCovenantActivationRequestSchema],
  ["ActionCovenant", actionCovenantSchema],
  ["EvidenceObservation", evidenceObservationSchema],
  ["SignalObservation", signalObservationSchema],
  ["ActionCovenantAuthorizationRequest", actionCovenantAuthorizationRequestSchema],
  ["AuthorizationReceiptPayload", authorizationReceiptPayloadSchema],
  ["SignedAuthorizationReceipt", signedAuthorizationReceiptSchema],
  ["ActionCovenantAuthorizationResponse", actionCovenantAuthorizationResponseContractSchema],
  ["ExecutionOutcome", executionOutcomeSchema],
  ["OutcomeRecordingRequest", outcomeRecordingRequestSchema],
  ["OutcomeReceiptPayload", outcomeReceiptPayloadSchema],
  ["SignedOutcomeReceipt", signedOutcomeReceiptSchema],
  ["ApiError", apiErrorContractSchema],
];

for (const [id, schema] of schemas) {
  registry.add(schema, { id });
}

function createComponentSchemas(): Readonly<Record<string, unknown>> {
  const generated = z.toJSONSchema(registry, {
    target: "draft-2020-12",
    io: "input",
    uri: (id) => `#/components/schemas/${id}`,
  }).schemas;
  return Object.freeze(
    Object.fromEntries(
      Object.entries(generated).map(([id, schema]) => {
        const component = { ...schema } as Record<string, unknown>;
        delete component.$id;
        delete component.$schema;
        return [id, Object.freeze(component)];
      }),
    ),
  );
}

const COMPONENT_SCHEMAS = createComponentSchemas();
const ERROR_RESPONSE_REFS = Object.freeze({
  "400": { $ref: "#/components/responses/BadRequest" },
  "401": { $ref: "#/components/responses/Unauthorized" },
  "413": { $ref: "#/components/responses/PayloadTooLarge" },
  "415": { $ref: "#/components/responses/UnsupportedMediaType" },
  "422": { $ref: "#/components/responses/ValidationError" },
  "500": { $ref: "#/components/responses/InternalError" },
});

function jsonContent(schemaRef: string): Readonly<Record<string, unknown>> {
  return {
    "application/json": {
      schema: { $ref: `#/components/schemas/${schemaRef}` },
    },
  };
}

function requestBody(schemaRef: string): Readonly<Record<string, unknown>> {
  return {
    required: true,
    content: jsonContent(schemaRef),
  };
}

function successResponse(
  description: string,
  schemaRef: string,
): Readonly<Record<string, unknown>> {
  return {
    description,
    content: jsonContent(schemaRef),
  };
}

function errorResponse(description: string): Readonly<Record<string, unknown>> {
  return {
    description,
    content: jsonContent("ApiError"),
  };
}

export function createOpenApiDocument(
  origin: string,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    openapi: "3.1.0",
    jsonSchemaDialect: "https://json-schema.org/draft/2020-12/schema",
    info: {
      title: "Vizier action authorization API",
      version: "0.2.1",
      description:
        "Deterministic authorization for exact agent actions. The integration supplies authority, evidence, invalidation signals, and reported outcomes. Vizier verifies structure, freshness, exact matching, and cryptographic bindings; it does not independently establish that supplied facts or reported execution are true.",
      contact: {
        name: "Vassiliy Lakhonin",
        url: "https://vassiliylakhonin.github.io/vizier-ai-agent-authorization.html",
      },
    },
    servers: [{ url: origin }],
    tags: [
      { name: "Verification", description: "Single-action policy evaluation." },
      {
        name: "Action Covenants",
        description:
          "Authenticated activation, exact-action authorization, and reported-outcome binding.",
      },
    ],
    security: [{ bearerAuth: [] }],
    paths: {
      "/v1/verify": {
        post: {
          operationId: "verifyAgentAction",
          tags: ["Verification"],
          summary: "Evaluate one proposed agent action",
          description:
            "Returns ALLOW, REVIEW, or BLOCK against caller-supplied authority. The public deployment requires a Bearer credential for enforcement results.",
          requestBody: requestBody("VerificationRequest"),
          responses: {
            "200": successResponse("Authorization decision.", "VerificationResponse"),
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/v1/covenants": {
        post: {
          operationId: "activateActionCovenant",
          tags: ["Action Covenants"],
          summary: "Activate an accepted exact-action covenant",
          description:
            "Checks that the authenticated integration supplied acceptance from the covenant principal bound to the exact draft hash. Principal-signed acceptance is not independently verified in v0.2.1.",
          requestBody: requestBody("ActionCovenantActivationRequest"),
          responses: {
            "201": successResponse("Activated Action Covenant.", "ActionCovenant"),
            ...ERROR_RESPONSE_REFS,
            "503": { $ref: "#/components/responses/ServiceUnavailable" },
          },
        },
      },
      "/v1/authorizations": {
        post: {
          operationId: "authorizeCovenantAction",
          tags: ["Action Covenants"],
          summary: "Authorize the exact action bound to a covenant",
          description:
            "Checks covenant integrity and expiry, exact action matching, supplied evidence freshness, supplied invalidation signals, and delegated authority. Returns a compact ES256 authorization JWS for every decision.",
          requestBody: requestBody("ActionCovenantAuthorizationRequest"),
          responses: {
            "200": successResponse(
              "Authorization decision and signed receipt.",
              "ActionCovenantAuthorizationResponse",
            ),
            ...ERROR_RESPONSE_REFS,
            "503": { $ref: "#/components/responses/ServiceUnavailable" },
          },
        },
      },
      "/v1/outcomes": {
        post: {
          operationId: "recordActionOutcome",
          tags: ["Action Covenants"],
          summary: "Bind a reported execution outcome to an authorization",
          description:
            "Verifies the ALLOW authorization receipt and exact bindings, checks forbidden-effect rules, and signs the caller-reported outcome. This is not independent proof that execution occurred as reported.",
          requestBody: requestBody("OutcomeRecordingRequest"),
          responses: {
            "201": successResponse("Signed reported-outcome receipt.", "SignedOutcomeReceipt"),
            ...ERROR_RESPONSE_REFS,
            "503": { $ref: "#/components/responses/ServiceUnavailable" },
          },
        },
      },
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          description:
            "Integration credential required by the public deployment. Anonymous A2A calls remain evaluation-only and cannot return ALLOW.",
        },
      },
      schemas: COMPONENT_SCHEMAS,
      responses: {
        BadRequest: errorResponse("Malformed JSON request."),
        Unauthorized: errorResponse("Missing or invalid integration credential."),
        PayloadTooLarge: errorResponse("Request exceeds the 64 KiB body limit."),
        UnsupportedMediaType: errorResponse("Content-Type must be application/json."),
        ValidationError: errorResponse("Request failed schema or lifecycle validation."),
        ServiceUnavailable: errorResponse(
          "Enforcement or receipt signing is not configured correctly.",
        ),
        InternalError: errorResponse("The request could not be processed."),
      },
    },
    externalDocs: {
      description: "Vizier product page and pilot boundary",
      url: "https://vassiliylakhonin.github.io/vizier-ai-agent-authorization.html",
    },
  });
}
