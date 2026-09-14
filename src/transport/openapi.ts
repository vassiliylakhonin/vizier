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
  auditInsightsContractSchema,
  verificationResponseContractSchema,
} from "./contracts";
import { SERVICE_VERSION } from "../version";

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
  ["AuditInsights", auditInsightsContractSchema],
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
      version: SERVICE_VERSION,
      description:
        "Deterministic authorization for exact agent actions. Authority may be asserted by the integration or proved with a delegation grant the principal signed, which Vizier verifies against a registered key and records in the receipt. Evidence, invalidation signals, and reported outcomes remain integration-supplied: Vizier verifies structure, freshness, exact matching, and cryptographic bindings, and does not independently establish that supplied facts or reported execution are true.",
      contact: {
        name: "Vassiliy Lakhonin",
        url: "https://github.com/vassiliylakhonin",
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
      {
        name: "Audit",
        description:
          "Authenticated aggregate counts over metadata-only operational records.",
      },
      {
        name: "AI Proxy",
        description: "OpenAI-compatible gateway with transparent edge guardrails.",
      },
      {
        name: "Circuit Breaker",
        description: "Session loop detection and budget reset controls.",
      },
      {
        name: "Sanctions",
        description: "Pre-action counterparty and entity sanctions screening.",
      },
      {
        name: "DLP",
        description: "Data loss prevention scanner for secrets and credentials.",
      },
      {
        name: "Quorum",
        description: "Dual-control (4-eyes principle) multi-party authorization.",
      },
      {
        name: "Admin",
        description: "Organization API key and monthly quota management.",
      },
      {
        name: "A2A",
        description: "Agent-to-Agent communication and cross-agent verification protocol.",
      },
      {
        name: "MCP",
        description: "Model Context Protocol JSON-RPC gateway and tool policy enforcement.",
      },
      {
        name: "Discovery",
        description: "Public metadata, capability descriptors, and cryptographic keysets.",
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
            "Returns ALLOW, REVIEW, or BLOCK. Authority is caller-asserted unless the request carries a `grant`: a compact JWS signed by the principal that binds this exact authority to this agent. A grant is verified against a key registered for the principal, must match the request, and is refused rather than downgraded when it does not verify. The receipt reports which of the two the decision rested on in `authority_provenance`. The public deployment requires a Bearer credential for enforcement results.",
          requestBody: requestBody("VerificationRequest"),
          responses: {
            "200": successResponse("Authorization decision.", "VerificationResponse"),
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/v1/verify/evaluate": {
        post: {
          operationId: "evaluateAgentAction",
          tags: ["Verification"],
          summary: "Safely evaluate one proposed agent action without audit log persistence",
          security: [],
          requestBody: requestBody("VerificationRequest"),
          responses: {
            "200": successResponse("Evaluation decision.", "VerificationResponse"),
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/playground/evaluate": {
        post: {
          operationId: "playgroundEvaluate",
          tags: ["Verification"],
          summary: "Safe anonymous action evaluation for browser playground",
          security: [],
          requestBody: requestBody("VerificationRequest"),
          responses: {
            "200": successResponse("Evaluation decision.", "VerificationResponse"),
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
      "/v1/insights": {
        get: {
          operationId: "getAuditInsights",
          tags: ["Audit"],
          summary: "Read aggregate authorization and outcome counts",
          description:
            "Returns authenticated operational aggregates. The audit store excludes action parameters, evidence, signals, outcome effects, credentials, and JWS tokens. Counts are best-effort instrumentation, not proof of adoption or complete execution history.",
          responses: {
            "200": successResponse("Metadata-only audit aggregates.", "AuditInsights"),
            "401": { $ref: "#/components/responses/Unauthorized" },
            "500": { $ref: "#/components/responses/InternalError" },
            "503": { $ref: "#/components/responses/ServiceUnavailable" },
          },
        },
      },
      "/v1/chat/completions": {
        post: {
          operationId: "createChatCompletion",
          tags: ["AI Proxy"],
          summary: "OpenAI-compatible chat completion proxy with DLP, Circuit Breaker, Sanctions and Quorum guardrails",
          responses: {
            "200": { description: "Chat completion response." },
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/v1/models": {
        get: {
          operationId: "listModels",
          tags: ["AI Proxy"],
          summary: "List available models supported by the proxy",
          security: [],
          responses: {
            "200": { description: "Model list response." },
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/v1/circuit-breaker/reset": {
        post: {
          operationId: "resetCircuitBreaker",
          tags: ["Circuit Breaker"],
          summary: "Reset tripped loop detection or action budget for a session",
          responses: {
            "200": { description: "Circuit breaker reset response." },
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/v1/sanctions/screen": {
        post: {
          operationId: "screenSanctions",
          tags: ["Sanctions"],
          summary: "Screen a proposed action or entity against sanctions lists",
          responses: {
            "200": { description: "Sanctions screening result." },
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/v1/sanctions/screen-entity": {
        post: {
          operationId: "screenSanctionsEntity",
          tags: ["Sanctions"],
          summary: "Screen an entity name and ownership graph against OFAC 50% rule",
          responses: {
            "200": { description: "Sanctions 50% rule screening result." },
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/v1/sanctions/entries": {
        post: {
          operationId: "addSanctionsEntry",
          tags: ["Sanctions"],
          summary: "Add custom sanction entry to edge KV registry",
          responses: {
            "201": { description: "Sanctions entry created." },
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/v1/dlp/scan": {
        post: {
          operationId: "scanDlp",
          tags: ["DLP"],
          summary: "Scan text or structured parameters for secrets and sensitive data",
          responses: {
            "200": { description: "DLP scan findings." },
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/v1/quorum/propose": {
        post: {
          operationId: "proposeQuorum",
          tags: ["Quorum"],
          summary: "Propose a dual-control quorum action",
          responses: {
            "201": { description: "Quorum proposal created." },
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/v1/quorum/approve": {
        post: {
          operationId: "approveQuorum",
          tags: ["Quorum"],
          summary: "Record approval or rejection for a quorum proposal",
          responses: {
            "200": { description: "Quorum approval recorded." },
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/v1/quorum/proposals/{proposal_id}": {
        get: {
          operationId: "getQuorumProposal",
          tags: ["Quorum"],
          summary: "Retrieve the current state and approval progress of a quorum proposal",
          parameters: [
            {
              name: "proposal_id",
              in: "path",
              required: true,
              schema: { type: "string" },
            },
          ],
          responses: {
            "200": { description: "Quorum proposal state." },
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/v1/admin/keys": {
        get: {
          operationId: "listAdminKeys",
          tags: ["Admin"],
          summary: "List multi-tenant API keys for an organization",
          responses: {
            "200": { description: "List of API key metadata." },
            ...ERROR_RESPONSE_REFS,
          },
        },
        post: {
          operationId: "createAdminKey",
          tags: ["Admin"],
          summary: "Create a new multi-tenant API key",
          responses: {
            "201": { description: "API key created with secret." },
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/v1/admin/keys/{key_id}": {
        delete: {
          operationId: "revokeAdminKey",
          tags: ["Admin"],
          summary: "Revoke a tenant API key",
          parameters: [
            {
              name: "key_id",
              in: "path",
              required: true,
              schema: { type: "string" },
            },
          ],
          responses: {
            "200": { description: "API key revoked." },
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/a2a": {
        post: {
          operationId: "handleA2aMessage",
          tags: ["A2A"],
          summary: "Agent-to-Agent (A2A) protocol endpoint for cross-agent verification",
          description: "Handles A2A SendMessage JSON-RPC requests for inter-agent delegation and verification.",
          security: [],
          responses: {
            "200": { description: "A2A JSON-RPC response." },
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/mcp": {
        post: {
          operationId: "handleMcpJsonRpc",
          tags: ["MCP"],
          summary: "Model Context Protocol (MCP) JSON-RPC 2.0 gateway and proxy",
          description: "Inspects and verifies MCP tool call requests before dispatching to upstream tool servers.",
          security: [],
          responses: {
            "200": { description: "MCP JSON-RPC response." },
            ...ERROR_RESPONSE_REFS,
          },
        },
      },
      "/.well-known/agent-card.json": {
        get: {
          operationId: "getAgentCard",
          tags: ["Discovery"],
          summary: "A2A Agent Card describing identity, capabilities, and verification skills",
          security: [],
          responses: {
            "200": { description: "A2A Agent Card JSON metadata." },
          },
        },
      },
      "/.well-known/agent.json": {
        get: {
          operationId: "getLegacyAgentCard",
          tags: ["Discovery"],
          summary: "Legacy A2A Agent Card alias",
          security: [],
          responses: {
            "200": { description: "A2A Agent Card JSON metadata." },
          },
        },
      },
      "/.well-known/mcp.json": {
        get: {
          operationId: "getMcpServerManifest",
          tags: ["Discovery"],
          summary: "MCP server manifest and tool registry descriptor",
          security: [],
          responses: {
            "200": { description: "MCP server manifest JSON." },
          },
        },
      },
      "/.well-known/ai-catalog.json": {
        get: {
          operationId: "getAiCatalog",
          tags: ["Discovery"],
          summary: "Machine discovery catalog for AI agents and services",
          security: [],
          responses: {
            "200": { description: "AI catalog JSON metadata." },
          },
        },
      },
      "/.well-known/llms.txt": {
        get: {
          operationId: "getLlmsTxt",
          tags: ["Discovery"],
          summary: "Curated text summary of Vizier policy enforcement engine for LLMs",
          security: [],
          responses: {
            "200": {
              description: "LLMs context plain text.",
              content: { "text/plain": { schema: { type: "string" } } },
            },
          },
        },
      },
      "/.well-known/agents.txt": {
        get: {
          operationId: "getAgentsTxt",
          tags: ["Discovery"],
          summary: "Agent discovery index and system directives",
          security: [],
          responses: {
            "200": {
              description: "Agents discovery plain text.",
              content: { "text/plain": { schema: { type: "string" } } },
            },
          },
        },
      },
      "/.well-known/ard.json": {
        get: {
          operationId: "getAgentResourceDescriptor",
          tags: ["Discovery"],
          summary: "Agent Resource Descriptor and capability discovery",
          security: [],
          responses: {
            "200": { description: "ARD JSON metadata." },
          },
        },
      },
      "/.well-known/glama.json": {
        get: {
          operationId: "getGlamaManifest",
          tags: ["Discovery"],
          summary: "Glama MCP server ownership verification manifest",
          security: [],
          responses: {
            "200": { description: "Glama MCP server ownership metadata." },
          },
        },
      },
      "/.well-known/jwks.json": {
        get: {
          operationId: "getJwks",
          tags: ["Discovery"],
          summary: "Public JWKS keyset for receipt and card verification",
          security: [],
          responses: {
            "200": { description: "JWKS key set." },
          },
        },
      },
      "/.well-known/oauth-protected-resource": {
        get: {
          operationId: "getOAuthProtectedResourceMetadata",
          tags: ["Discovery"],
          summary: "RFC 9728 OAuth 2.0 Protected Resource Metadata for MCP",
          security: [],
          responses: {
            "200": { description: "OAuth Protected Resource JSON metadata." },
          },
        },
      },
      "/health": {
        get: {
          operationId: "getHealth",
          tags: ["Discovery"],
          summary: "Service health status",
          security: [],
          responses: {
            "200": { description: "Health status OK." },
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
        PayloadTooLarge: errorResponse("Request exceeds the 1 MiB body limit."),
        UnsupportedMediaType: errorResponse("Content-Type must be application/json."),
        ValidationError: errorResponse("Request failed schema or lifecycle validation."),
        ServiceUnavailable: errorResponse(
          "Enforcement or receipt signing is not configured correctly.",
        ),
        InternalError: errorResponse("The request could not be processed."),
      },
    },
  });
}
