export const MCP_SERVER_SCHEMA =
  "https://static.modelcontextprotocol.io/schemas/2025-09-29/server.schema.json";

export function createAiCatalog(origin: string): Readonly<Record<string, unknown>> {
  return Object.freeze({
    specVersion: "1.0",
    host: {
      displayName: "Vizier",
      documentationUrl: `${origin}/docs`,
    },
    entries: [
      {
        identifier: "urn:ai:vizier.vassiliy-lakhonin.workers.dev:agent:vizier",
        displayName: "Vizier",
        type: "application/a2a-agent-card+json",
        url: `${origin}/.well-known/agent-card.json`,
        description:
          "Deterministic authorization for proposed agent actions, with an authenticated Action Covenant lifecycle and signed authorization and reported-outcome receipts. Caller-supplied authority and evidence; not factuality verification or independent execution proof.",
        capabilities: [
          "verify-agent-action",
          "activate-action-covenant",
          "authorize-covenant-action",
          "record-action-outcome",
          "verify-signed-receipt",
        ],
        tags: [
          "agent-authorization",
          "action-covenant",
          "policy-engine",
          "signed-receipts",
          "a2a",
        ],
        representativeQueries: [
          "authorize an exact AI agent action before a write-capable tool call",
          "bind delegated authority and evidence to a signed action authorization",
          "record a reported execution outcome against an authorization receipt",
        ],
        updatedAt: "2026-08-24T00:00:00Z",
      },
      {
        identifier: "urn:ai:vizier.vassiliy-lakhonin.workers.dev:api:openapi",
        displayName: "Vizier action authorization API",
        type: "application/vnd.oai.openapi+json;version=3.1",
        url: `${origin}/openapi.json`,
        description:
          "OpenAPI 3.1 contract for verification, Action Covenant activation, exact-action authorization, and reported-outcome binding.",
        capabilities: [
          "rest-contract",
          "json-schema",
          "action-covenant-lifecycle",
        ],
        tags: ["openapi", "rest", "agent-authorization", "machine-discovery"],
        representativeQueries: [
          "find the machine-readable Vizier REST contract",
          "generate a client for the Vizier Action Covenant lifecycle",
        ],
        updatedAt: "2026-08-24T00:00:00Z",
      },
      {
        identifier: "urn:ai:vizier.vassiliy-lakhonin.workers.dev:mcp:vizier",
        displayName: "Vizier MCP server",
        type: `application/json;profile=${MCP_SERVER_SCHEMA}`,
        url: `${origin}/.well-known/mcp.json`,
        description:
          "MCP server manifest for the Streamable HTTP endpoint at /mcp, which exposes one tool, vizier_verify_action. Anonymous callers receive evaluation-only decisions; an integration credential unlocks enforcement results.",
        capabilities: [
          "verify-agent-action",
          "mcp-streamable-http",
          "tool-call-authorization",
        ],
        tags: ["mcp", "streamable-http", "agent-authorization", "tool-gating"],
        representativeQueries: [
          "connect an MCP client to a pre-execution authorization check",
          "gate an agent tool call on a deterministic ALLOW decision",
        ],
        registryEntry: "io.github.vassiliylakhonin/vizier",
        updatedAt: "2026-09-02T00:00:00Z",
      },
    ],
  });
}

// The same document `mcp-publisher` uploads from server.json at the repository
// root, served from the origin so a client that reached the Worker first can
// learn how to connect without going through the registry. Tests keep the two
// copies identical. No `repository` block: the source repository is private, and
// a registry entry pointing at a URL that answers 404 is worse than none.
export function createMcpServerManifest(
  origin: string,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    $schema: MCP_SERVER_SCHEMA,
    name: "io.github.vassiliylakhonin/vizier",
    description:
      "Deterministic authorization for one proposed AI agent action, returned with a signed receipt.",
    version: "0.2.1",
    websiteUrl: `${origin}/docs`,
    remotes: [
      {
        type: "streamable-http",
        url: `${origin}/mcp`,
        headers: [
          {
            name: "Authorization",
            description:
              "Bearer <integration credential>. Optional: an anonymous call returns an evaluation-only decision that never grants ALLOW, and the credential unlocks enforcement results.",
            isRequired: false,
            isSecret: true,
          },
        ],
      },
    ],
  });
}
