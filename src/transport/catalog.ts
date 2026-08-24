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
    ],
  });
}
