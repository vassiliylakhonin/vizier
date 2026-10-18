/** One protocol inventory for negotiation, discovery and connection recovery. */
export const MCP_PROTOCOL_VERSION = "2026-07-28";
export const SESSION_PROTOCOL_VERSIONS: readonly string[] = Object.freeze([
  "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05",
]);
export const DEFAULT_SESSION_PROTOCOL_VERSION = "2025-11-25";

export type McpRejection = "accept_mismatch" | "invalid_request" | "invalid_json"
  | "header_mismatch" | "unsupported_version" | "profile_method_mismatch"
  | "method_not_found" | "origin_rejected" | "body_too_large" | "content_type_mismatch";

export function connectionHint(reason: McpRejection) {
  const headers = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
  return {
    reason,
    endpoint: "/mcp",
    method: "POST",
    content_type: "application/json",
    accept: ["application/json", "text/event-stream"],
    recovery_requests: [
      {
        profile: "session", method: "POST", endpoint: "/mcp", headers,
        body: { jsonrpc: "2.0", id: "connect-session", method: "initialize", params: {
          protocolVersion: DEFAULT_SESSION_PROTOCOL_VERSION, capabilities: {},
          clientInfo: { name: "connection-recovery", version: "1" },
        } },
      },
      {
        profile: "stateless", method: "POST", endpoint: "/mcp",
        headers: { ...headers, "MCP-Protocol-Version": MCP_PROTOCOL_VERSION, "Mcp-Method": "server/discover" },
        body: { jsonrpc: "2.0", id: "connect-stateless", method: "server/discover", params: { _meta: {
          "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
          "io.modelcontextprotocol/clientCapabilities": {},
        } } },
      },
    ],
    session: { start_with: "initialize", protocol_versions: SESSION_PROTOCOL_VERSIONS },
    stateless: {
      start_with: "server/discover", protocol_version: MCP_PROTOCOL_VERSION,
      required_headers: ["MCP-Protocol-Version", "Mcp-Method"],
      params_meta: {
        "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
      },
      note: "Mirror the protocol version from params._meta and the request method in these headers. tools/call also requires Mcp-Name to match params.name. Do not use initialize in this profile.",
    },
  };
}

/** Only public revisions and finite categories survive the observation boundary. */
export type McpRevision = typeof MCP_PROTOCOL_VERSION | "2025-11-25" | "2025-06-18" | "2025-03-26" | "2024-11-05" | "missing" | "other" | "invalid" | "unmeasured";
export type McpConnectionObservation = {
  mcp_profile: "session" | "stateless" | "unmeasured";
  mcp_header_revision: McpRevision;
  mcp_body_revision: McpRevision;
  mcp_client_family: McpClientFamily;
};
export type McpClientFamily = "glama" | "agenstry" | "claude" | "cursor" | "inspector" | "mcp_sdk" | "other" | "missing" | "unmeasured";

/** Declared software only: never authenticated identity or raw client text. */
export function observedClientFamily(name: unknown, userAgent: string | null): McpClientFamily {
  const declared = typeof name === "string" ? name.slice(0, 128) : "";
  const value = `${declared} ${(userAgent ?? "").slice(0, 256)}`.toLowerCase();
  for (const family of ["glama", "agenstry", "claude", "cursor", "inspector"] as const) {
    if (new RegExp(`(?:^|[^a-z])${family}(?:$|[^a-z])`).test(value)) return family;
  }
  if (/\bmcp[-_/ ]sdk\b|@modelcontextprotocol\/sdk/.test(value)) return "mcp_sdk";
  return value.trim() ? "other" : "missing";
}
export function observedRevision(value: unknown): McpRevision {
  if (value === undefined || value === null) return "missing";
  if (typeof value !== "string") return "invalid";
  return value === MCP_PROTOCOL_VERSION || SESSION_PROTOCOL_VERSIONS.includes(value) ? value as McpRevision : "other";
}
