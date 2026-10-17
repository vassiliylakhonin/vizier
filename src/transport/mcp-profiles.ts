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
  return {
    reason,
    endpoint: "/mcp",
    method: "POST",
    content_type: "application/json",
    accept: ["application/json", "text/event-stream"],
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
};
export function observedRevision(value: unknown): McpRevision {
  if (value === undefined || value === null) return "missing";
  if (typeof value !== "string") return "invalid";
  return value === MCP_PROTOCOL_VERSION || SESSION_PROTOCOL_VERSIONS.includes(value) ? value as McpRevision : "other";
}
