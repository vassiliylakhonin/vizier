/** One protocol inventory for negotiation, discovery and connection recovery. */
export const MCP_PROTOCOL_VERSION = "2026-07-28";
export const SESSION_PROTOCOL_VERSIONS: readonly string[] = Object.freeze([
  "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05",
]);
export const DEFAULT_SESSION_PROTOCOL_VERSION = "2025-11-25";

export type McpRejection = "accept_mismatch" | "invalid_request" | "invalid_json"
  | "header_mismatch" | "unsupported_version" | "profile_method_mismatch"
  | "method_not_found" | "origin_rejected" | "body_too_large" | "content_type_mismatch";

export function connectionHint(reason: McpRejection, observation?: McpConnectionObservation) {
  return { reason, ...connectionGuide(observation) };
}

/** Publish working read-only connection sequences before a caller mixes eras. */
export function connectionGuide(observation?: McpConnectionObservation) {
  const headers = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
  // Only public revisions enter guidance. Prefer the body contract when header
  // and body disagree; never infer authority or replay the rejected method.
  const revision = [observation?.mcp_body_revision, observation?.mcp_header_revision]
    .find(value => value === MCP_PROTOCOL_VERSION || (value !== undefined && SESSION_PROTOCOL_VERSIONS.includes(value)));
  const recommendedProfile = revision === MCP_PROTOCOL_VERSION ? "stateless" : "session";
  const sessionVersion = revision !== undefined && SESSION_PROTOCOL_VERSIONS.includes(revision)
    ? revision : DEFAULT_SESSION_PROTOCOL_VERSION;
  const sessionHeaders = { ...headers, "MCP-Protocol-Version": sessionVersion };
  const statelessMeta = {
    "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
  };
  return {
    endpoint: "/mcp",
    method: "POST",
    content_type: "application/json",
    accept: ["application/json", "text/event-stream"],
    recommended_profile: recommendedProfile,
    recommended_protocol_version: recommendedProfile === "stateless" ? MCP_PROTOCOL_VERSION : sessionVersion,
    automatic_retry: false,
    instruction: "Choose one profile and inspect its read-only sequence. Remove stateless protocol metadata from session requests; mirror the version and method for stateless requests. Do not automatically replay tools/call or treat discovery as authorization.",
    recovery_requests: [
      {
        profile: "session", method: "POST", endpoint: "/mcp", headers,
        body: { jsonrpc: "2.0", id: "connect-session", method: "initialize", params: {
          protocolVersion: sessionVersion, capabilities: {},
          clientInfo: { name: "connection-recovery", version: "1" },
        } },
        follow_up_requests: [
          { method: "POST", endpoint: "/mcp", headers: sessionHeaders,
            body: { jsonrpc: "2.0", method: "notifications/initialized" } },
          { method: "POST", endpoint: "/mcp", headers: sessionHeaders,
            body: { jsonrpc: "2.0", id: "list-session-tools", method: "tools/list" } },
        ],
      },
      {
        profile: "stateless", method: "POST", endpoint: "/mcp",
        headers: { ...headers, "MCP-Protocol-Version": MCP_PROTOCOL_VERSION, "Mcp-Method": "server/discover" },
        body: { jsonrpc: "2.0", id: "connect-stateless", method: "server/discover", params: { _meta: statelessMeta } },
        follow_up_requests: [
          { method: "POST", endpoint: "/mcp",
            headers: { ...headers, "MCP-Protocol-Version": MCP_PROTOCOL_VERSION, "Mcp-Method": "tools/list" },
            body: { jsonrpc: "2.0", id: "list-stateless-tools", method: "tools/list", params: { _meta: statelessMeta } } },
        ],
      },
    ],
    session: { start_with: "initialize", protocol_versions: SESSION_PROTOCOL_VERSIONS,
      methods:["initialize","notifications/initialized","ping","tools/list","tools/call"] },
    stateless: {
      start_with: "server/discover", protocol_version: MCP_PROTOCOL_VERSION,
      methods:["server/discover","tools/list","tools/call"],
      required_headers: ["MCP-Protocol-Version", "Mcp-Method"],
      params_meta: {
        "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
      },
      note: "Mirror the protocol version from params._meta and the request method in these headers. tools/call also requires Mcp-Name to match params.name. Do not use initialize in this profile.",
    },
  };
}

/** Discover names after an invalid call; never synthesize or replay an action. */
export function toolDiscoveryHint(stateless: boolean, toolNames: readonly string[], revision: string | null) {
  const protocolVersion = stateless ? MCP_PROTOCOL_VERSION
    : revision !== null && SESSION_PROTOCOL_VERSIONS.includes(revision) ? revision : DEFAULT_SESSION_PROTOCOL_VERSION;
  return {
    available_tools: toolNames,
    automatic_tool_retry: false,
    instruction: "Run the read-only tools/list request, select an advertised tool and validate its inputSchema. Review before making a new tools/call; the failed call was not replayed.",
    recovery_request: {
      endpoint:"/mcp", method:"POST",
      headers:{"Content-Type":"application/json",Accept:"application/json, text/event-stream",
        "MCP-Protocol-Version":protocolVersion,...(stateless?{"Mcp-Method":"tools/list"}:{})},
      body:{jsonrpc:"2.0",id:"discover-tools",method:"tools/list",params:stateless?{_meta:{
        "io.modelcontextprotocol/protocolVersion":MCP_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities":{}
      }}:{}}
    }
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
