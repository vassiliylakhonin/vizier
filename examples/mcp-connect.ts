/** Node 24, no dependencies: explicit read-only MCP connection, never an action. */
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";

type Profile = "session" | "stateless";
type Options = { fetchImpl?: typeof fetch; ownerCheck?: boolean };
const VERSIONS = { session: "2025-11-25", stateless: "2026-07-28" } as const;

const SESSION_REVISIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"] as const;
const REASONS = ["accept_mismatch", "invalid_request", "invalid_json", "header_mismatch",
  "unsupported_version", "profile_method_mismatch", "method_not_found", "origin_rejected",
  "body_too_large", "content_type_mismatch"] as const;

/** A bounded, sanitized server hint, never an instruction to replay a call. */
export class McpConnectionError extends Error {
  readonly status: number;
  readonly reason: string | null;
  readonly recommendedProfile: Profile | null;
  readonly recommendedVersion: string | null;

  constructor(status: number, reason: string | null,
    recommendedProfile: Profile | null, recommendedVersion: string | null) {
    const next = recommendedProfile && recommendedVersion
      ? ` Suggested read-only profile: ${recommendedProfile} (${recommendedVersion}); start a new connection explicitly.` : "";
    super(`MCP connection refused (HTTP ${status}${reason ? `, ${reason}` : ""}).${next} No retry performed.`);
    this.name = "McpConnectionError";
    this.status = status;
    this.reason = reason;
    this.recommendedProfile = recommendedProfile;
    this.recommendedVersion = recommendedVersion;
  }
}

function safeHint(value: unknown): {reason: string; profile: Profile; version: string} | null {
  if (!value || typeof value !== "object") return null;
  const v = value as { error?: { data?: { connection_hint?: {reason?: unknown;
    recommended_profile?: unknown; recommended_protocol_version?: unknown} } } };
  const h = v.error?.data?.connection_hint;
  if (!h || typeof h.reason !== "string" || !REASONS.some(reason => reason === h.reason)) return null;
  const profile = h.recommended_profile;
  const version = h.recommended_protocol_version;
  if (typeof version !== "string" || !(profile === "session" && SESSION_REVISIONS.some(v => v === version)
    || profile === "stateless" && version === VERSIONS.stateless)) return null;
  return {reason: h.reason, profile, version};
}

async function refusal(response: Response): Promise<McpConnectionError> {
  // Limit untrusted error bodies before parsing; no raw server text is printed.
  let hint: ReturnType<typeof safeHint> = null;
  try {
    const reader = response.body?.getReader();
    if (reader) {
      const chunks: Uint8Array[] = []; let size = 0;
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        size += part.value.byteLength;
        if (size > 65_536) { await reader.cancel(); break; }
        chunks.push(part.value);
      }
      if (size <= 65_536) {
        const bytes = new Uint8Array(size); let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        hint = safeHint(JSON.parse(new TextDecoder().decode(bytes)));
      }
    }
  } catch { /* malformed or unavailable error payload: report status only */ }
  return new McpConnectionError(response.status, hint?.reason ?? null, hint?.profile ?? null, hint?.version ?? null);
}

export async function connectMcp(origin: string, profile: Profile, options: Options = {}) {
  const base = new URL(origin);
  if (!(base.protocol === "https:" || (base.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(base.hostname)))
      || base.username || base.password || base.search || base.hash || base.pathname !== "/") {
    throw new Error("Use an HTTPS origin, or localhost HTTP, without a path, credentials or query.");
  }
  if (profile !== "session" && profile !== "stateless") throw new Error("Choose session or stateless explicitly.");
  const request = options.fetchImpl ?? fetch;
  const owner = options.ownerCheck ? { "X-Client-Id": "agenda-owner-vizier-connect-example" } : {};
  const version = VERSIONS[profile];
  const send = async (path: string, body?: Record<string, unknown>, extra: Record<string, string> = {}) => {
    const response = await request(`${base.origin}${path}`, {
      method: body ? "POST" : "GET", redirect: "error", signal: AbortSignal.timeout(10_000),
      headers: { Accept: "application/json, text/event-stream", ...owner,
        ...(body ? { "Content-Type": "application/json" } : {}), ...extra },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (response.status === 202 && body?.method === "notifications/initialized") return null;
    if (!response.ok) throw await refusal(response);
    const value = await response.json() as Record<string, unknown>;
    if (value.error) {
      const hint = safeHint(value);
      throw new McpConnectionError(response.status, hint?.reason ?? null, hint?.profile ?? null, hint?.version ?? null);
    }
    return value;
  };
  // The guide confirms the selected contract. Server-supplied URLs, headers and
  // executable requests are never followed; all paths and methods below are fixed.
  const document = await send("/.well-known/mcp-probing.json") as {
    connection_guide?: { session?: { protocol_versions?: string[] }; stateless?: { protocol_version?: string } };
  };
  const guide = document.connection_guide;
  if (profile === "session" ? !(Array.isArray(guide?.session?.protocol_versions) && guide.session.protocol_versions.includes(version))
    : guide?.stateless?.protocol_version !== version) {
    throw new Error("Selected MCP profile/revision is not advertised. No POST was sent.");
  }
  const headers = { "MCP-Protocol-Version": version };
  const rpc = async (method: string, params: Record<string, unknown>, id: string | null) => send("/mcp", {
    jsonrpc: "2.0", ...(id === null ? {} : { id }), method, params,
  }, { ...headers, ...(profile === "stateless" ? { "Mcp-Method": method } : {}) });
  let params: Record<string, unknown> = {};
  if (profile === "session") {
    const initialized = await rpc("initialize", { protocolVersion: version, capabilities: {},
      clientInfo: { name: "vizier-connection-example", version: "1" } }, "connect");
    if ((initialized?.result as { protocolVersion?: string } | undefined)?.protocolVersion !== version) {
      throw new Error("Unexpected negotiated revision. No follow-up or action was sent.");
    }
    await rpc("notifications/initialized", {}, null);
  } else {
    params = { _meta: { "io.modelcontextprotocol/protocolVersion": version,
      "io.modelcontextprotocol/clientCapabilities": {} } };
    const discovered = await rpc("server/discover", params, "discover");
    if (!(discovered?.result as { supportedVersions?: string[] } | undefined)?.supportedVersions?.includes(version)) {
      throw new Error("Stateless discovery did not confirm the selected revision. No follow-up was sent.");
    }
  }
  const listed = await rpc("tools/list", params, "list");
  const tools = (listed?.result as { tools?: { name?: string }[] } | undefined)?.tools;
  if (!Array.isArray(tools) || tools.length !== 1 || tools[0]?.name !== "vizier_verify_action") {
    throw new Error("Unexpected tool catalog. Inspect the published schema before constructing an action.");
  }
  return { profile, protocolVersion: version, tools: tools.map(tool => tool.name),
    discoveryOnly: true, authorizationGranted: false };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const { values } = parseArgs({ options: {
      origin: { type: "string", default: "https://vizier.agendamcp.dpdns.org" },
      profile: { type: "string" }, "owner-check": { type: "boolean", default: false },
    } });
    if (values.profile !== "session" && values.profile !== "stateless") {
      throw new Error("Usage: node examples/mcp-connect.ts --profile session|stateless [--origin URL] [--owner-check]");
    }
    console.log(JSON.stringify(await connectMcp(values.origin, values.profile,
      { ownerCheck: values["owner-check"] }), null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : "MCP connection failed");
    process.exitCode = 1;
  }
}
