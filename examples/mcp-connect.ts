/** Node 24, no dependencies: explicit read-only MCP connection, never an action. */
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";

type Profile = "session" | "stateless";
type Options = { fetchImpl?: typeof fetch; ownerCheck?: boolean };
const VERSIONS = { session: "2025-11-25", stateless: "2026-07-28" } as const;

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
    if (!response.ok) throw new Error(`MCP ${profile}: HTTP ${response.status}; inspect connection_hint before a new request. No retry performed.`);
    const value = await response.json() as Record<string, unknown>;
    if (value.error) throw new Error(`MCP ${profile}: JSON-RPC refusal. Inspect connection_hint; no retry performed.`);
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
