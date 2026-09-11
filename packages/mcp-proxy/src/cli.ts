#!/usr/bin/env node

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import { parseArgs } from "node:util";

import { Vizier } from "@vizier/sdk";
import { z } from "zod";

import { createMcpEnforcementProxy } from "./index.js";

const MAX_BODY_BYTES = 64 * 1024;

const helpText = `
Vizier MCP Enforcement Proxy (v0.3.0)
Deterministic authorization firewall for MCP servers and AI agents.

Usage:
  vizier-mcp-proxy --upstream <url> --tools <allowed_tools> [options]

Options:
  --upstream <url>          Upstream MCP server URL (e.g. http://localhost:3000/mcp)
  --tools <list>            Comma-separated list of allowed tool names (e.g. "search,query_db")
  --vizier <url>            Vizier base URL (default: https://vizier.vassiliy-lakhonin.workers.dev)
  --api-key <key>           Vizier API key (or env VIZIER_API_KEY)
  --port <port>             Proxy listen port (default: 8790)
  --host <host>             Proxy listen host (default: 127.0.0.1)
  --token <token>           Client bearer token for agent authentication (auto-generated if omitted)
  --upstream-token <token>  Optional upstream Bearer token if upstream requires auth
  --agent-id <id>           Agent identifier (default: agent)
  --principal-id <id>       Principal identifier (default: principal)
  -h, --help                Show this help message

Environment Variables:
  VIZIER_PROXY_UPSTREAM_URL, VIZIER_PROXY_ALLOWED_TOOLS, VIZIER_BASE_URL,
  VIZIER_API_KEY, VIZIER_PROXY_PORT, VIZIER_PROXY_HOST, VIZIER_PROXY_CLIENT_TOKEN
`;

const configSchema = z.strictObject({
  host: z.enum(["127.0.0.1", "localhost"]).default("127.0.0.1"),
  port: z.coerce.number().int().min(1).max(65_535).default(8_790),
  vizierBaseUrl: z.string().url().default("https://vizier.vassiliy-lakhonin.workers.dev"),
  vizierApiKey: z.string().min(1),
  integrationId: z.string().trim().min(1).max(256).default("mcp-proxy-integration"),
  clientBearerToken: z.string().min(16),
  upstreamId: z.string().trim().min(1).max(256).default("upstream-mcp"),
  upstreamUrl: z.string().url(),
  upstreamBearerToken: z.string().min(1).optional(),
  allowedTools: z
    .string()
    .transform((value) => value.split(",").map((item) => item.trim()).filter(Boolean))
    .pipe(z.array(z.string().min(1).max(256)).min(1).max(100)),
  agentId: z.string().trim().min(1).max(256).default("agent"),
  agentOwner: z.string().trim().min(1).max(256).nullable().default(null),
  principalId: z.string().trim().min(1).max(256).default("principal"),
});

function loadConfig(): z.infer<typeof configSchema> {
  const { values } = parseArgs({
    options: {
      help: { type: "boolean", short: "h" },
      upstream: { type: "string" },
      tools: { type: "string" },
      vizier: { type: "string" },
      "api-key": { type: "string" },
      port: { type: "string" },
      host: { type: "string" },
      token: { type: "string" },
      "upstream-token": { type: "string" },
      "agent-id": { type: "string" },
      "principal-id": { type: "string" },
    },
    strict: false,
  });

  if (values.help) {
    console.log(helpText);
    process.exit(0);
  }

  const generatedToken = randomBytes(16).toString("hex");

  const config = configSchema.parse({
    host: values.host ?? process.env.VIZIER_PROXY_HOST ?? "127.0.0.1",
    port: values.port ?? process.env.VIZIER_PROXY_PORT ?? 8790,
    vizierBaseUrl: values.vizier ?? process.env.VIZIER_BASE_URL ?? "https://vizier.vassiliy-lakhonin.workers.dev",
    vizierApiKey: values["api-key"] ?? process.env.VIZIER_API_KEY,
    integrationId: process.env.VIZIER_PROXY_INTEGRATION_ID ?? "mcp-proxy-integration",
    clientBearerToken: values.token ?? process.env.VIZIER_PROXY_CLIENT_TOKEN ?? generatedToken,
    upstreamId: process.env.VIZIER_PROXY_UPSTREAM_ID ?? "upstream-mcp",
    upstreamUrl: values.upstream ?? process.env.VIZIER_PROXY_UPSTREAM_URL,
    upstreamBearerToken: values["upstream-token"] ?? process.env.VIZIER_PROXY_UPSTREAM_BEARER_TOKEN,
    allowedTools: values.tools ?? process.env.VIZIER_PROXY_ALLOWED_TOOLS,
    agentId: values["agent-id"] ?? process.env.VIZIER_PROXY_AGENT_ID ?? "agent",
    agentOwner: process.env.VIZIER_PROXY_AGENT_OWNER ?? null,
    principalId: values["principal-id"] ?? process.env.VIZIER_PROXY_PRINCIPAL_ID ?? "principal",
  });

  const vizierUrl = new URL(config.vizierBaseUrl);
  if (
    vizierUrl.protocol !== "https:" &&
    !["localhost", "127.0.0.1", "[::1]"].includes(vizierUrl.hostname)
  ) {
    throw new TypeError("A non-loopback VIZIER_BASE_URL must use https.");
  }
  return config;
}

async function readIncomingBody(request: IncomingMessage): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  for await (const chunk of request) {
    const bytes = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
    totalBytes += bytes.byteLength;
    if (totalBytes > MAX_BODY_BYTES) {
      throw new RangeError("Request body is too large.");
    }
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, totalBytes);
}

function writeResponse(response: ServerResponse, result: Response): Promise<void> {
  response.statusCode = result.status;
  result.headers.forEach((value, name) => response.setHeader(name, value));
  return result.arrayBuffer().then((body) => {
    response.end(Buffer.from(body));
  });
}

async function main(): Promise<void> {
  const config = loadConfig();
  const verifier = new Vizier({
    baseUrl: config.vizierBaseUrl,
    apiKey: config.vizierApiKey,
    fetch: (input, init) => fetch(input, { ...init, redirect: "error" }),
  });
  const proxy = createMcpEnforcementProxy({
    integrationId: config.integrationId,
    clientBearerToken: config.clientBearerToken,
    upstreamId: config.upstreamId,
    upstreamUrl: config.upstreamUrl,
    ...(config.upstreamBearerToken === undefined
      ? {}
      : { upstreamBearerToken: config.upstreamBearerToken }),
    allowedTools: config.allowedTools,
    agent: { id: config.agentId, owner: config.agentOwner },
    principal: { id: config.principalId },
    verifier,
  });
  const server = createServer(async (incoming, outgoing) => {
    try {
      if (incoming.url !== "/mcp") {
        outgoing.statusCode = 404;
        outgoing.end();
        return;
      }
      const body = await readIncomingBody(incoming);
      const headers = new Headers();
      for (const [name, value] of Object.entries(incoming.headers)) {
        if (value !== undefined) {
          headers.set(name, Array.isArray(value) ? value.join(", ") : value);
        }
      }
      const request = new Request(
        `http://${config.host}:${config.port}${incoming.url}`,
        {
          method: incoming.method ?? "GET",
          headers,
          ...(incoming.method === "GET" || incoming.method === "HEAD"
            ? {}
            : { body: new Uint8Array(body).buffer }),
        },
      );
      await writeResponse(outgoing, await proxy.handle(request));
    } catch (error) {
      const status = error instanceof RangeError ? 413 : 500;
      outgoing.statusCode = status;
      outgoing.setHeader("Content-Type", "application/json; charset=utf-8");
      outgoing.end(
        JSON.stringify({
          jsonrpc: "2.0",
          error: {
            code: status === 413 ? -32600 : -32603,
            message:
              status === 413 ? "Request body is too large." : "Internal error.",
          },
        }),
      );
    }
  });
  server.listen(config.port, config.host, () => {
    console.log(
      JSON.stringify({
        event: "vizier.mcp_proxy.started",
        integration_id: config.integrationId,
        listen: `http://${config.host}:${config.port}/mcp`,
        client_bearer_token: config.clientBearerToken,
        upstream_url: config.upstreamUrl,
        allowed_tools: config.allowedTools,
      }),
    );
  });
}

try {
  await main();
} catch (error) {
  console.error(
    JSON.stringify({
      event: "vizier.mcp_proxy.failed",
      code: "INVALID_CONFIGURATION",
      fields:
        error instanceof z.ZodError
          ? [...new Set(error.issues.map((issue) => issue.path.join(".")))]
          : [],
      message:
        error instanceof z.ZodError
          ? "Required proxy configuration is missing or invalid. Use --help for usage."
          : error instanceof Error
            ? error.message
            : "Proxy startup failed.",
    }),
  );
  process.exitCode = 1;
}
