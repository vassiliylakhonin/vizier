#!/usr/bin/env node

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { Vizier } from "@vizier/sdk";
import { z } from "zod";

import { createMcpEnforcementProxy } from "./index.js";

const MAX_BODY_BYTES = 64 * 1024;

const configSchema = z.strictObject({
  host: z.enum(["127.0.0.1", "localhost"]).default("127.0.0.1"),
  port: z.coerce.number().int().min(1).max(65_535).default(8_790),
  vizierBaseUrl: z.string().url(),
  vizierApiKey: z.string().min(1),
  integrationId: z.string().trim().min(1).max(256),
  clientBearerToken: z.string().min(16),
  upstreamId: z.string().trim().min(1).max(256),
  upstreamUrl: z.string().url(),
  upstreamBearerToken: z.string().min(1).optional(),
  allowedTools: z
    .string()
    .transform((value) => value.split(",").map((item) => item.trim()).filter(Boolean))
    .pipe(z.array(z.string().min(1).max(256)).min(1).max(100)),
  agentId: z.string().trim().min(1).max(256),
  agentOwner: z.string().trim().min(1).max(256).nullable(),
  principalId: z.string().trim().min(1).max(256),
});

function loadConfig(): z.infer<typeof configSchema> {
  const config = configSchema.parse({
    host: process.env.VIZIER_PROXY_HOST,
    port: process.env.VIZIER_PROXY_PORT,
    vizierBaseUrl: process.env.VIZIER_BASE_URL,
    vizierApiKey: process.env.VIZIER_API_KEY,
    integrationId: process.env.VIZIER_PROXY_INTEGRATION_ID,
    clientBearerToken: process.env.VIZIER_PROXY_CLIENT_TOKEN,
    upstreamId: process.env.VIZIER_PROXY_UPSTREAM_ID,
    upstreamUrl: process.env.VIZIER_PROXY_UPSTREAM_URL,
    upstreamBearerToken: process.env.VIZIER_PROXY_UPSTREAM_BEARER_TOKEN,
    allowedTools: process.env.VIZIER_PROXY_ALLOWED_TOOLS,
    agentId: process.env.VIZIER_PROXY_AGENT_ID,
    agentOwner: process.env.VIZIER_PROXY_AGENT_OWNER ?? null,
    principalId: process.env.VIZIER_PROXY_PRINCIPAL_ID,
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
        upstream_id: config.upstreamId,
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
          ? "Required proxy configuration is missing or invalid."
          : error instanceof Error
            ? error.message
            : "Proxy startup failed.",
    }),
  );
  process.exitCode = 1;
}
