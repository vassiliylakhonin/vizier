// Answers one question: does the deployed Worker actually answer?
//
// Why this exists: check-deployed.mjs compares bundle digests, which tells you
// production is running this code and nothing about whether it responds. Until
// 2026-09-02 nothing in this repository ever called the live Worker — every
// functional check of production was a person with curl. A missing secret, a
// dropped binding, or a platform change leaves the digest matching and the
// pipeline green while the endpoint is broken.
//
//   npm run check:live
//   VIZIER_ORIGIN=http://127.0.0.1:8787 npm run check:live
//
// The MCP probes are deliberately anonymous, because the credential-free path
// is the one exposed to the world and the one no test can reach offline. That
// costs four counted calls per run: this script is the only predictable
// contributor to the `mcp` / `served` counter in GET /v1/insights.

import { readFileSync } from "node:fs";

const ORIGIN =
  process.env.VIZIER_ORIGIN ?? "https://vizier.vassiliy-lakhonin.workers.dev";
const SESSION_VERSION = "2025-06-18";
const STATELESS_VERSION = "2026-07-28";

const manifest = JSON.parse(
  readFileSync(new URL("../server.json", import.meta.url), "utf8"),
);
const expectedVersion = manifest.version;

const failures = [];

function check(name, condition, detail) {
  if (condition) {
    console.log(`  ok    ${name}`);
    return;
  }
  console.log(`  FAIL  ${name}${detail === undefined ? "" : ` — ${detail}`}`);
  failures.push(name);
}

async function getJson(path) {
  const response = await fetch(`${ORIGIN}${path}`, {
    headers: { Accept: "application/json" },
  });
  return { status: response.status, body: await response.json() };
}

async function mcp(body, headers = {}) {
  const response = await fetch(`${ORIGIN}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...headers,
    },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

console.log(`${ORIGIN}\n`);

try {
  const health = await getJson("/health");
  check("GET /health", health.status === 200 && health.body.status === "ok");

  const root = await getJson("/");
  check(
    "GET / reports the released version",
    root.body.version === expectedVersion,
    `expected ${expectedVersion}, got ${root.body.version}`,
  );

  const card = await getJson("/.well-known/agent-card.json");
  check(
    "agent card carries a signature",
    Array.isArray(card.body.signatures) && card.body.signatures.length > 0,
    "AGENT_CARD_SIGNING_KEY may be unset",
  );

  const jwks = await getJson("/.well-known/jwks.json");
  check(
    "JWKS publishes the card and receipt keys",
    Array.isArray(jwks.body.keys) && jwks.body.keys.length >= 2,
    `got ${jwks.body.keys?.length ?? 0} keys`,
  );

  const served = await getJson("/.well-known/mcp.json");
  check(
    "served MCP manifest matches server.json",
    served.body.name === manifest.name &&
      served.body.version === expectedVersion &&
      served.body.remotes?.[0]?.url === `${ORIGIN}/mcp`,
  );

  // Session profile: the handshake every shipping client opens with.
  const initialized = await mcp({
    jsonrpc: "2.0",
    id: "live-1",
    method: "initialize",
    params: {
      protocolVersion: SESSION_VERSION,
      capabilities: {},
      clientInfo: { name: "vizier-check-live", version: expectedVersion },
    },
  });
  check(
    "MCP initialize negotiates a session",
    initialized.body.result?.protocolVersion === SESSION_VERSION &&
      initialized.body.result?.serverInfo?.version === expectedVersion,
    JSON.stringify(initialized.body).slice(0, 200),
  );

  const listed = await mcp(
    { jsonrpc: "2.0", id: "live-2", method: "tools/list" },
    { "MCP-Protocol-Version": SESSION_VERSION },
  );
  check(
    "MCP tools/list exposes vizier_verify_action",
    listed.body.result?.tools?.some(
      (tool) => tool.name === "vizier_verify_action",
    ) === true,
  );

  // Anonymous enforcement boundary: a real decision that cannot grant ALLOW.
  const example = JSON.parse(
    readFileSync(new URL("../examples/allow.json", import.meta.url), "utf8"),
  );
  const called = await mcp(
    {
      jsonrpc: "2.0",
      id: "live-3",
      method: "tools/call",
      params: { name: "vizier_verify_action", arguments: example },
    },
    { "MCP-Protocol-Version": SESSION_VERSION },
  );
  const decision = called.body.result?.structuredContent;
  check(
    "anonymous tools/call returns a receipt",
    typeof decision?.receipt?.id === "string",
    JSON.stringify(called.body).slice(0, 200),
  );
  check(
    "anonymous tools/call cannot grant ALLOW",
    decision?.decision !== undefined && decision.decision !== "ALLOW",
    `decision was ${decision?.decision}`,
  );

  // Stateless profile: unchanged by the session work, and nothing else calls it.
  const discovered = await mcp(
    {
      jsonrpc: "2.0",
      id: "live-4",
      method: "server/discover",
      params: {
        _meta: {
          "io.modelcontextprotocol/protocolVersion": STATELESS_VERSION,
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    },
    {
      "MCP-Protocol-Version": STATELESS_VERSION,
      "Mcp-Method": "server/discover",
    },
  );
  check(
    "MCP server/discover still answers the stateless profile",
    discovered.body.result?.supportedVersions?.includes(STATELESS_VERSION) ===
      true,
  );
} catch (error) {
  console.log(
    `  FAIL  reaching ${ORIGIN} — ${error instanceof Error ? error.message : "unknown error"}`,
  );
  failures.push("transport");
}

if (failures.length > 0) {
  console.log(`\n${failures.length} live check(s) failed.`);
  process.exit(1);
}
console.log("\nThe deployed Worker answers on every checked surface.");
