// Keeps the MCP Registry entry in step with this repository.
//
// Why this exists: server.json is the one copy of the service version that no
// test can reach, because it lives in a registry outside the repository and
// changes only when a person remembers to run `mcp-publisher publish`. The
// first release that forgets leaves the registry pointing at a version this
// Worker no longer serves — and a stale listing is worse than no listing,
// because a client that found it there has no way to tell.
//
// The registry keys an entry on its version, so this republishes only when
// server.json carries a version the registry does not have yet. A manifest
// edit that does not bump the version is deliberately not republished: rather
// than fail the deploy, it is reported, because the registry would reject the
// duplicate anyway.
//
//   node scripts/publish-registry.mjs           decide and publish
//   node scripts/publish-registry.mjs --dry-run decide and report only
//
// Authentication comes from GitHub Actions OIDC, so no long-lived registry
// token is stored anywhere. Run it locally with an existing `mcp-publisher
// login github` session instead.

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";

const REGISTRY = process.env.MCP_REGISTRY_URL ?? "https://registry.modelcontextprotocol.io";
const dryRun = process.argv.includes("--dry-run");

function run(command, args) {
  return new Promise((resolve) => {
    spawn(command, args, { stdio: "inherit", shell: false }).on("close", (code) =>
      resolve(code ?? 1),
    );
  });
}

const manifest = JSON.parse(
  readFileSync(new URL("../server.json", import.meta.url), "utf8"),
);
const { name, version } = manifest;
if (typeof name !== "string" || typeof version !== "string") {
  console.error("server.json must carry a string name and version.");
  process.exit(1);
}

// `?search=` is the only filter this API honours: `?name=` is accepted and
// silently ignored, returning the unfiltered first page. Measured 2026-09-02.
// So the exact name is matched here rather than trusted from the query.
let published = null;
try {
  const response = await fetch(
    `${REGISTRY}/v0/servers?search=${encodeURIComponent(name)}`,
    { headers: { Accept: "application/json" } },
  );
  if (!response.ok) {
    console.error(`Registry lookup failed with ${response.status}.`);
    process.exit(1);
  }
  const body = await response.json();
  published = (body.servers ?? [])
    .filter((entry) => entry?.server?.name === name)
    .find(
      (entry) =>
        entry?._meta?.["io.modelcontextprotocol.registry/official"]?.isLatest ===
        true,
    ) ?? null;
} catch (error) {
  console.error(
    `Registry lookup failed: ${error instanceof Error ? error.name : "UnknownError"}.`,
  );
  process.exit(1);
}

const live = published?.server?.version ?? null;
console.log(`server.json ${name} ${version}`);
console.log(`registry    ${live === null ? "not listed" : `${name} ${live}`}`);

if (live === version) {
  console.log("\nAlready published at this version; nothing to do.");
  process.exit(0);
}
if (dryRun) {
  console.log("\n--dry-run: would publish.");
  process.exit(0);
}

if (process.env.GITHUB_ACTIONS === "true") {
  const loggedIn = await run("mcp-publisher", ["login", "github-oidc"]);
  if (loggedIn !== 0) {
    process.exit(loggedIn);
  }
}

const code = await run("mcp-publisher", ["publish"]);
if (code !== 0) {
  process.exit(code);
}
console.log(`\npublished ${name} ${version}`);
