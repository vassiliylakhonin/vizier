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
// That check reads before it writes, so two deploys of the same commit both see
// the old version and both try to publish. On 2026-09-07 three runs raced for
// v0.3.0: one published, two exited 1 on "cannot publish duplicate version" and
// marked a successful deploy red. A duplicate rejection is confirmation that the
// registry holds this version, so it is now verified and treated as success —
// only after re-reading the registry, so a genuine publish failure still fails.
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

// Same as `run`, but keeps the output so the caller can tell one failure from
// another. Still streamed, so the log reads the same as before.
function runCaptured(command, args) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
    });
    let output = "";
    for (const stream of [child.stdout, child.stderr]) {
      stream.on("data", (chunk) => {
        output += chunk.toString();
        process.stderr.write(chunk);
      });
    }
    child.on("close", (code) => resolve({ code: code ?? 1, output }));
  });
}

// `?search=` is the only filter this API honours: `?name=` is accepted and
// silently ignored, returning the unfiltered first page. Measured 2026-09-02.
// So the exact name is matched here rather than trusted from the query.
//
// `ok` separates "the registry says nothing is listed" from "the registry did
// not answer". The pre-flight must fail on the second; the confirmation after a
// duplicate rejection must not read it as success.
async function registryVersion(serverName) {
  try {
    const response = await fetch(
      `${REGISTRY}/v0/servers?search=${encodeURIComponent(serverName)}`,
      { headers: { Accept: "application/json" } },
    );
    if (!response.ok) {
      return { ok: false, version: null, reason: `status ${response.status}` };
    }
    const body = await response.json();
    const entry = (body.servers ?? [])
      .filter((item) => item?.server?.name === serverName)
      .find(
        (item) =>
          item?._meta?.["io.modelcontextprotocol.registry/official"]?.isLatest ===
          true,
      );
    return { ok: true, version: entry?.server?.version ?? null, reason: null };
  } catch (error) {
    return {
      ok: false,
      version: null,
      reason: error instanceof Error ? error.name : "UnknownError",
    };
  }
}

const manifest = JSON.parse(
  readFileSync(new URL("../server.json", import.meta.url), "utf8"),
);
const { name, version } = manifest;
if (typeof name !== "string" || typeof version !== "string") {
  console.error("server.json must carry a string name and version.");
  process.exit(1);
}

const lookup = await registryVersion(name);
if (!lookup.ok) {
  console.error(`Registry lookup failed: ${lookup.reason}.`);
  process.exit(1);
}

const live = lookup.version;
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

const { code, output } = await runCaptured("mcp-publisher", ["publish"]);
if (code !== 0) {
  if (!/cannot publish duplicate version/i.test(output)) {
    process.exit(code);
  }
  // Another run of the same commit got there first. Confirm rather than assume.
  const confirmation = await registryVersion(name);
  if (!confirmation.ok || confirmation.version !== version) {
    console.error(
      `\nRegistry rejected ${version} as a duplicate but reports ${
        confirmation.ok ? (confirmation.version ?? "nothing") : "no answer"
      }. Not treating that as published.`,
    );
    process.exit(code);
  }
  console.log(`\nalready published ${name} ${version} by a concurrent run.`);
  process.exit(0);
}
console.log(`\npublished ${name} ${version}`);
