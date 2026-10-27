import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const root = new URL("../", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("server.json", root), "utf8"));
const preloader = new URL("./fixtures/registry-response.mjs", import.meta.url).href;

function run(server: unknown, status = 200) {
  const body = { server, _meta: { "io.modelcontextprotocol.registry/official": { isLatest: true } } };
  return spawnSync(process.execPath, ["--import", preloader, "scripts/publish-registry.mjs", "--dry-run"], {
    cwd: root, encoding: "utf8", timeout: 10000, input: JSON.stringify({ body, status }),
  });
}

function revision() {
  const server = structuredClone(manifest);
  const [major, minor, patch] = manifest.version.split(".").map(Number);
  server.version = `${major}.${minor}.${patch + 1}-registry.1`;
  // Registry omits the optional false value.
  delete server.remotes[0].headers[0].isRequired;
  return server;
}

describe("automatic Registry publication after metadata-only migration", () => {
  it("recognizes the exact published metadata revision without republishing the old service version", () => {
    const result = run(revision());
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Already published");
    expect(result.stdout).not.toContain("would publish");
  });

  it.each(["remote", "auth", "version"])("does not accept a revision with different %s metadata", (field) => {
    const server = revision();
    if (field === "remote") server.remotes[0].url = "https://stale.example/mcp";
    if (field === "auth") server.remotes[0].headers[0].isRequired = true;
    if (field === "version") server.version = "0.6.0";
    const result = run(server);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("would publish");
  });

  it("publishes the new stable service version rather than accepting its earlier prerelease", () => {
    const server = revision();
    server.version = `${manifest.version}-registry.1`;
    expect(run(server).stdout).toContain("would publish");
  });

  it("fails when Registry is unavailable", () => {
    const result = run(revision(), 503);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Registry lookup failed");
  });

  it.each([
    "\"); process.exit(86); //",
    "</script><script>process.exit(86)</script>",
    "` ${process.exit(86)} \\\n\u2028\u2029",
  ])("keeps code-like Registry metadata as data: %j", description => {
    const server = revision();
    server.description = description;
    const result = run(server);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("--dry-run: would publish");
    expect(result.stderr).toBe("");
  });
});
