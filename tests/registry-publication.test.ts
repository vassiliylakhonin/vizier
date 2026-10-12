import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const root = new URL("../", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("server.json", root), "utf8"));

function run(server: unknown, status = 200) {
  const body = { servers: [{ server, _meta: { "io.modelcontextprotocol.registry/official": { isLatest: true } } }] };
  const stub = `globalThis.fetch = async () => new Response(${JSON.stringify(JSON.stringify(body))}, {status: ${status}});`;
  return spawnSync(process.execPath, ["--import", `data:text/javascript,${encodeURIComponent(stub)}`, "scripts/publish-registry.mjs", "--dry-run"], { cwd: root, encoding: "utf8", timeout: 10000 });
}

function revision() {
  const server = structuredClone(manifest);
  server.version = "0.5.8-registry.1";
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

  it("fails when Registry is unavailable", () => {
    const result = run(revision(), 503);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Registry lookup failed");
  });
});
