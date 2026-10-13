// Install the exact shipped archives outside the checkout and exercise their CLI.
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const directory = resolve(process.argv[2] ?? "release-archives");
const version = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")).version;
const expected = ["sdk", "mcp-proxy", "gated-deploy"].map(name => `vizier-${name}-${version}.tgz`).sort();
const actual = (await readdir(directory)).filter(name => name.endsWith(".tgz")).sort();
if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error("Unexpected release archive set");
const installation = await mkdtemp(join(tmpdir(), "vizier-archive-install-"));
try {
  execFileSync("npm", ["install", "--prefix", installation, "--ignore-scripts", "--no-audit", "--no-fund", ...actual.map(name => join(directory, name))], { stdio: "inherit" });
  execFileSync(process.execPath, ["--input-type=module", "-e", 'import {Vizier} from "@vizier/sdk"; import {createWorkerVersionDeployer} from "@vizier/gated-deploy"; import {createMcpEnforcementProxy} from "@vizier/mcp-proxy"; if(typeof Vizier.prototype.claimHumanReview !== "function" || typeof createWorkerVersionDeployer !== "function" || typeof createMcpEnforcementProxy !== "function") process.exit(1);'], { cwd: installation, stdio: "inherit" });
  const packagePath = join(installation, "node_modules/@vizier/gated-deploy");
  const cli = join(installation, "node_modules/.bin/vizier-worker-deploy");
  const denyNetwork = join(installation, "deny-network.mjs");
  await writeFile(denyNetwork, 'globalThis.fetch = async () => { throw new Error("Network forbidden during CLI preparation"); };\n');
  const args = ["--import", denyNetwork, cli, "prepare", "--scope", join(packagePath, "examples/scope.json"), "--plan", join(packagePath, "examples/plan.json")];
  const output = execFileSync(process.execPath, args, { encoding: "utf8", cwd: installation });
  const prepared = JSON.parse(output);
  if (prepared.review_hash !== "7b3589310d98a51a5aa513b484a568c9d2fc511e2983fdc590c307f9d3cf9077" || prepared.review.action.parameters.percentage !== 100) {
    throw new Error("Installed CLI does not prepare the expected synthetic review");
  }
  const help = execFileSync(process.execPath, ["--import", denyNetwork, cli, "--help"], { encoding: "utf8", cwd: installation });
  if (!help.includes("prepare|submit|execute")) throw new Error("Installed CLI help unavailable");
  console.log("Release archives: clean installation, SDK/proxy/adapter imports, packaged CLI/fixtures and network-free preparation passed.");
} finally {
  await rm(installation, { recursive: true, force: true });
}
