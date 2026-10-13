// Run in the operator-owned executor, never in an agent-controlled workspace.
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { Vizier, hashCanonicalJson } from "../packages/sdk/dist/index.js";
import {
  createWorkerVersionDeployer,
  prepareWorkerDeploymentReview,
  workerDeploymentAuthority,
} from "../packages/gated-deploy/dist/index.js";

async function jsonFile(path) {
  const value = await readFile(path, "utf8");
  if (Buffer.byteLength(value) > 32_768) throw new Error("Input file too large");
  return JSON.parse(value);
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: { scope: { type: "string" }, plan: { type: "string" }, grant: { type: "string" }, approval: { type: "string" } },
  });
  const mode = positionals[0];
  if (positionals.length !== 1 || !["prepare", "submit", "execute"].includes(mode) || !values.scope || !values.plan) {
    throw new Error("Usage: worker-deploy-pilot.mjs prepare|submit|execute --scope FILE --plan FILE [--grant FILE --approval FILE]");
  }
  const scope = await jsonFile(values.scope);
  const plan = await jsonFile(values.plan);
  const review = prepareWorkerDeploymentReview(scope, plan);
  if (mode === "prepare") {
    console.log(JSON.stringify({ review, review_hash: await hashCanonicalJson(review), authority: workerDeploymentAuthority(scope) }, null, 2));
    return;
  }
  const baseUrl = new URL(process.env.VIZIER_BASE_URL ?? "https://vizier.agendamcp.dpdns.org");
  if (baseUrl.protocol !== "https:" || baseUrl.username || baseUrl.password || baseUrl.search || baseUrl.hash || baseUrl.pathname !== "/") {
    throw new Error("Configure an operator-trusted HTTPS Vizier origin");
  }
  if (!process.env.VIZIER_API_KEY) throw new Error("Operator VIZIER_API_KEY is required");
  const vizier = new Vizier({ baseUrl: baseUrl.origin, apiKey: process.env.VIZIER_API_KEY });
  if (mode === "submit") {
    console.log(JSON.stringify(await vizier.submitHumanReview(review, { signal: globalThis.AbortSignal.timeout(10_000) }), null, 2));
    return;
  }
  if (!values.grant || !values.approval || !process.env.CLOUDFLARE_API_TOKEN) {
    throw new Error("Execution requires operator grant, approval and Cloudflare credential");
  }
  const grant = (await readFile(values.grant, "utf8")).trim();
  if (grant.length > 8192) throw new Error("Grant too large");
  const approval = await jsonFile(values.approval);
  const execute = createWorkerVersionDeployer({ scope, vizier, cloudflareApiToken: process.env.CLOUDFLARE_API_TOKEN });
  const result = await execute({ plan, grant, approval });
  console.log(JSON.stringify(result, null, 2));
  if (result.status !== "deployment_created") process.exitCode = 1;
}

main().catch(() => {
  // Avoid echoing API errors, secret file contents, tokens or credentials.
  console.error("Worker deployment pilot stopped. Check operator configuration and reconcile approval/deployment state before retrying.");
  process.exitCode = 1;
});
