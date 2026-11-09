// A real local Worker, with a throwaway credential and in-memory-generated receipt key.
// Requires npm ci, a built SDK, and an installed Python client (see docs/FIRST_BLOCK.md).
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const signed = process.argv.includes("--signed");
const dir = await mkdtemp(join(tmpdir(), "vizier-first-block-"));
const socket = createServer();
await new Promise((done) => socket.listen(0, "127.0.0.1", done));
const port = socket.address().port;
await new Promise((done) => socket.close(done));
const baseUrl = `http://127.0.0.1:${port}`;
const apiKey = "local-demo-only-not-a-production-credential";
const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
const config = join(dir, "wrangler.json");
await writeFile(config, JSON.stringify({
  name: "vizier-first-block-local",
  main: resolve(root, "src/index.ts"),
  compatibility_date: "2026-09-27",
  compatibility_flags: ["nodejs_compat"],
  vars: {
    VIZIER_API_KEY: apiKey,
    VIZIER_SIGNED_GRANT_MODE: "required",
    RECEIPT_SIGNING_KEY: JSON.stringify({ ...privateJwk, alg: "ES256", kid: "local-demo-receipt", use: "sig" }),
  },
}), { mode: 0o600 });
const worker = spawn(process.execPath, [
  resolve(root, "node_modules/wrangler/bin/wrangler.js"), "dev", "--config", config,
  "--local", "--ip", "127.0.0.1", "--port", String(port), "--persist-to", join(dir, "state"),
], { cwd: dir, env: { ...process.env, WRANGLER_SEND_METRICS: "false" }, stdio: ["ignore", "pipe", "pipe"] });
// Do not print Wrangler's config dump: it includes the local-only private key.
let logs = "";
worker.stdout.on("data", (chunk) => { logs = (logs + chunk).slice(-16000); });
worker.stderr.on("data", (chunk) => { logs = (logs + chunk).slice(-16000); });
let workerError;
worker.on("error", (err) => { workerError = err; });
const env = { ...process.env, VIZIER_BASE_URL: baseUrl, VIZIER_API_KEY: apiKey };
async function run(command, args) {
  const child = spawn(command, args, { cwd: root, env, stdio: "inherit" });
  const code = await new Promise((done, reject) => {
    child.once("error", reject);
    child.once("close", done);
  });
  assert.equal(code, 0, `${command} demo failed`);
}
try {
  let ready = false;
  for (let attempt = 0; attempt < 120; attempt++) {
    if (workerError) throw workerError;
    if (worker.exitCode !== null) throw new Error("Local Worker exited. Check Node 24+ and npm ci.");
    try { ready = (await fetch(`${baseUrl}/health`)).ok; } catch { /* still starting */ }
    if (ready) break;
    await setTimeout(250);
  }
  assert(ready, "Local Worker did not start within 30 seconds.");
  assert(logs.length > 0, "Worker startup produced no output.");
  console.log(`Disposable local Worker ready; ${signed ? "source signed-receipt" : "request-hash"} mode.`);
  const args = signed ? ["--signed"] : [];
  await run(process.execPath, ["scripts/first-block-client.mjs", ...args]);
  await run(process.env.VIZIER_DEMO_PYTHON || "python3", ["examples/first_block.py", ...args]);
  console.log("PASS: both clients refused the action and detected receipt tampering. Nothing deployed or executed.");
} finally {
  if (worker.exitCode === null) {
    worker.kill("SIGTERM");
    await new Promise((done) => worker.once("close", done));
  }
  await rm(dir, { recursive: true, force: true });
}
