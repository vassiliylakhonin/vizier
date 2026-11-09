// Synthetic mass-ban authorization demo. Disposable and local only.
//
// Story: a community owner agreed that a moderation agent may ban five
// specific fake accounts. The agent then proposes a mass ban of eight:
// the five agreed accounts plus three it added on its own. A trusted guard
// checks every proposed ban with Vizier before the mock executor may run it.
//
// Expected outcome:
//   - the five agreed bans return ALLOW and the mock executor records them;
//   - the three added accounts return BLOCK (TARGET_NOT_ALLOWED) and the
//     executor is never called for them;
//   - presenting the same grant beside an enlarged authority (the agent
//     claims a longer allowed list than the owner signed) returns BLOCK
//     with GRANT_AUTHORITY_MISMATCH.
//
// What this proves: Vizier's existing grant + constraint model can bind a
// moderation agent to an exact account list, and a guard that enforces the
// decision executes only the authorized bans. What it does not prove: any
// real platform integration, fraud detection, host isolation, or production
// security. Accounts are synthetic strings; no real service is contacted.
//
// Requires: Node.js 24+, `npm ci`, and a built SDK
// (`npm run build --workspace @agenda-intelligence/vizier-sdk`).
// Run from the repository root: node scripts/mass-ban-guard-demo.mjs

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const PRINCIPAL = "community-owner";
const AGENT = "moderation-agent-01";
const AGREED = Array.from({ length: 5 }, (_, i) => `fake-user-00${i + 1}`);
const EXTRA = ["fake-user-006", "fake-user-007", "fake-user-008"];
const AUTHORITY = {
  allowed_actions: ["ban_account"],
  constraints: { allowed_targets: AGREED },
};

function mintGrant(args, options = {}) {
  const result = spawnSync(
    process.execPath,
    [resolve(root, "scripts/mint-grant.mjs"), ...args],
    { encoding: "utf8", ...options },
  );
  assert.equal(result.status, 0, `mint-grant failed: ${result.stderr}`);
  return result.stdout.trim();
}

const dir = await mkdtemp(join(tmpdir(), "vizier-mass-ban-"));
const socket = createServer();
await new Promise((done) => socket.listen(0, "127.0.0.1", done));
const port = socket.address().port;
await new Promise((done) => socket.close(done));
const baseUrl = `http://127.0.0.1:${port}`;
const apiKey = "local-demo-only-not-a-production-credential";

// The principal's signing key is minted in the temp dir and never leaves it.
const keyPath = join(dir, "principal.jwk.json");
const keygenOut = mintGrant(["keygen", "--kid", "demo-2026-11", "--out", keyPath]);
const publicJwk = Object.values(JSON.parse(keygenOut))[0];
assert(publicJwk?.kty === "EC" && publicJwk?.kid === "demo-2026-11");

const grantClaims = join(dir, "grant.json");
await writeFile(
  grantClaims,
  JSON.stringify({ iss: PRINCIPAL, sub: AGENT, authority: AUTHORITY }),
  { mode: 0o600 },
);
const grant = mintGrant(["sign", "--key", keyPath, "--grant", grantClaims, "--ttl", "600"]);
assert(grant.split(".").length === 3, "grant is not a compact JWS");

const receiptPair = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"],
);
const receiptPrivateJwk = await crypto.subtle.exportKey("jwk", receiptPair.privateKey);

const config = join(dir, "wrangler.json");
await writeFile(config, JSON.stringify({
  name: "vizier-mass-ban-local",
  main: resolve(root, "src/index.ts"),
  compatibility_date: "2026-09-27",
  compatibility_flags: ["nodejs_compat"],
  vars: {
    VIZIER_API_KEY: apiKey,
    VIZIER_SIGNED_GRANT_MODE: "required",
    VIZIER_PRINCIPAL_KEYS: JSON.stringify({ [PRINCIPAL]: [publicJwk] }),
    RECEIPT_SIGNING_KEY: JSON.stringify({ ...receiptPrivateJwk, alg: "ES256", kid: "local-demo-receipt", use: "sig" }),
  },
}), { mode: 0o600 });

const worker = spawn(process.execPath, [
  resolve(root, "node_modules/wrangler/bin/wrangler.js"), "dev", "--config", config,
  "--local", "--ip", "127.0.0.1", "--port", String(port), "--persist-to", join(dir, "state"),
], { cwd: dir, env: { ...process.env, WRANGLER_SEND_METRICS: "false" }, stdio: ["ignore", "pipe", "pipe"] });
// Worker logs can include the config dump with local-only keys; never print them.
let logs = "";
worker.stdout.on("data", (chunk) => { logs = (logs + chunk).slice(-16000); });
worker.stderr.on("data", (chunk) => { logs = (logs + chunk).slice(-16000); });
let workerError;
worker.on("error", (err) => { workerError = err; });

// The mock executor stands in for a real moderation backend. It records bans
// in memory and is only reachable through the guard below.
const executed = [];
const executor = {
  ban(target) {
    executed.push(target);
    return { target, status: "banned", backend: "mock" };
  },
};

const { Vizier, VizierError } = await import(resolve(root, "packages/sdk/dist/index.js"));
const client = new Vizier({ baseUrl, apiKey });

// The trusted guard: the executor runs only after an established ALLOW.
// authorize() requires the integration credential, principal and grant,
// verifies the signed receipt, and checks the receipt's grant binding.
async function guardedBan(target, authority = AUTHORITY) {
  const request = {
    agent: { id: AGENT, owner: PRINCIPAL },
    principal: { id: PRINCIPAL },
    action: {
      type: "ban_account",
      target,
      parameters: { reason: "coordinated-spam", wave: "synthetic-demo" },
    },
    authority,
    context: { request_id: crypto.randomUUID(), timestamp: null, source: "rest" },
    grant,
  };
  try {
    const result = await client.authorize(request);
    assert.equal(result.decision, "ALLOW");
    executor.ban(target);
    return { target, decision: "ALLOW", reason_codes: [] };
  } catch (err) {
    if (err instanceof VizierError && err.code === "AUTHORIZATION_NOT_GRANTED") {
      return {
        target,
        decision: err.details?.decision ?? "BLOCK",
        reason_codes: err.details?.reason_codes ?? [],
      };
    }
    throw err;
  }
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
  console.log("Disposable local Worker ready; grant-required mode with a registered principal key.");

  // The agent proposes the agreed bans plus three accounts it added itself.
  const proposed = [...AGREED, ...EXTRA];
  const outcomes = [];
  for (const target of proposed) {
    outcomes.push(await guardedBan(target));
  }
  for (const outcome of outcomes) {
    if (outcome.decision === "ALLOW") {
      console.log(`ALLOW ${outcome.target}: mock executor recorded the ban`);
    } else {
      console.log(`${outcome.decision} ${outcome.target}: ${outcome.reason_codes.join(", ")}; executor not called`);
    }
  }

  // The agent retries one extra account beside an enlarged, unsigned authority.
  const enlarged = await guardedBan(EXTRA[0], {
    allowed_actions: ["ban_account"],
    constraints: { allowed_targets: [...AGREED, EXTRA[0]] },
  });
  console.log(`${enlarged.decision} enlarged authority for ${enlarged.target}: ${enlarged.reason_codes.join(", ")}; executor not called`);

  const agreedOutcomes = outcomes.slice(0, AGREED.length);
  const extraOutcomes = outcomes.slice(AGREED.length);
  assert(agreedOutcomes.every((o) => o.decision === "ALLOW"), "an agreed ban was refused");
  assert(extraOutcomes.every((o) => o.decision === "BLOCK"), "an extra account was not blocked");
  assert(
    extraOutcomes.every((o) => o.reason_codes.includes("TARGET_NOT_ALLOWED")),
    "extra accounts blocked for an unexpected reason",
  );
  assert.equal(enlarged.decision, "BLOCK");
  assert(enlarged.reason_codes.includes("GRANT_AUTHORITY_MISMATCH"), "enlarged authority not detected");
  assert.deepEqual(executed, AGREED, "executor banned anything beyond the agreed list");
  console.log(
    `PASS: ${AGREED.length} authorized bans executed, ${EXTRA.length} added accounts blocked, ` +
    "enlarged authority rejected. The mock executor banned exactly the agreed accounts.",
  );
} finally {
  if (worker.exitCode === null) {
    worker.kill("SIGTERM");
    await new Promise((done) => worker.once("close", done));
  }
  await rm(dir, { recursive: true, force: true });
}
