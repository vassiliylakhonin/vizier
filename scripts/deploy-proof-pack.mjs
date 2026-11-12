// Runs the Worker-deployment boundary tests and prints which claim each proves.
// Layers: Vizier transport, SDK, signatures and SQLite are real and in-process;
// Cloudflare is a local simulator. This does NOT touch a real Cloudflare
// account and does NOT establish isolation of any production host.
import { spawnSync } from "node:child_process";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const FILES = [
  "tests/worker-version-deploy.test.ts",
  "tests/gated-deploy.test.ts",
  "tests/execution-journal.test.ts",
];

const CLAIMS = [
  ["P1", "Changed plan (version, worker, account, percentage, operation) sends nothing to the cloud",
    ["rejects a changed version despite valid owner scope", "sends nothing to the cloud for changed arguments"]],
  ["P2", "Missing, expired, forged, other-agent or widened grant: no cloud call",
    ["rejects a missing grant", "rejects a expired grant", "rejects a forged grant", "rejects a different agent grant", "rejects a widened authority grant"]],
  ["P3", "Revoked grant (by jti) stops execution before approval consumption, at executor and gateway; an already accepted cloud operation is not undone",
    ["stops a revoked grant before approval consumption", "applies grant revocation at the gateway", "does not revoke an operation the cloud already accepted"]],
  ["P4", "Missing, forged, rejected or expired human approval: no cloud call",
    ["requires human approval even when owner delegation is valid", "rejects a forged human approval", "rejects a human rejection", "rejects expired human approval"]],
  ["P5", "Opt-in requireSignedReceipt: missing or tampered receipt JWS stops execution before approval consumption (default tolerates an unsigned receipt)",
    ["with requireSignedReceipt, refuses a response without receipt_jws", "with requireSignedReceipt, refuses a tampered receipt_jws",
      "with requireSignedReceipt, still deploys", "without requireSignedReceipt the default tolerates"]],
  ["P6", "Authorization deadline and a hung cloud request end without a retry; the latter requires reconciliation",
    ["fails closed when the authorization deadline aborts the request", "aborts a hung cloud request"]],
  ["P7", "Approval replay, including after gateway restart and journal reopen, deploys nothing more",
    ["does not execute twice for a replayed approval", "refuses approval replay across gateway restarts", "persists acknowledgement across reopen"]],
  ["P8", "Lost or unconfirmed cloud response requires reconciliation and is never re-sent",
    ["preserves uncertainty and never redeploys after a lost cloud response", "requires reconciliation after Cloudflare", "persists unknown after a lost cloud response"]],
  ["P9", "Gateway accepts one route only: no unauthenticated, browser, alternate-path, oversized or agent-supplied grant/scope/URL/credential",
    ["rejects unauthenticated, browser, alternate-path and oversized calls", "rejects agent-supplied"]],
  ["P10", "Concurrent claimants: one admitted; busy gateway refuses the second",
    ["admits one of two concurrent claimants", "rejects concurrent requests while an execution is in flight"]],
  ["P11", "Verifier or approval store unavailable: fail closed",
    ["fails closed at the HTTP boundary when Vizier is unavailable", "fails closed when approval consumption is unavailable", "fails closed when /v1/verify is unavailable"]],
];

const dir = mkdtempSync(join(tmpdir(), "proof-pack-"));
const out = join(dir, "vitest.json");
const run = spawnSync("npx", ["vitest", "run", ...FILES, "--reporter=json", `--outputFile=${out}`], { encoding: "utf8" });
let report;
try { report = JSON.parse(readFileSync(out, "utf8")); }
catch { console.error(run.stdout, run.stderr); console.error("vitest produced no report"); process.exit(2); }
const tests = report.testResults.flatMap(file => file.assertionResults.map(t => ({ name: t.fullName, status: t.status })));

let failed = 0;
for (const [id, claim, needles] of CLAIMS) {
  const rows = needles.map(needle => {
    const hits = tests.filter(t => t.name.includes(needle));
    const ok = hits.length > 0 && hits.every(t => t.status === "passed");
    return { needle, hits: hits.length, ok };
  });
  const ok = rows.every(row => row.ok);
  if (!ok) failed += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${id}  ${claim}`);
  for (const row of rows) console.log(`       ${row.ok ? "ok " : "!! "} ${row.hits} test(s): ${row.needle}`);
}
console.log("\nNot covered by this run: real Cloudflare (simulated), production host isolation (unverified).");
console.log("Linux separate-UID boundary test runs only in the CI 'deployment-isolation' Docker job (sandbox/worker-deploy).");
process.exit(failed === 0 ? 0 : 1);
