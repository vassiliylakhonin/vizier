import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

// The Worker runs at 03:17 UTC; the observation workflow checks at 04:17.
// Scheduling delays are allowed, but missing a daily scan is not healthy.
const MAX_AGE_SECONDS = 18 * 3600;
const sql = `SELECT m.state,m.checked_at,m.observed_outgoing,m.start_block,m.end_block,
  m.end_block_hash,m.reason,p.enabled FROM wallet_history_monitor m
  LEFT JOIN financial_policies p ON p.wallet=m.wallet WHERE m.id=1`;
const historyCodes = new Set([
  "RPC_TIMEOUT", "RPC_ENVELOPE", "RPC_EMPTY", "RPC_TOO_LARGE", "INVALID_SCHEMA",
  "WRONG_CHAIN", "INSUFFICIENT_HISTORY", "STALE_OR_SHORT_HISTORY", "INCOMPLETE_LOGS",
  "INVALID_LOG", "UNSUPPORTED_SPEND", "HISTORY_TIMEOUT", "ANCHOR_CHANGED",
  "SUBREQUEST_LIMIT", "UNKNOWN",
]);
const messages = {
  OBSERVED: "Complete fresh wallet history observed; financial policy remains disabled. This is not spending authorization.",
  PROVIDER_UNAVAILABLE: "RPC provider unavailable or throttled. Wallet history is unknown, not healthy. Wait for a complete scheduled scan; do not enable spending.",
  EVIDENCE_UNAVAILABLE: "History collection failed validation or could not finish. Wallet history is unknown; investigate the diagnostic. Do not enable spending.",
  MISSING_OBSERVATION: "No wallet observation exists. Check Worker monitor configuration and scheduled execution. Wallet history is unknown.",
  STALE_OBSERVATION: "The wallet observation is too old. Check Worker scheduled execution. Wallet history is unknown.",
  POLICY_UNSAFE: "The monitored wallet financial policy is enabled; this monitor requires it to remain disabled. Investigate the policy separately from RPC availability.",
  CONFIGURATION_ERROR: "The wallet financial policy is missing or invalid. Check monitor configuration; no healthy verdict is possible.",
  INVALID_EVIDENCE: "The stored observation is malformed or inconsistent. No healthy verdict is possible; investigate the monitor record.",
  MONITOR_FAILURE: "The monitor reported an unrecognized failure. Wallet history is unknown; investigate Worker logs.",
  CHECK_UNAVAILABLE: "Could not read the monitor record from D1. Monitor status and wallet history are unknown, not healthy.",
};
function result(outcome, diagnostic = null) {
  return { outcome, ok: outcome === "OBSERVED", diagnostic, message: messages[outcome] };
}

// Deliberately independent of spending admission. Never infer wallet trouble
// from provider trouble, and never treat unknown history as successful evidence.
export function assessWalletMonitor(row, now = Math.floor(Date.now() / 1000)) {
  if (!row) return result("MISSING_OBSERVATION");
  if (row.enabled === 1) return result("POLICY_UNSAFE");
  if (row.enabled !== 0) return result("CONFIGURATION_ERROR");
  if (row.state === "FAILED") {
    const reason = typeof row.reason === "string" ? row.reason : "";
    if (reason === "MONITOR_POLICY_ENABLED") return result("POLICY_UNSAFE");
    if (reason === "MONITOR_POLICY_MISSING") return result("CONFIGURATION_ERROR");
    const code = reason.startsWith("MONITOR_HISTORY_UNAVAILABLE:") ? reason.slice("MONITOR_HISTORY_UNAVAILABLE:".length) : "UNKNOWN";
    const http = /^RPC_HTTP_[1-5]\d{2}$/.test(code);
    const envelope = /^RPC_ENVELOPE_eth_(chainId|getBlockByNumber|getLogs)_CODE_-?\d{1,16}$/.test(code);
    // JSON-RPC error codes are provider-specific. Do not call every -32000
    // a rate limit; only HTTP 429/5xx and explicit timeouts prove availability trouble.
    if (/^RPC_HTTP_(429|5\d{2})$/.test(code) || code === "RPC_TIMEOUT") return result("PROVIDER_UNAVAILABLE", code);
    if (reason.startsWith("MONITOR_HISTORY_UNAVAILABLE")) {
      return result("EVIDENCE_UNAVAILABLE", historyCodes.has(code) || http || envelope ? code : "UNKNOWN");
    }
    return result("MONITOR_FAILURE");
  }
  if (row.state !== "OK" || row.reason !== null || !Number.isSafeInteger(row.checked_at)
    || row.checked_at < 0 || row.checked_at > now + 60
    || !Number.isSafeInteger(row.observed_outgoing) || row.observed_outgoing < 0 || row.observed_outgoing > 1000000000000
    || !Number.isSafeInteger(row.start_block) || row.start_block < 0 || !Number.isSafeInteger(row.end_block)
    || row.end_block <= row.start_block || typeof row.end_block_hash !== "string" || !/^0x[0-9a-f]{64}$/.test(row.end_block_hash)) {
    return result("INVALID_EVIDENCE");
  }
  if (now - row.checked_at > MAX_AGE_SECONDS) return result("STALE_OBSERVATION");
  return result("OBSERVED");
}

export function readWalletMonitor(read = () => execFileSync("npx", ["--yes", "wrangler", "d1", "execute", "vizier-audit",
  "--remote", "--json", "--command", sql], { encoding: "utf8", maxBuffer: 1024 * 1024, stdio: "pipe" })) {
  try {
    const response = JSON.parse(read());
    if (!Array.isArray(response) || response.length !== 1 || response[0]?.success !== true || !Array.isArray(response[0]?.results)
      || response[0].results.length > 1) return result("CHECK_UNAVAILABLE");
    return assessWalletMonitor(response[0].results[0]);
  } catch {
    // Wrangler stderr and provider errors may contain URLs or credentials.
    // Emit fixed diagnostic categories only, never command output or exceptions.
    return result("CHECK_UNAVAILABLE");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const assessment = readWalletMonitor();
  console.log(JSON.stringify({ event: "vizier.wallet_observation.check", ...assessment }));
  if (!assessment.ok) console.error(`::error title=Wallet observation: ${assessment.outcome}::${assessment.message}${assessment.diagnostic ? ` Diagnostic: ${assessment.diagnostic}.` : ""}`);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY,
    `## Wallet observation: ${assessment.outcome}\n\n${assessment.message}\n\nDiagnostic: ${assessment.diagnostic ?? "none"}.\n\nThis check does not report deployment status or authorize transactions.\n`);
  process.exitCode = assessment.ok ? 0 : 1;
}
