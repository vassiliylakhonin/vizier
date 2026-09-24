import { execFileSync } from "node:child_process";

// The Worker runs at 03:17 UTC; the existing drift workflow checks at 04:17.
// An 18-hour limit allows scheduling delays but catches a missed daily run.
const MAX_AGE_SECONDS = 18 * 3600;
const sql = `SELECT m.state,m.checked_at,m.observed_outgoing,m.start_block,m.end_block,
  m.end_block_hash,m.reason,p.enabled FROM wallet_history_monitor m
  LEFT JOIN financial_policies p ON p.wallet=m.wallet WHERE m.id=1`;

const output = execFileSync("npx", ["--yes", "wrangler", "d1", "execute", "vizier-audit",
  "--remote", "--json", "--command", sql], { encoding: "utf8", maxBuffer: 1024 * 1024 });
const row = JSON.parse(output)?.[0]?.results?.[0];
const now = Math.floor(Date.now() / 1000);
if (!row || row.state !== "OK" || row.enabled !== 0 || !Number.isSafeInteger(row.checked_at)
  || row.checked_at > now + 60 || now - row.checked_at > MAX_AGE_SECONDS
  || !Number.isSafeInteger(row.observed_outgoing) || row.observed_outgoing < 0
  || !Number.isSafeInteger(row.start_block) || !Number.isSafeInteger(row.end_block)
  || row.end_block <= row.start_block || !/^0x[0-9a-f]{64}$/.test(row.end_block_hash)) {
  console.error(`Wallet history monitor failed, stale or policy enabled: ${row?.reason ?? row?.state ?? "no result"}`);
  process.exit(1);
}
console.log(`Wallet history monitor OK: checked_at=${row.checked_at} end_block=${row.end_block} outgoing_base_units=${row.observed_outgoing}; policy disabled.`);
