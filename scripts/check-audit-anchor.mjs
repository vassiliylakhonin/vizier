#!/usr/bin/env node
/**
 * Re-verify the live audit chain head against the latest external anchor.
 *
 * Fetches the public chain-head endpoint and the newest anchor committed by
 * the Anchor audit chain workflow, and reports whether the live head is
 * covered by an anchor. Run: `node scripts/check-audit-anchor.mjs`.
 *
 * A match means the history up to the anchor is unchanged since the anchor
 * was committed. It does not prove the live database was not rewritten after
 * the anchor; receipts newer than the anchor are unanchored by construction
 * (see docs/AUDIT_ANCHORS.md).
 */
const HEAD_URL = "https://vizier.agendamcp.dpdns.org/v1/audit/chain/head";
const ANCHOR_URL =
  "https://raw.githubusercontent.com/vassiliylakhonin/vizier/audit-anchors/latest.json";

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`GET ${url} failed: ${response.status}`);
  }
  return response.json();
}

const [live, anchor] = await Promise.all([
  fetchJson(HEAD_URL),
  fetchJson(ANCHOR_URL),
]);

const report = {
  live_head: live.head_hash,
  live_chained_rows: live.chained_rows,
  live_computed_at: live.computed_at,
  anchored_head: anchor.head_hash,
  anchored_chained_rows: anchor.chained_rows,
  anchor_computed_at: anchor.computed_at,
};
console.log(JSON.stringify(report, null, 2));

if (live.head_hash === anchor.head_hash) {
  console.log("OK: live chain head matches the latest external anchor.");
  process.exit(0);
}
if (
  typeof live.chained_rows === "number" &&
  typeof anchor.chained_rows === "number" &&
  live.chained_rows > anchor.chained_rows
) {
  console.log(
    "PENDING: the live chain is longer than the latest anchor. Rows past the " +
      "anchor are unanchored until the next scheduled run; this is expected " +
      "right after new receipts are stored, and suspicious only if the gap " +
      "survives the next anchor.",
  );
  process.exit(0);
}
console.error(
  "MISMATCH: the live chain head is neither the anchored head nor a longer " +
    "chain. The newest rows may have been rewritten or deleted after the " +
    "anchor was committed. Recompute the chain with GET /v1/audit/chain.",
);
process.exit(1);
