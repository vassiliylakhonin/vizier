# External audit chain anchors

The audit receipt chain (migration 0012, `GET /v1/audit/chain`) is
tamper-evident inside the database: editing, inserting, reordering, or
deleting any chained row that still has a chained successor breaks the chain.
What it cannot detect on its own is a silent deletion of the *newest* rows,
because the head of the chain is whatever the newest remaining row says it
is. Anchoring closes that specific hole by publishing the chain head outside
the audited system on a schedule.

## Mechanism

1. `GET /v1/audit/chain/head` is a public endpoint (hashes and counts only,
   rate limited like the other anonymous surfaces). It returns the newest
   chained receipt hash, the chained and legacy row counts, the retention
   anchor recorded by pruning (migration 0014), and the time it was computed.
2. The GitHub Actions workflow `.github/workflows/anchor-audit-chain.yml`
   fetches that endpoint every 6 hours and commits the response verbatim to
   the public `audit-anchors` branch of this repository: one file per run
   under `anchors/`, plus `latest.json`. Every run commits, even when the
   head is unchanged, so the branch is also a heartbeat.

The anchor store is external to the audited system: the audit log lives in
Cloudflare D1, the anchor history lives in GitHub's git object store. An
operator with D1 write access can still rewrite the D1 side, but after an
anchor has landed they can no longer make the D1 head match the published
anchor without also force-pushing the public branch — which appears in the
repository's event feed and in every clone.

## Verifying the chain against an anchor

```sh
node scripts/check-audit-anchor.mjs
```

This fetches the live head and the latest committed anchor:

- **Match**: the history up to the anchor is unchanged since the anchor was
  committed.
- **Live chain longer**: expected right after new receipts are stored; only
  the rows past the anchor are unanchored, and only until the next run. To
  verify those rows, recompute the chain with `GET /v1/audit/chain`
  (authenticated) and confirm its `head_hash` is the one you expect.
- **Mismatch with a shorter or divergent live chain**: the newest rows may
  have been rewritten or deleted after the anchor. Investigate before
  trusting any receipt.

Anyone with the integration credential can also do this by hand: call
`GET /v1/audit/chain`, note `head_hash`, and compare it with
`anchors/<timestamp>.json` on the `audit-anchors` branch.

## Honest limits

- **Lag.** Anchors land every 6 hours (plus GitHub's scheduler jitter, which
  can delay or skip a run). Receipts written since the last anchor are not
  covered by it. A smaller interval narrows the window; it does not remove
  it.
- **Missed anchors.** A skipped or failed run leaves a gap that is visible in
  the branch history and in the workflow run list, but nothing alerts on it
  today.
- **Same-repository anchor.** The branch lives in this repository, so a
  repository admin can rewrite it. That is a higher bar than editing D1 —
  force-pushing a public branch is visible — but it is not a third-party
  transparency log. Moving the anchor to a dedicated repository or a public
  transparency log is the documented hardening path.
- **Pre-chain rows and the retention anchor.** Rows written before migration
  0012 carry no hash and are outside the chain. The migration 0014 retention
  anchor row in D1 is editable by anyone with D1 write access; anchoring the
  head does not change that.
- **No cross-organization audit correlation.** The anchor covers this
  deployment's chain only.
