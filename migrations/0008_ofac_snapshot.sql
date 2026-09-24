-- A single atomically replaced snapshot, validated by the Worker before use.
-- The existing D1 deployment credential can refresh this table; no new
-- Cloudflare KV write permission is required.
CREATE TABLE ofac_snapshots (
  id INTEGER PRIMARY KEY CHECK(id=1),
  payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
  checked_at INTEGER NOT NULL CHECK(checked_at > 0)
);
