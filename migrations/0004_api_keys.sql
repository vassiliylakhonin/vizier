-- Multi-Tenant B2B API Keys & Quota Management
--
-- Stores client API keys hashed with SHA-256 for fast lookup.
-- Includes organization binding, monthly quota, usage counter, and revocation timestamp.
CREATE TABLE IF NOT EXISTS vizier_api_keys (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  tier TEXT NOT NULL DEFAULT 'developer',
  monthly_quota INTEGER NOT NULL DEFAULT 10000,
  current_usage INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS vizier_api_keys_org_idx ON vizier_api_keys (org_id);
CREATE INDEX IF NOT EXISTS vizier_api_keys_hash_idx ON vizier_api_keys (key_hash);
