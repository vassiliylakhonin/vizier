-- Pseudonymous daily activity per signed-grant principal, for measuring
-- whether integrations repeat on later days. Written only when the operator
-- sets VIZIER_ACTIVITY_KEY. integration_hash is an HMAC-SHA-256 of the verified
-- grant issuer under that server-only key: no principal, agent, request id,
-- action, target or amount is stored, and the hash is never returned by the
-- API. Rows older than 35 days are pruned by the daily cron.
CREATE TABLE integration_activity (
  integration_hash TEXT NOT NULL,
  day TEXT NOT NULL CHECK (length(day) = 10),
  allow_count INTEGER NOT NULL DEFAULT 0 CHECK (allow_count >= 0),
  other_count INTEGER NOT NULL DEFAULT 0 CHECK (other_count >= 0),
  is_excluded INTEGER NOT NULL DEFAULT 0 CHECK (is_excluded IN (0, 1)),
  PRIMARY KEY (integration_hash, day)
);
CREATE INDEX integration_activity_day ON integration_activity (day);
