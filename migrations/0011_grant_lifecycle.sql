-- Delegation grant lifecycle. Holds only grant ids (jti) and timestamps: no
-- authority, agent, principal or action data. Rows expire with the grant.
CREATE TABLE revoked_grants (
  jti TEXT PRIMARY KEY,
  revoked_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE consumed_grants (
  jti TEXT PRIMARY KEY,
  consumed_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX idx_revoked_grants_expires ON revoked_grants(expires_at);
CREATE INDEX idx_consumed_grants_expires ON consumed_grants(expires_at);
