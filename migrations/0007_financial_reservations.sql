-- Workflow limits only; not a claim to cover out-of-band wallet spending.
-- No seeded policy. Owner configuration is required before financial reviews.
CREATE TABLE financial_policies (
  wallet TEXT PRIMARY KEY,
  single_limit INTEGER NOT NULL CHECK(single_limit BETWEEN 1 AND 1000000000000),
  daily_limit INTEGER NOT NULL CHECK(daily_limit BETWEEN single_limit AND 1000000000000),
  enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
  updated_at INTEGER NOT NULL,
  reason TEXT NOT NULL
);
CREATE TABLE financial_reservations (
  review_id TEXT PRIMARY KEY REFERENCES human_reviews(id) ON DELETE CASCADE,
  wallet TEXT NOT NULL REFERENCES financial_policies(wallet),
  amount INTEGER NOT NULL CHECK(amount BETWEEN 1 AND 1000000000000),
  state TEXT NOT NULL CHECK(state IN ('RESERVED','CLAIMED','SETTLED','REVERTED')),
  tx_hash TEXT UNIQUE,
  settled_at INTEGER,
  block_number INTEGER,
  block_hash TEXT
);
CREATE INDEX financial_reservations_wallet ON financial_reservations(wallet,state);
CREATE TABLE financial_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  review_id TEXT NOT NULL REFERENCES human_reviews(id) ON DELETE CASCADE,
  state TEXT NOT NULL,
  occurred_at INTEGER NOT NULL,
  tx_hash TEXT
);
CREATE TABLE financial_policy_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  wallet TEXT NOT NULL,
  single_limit INTEGER NOT NULL,
  daily_limit INTEGER NOT NULL,
  enabled INTEGER NOT NULL,
  occurred_at INTEGER NOT NULL,
  reason TEXT NOT NULL
);
CREATE TRIGGER financial_policy_insert AFTER INSERT ON financial_policies BEGIN
  INSERT INTO financial_policy_events(wallet,single_limit,daily_limit,enabled,occurred_at,reason)
  VALUES(NEW.wallet,NEW.single_limit,NEW.daily_limit,NEW.enabled,NEW.updated_at,NEW.reason);
END;
CREATE TRIGGER financial_policy_update AFTER UPDATE ON financial_policies BEGIN
  INSERT INTO financial_policy_events(wallet,single_limit,daily_limit,enabled,occurred_at,reason)
  VALUES(NEW.wallet,NEW.single_limit,NEW.daily_limit,NEW.enabled,NEW.updated_at,NEW.reason);
END;
-- Check and reserve in the same write transaction, including concurrent callers.
CREATE TRIGGER financial_reserve BEFORE INSERT ON financial_reservations BEGIN
  SELECT CASE WHEN NEW.state <> 'RESERVED' OR NOT EXISTS (
    SELECT 1 FROM financial_policies p WHERE p.wallet=NEW.wallet AND p.enabled=1
    AND NEW.amount <= p.single_limit
    AND NEW.amount + COALESCE((
      SELECT SUM(r.amount) FROM financial_reservations r JOIN human_reviews h ON h.id=r.review_id
      WHERE r.wallet=NEW.wallet AND (
        r.state='CLAIMED' OR (r.state='SETTLED' AND r.settled_at > unixepoch()-86400)
        OR (r.state='RESERVED' AND h.expires_at > unixepoch() AND
          (h.status='PENDING' OR (h.status='APPROVED' AND h.token_expires_at > unixepoch())))
      )
    ),0) <= p.daily_limit
  ) THEN RAISE(ABORT,'FINANCIAL_BUDGET_UNAVAILABLE') END;
END;
CREATE TRIGGER financial_reserved AFTER INSERT ON financial_reservations BEGIN
  INSERT INTO financial_events(review_id,state,occurred_at) VALUES(NEW.review_id,NEW.state,unixepoch());
END;
-- Legacy financial approvals without reservations cannot be approved or consumed.
CREATE TRIGGER financial_claim BEFORE UPDATE OF status ON human_reviews
WHEN NEW.status IN ('APPROVED','CONSUMED') AND (
  json_extract(NEW.payload_json,'$.audience')='agenda-financial-guard:base-native-usdc'
  OR json_extract(NEW.payload_json,'$.action.type')='base-native-usdc-transfer'
) BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM financial_reservations r JOIN financial_policies p ON p.wallet=r.wallet
    WHERE r.review_id=NEW.id AND r.state='RESERVED' AND p.enabled=1 AND NEW.expires_at > unixepoch() AND NEW.token_expires_at > unixepoch() AND r.amount <= p.single_limit
    AND (SELECT COALESCE(SUM(r2.amount),0) FROM financial_reservations r2 JOIN human_reviews h ON h.id=r2.review_id
      WHERE r2.wallet=r.wallet AND (r2.state='CLAIMED' OR (r2.state='SETTLED' AND r2.settled_at > unixepoch()-86400)
      OR (r2.state='RESERVED' AND h.expires_at > unixepoch() AND (h.status='PENDING' OR (h.status='APPROVED' AND h.token_expires_at > unixepoch()))))) <= p.daily_limit
  ) THEN RAISE(ABORT,'FINANCIAL_RESERVATION_UNAVAILABLE') END;
  UPDATE financial_reservations SET state='CLAIMED' WHERE review_id=NEW.id AND NEW.status='CONSUMED';
END;
CREATE TRIGGER financial_transition AFTER UPDATE ON financial_reservations
WHEN NEW.state <> OLD.state OR NEW.tx_hash IS NOT OLD.tx_hash BEGIN
  INSERT INTO financial_events(review_id,state,occurred_at,tx_hash)
  VALUES(NEW.review_id,NEW.state,unixepoch(),NEW.tx_hash);
END;
-- Retention must never erase an unresolved hold, or recent settled spend.
CREATE TRIGGER financial_preserve BEFORE DELETE ON human_reviews
WHEN EXISTS (SELECT 1 FROM financial_reservations WHERE review_id=OLD.id
  AND (state='CLAIMED' OR (state='SETTLED' AND settled_at > unixepoch()-86400)))
BEGIN SELECT RAISE(ABORT,'FINANCIAL_RETENTION_HOLD'); END;
