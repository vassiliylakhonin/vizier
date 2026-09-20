-- Explicit opt-in review payloads, isolated from metadata-only verification audit.
CREATE TABLE human_reviews (
  id TEXT PRIMARY KEY,
  request_hash TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING','APPROVED','REJECTED','CONSUMED')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  decided_at INTEGER,
  reason TEXT,
  token TEXT,
  token_expires_at INTEGER,
  consumed_at INTEGER
);
CREATE INDEX human_reviews_created ON human_reviews(created_at DESC);
-- Events are written by triggers in the same transaction as the state change.
CREATE TABLE human_review_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  review_id TEXT NOT NULL REFERENCES human_reviews(id) ON DELETE CASCADE,
  state TEXT NOT NULL,
  occurred_at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  reason TEXT
);
CREATE TRIGGER human_review_created AFTER INSERT ON human_reviews BEGIN
  INSERT INTO human_review_events(review_id,state,occurred_at,actor)
  VALUES (NEW.id,'PENDING',NEW.created_at,'integration');
END;
CREATE TRIGGER human_review_transition AFTER UPDATE OF status ON human_reviews
WHEN NEW.status <> OLD.status BEGIN
  INSERT INTO human_review_events(review_id,state,occurred_at,actor,reason)
  VALUES (NEW.id,NEW.status,COALESCE(NEW.consumed_at,NEW.decided_at),
    CASE WHEN NEW.status = 'CONSUMED' THEN 'integration' ELSE 'reviewer' END,NEW.reason);
END;
