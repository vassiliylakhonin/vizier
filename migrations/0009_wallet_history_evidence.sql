-- Independent, conservative finalized Base USDC evidence at review submission.
-- Existing policy remains disabled until pending and wallet-wide enforcement exist.
ALTER TABLE financial_reservations ADD COLUMN observed_outgoing INTEGER;
ALTER TABLE financial_reservations ADD COLUMN observed_at INTEGER;
ALTER TABLE financial_reservations ADD COLUMN observed_start_block INTEGER;
ALTER TABLE financial_reservations ADD COLUMN observed_end_block INTEGER;
ALTER TABLE financial_reservations ADD COLUMN observed_end_hash TEXT;

DROP TRIGGER financial_reserve;
CREATE TRIGGER financial_reserve BEFORE INSERT ON financial_reservations BEGIN
  SELECT (CASE WHEN NEW.state <> 'RESERVED'
    OR NEW.observed_outgoing IS NULL OR NEW.observed_outgoing < 0
    OR NEW.observed_at IS NULL OR NEW.observed_at < unixepoch()-300 OR NEW.observed_at > unixepoch()+60
    OR NEW.observed_start_block IS NULL OR NEW.observed_end_block IS NULL
    OR NEW.observed_end_block <= NEW.observed_start_block
    OR NEW.observed_end_hash IS NULL OR length(NEW.observed_end_hash) <> 66
    OR NOT EXISTS (
      SELECT 1 FROM financial_policies p WHERE p.wallet=NEW.wallet AND p.enabled=1
      AND NEW.amount <= p.single_limit
      -- The history window may include extra blocks and verified settled
      -- reservations. Double counting is conservative, never extra capacity.
      AND NEW.amount + NEW.observed_outgoing + COALESCE((
        SELECT SUM(r.amount) FROM financial_reservations r JOIN human_reviews h ON h.id=r.review_id
        WHERE r.wallet=NEW.wallet AND (
          r.state='CLAIMED' OR (r.state='SETTLED' AND r.settled_at > unixepoch()-86400)
          OR (r.state='RESERVED' AND h.expires_at > unixepoch() AND
            (h.status='PENDING' OR (h.status='APPROVED' AND h.token_expires_at > unixepoch())))
        )
      ),0) <= p.daily_limit
    ) THEN RAISE(ABORT,'FINANCIAL_BUDGET_UNAVAILABLE') END);
END;
