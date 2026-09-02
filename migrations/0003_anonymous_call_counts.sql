-- Counts the traffic that leaves no receipt.
--
-- /mcp and /a2a answer without a credential, and neither writes a receipt, so
-- the only record of an anonymous call was a line in the Worker log. That made
-- "did the registry listing bring anyone?" a question nothing here could
-- answer, and FUTURE.md defers work until observed use argues for it.
--
-- One row per day per surface per outcome, incremented in place: at most four
-- rows a day, no row per call, and nothing about the caller. The metadata-only
-- audit store stays metadata-only.
CREATE TABLE IF NOT EXISTS anonymous_call_counts (
  day TEXT NOT NULL,
  surface TEXT NOT NULL,
  outcome TEXT NOT NULL,
  calls INTEGER NOT NULL,
  PRIMARY KEY (day, surface, outcome)
);

CREATE INDEX anonymous_call_counts_day_idx ON anonymous_call_counts (day);
