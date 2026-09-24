-- Latest daily read-only wallet-history check. It never authorizes spending.
CREATE TABLE wallet_history_monitor (
  id INTEGER PRIMARY KEY CHECK(id=1),
  wallet TEXT NOT NULL,
  checked_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('OK','FAILED')),
  observed_outgoing INTEGER,
  start_block INTEGER,
  end_block INTEGER,
  end_block_hash TEXT,
  reason TEXT,
  CHECK((state='OK' AND observed_outgoing IS NOT NULL AND start_block IS NOT NULL
    AND end_block IS NOT NULL AND end_block_hash IS NOT NULL AND reason IS NULL)
    OR (state='FAILED' AND observed_outgoing IS NULL AND start_block IS NULL
    AND end_block IS NULL AND end_block_hash IS NULL AND reason IS NOT NULL))
);
