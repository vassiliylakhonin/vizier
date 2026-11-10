-- Tamper-evident audit chain. Each stored verification receipt carries the
-- SHA-256 hash of its own canonical metadata row (receipt_hash) and the hash
-- of the previous chained receipt (prev_receipt_hash), so modification,
-- insertion, reordering, or deletion of a chained row breaks every later
-- link. Rows written before this migration keep empty hashes and are skipped
-- as legacy by chain verification.

ALTER TABLE audit_receipts ADD COLUMN receipt_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_receipts ADD COLUMN prev_receipt_hash TEXT NOT NULL DEFAULT '';
