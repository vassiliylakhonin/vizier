-- Track monthly quota periods and reset usage per calendar month
ALTER TABLE vizier_api_keys ADD COLUMN period_month TEXT NOT NULL DEFAULT '';
