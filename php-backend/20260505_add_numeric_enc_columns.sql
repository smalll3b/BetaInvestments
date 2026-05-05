-- Add encrypted shadow columns for sensitive numeric values.
-- These columns allow the app to keep doing arithmetic on the original DECIMAL
-- fields while also storing an at-rest encrypted copy.

ALTER TABLE users
  ADD COLUMN cash_balance_enc TEXT NULL AFTER cash_balance;

ALTER TABLE trades
  ADD COLUMN price_enc TEXT NULL AFTER price,
  ADD COLUMN total_amount_enc TEXT NULL AFTER total_amount;


