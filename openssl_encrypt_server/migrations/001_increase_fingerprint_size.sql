-- Migration: Increase fingerprint column size from 64 to 100
-- Date: 2026-01-03
-- Reason: SHA-256 fingerprints with colon separators are 95 characters (32 bytes * 2 hex + 31 colons)
--         Previous size of 64 was insufficient

-- Update ks_keys table fingerprint column
ALTER TABLE ks_keys
ALTER COLUMN fingerprint TYPE VARCHAR(100);

-- Update ks_access_log table key_fingerprint column
ALTER TABLE ks_access_log
ALTER COLUMN key_fingerprint TYPE VARCHAR(100);

-- Add comment explaining the size
COMMENT ON COLUMN ks_keys.fingerprint IS 'SHA-256 fingerprint with colons (e.g., 3a:4b:5c:...) - 95 characters';
COMMENT ON COLUMN ks_access_log.key_fingerprint IS 'SHA-256 fingerprint with colons (e.g., 3a:4b:5c:...) - 95 characters';
