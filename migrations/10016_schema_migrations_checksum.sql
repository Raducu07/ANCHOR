-- ============================================================
-- 10016_schema_migrations_checksum.sql
--
-- 2A-D.1 Patch 6 — Migration checksum verification.
--
-- Adds the `checksum` column to public.schema_migrations so that the
-- migration runner can verify, on every startup, that the on-disk
-- contents of each applied migration still match the SHA-256 captured
-- when the migration was first applied.
--
-- Doctrine:
-- - "Existing migrations are never retroactively edited." This column
--   is the substrate that lets the runner enforce that rule at startup,
--   rather than relying on reviewer discipline alone.
-- - The column is nullable (no NOT NULL) so older applied rows that
--   pre-date this migration can be backfilled gracefully by the runner
--   instead of blocking startup.
--
-- Safety:
-- - ADD COLUMN IF NOT EXISTS → idempotent. Replayable on a DB that
--   already has the column (e.g. operator-applied historical schema).
-- - No DROP, no DEFAULT change, no NOT NULL.
-- - No data rewrite — existing rows keep NULL checksum until the runner
--   backfills them on the next boot.
-- ============================================================

BEGIN;

ALTER TABLE public.schema_migrations
    ADD COLUMN IF NOT EXISTS checksum text;

COMMIT;
