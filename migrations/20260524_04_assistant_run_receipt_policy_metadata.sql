-- ============================================================
-- 20260524_04_assistant_run_receipt_policy_metadata.sql
--
-- M6.7.1 — surface Assistant policy context in metadata-only receipts.
--
-- Adds three nullable columns to assistant_run_receipts so newly-created
-- receipts persist the policy snapshot (governance evidence) for the run.
-- Legacy receipts written before M6.7.1 carry NULLs in these columns and
-- continue to deserialize cleanly through the existing receipt response
-- mapper (`_row_to_receipt`).
--
-- No data is backfilled. No raw policy notes are surfaced — only the
-- policy id (UUID reference), the version, and the validation profile.
--
-- Idempotent + boot-safe.
-- ============================================================

BEGIN;

ALTER TABLE public.assistant_run_receipts
    ADD COLUMN IF NOT EXISTS assistant_policy_id uuid NULL;

ALTER TABLE public.assistant_run_receipts
    ADD COLUMN IF NOT EXISTS assistant_policy_version integer NULL;

ALTER TABLE public.assistant_run_receipts
    ADD COLUMN IF NOT EXISTS assistant_validation_profile text NULL;

COMMIT;
