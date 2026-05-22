-- ============================================================
-- 20260520_01_assistant_runs_run_status.sql
--
-- Backend PR 2B — add run_status to assistant_runs.
--
-- Allowed values:
--   * created                 (insert-before-model)
--   * generation_succeeded    (model call returned a draft)
--   * generation_failed       (technical failure / API key missing)
--   * generation_refused      (input-side safety gate blocked model call)
--
-- Idempotent + boot-safe. Existing rows backfill to 'created'.
-- ============================================================

BEGIN;

ALTER TABLE public.assistant_runs
    ADD COLUMN IF NOT EXISTS run_status text NOT NULL DEFAULT 'created';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'assistant_runs_run_status_check'
    ) THEN
        ALTER TABLE public.assistant_runs
            ADD CONSTRAINT assistant_runs_run_status_check
            CHECK (run_status IN (
                'created',
                'generation_succeeded',
                'generation_failed',
                'generation_refused'
            ));
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_assistant_runs_clinic_run_status_created_at
    ON public.assistant_runs (clinic_id, run_status, created_at DESC);

COMMIT;
