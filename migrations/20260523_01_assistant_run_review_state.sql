-- ============================================================
-- 20260523_01_assistant_run_review_state.sql
--
-- M6.4 — Human review-state workflow for assistant_runs.
--
-- Adds metadata-only review fields:
--   * review_decision       (short controlled value, never free text)
--   * reviewed_at           (when the review was recorded)
--   * reviewed_by_user_id   (which clinic_user recorded the review)
--
-- review_status (already on the table) takes the new completion values:
--   reviewed_approved | reviewed_rejected | reviewed_needs_edit
-- in addition to the existing 'not_reviewed' default.
--
-- review_decision allowed values:
--   approved_for_use | rejected_not_safe | needs_edit_before_use | NULL
--
-- Idempotent + boot-safe.
-- ============================================================

BEGIN;

ALTER TABLE public.assistant_runs
    ADD COLUMN IF NOT EXISTS reviewed_at timestamptz NULL;

ALTER TABLE public.assistant_runs
    ADD COLUMN IF NOT EXISTS reviewed_by_user_id uuid NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT;

ALTER TABLE public.assistant_runs
    ADD COLUMN IF NOT EXISTS review_decision text NULL;

-- review_status check constraint (idempotent guard).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'assistant_runs_review_status_check'
    ) THEN
        ALTER TABLE public.assistant_runs
            ADD CONSTRAINT assistant_runs_review_status_check
            CHECK (review_status IN (
                'not_reviewed',
                'reviewed_approved',
                'reviewed_rejected',
                'reviewed_needs_edit'
            ));
    END IF;
END
$$;

-- review_decision check constraint (idempotent guard); NULL allowed.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'assistant_runs_review_decision_check'
    ) THEN
        ALTER TABLE public.assistant_runs
            ADD CONSTRAINT assistant_runs_review_decision_check
            CHECK (
                review_decision IS NULL
                OR review_decision IN (
                    'approved_for_use',
                    'rejected_not_safe',
                    'needs_edit_before_use'
                )
            );
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_assistant_runs_clinic_review_status_reviewed_at
    ON public.assistant_runs (clinic_id, review_status, reviewed_at DESC);

COMMIT;
