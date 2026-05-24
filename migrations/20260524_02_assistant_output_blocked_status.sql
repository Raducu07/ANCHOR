-- ============================================================
-- 20260524_02_assistant_output_blocked_status.sql
--
-- M6.6 — extend assistant_runs.run_status CHECK to include 'output_blocked'.
--
-- 'output_blocked' marks runs where the model was invoked but the generated
-- draft failed ANCHOR's post-output safety validation. It is NOT a provider
-- failure (those stay generation_failed) and NOT an input-side refusal
-- (those stay generation_refused).
--
-- Idempotent + boot-safe: drop-if-exists then recreate with the expanded
-- allowlist. Matches the existing migration style.
-- ============================================================

BEGIN;

ALTER TABLE public.assistant_runs
    DROP CONSTRAINT IF EXISTS assistant_runs_run_status_check;

ALTER TABLE public.assistant_runs
    ADD CONSTRAINT assistant_runs_run_status_check
    CHECK (run_status IN (
        'created',
        'generation_succeeded',
        'generation_failed',
        'generation_refused',
        'output_blocked'
    ));

COMMIT;
