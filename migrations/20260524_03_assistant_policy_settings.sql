-- ============================================================
-- 20260524_03_assistant_policy_settings.sql
--
-- M6.7 — Clinic-scoped Assistant policy / settings persistence.
--
-- Hard doctrine (DB-enforced):
--   * require_human_review must always be TRUE
--   * allow_receipts_after_review must always be TRUE
--   * validation_profile is one of 'standard' | 'conservative'
--   * No fields exist that could enable diagnosis, prescribing, dosing,
--     or autonomous triage — those prohibitions are not configurable.
--
-- Versioning:
--   * Each update inserts a new (clinic_id, policy_version) row.
--   * Only one row per clinic may be active at a time (partial unique).
--   * Old rows are flipped is_active=false, superseded_at=now() by app.
--
-- Tenancy:
--   * RLS ENABLED + FORCED.
--   * Policy uses app_current_clinic_id() (same pattern as assistant_runs).
--
-- assistant_runs gets three nullable forward-link columns so each run
-- records which Assistant policy version governed it.
--
-- Idempotent + boot-safe.
-- ============================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.assistant_policy_settings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id uuid NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,

    policy_version integer NOT NULL,
    is_active boolean NOT NULL DEFAULT false,

    -- Operational toggles.
    client_communication_enabled boolean NOT NULL DEFAULT true,
    generation_enabled boolean NOT NULL DEFAULT true,
    validation_profile text NOT NULL DEFAULT 'standard',

    -- Cost / abuse caps. Mirror the env defaults used by PR 2D.
    daily_run_limit_per_clinic integer NOT NULL DEFAULT 50,
    monthly_run_limit_per_clinic integer NOT NULL DEFAULT 1000,

    -- Hard doctrine — must remain TRUE. CHECK constraint enforces this
    -- at the DB level. App-level PATCH validation also rejects attempts
    -- to set these to false.
    require_human_review boolean NOT NULL DEFAULT true,
    allow_receipts_after_review boolean NOT NULL DEFAULT true,

    -- Display metadata.
    policy_label text NOT NULL DEFAULT 'Default Assistant Policy',
    policy_notes text NULL,
    created_by_user_id uuid NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz NULL,
    superseded_at timestamptz NULL,

    CONSTRAINT assistant_policy_settings_unique_version
        UNIQUE (clinic_id, policy_version),

    CONSTRAINT assistant_policy_settings_validation_profile_check
        CHECK (validation_profile IN ('standard', 'conservative')),

    CONSTRAINT assistant_policy_settings_daily_limit_check
        CHECK (daily_run_limit_per_clinic BETWEEN 1 AND 500),

    CONSTRAINT assistant_policy_settings_monthly_limit_check
        CHECK (monthly_run_limit_per_clinic BETWEEN 1 AND 10000),

    -- Hard doctrine — non-configurable safety guarantees.
    CONSTRAINT assistant_policy_settings_require_review_check
        CHECK (require_human_review = true),

    CONSTRAINT assistant_policy_settings_allow_receipts_check
        CHECK (allow_receipts_after_review = true)
);

-- One active policy per clinic.
CREATE UNIQUE INDEX IF NOT EXISTS uq_assistant_policy_settings_one_active_per_clinic
    ON public.assistant_policy_settings (clinic_id)
    WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_assistant_policy_settings_clinic_version_desc
    ON public.assistant_policy_settings (clinic_id, policy_version DESC);

-- Tenant isolation.
ALTER TABLE public.assistant_policy_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.assistant_policy_settings FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'assistant_policy_settings'
          AND policyname = 'rls_assistant_policy_settings_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_assistant_policy_settings_tenant
            ON public.assistant_policy_settings
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- Forward-link policy onto assistant_runs (all nullable, backward-safe).
ALTER TABLE public.assistant_runs
    ADD COLUMN IF NOT EXISTS assistant_policy_id uuid NULL;

ALTER TABLE public.assistant_runs
    ADD COLUMN IF NOT EXISTS assistant_policy_version integer NULL;

ALTER TABLE public.assistant_runs
    ADD COLUMN IF NOT EXISTS assistant_validation_profile text NULL;

COMMIT;
