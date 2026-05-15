-- ============================================================
-- 20260515_01_assistant_runs.sql
--
-- Governed Vet Assistant — PR 1 (schema only).
--
-- Metadata-only table for assistant runs:
--   - No raw input column
--   - No raw output column
--   - No clinical content column
--   - Only hashes, key lists, flags, and governance pointers
--
-- Tenancy:
--   - clinic_id FK -> public.clinics(clinic_id) ON DELETE RESTRICT
--   - clinic_user_id FK -> public.clinic_users(user_id) ON DELETE RESTRICT
--   - RLS ENABLED + FORCED
--   - Tenant policy uses app_current_clinic_id() (app.clinic_id session var)
--
-- This migration must remain idempotent and boot-safe.
-- ============================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.assistant_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id uuid NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    clinic_user_id uuid NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,

    mode text NOT NULL,
    contract_version text NOT NULL,
    workflow_origin text NOT NULL DEFAULT 'anchor_assistant',

    input_sha256 text NOT NULL,
    output_sha256 text NULL,

    input_field_keys jsonb NOT NULL DEFAULT '[]'::jsonb,

    pii_detected boolean NOT NULL DEFAULT false,
    pii_types jsonb NOT NULL DEFAULT '[]'::jsonb,
    safety_flags jsonb NOT NULL DEFAULT '[]'::jsonb,
    refusal_reason_codes jsonb NOT NULL DEFAULT '[]'::jsonb,

    review_status text NOT NULL DEFAULT 'not_reviewed',

    receipt_id uuid NULL,
    governance_event_id uuid NULL,

    model_provider text NULL,
    model_name text NULL,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_assistant_runs_clinic_created_at
    ON public.assistant_runs (clinic_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_assistant_runs_clinic_user_created_at
    ON public.assistant_runs (clinic_id, clinic_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_assistant_runs_clinic_mode_created_at
    ON public.assistant_runs (clinic_id, mode, created_at DESC);

-- Enable RLS
ALTER TABLE public.assistant_runs ENABLE ROW LEVEL SECURITY;

-- Tenant policy (idempotent: only create if missing)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'assistant_runs'
          AND policyname = 'rls_assistant_runs_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_assistant_runs_tenant
            ON public.assistant_runs
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- Force RLS (table owner cannot bypass tenant policy)
ALTER TABLE public.assistant_runs FORCE ROW LEVEL SECURITY;

COMMIT;
