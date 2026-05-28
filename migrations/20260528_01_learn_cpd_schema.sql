-- ============================================================
-- 20260528_01_learn_cpd_schema.sql
--
-- Phase 2A-1 - CPD-Recordable AI Literacy (schema only).
--
-- Creates four objects:
--   * learning_modules  - ANCHOR-curated GLOBAL catalogue. NOT clinic-scoped.
--                         No RLS (shared metadata, identical across clinics).
--   * learning_completions - per-user per-clinic completion records.
--                            RLS ENABLED + FORCED.
--   * v_cpd_records     - derived per-user CPD record view; excludes voided rows.
--   * cpd_exports       - immutable per-user export artefacts. RLS ENABLED + FORCED.
--
-- Metadata-only doctrine:
--   * No raw learning content is stored. learning_modules.content_reference is a
--     relative path / URL to markdown shipped with the deploy.
--   * No quiz answers, no clinical content, no free-text learner submissions.
--   * Completion corrections use void-with-reason; rows are never deleted/overwritten.
--   * cpd_exports stores a SHA-256 of its payload for downstream integrity checks.
--
-- role_applicability is AUDIENCE METADATA only. It is NOT an access-control role
-- and has no relationship to clinic_users.role. The DB role enum is untouched.
--
-- Tenancy:
--   * clinic-scoped tables use the existing helper app_current_clinic_id()
--     (defined in app/schema.sql), matching assistant_runs / assistant_policy_settings.
--   * RLS policies created inside DO $$ pg_policies guards (idempotent).
--
-- This migration must remain idempotent and boot-safe.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- 2A-1.a - learning_modules: GLOBAL catalogue (NOT clinic-scoped, NO RLS)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.learning_modules (
    module_id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    module_slug            text        NOT NULL UNIQUE,
    version                text        NOT NULL,
    title                  text        NOT NULL,
    summary                text        NOT NULL,
    learning_objectives    text[]      NOT NULL,
    role_applicability     text[]      NOT NULL,
    cpd_minutes            integer     NOT NULL CHECK (cpd_minutes > 0),
    category               text        NOT NULL
        CHECK (category IN (
            'literacy', 'bias_detection', 'ethical_use',
            'confidentiality', 'transparency', 'preparation_for_practice'
        )),
    rcvs_principle_mappings    text[]  NOT NULL,
    eu_ai_act_article_mappings text[]  NOT NULL,
    content_reference      text        NOT NULL,
    is_active              boolean     NOT NULL DEFAULT true,
    superseded_by          uuid        NULL
        REFERENCES public.learning_modules(module_id) ON DELETE SET NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_learning_modules_active
    ON public.learning_modules (is_active);

CREATE INDEX IF NOT EXISTS idx_learning_modules_category
    ON public.learning_modules (category);

-- ------------------------------------------------------------
-- 2A-1.b - learning_completions: per-user per-clinic records (RLS + FORCE)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.learning_completions (
    completion_id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id                uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    user_id                  uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,
    module_id                uuid        NOT NULL
        REFERENCES public.learning_modules(module_id) ON DELETE RESTRICT,

    module_version           text        NOT NULL,
    completed_at             timestamptz NOT NULL DEFAULT now(),
    acknowledgement_provided boolean     NOT NULL DEFAULT false,
    cpd_minutes_credited     integer     NOT NULL CHECK (cpd_minutes_credited > 0),

    is_voided                boolean     NOT NULL DEFAULT false,
    void_reason              text        NULL,
    voided_at                timestamptz NULL,
    voided_by_user_id        uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,

    created_at               timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT learning_completions_unique
        UNIQUE (clinic_id, user_id, module_id, module_version)
);

CREATE INDEX IF NOT EXISTS idx_learning_completions_user
    ON public.learning_completions (clinic_id, user_id);

CREATE INDEX IF NOT EXISTS idx_learning_completions_module
    ON public.learning_completions (clinic_id, module_id);

ALTER TABLE public.learning_completions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.learning_completions FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'learning_completions'
          AND policyname = 'rls_learning_completions_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_learning_completions_tenant
            ON public.learning_completions
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- ------------------------------------------------------------
-- 2A-1.c - v_cpd_records: derived per-user CPD record (excludes voided rows)
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW public.v_cpd_records AS
SELECT
    clinic_id,
    user_id,
    COUNT(*)                              AS total_modules_completed,
    SUM(cpd_minutes_credited)             AS total_cpd_minutes,
    MIN(completed_at)                     AS first_completion_at,
    MAX(completed_at)                     AS most_recent_completion_at,
    bool_or(acknowledgement_provided)     AS any_acknowledgement_provided
FROM public.learning_completions
WHERE is_voided = false
GROUP BY clinic_id, user_id;

-- ------------------------------------------------------------
-- 2A-1.d - cpd_exports: immutable export artefacts (RLS + FORCE)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.cpd_exports (
    export_id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id              uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    user_id                uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,
    generated_by_user_id   uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,

    export_version         text        NOT NULL,
    export_hash            text        NOT NULL,
    export_payload         jsonb       NOT NULL,
    generated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cpd_exports_user
    ON public.cpd_exports (clinic_id, user_id);

ALTER TABLE public.cpd_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cpd_exports FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'cpd_exports'
          AND policyname = 'rls_cpd_exports_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_cpd_exports_tenant
            ON public.cpd_exports
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

COMMIT;
