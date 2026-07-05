-- ============================================================
-- 20260705_01_learn_maturity_schema.sql
--
-- M4.6 - Learn Maturity and Enablement (schema only). Code-wise
-- completion under the 2026-07-05 founder code-completion decision
-- record (docs/operations/). Non-certifying by design.
--
-- Creates four objects:
--   * learning_module_checks  - ANCHOR-curated GLOBAL self-check /
--                               scenario question catalogue. NOT
--                               clinic-scoped. No RLS (shared metadata,
--                               identical across clinics).
--   * learning_check_attempts - per-user per-clinic self-check
--                               reinforcement records. RLS ENABLED +
--                               FORCED. Aggregate counts only - no
--                               per-question answers are stored.
--   * learning_role_paths     - GLOBAL role-based learning path
--                               definitions. NOT clinic-scoped. No RLS.
--   * learning_renewal_policies - per-clinic renewal cadence setting.
--                               RLS ENABLED + FORCED.
--
-- Non-certifying doctrine (M4.6):
--   * Self-check attempts are reinforcement activity, NOT competence
--     assessment. No pass/fail column, no grade column, no
--     certification column exists or may be added here.
--   * questions_total / questions_correct are activity metadata for
--     the learner's own reinforcement view, never a competence claim.
--
-- Metadata-only doctrine:
--   * No free-text learner submissions. No clinical content.
--   * Check prompts/options/explanations are ANCHOR-authored global
--     educational content, not clinic data.
--
-- Tenancy: clinic-scoped tables use app_current_clinic_id()
-- (app/schema.sql), matching learning_completions. Policies are
-- created inside DO $$ pg_policies guards (idempotent).
--
-- This migration must remain idempotent and boot-safe.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- M4.6.a - learning_module_checks: GLOBAL catalogue (NO RLS)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.learning_module_checks (
    check_id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id             uuid        NOT NULL
        REFERENCES public.learning_modules(module_id) ON DELETE RESTRICT,
    check_slug            text        NOT NULL UNIQUE,
    version               text        NOT NULL,
    kind                  text        NOT NULL
        CHECK (kind IN ('knowledge_check', 'scenario')),
    prompt                text        NOT NULL,
    options               text[]      NOT NULL,
    correct_option_index  integer     NOT NULL CHECK (correct_option_index >= 0),
    explanation           text        NOT NULL,
    display_order         integer     NOT NULL DEFAULT 0,
    is_active             boolean     NOT NULL DEFAULT true,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_learning_module_checks_module
    ON public.learning_module_checks (module_id, is_active, display_order);

-- ------------------------------------------------------------
-- M4.6.b - learning_check_attempts: per-user records (RLS + FORCE)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.learning_check_attempts (
    attempt_id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id          uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    user_id            uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,
    module_id          uuid        NOT NULL
        REFERENCES public.learning_modules(module_id) ON DELETE RESTRICT,

    module_version     text        NOT NULL,
    questions_total    integer     NOT NULL CHECK (questions_total > 0),
    questions_correct  integer     NOT NULL CHECK (questions_correct >= 0),
    completed_at       timestamptz NOT NULL DEFAULT now(),
    created_at         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT learning_check_attempts_correct_lte_total
        CHECK (questions_correct <= questions_total)
);

CREATE INDEX IF NOT EXISTS idx_learning_check_attempts_user
    ON public.learning_check_attempts (clinic_id, user_id, module_id);

ALTER TABLE public.learning_check_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.learning_check_attempts FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'learning_check_attempts'
          AND policyname = 'rls_learning_check_attempts_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_learning_check_attempts_tenant
            ON public.learning_check_attempts
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- ------------------------------------------------------------
-- M4.6.c - learning_role_paths: GLOBAL path definitions (NO RLS)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.learning_role_paths (
    path_id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    path_slug          text        NOT NULL UNIQUE,
    version            text        NOT NULL,
    title              text        NOT NULL,
    summary            text        NOT NULL,
    role_applicability text[]      NOT NULL,
    module_slugs       text[]      NOT NULL,
    display_order      integer     NOT NULL DEFAULT 0,
    is_active          boolean     NOT NULL DEFAULT true,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_learning_role_paths_active
    ON public.learning_role_paths (is_active, display_order);

-- ------------------------------------------------------------
-- M4.6.d - learning_renewal_policies: per-clinic cadence (RLS + FORCE)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.learning_renewal_policies (
    renewal_policy_id  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id          uuid        NOT NULL UNIQUE
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,

    renewal_months     integer     NOT NULL DEFAULT 12
        CHECK (renewal_months >= 1 AND renewal_months <= 60),
    updated_by_user_id uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.learning_renewal_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.learning_renewal_policies FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'learning_renewal_policies'
          AND policyname = 'rls_learning_renewal_policies_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_learning_renewal_policies_tenant
            ON public.learning_renewal_policies
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

COMMIT;
