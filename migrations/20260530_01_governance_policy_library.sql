-- ------------------------------------------------------------
-- 20260530_01_governance_policy_library.sql
--
-- Phase 2A-2.1 - Governance Policy Library + Staff Attestation schema.
--
-- Creates five objects:
--   * policy_templates                - ANCHOR-curated GLOBAL catalogue
--                                       of organisational AI-use policy
--                                       templates. NOT clinic-scoped.
--                                       No RLS (shared metadata).
--   * clinic_policy_versions          - per-clinic adoption of a template
--                                       at a chosen version.
--                                       RLS ENABLED + FORCED.
--   * policy_attestations             - per-user per-clinic staff
--                                       acknowledgement of a specific
--                                       clinic policy version.
--                                       RLS ENABLED + FORCED.
--   * v_clinic_active_policies        - derived view of currently-active
--                                       clinic policy versions.
--   * v_clinic_policy_attestation_coverage
--                                     - derived view: per-active-policy
--                                       attestation counts, excluding
--                                       voided attestations.
--
-- IMPORTANT distinction:
--   * `assistant_policy_settings`     = Assistant RUNTIME configuration
--                                       (validation profile, limits,
--                                       enabled flags). UNCHANGED here.
--   * `policy_templates` / `clinic_policy_versions`
--                                     = ORGANISATIONAL AI-use policy
--                                       artefacts (this migration).
--   These two surfaces are deliberately separate.
--
-- Metadata-only doctrine:
--   * Policy BODY text is NOT stored in the DB. Templates carry only a
--     `content_reference` pointing at markdown shipped under
--     docs/governance/policies/<slug>-<version>.md. An optional
--     `content_sha256` provides tamper-evidence.
--   * Clinic adoption snapshots the title/summary/hash at activation
--     time so audit evidence survives template churn upstream.
--   * Attestation is governance evidence ONLY. No competence_grade,
--     pass_fail, score, free-text reflection, staff_certified,
--     compliance_status, or clinical_safety_proof columns. The schema
--     intentionally cannot carry those concepts.
--   * Corrections use void-with-reason; rows are never deleted or
--     overwritten silently.
--
-- role_applicability on templates is AUDIENCE METADATA only. It is NOT
-- an access-control role and has no relationship to clinic_users.role.
--
-- Tenancy:
--   * Clinic-scoped tables use `app_current_clinic_id()` (defined in
--     app/schema.sql), matching learning_completions / assistant_runs /
--     assistant_policy_settings.
--   * RLS policies created inside DO $$ pg_policies guards (idempotent).
--
-- Audit:
--   * Admin-side governance actions (create/activate/archive/void)
--     reuse the existing append-only admin_audit_events table from a
--     LATER endpoint slice (2A-2.2/2A-2.3). This migration does not
--     insert into admin_audit_events. We deliberately do NOT use
--     ON CONFLICT against the partial admin_audit_events_idem_uq index
--     anywhere in this file (see TD-BE / M6.10.1B postmortem).
--
-- This migration must remain idempotent and boot-safe.
-- ------------------------------------------------------------

BEGIN;

-- ------------------------------------------------------------
-- 2A-2.1.a - policy_templates: GLOBAL catalogue (NOT clinic-scoped, NO RLS)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.policy_templates (
    template_id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    template_slug          text        NOT NULL UNIQUE,
    template_version       text        NOT NULL,
    title                  text        NOT NULL,
    summary                text        NOT NULL,
    category               text        NOT NULL,
    role_applicability     text[]      NOT NULL,
    jurisdiction_tags      text[]      NOT NULL,
    source_basis           text[]      NOT NULL,
    content_reference      text        NOT NULL,
    content_sha256         text        NULL,
    is_active              boolean     NOT NULL DEFAULT true,
    superseded_by          uuid        NULL
        REFERENCES public.policy_templates(template_id) ON DELETE SET NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policy_templates_active
    ON public.policy_templates (is_active);

CREATE INDEX IF NOT EXISTS idx_policy_templates_category
    ON public.policy_templates (category);

CREATE INDEX IF NOT EXISTS idx_policy_templates_slug
    ON public.policy_templates (template_slug);

-- ------------------------------------------------------------
-- 2A-2.1.b - clinic_policy_versions: per-clinic adoption (RLS + FORCE)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.clinic_policy_versions (
    clinic_policy_version_id  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id                 uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    policy_template_id        uuid        NOT NULL
        REFERENCES public.policy_templates(template_id) ON DELETE RESTRICT,

    template_version_snapshot text        NOT NULL,
    clinic_policy_version     integer     NOT NULL,

    status                    text        NOT NULL
        CHECK (status IN ('draft','active','superseded','archived')),

    title_snapshot            text        NOT NULL,
    summary_snapshot          text        NOT NULL,
    content_sha256_snapshot   text        NULL,

    effective_from            timestamptz NULL,

    created_by_user_id        uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,
    activated_by_user_id      uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,
    activated_at              timestamptz NULL,
    superseded_at             timestamptz NULL,

    created_at                timestamptz NOT NULL DEFAULT now(),
    updated_at                timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT clinic_policy_versions_unique
        UNIQUE (clinic_id, policy_template_id, clinic_policy_version)
);

-- One active row per (clinic, template). Partial unique index allows
-- multiple non-active (draft / superseded / archived) rows to coexist.
CREATE UNIQUE INDEX IF NOT EXISTS clinic_policy_versions_one_active_per_template
    ON public.clinic_policy_versions (clinic_id, policy_template_id)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_clinic_policy_versions_clinic_template_version
    ON public.clinic_policy_versions
        (clinic_id, policy_template_id, clinic_policy_version DESC);

CREATE INDEX IF NOT EXISTS idx_clinic_policy_versions_clinic_status
    ON public.clinic_policy_versions (clinic_id, status);

CREATE INDEX IF NOT EXISTS idx_clinic_policy_versions_clinic_activated_at
    ON public.clinic_policy_versions (clinic_id, activated_at DESC);

ALTER TABLE public.clinic_policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_policy_versions FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'clinic_policy_versions'
          AND policyname = 'rls_clinic_policy_versions_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_clinic_policy_versions_tenant
            ON public.clinic_policy_versions
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- ------------------------------------------------------------
-- 2A-2.1.c - policy_attestations: per-user per-clinic (RLS + FORCE)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.policy_attestations (
    attestation_id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id                   uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    clinic_policy_version_id    uuid        NOT NULL
        REFERENCES public.clinic_policy_versions(clinic_policy_version_id)
        ON DELETE RESTRICT,
    user_id                     uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,

    attestation_statement_version text      NOT NULL,
    acknowledged_at             timestamptz NOT NULL DEFAULT now(),
    acknowledgement_method      text        NOT NULL,
    policy_content_sha256_snapshot text     NULL,
    ip_hash                     text        NULL,

    is_voided                   boolean     NOT NULL DEFAULT false,
    void_reason                 text        NULL,
    voided_at                   timestamptz NULL,
    voided_by_user_id           uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,

    created_at                  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT policy_attestations_unique
        UNIQUE (clinic_id, clinic_policy_version_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_policy_attestations_clinic_user
    ON public.policy_attestations (clinic_id, user_id);

CREATE INDEX IF NOT EXISTS idx_policy_attestations_clinic_policy_version
    ON public.policy_attestations (clinic_id, clinic_policy_version_id);

CREATE INDEX IF NOT EXISTS idx_policy_attestations_clinic_acknowledged_at
    ON public.policy_attestations (clinic_id, acknowledged_at DESC);

ALTER TABLE public.policy_attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.policy_attestations FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'policy_attestations'
          AND policyname = 'rls_policy_attestations_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_policy_attestations_tenant
            ON public.policy_attestations
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- ------------------------------------------------------------
-- 2A-2.1.d - v_clinic_active_policies: derived active-policy view
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW public.v_clinic_active_policies AS
SELECT
    clinic_id,
    policy_template_id,
    clinic_policy_version_id,
    clinic_policy_version,
    title_snapshot,
    summary_snapshot,
    content_sha256_snapshot,
    activated_at
FROM public.clinic_policy_versions
WHERE status = 'active';

-- ------------------------------------------------------------
-- 2A-2.1.e - v_clinic_policy_attestation_coverage: derived coverage view
-- ------------------------------------------------------------
-- Per active clinic policy version: count of NON-voided attestations
-- and distinct attesting users. Active policies with zero attestations
-- are preserved (LEFT JOIN) so the Trust posture can surface them.
CREATE OR REPLACE VIEW public.v_clinic_policy_attestation_coverage AS
SELECT
    cpv.clinic_id,
    cpv.policy_template_id,
    cpv.clinic_policy_version_id,
    COUNT(pa.attestation_id) FILTER (WHERE pa.is_voided = false)
        AS attestation_count,
    COUNT(DISTINCT pa.user_id) FILTER (WHERE pa.is_voided = false)
        AS distinct_user_count,
    MAX(pa.acknowledged_at) FILTER (WHERE pa.is_voided = false)
        AS most_recent_acknowledged_at
FROM public.clinic_policy_versions cpv
LEFT JOIN public.policy_attestations pa
    ON pa.clinic_policy_version_id = cpv.clinic_policy_version_id
   AND pa.clinic_id = cpv.clinic_id
WHERE cpv.status = 'active'
GROUP BY cpv.clinic_id, cpv.policy_template_id, cpv.clinic_policy_version_id;

COMMIT;
