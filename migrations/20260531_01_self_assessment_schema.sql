-- ------------------------------------------------------------
-- 20260531_01_self_assessment_schema.sql
--
-- Phase 2A-3.1 - RCVS-aligned AI Governance Self-Assessment schema.
--
-- Creates five objects:
--   * self_assessment_templates       - ANCHOR-curated GLOBAL catalogue
--                                       of self-assessment templates.
--                                       NOT clinic-scoped. No RLS
--                                       (shared metadata).
--   * self_assessment_questions       - ANCHOR-curated GLOBAL catalogue
--                                       of questions belonging to a
--                                       template. NOT clinic-scoped.
--                                       No RLS.
--   * clinic_self_assessments         - per-clinic self-assessment
--                                       lifecycle row
--                                       (draft -> submitted ->
--                                        superseded / archived).
--                                       RLS ENABLED + FORCED.
--   * clinic_self_assessment_answers  - per-question bounded enum
--                                       answers for a clinic
--                                       assessment.
--                                       RLS ENABLED + FORCED.
--   * v_clinic_latest_self_assessment - derived view: latest submitted
--                                       (or superseded) self-assessment
--                                       metadata per clinic/template.
--
-- Distinction from prior phases:
--   * policy_templates / clinic_policy_versions (Phase 2A-2)
--     = organisational AI-use POLICY artefacts.
--   * learning_modules / learning_completions (Phase 2A-1)
--     = CPD-recordable AI literacy training records.
--   * self_assessment_templates / clinic_self_assessments
--     = clinic-self-attested governance POSTURE snapshot.
--   These three surfaces are deliberately separate. A self-assessment
--   answer MAY reference the prior surfaces via bounded
--   `evidence_links` enum metadata, but does NOT mutate them and is
--   never treated as a substitute for them.
--
-- Metadata-only doctrine:
--   * Self-assessment is a dated metadata-only governance artefact.
--     It is NOT legal advice,
--     a clinical-safety record, a competence assessment, or a
--     substitute for professional judgement. Human professional review
--     remains required.
--   * Question prompt_text is ANCHOR-curated catalogue copy ONLY. It
--     is not user-entered, not clinical content, and not vendor copy.
--   * Answer values are a bounded enum (CHECK constraint). There is
--     NO free-text answer field, NO notes column, NO reflection
--     column, NO competence_grade / score / pass_fail /
--     compliance_status / staff_certified / clinical_safety_proof /
--     legal_approval column. The schema is structurally incapable of
--     carrying those concepts.
--   * Submission freezes aggregate counts in
--     readiness_summary_snapshot / linked_evidence_counts_snapshot
--     jsonb columns. These hold aggregate counts only - NOT raw
--     answers, NOT staff identifiers.
--   * Corrections / re-assessments use status transitions
--     (draft -> submitted -> superseded) plus a new draft row with a
--     monotonic clinic_assessment_version. Rows are never deleted or
--     silently overwritten.
--
-- Question slug stability contract:
--   * question_slug values are STABLE across template versions. When
--     a template is bumped to a future version (e.g. 1.0.1), the same
--     slug must be reused for the same conceptual question so
--     longitudinal Trust deltas remain interpretable. Adding a new
--     conceptual question requires a new slug.
--
-- Tenancy:
--   * Clinic-scoped tables use the existing helper
--     `app_current_clinic_id()` (defined in app/schema.sql), matching
--     learning_completions / clinic_policy_versions /
--     policy_attestations.
--   * RLS policies are created inside DO $$ pg_policies guards
--     (idempotent).
--   * Every clinic-scoped RLS policy carries BOTH USING and
--     WITH CHECK against app_current_clinic_id().
--
-- Audit:
--   * Endpoints (a later slice) will write admin-side governance
--     actions to admin_audit_events using pure append-only inserts.
--     This migration does NOT insert into admin_audit_events and does
--     NOT use ON CONFLICT against the partial
--     admin_audit_events_idem_uq index (see TD-BE / M6.10.1B
--     postmortem).
--
-- This migration must remain idempotent and boot-safe.
-- ------------------------------------------------------------

BEGIN;

-- ------------------------------------------------------------
-- 2A-3.1.a - self_assessment_templates: GLOBAL catalogue
--             (NOT clinic-scoped, NO RLS)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.self_assessment_templates (
    template_id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    template_slug              text        NOT NULL UNIQUE,
    template_version           text        NOT NULL,
    title                      text        NOT NULL,
    summary                    text        NOT NULL,
    rcvs_principle_mappings    text[]      NOT NULL,
    eu_ai_act_article_mappings text[]      NOT NULL,
    is_active                  boolean     NOT NULL DEFAULT true,
    superseded_by              uuid        NULL
        REFERENCES public.self_assessment_templates(template_id) ON DELETE SET NULL,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    updated_at                 timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT self_assessment_templates_slug_version_unique
        UNIQUE (template_slug, template_version)
);

CREATE INDEX IF NOT EXISTS idx_self_assessment_templates_active
    ON public.self_assessment_templates (is_active);

-- ------------------------------------------------------------
-- 2A-3.1.b - self_assessment_questions: GLOBAL catalogue
--             (NOT clinic-scoped, NO RLS)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.self_assessment_questions (
    question_id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id                uuid        NOT NULL
        REFERENCES public.self_assessment_templates(template_id) ON DELETE RESTRICT,
    question_slug              text        NOT NULL,
    question_order             integer     NOT NULL CHECK (question_order > 0),
    theme                      text        NOT NULL
        CHECK (theme IN (
            'governance_ownership',
            'policy_availability',
            'staff_literacy',
            'staff_acknowledgement',
            'human_review',
            'data_handling',
            'transparency_to_clients',
            'incident_readiness',
            'tool_vendor_awareness',
            'evidence_audit_readiness'
        )),
    prompt_text                text        NOT NULL,
    guidance_reference         text        NULL,
    evidence_link_hints        text[]      NOT NULL DEFAULT '{}',
    rcvs_principle_mappings    text[]      NOT NULL,
    eu_ai_act_article_mappings text[]      NOT NULL,
    created_at                 timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT self_assessment_questions_template_slug_unique
        UNIQUE (template_id, question_slug),
    CONSTRAINT self_assessment_questions_template_order_unique
        UNIQUE (template_id, question_order)
);

CREATE INDEX IF NOT EXISTS idx_self_assessment_questions_template_order
    ON public.self_assessment_questions (template_id, question_order);

-- ------------------------------------------------------------
-- 2A-3.1.c - clinic_self_assessments: per-clinic lifecycle
--             (RLS + FORCE)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.clinic_self_assessments (
    assessment_id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id                      uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    template_id                    uuid        NOT NULL
        REFERENCES public.self_assessment_templates(template_id) ON DELETE RESTRICT,

    template_version_snapshot      text        NOT NULL,
    clinic_assessment_version      integer     NOT NULL,

    status                         text        NOT NULL
        CHECK (status IN ('draft','submitted','superseded','archived')),

    created_by_user_id             uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,
    submitted_by_user_id           uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,

    submitted_at                   timestamptz NULL,
    superseded_at                  timestamptz NULL,

    total_questions_snapshot       integer     NULL,
    answered_questions_snapshot    integer     NULL,
    readiness_summary_snapshot     jsonb       NULL,
    linked_evidence_counts_snapshot jsonb      NULL,

    created_at                     timestamptz NOT NULL DEFAULT now(),
    updated_at                     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT clinic_self_assessments_unique
        UNIQUE (clinic_id, template_id, clinic_assessment_version)
);

-- One draft row per (clinic, template). Partial unique index allows
-- multiple non-draft (submitted / superseded / archived) rows to
-- coexist.
CREATE UNIQUE INDEX IF NOT EXISTS clinic_self_assessments_one_draft_per_template
    ON public.clinic_self_assessments (clinic_id, template_id)
    WHERE status = 'draft';

CREATE INDEX IF NOT EXISTS idx_clinic_self_assessments_clinic_status
    ON public.clinic_self_assessments (clinic_id, status);

CREATE INDEX IF NOT EXISTS idx_clinic_self_assessments_clinic_submitted_at
    ON public.clinic_self_assessments (clinic_id, submitted_at DESC);

ALTER TABLE public.clinic_self_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_self_assessments FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'clinic_self_assessments'
          AND policyname = 'rls_clinic_self_assessments_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_clinic_self_assessments_tenant
            ON public.clinic_self_assessments
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- ------------------------------------------------------------
-- 2A-3.1.d - clinic_self_assessment_answers: bounded enum answers
--             (RLS + FORCE)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.clinic_self_assessment_answers (
    answer_id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id              uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    assessment_id          uuid        NOT NULL
        REFERENCES public.clinic_self_assessments(assessment_id) ON DELETE CASCADE,
    question_id            uuid        NOT NULL
        REFERENCES public.self_assessment_questions(question_id) ON DELETE RESTRICT,

    question_slug_snapshot text        NOT NULL,
    theme_snapshot         text        NOT NULL,

    answer_value           text        NOT NULL
        CHECK (answer_value IN (
            'yes','partial','planned','no','not_applicable'
        )),

    evidence_links         text[]      NOT NULL DEFAULT '{}',

    answered_by_user_id    uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,
    answered_at            timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT clinic_self_assessment_answers_unique
        UNIQUE (assessment_id, question_id)
);

CREATE INDEX IF NOT EXISTS idx_clinic_self_assessment_answers_clinic_assessment
    ON public.clinic_self_assessment_answers (clinic_id, assessment_id);

CREATE INDEX IF NOT EXISTS idx_clinic_self_assessment_answers_clinic_theme
    ON public.clinic_self_assessment_answers (clinic_id, theme_snapshot);

ALTER TABLE public.clinic_self_assessment_answers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_self_assessment_answers FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'clinic_self_assessment_answers'
          AND policyname = 'rls_clinic_self_assessment_answers_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_clinic_self_assessment_answers_tenant
            ON public.clinic_self_assessment_answers
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- ------------------------------------------------------------
-- 2A-3.1.e - v_clinic_latest_self_assessment: derived latest-per-template
-- ------------------------------------------------------------
-- For each (clinic_id, template_id), return the most recent row in
-- submitted or superseded status. Draft rows are excluded so the view
-- only surfaces dated artefacts. Archived rows are excluded so they
-- do not pollute the latest-evidence surface.
CREATE OR REPLACE VIEW public.v_clinic_latest_self_assessment AS
SELECT DISTINCT ON (clinic_id, template_id)
    clinic_id,
    template_id,
    assessment_id,
    clinic_assessment_version,
    status,
    template_version_snapshot,
    submitted_at,
    submitted_by_user_id,
    superseded_at,
    total_questions_snapshot,
    answered_questions_snapshot,
    readiness_summary_snapshot,
    linked_evidence_counts_snapshot,
    created_at,
    updated_at
FROM public.clinic_self_assessments
WHERE status IN ('submitted','superseded')
ORDER BY clinic_id, template_id, submitted_at DESC NULLS LAST, updated_at DESC;

COMMIT;
