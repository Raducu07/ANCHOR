-- ------------------------------------------------------------
-- 20260603_03_incident_near_miss_schema.sql
--
-- Phase 2A-5.1 - Basic Incident / Near-Miss Logging schema.
--
-- Creates one clinic-scoped table:
--
--   * ai_incident_near_miss_records
--       Structured, metadata-only governance records for AI-use
--       incident and near-miss review signals. RLS ENABLED + FORCED.
--
-- This is a structured AI-use review-signal record. It is NOT a
-- clinical record. It does NOT replace any professional incident
-- reporting duty the clinic may have under its own governance
-- arrangements. These records support reflective governance
-- learning, not blame.
--
-- IMPORTANT v1 doctrine (founder-confirmed in 2A-5.0):
--   * NO FREE TEXT COLUMNS AT ALL.
--     All "what happened" granularity flows through CHECK-enforced
--     enums (status / severity / category / source / outcome /
--     action_taken_category / void_reason_category).
--   * Linked governance metadata is ID-only - no body content is
--     duplicated from receipts, runs, or governance events.
--   * Append-only correction: voiding sets is-voided-equivalent
--     state via status='voided' + void_reason_category + voided_at +
--     voided_by_user_id. Rows are never deleted.
--   * No staff names / emails. Only `*_by_user_id` UUIDs.
--   * No client identifiers, patient identifiers, transcripts, raw
--     prompts, raw outputs, or case material. The schema simply
--     does not carry columns for those concepts.
--
-- Tenancy:
--   * Clinic-scoped via `app_current_clinic_id()` (defined in
--     app/schema.sql), matching learning_completions /
--     clinic_policy_versions / clinic_self_assessments /
--     clinic_client_transparency_profiles.
--   * RLS policy created inside a DO $$ pg_policies guard
--     (idempotent).
--
-- Audit:
--   * No admin_audit_events insert in this schema slice. The 2A-5.2
--     endpoint slice will write append-only audit events with NO
--     ON CONFLICT against the partial admin_audit_events_idem_uq
--     index (M6.10.1B / TD-BE postmortem).
--
-- This migration must remain idempotent and boot-safe.
-- ------------------------------------------------------------

BEGIN;

CREATE TABLE IF NOT EXISTS public.ai_incident_near_miss_records (
    incident_id                                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id                                   uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,

    -- Actor UUIDs only. The handler layer never returns staff
    -- names / emails alongside these IDs.
    created_by_user_id                          uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,
    reviewed_by_user_id                         uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,
    closed_by_user_id                           uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,
    voided_by_user_id                           uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,

    -- Controlled vocabulary. Every enum value here matches the
    -- canonical list the 2A-5.2 endpoint vocabulary route will
    -- expose.
    status                                      text        NOT NULL
        CHECK (status IN (
            'open','in_review','actioned','closed','voided'
        )),

    severity                                    text        NOT NULL
        CHECK (severity IN ('low','moderate','high','critical')),

    category                                    text        NOT NULL
        CHECK (category IN (
            'misleading_output',
            'inaccurate_output',
            'unsafe_suggestion',
            'privacy_or_identifier_risk',
            'overconfident_output',
            'missing_human_review',
            'policy_boundary_issue',
            'inappropriate_client_communication',
            'workflow_confusion',
            'other'
        )),

    source                                      text        NOT NULL
        CHECK (source IN (
            'assistant_workspace',
            'external_ai_tool',
            'ambient_or_scribe',
            'client_communication',
            'internal_summary',
            'clinical_note_support',
            'other'
        )),

    outcome                                     text        NOT NULL
        CHECK (outcome IN (
            'caught_before_use',
            'corrected_before_use',
            'used_with_correction',
            'escalated_for_review',
            'client_communication_delayed',
            'clinical_team_reviewed',
            'other'
        )),

    action_taken_category                       text        NULL
        CHECK (action_taken_category IS NULL OR action_taken_category IN (
            'no_action_required',
            'additional_review',
            'staff_briefing',
            'policy_review',
            'process_change',
            'vendor_followup',
            'other'
        )),

    -- Reflective signals: do we recommend extra learning,
    -- governance policy review, or client communication review
    -- as a follow-on?
    learning_recommended                        boolean     NOT NULL DEFAULT false,
    policy_review_recommended                   boolean     NOT NULL DEFAULT false,
    client_communication_review_recommended     boolean     NOT NULL DEFAULT false,

    -- Time metadata. occurred_at / detected_at are clinic-supplied
    -- approximations; reported_at is the wall-clock at create time.
    occurred_at                                 timestamptz NULL,
    detected_at                                 timestamptz NULL,
    reported_at                                 timestamptz NOT NULL DEFAULT now(),
    reviewed_at                                 timestamptz NULL,
    closed_at                                   timestamptz NULL,
    voided_at                                   timestamptz NULL,

    -- Optional ID-only links to existing governance metadata
    -- surfaces. NEVER duplicates body content from those tables.
    -- ON DELETE SET NULL: if the linked artefact is removed
    -- upstream, the incident record remains as a standalone
    -- governance signal.
    linked_receipt_id                           uuid        NULL
        REFERENCES public.assistant_run_receipts(id) ON DELETE SET NULL,
    linked_governance_event_id                  uuid        NULL
        REFERENCES public.clinic_governance_events(event_id) ON DELETE SET NULL,
    linked_assistant_run_id                     uuid        NULL
        REFERENCES public.assistant_runs(id) ON DELETE SET NULL,
    linked_clinic_policy_version_id             uuid        NULL
        REFERENCES public.clinic_policy_versions(clinic_policy_version_id) ON DELETE SET NULL,

    -- Void posture. Append-only - rows are never deleted.
    void_reason_category                        text        NULL
        CHECK (void_reason_category IS NULL OR void_reason_category IN (
            'duplicate',
            'wrong_clinic_record',
            'test_data',
            'incorrect_metadata',
            'other'
        )),

    created_at                                  timestamptz NOT NULL DEFAULT now(),
    updated_at                                  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_incident_near_miss_records_clinic_status
    ON public.ai_incident_near_miss_records (clinic_id, status);

CREATE INDEX IF NOT EXISTS idx_ai_incident_near_miss_records_clinic_severity
    ON public.ai_incident_near_miss_records (clinic_id, severity);

CREATE INDEX IF NOT EXISTS idx_ai_incident_near_miss_records_clinic_category
    ON public.ai_incident_near_miss_records (clinic_id, category);

CREATE INDEX IF NOT EXISTS idx_ai_incident_near_miss_records_clinic_source
    ON public.ai_incident_near_miss_records (clinic_id, source);

CREATE INDEX IF NOT EXISTS idx_ai_incident_near_miss_records_clinic_reported_at
    ON public.ai_incident_near_miss_records (clinic_id, reported_at DESC);

CREATE INDEX IF NOT EXISTS idx_ai_incident_near_miss_records_clinic_creator
    ON public.ai_incident_near_miss_records (clinic_id, created_by_user_id);

-- Partial indexes on optional ID-only links: most rows will not
-- carry these, so partial indexes keep the index footprint small
-- while supporting the "linked-to-X" Trust posture aggregates that
-- 2A-5.4 will build.
CREATE INDEX IF NOT EXISTS idx_ai_incident_near_miss_records_clinic_linked_receipt
    ON public.ai_incident_near_miss_records (clinic_id, linked_receipt_id)
    WHERE linked_receipt_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ai_incident_near_miss_records_clinic_linked_governance_event
    ON public.ai_incident_near_miss_records (clinic_id, linked_governance_event_id)
    WHERE linked_governance_event_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ai_incident_near_miss_records_clinic_linked_assistant_run
    ON public.ai_incident_near_miss_records (clinic_id, linked_assistant_run_id)
    WHERE linked_assistant_run_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ai_incident_near_miss_records_clinic_voided_at
    ON public.ai_incident_near_miss_records (clinic_id, voided_at)
    WHERE voided_at IS NOT NULL;

ALTER TABLE public.ai_incident_near_miss_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_incident_near_miss_records FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'ai_incident_near_miss_records'
          AND policyname = 'rls_ai_incident_near_miss_records_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_ai_incident_near_miss_records_tenant
            ON public.ai_incident_near_miss_records
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

COMMIT;
