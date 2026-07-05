-- ============================================================
-- 20260705_05_ambient_governance_schema.sql
--
-- M6.13 - Ambient Governance Integration (governance shell only).
-- Code-wise completion under the 2026-07-05 founder code-completion
-- decision record (docs/operations/). ANCHOR remains the governance
-- layer, NOT the scribe.
--
-- One table: ambient_governance_events (RLS ENABLED + FORCED).
--
-- Hard boundaries (schema-level impossibility, not just policy):
--   * NO transcript column. NO note-body column. NO audio column.
--     NO content column of any kind exists or may be added here.
--   * The only external pointer is workflow_reference_hash - a SHA-256
--     hex string validated at the API layer. Content never enters
--     ANCHOR; at most a hash of an artefact held elsewhere.
--   * source_label is a short clinic-controlled tool label, not a
--     vendor integration.
--   * The review gate records WHO reviewed WHAT WHEN and the decision
--     category - never what the note said.
--
-- This migration must remain idempotent and boot-safe.
-- ============================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.ambient_governance_events (
    ambient_event_id     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    clinic_id            uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    recorded_by_user_id  uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,

    source_label         text        NOT NULL,
    event_type           text        NOT NULL
        CHECK (event_type IN (
            'consult_recorded', 'note_generated',
            'note_reviewed_externally', 'other'
        )),
    occurred_at          timestamptz NOT NULL,
    duration_seconds     integer     NULL
        CHECK (duration_seconds IS NULL OR duration_seconds >= 0),
    workflow_reference_hash text     NULL,

    review_status        text        NOT NULL DEFAULT 'pending_review'
        CHECK (review_status IN (
            'pending_review', 'reviewed', 'discarded'
        )),
    review_decision      text        NULL
        CHECK (review_decision IS NULL OR review_decision IN (
            'approved_for_record', 'amended_before_use', 'rejected'
        )),
    reviewed_by_user_id  uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,
    reviewed_at          timestamptz NULL,

    created_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ambient_events_clinic_status
    ON public.ambient_governance_events (clinic_id, review_status, occurred_at DESC);

ALTER TABLE public.ambient_governance_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ambient_governance_events FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'ambient_governance_events'
          AND policyname = 'rls_ambient_governance_events_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_ambient_governance_events_tenant
            ON public.ambient_governance_events
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

COMMIT;
