-- ============================================================
-- 20260524_01_assistant_run_receipts.sql
--
-- M6.5 — Metadata-only Assistant receipts.
--
-- A receipt is a snapshot of governance metadata for one Assistant run at
-- the moment a human-reviewed run is sealed as evidence. It NEVER contains:
--   * raw input
--   * prompt text
--   * draft / output text
--   * clinical content
--
-- It only contains hashes, key/flag lists, status fields, model labels,
-- and timestamps — i.e. exactly the same metadata-only surface used by
-- the existing assistant_runs traceability path, frozen at receipt time.
--
-- One receipt per (clinic_id, assistant_run_id) — idempotent by unique
-- constraint, so repeated "Create receipt" clicks return the same row.
-- ============================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.assistant_run_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id uuid NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    assistant_run_id uuid NOT NULL
        REFERENCES public.assistant_runs(id) ON DELETE RESTRICT,
    created_by_user_id uuid NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,

    receipt_kind text NOT NULL DEFAULT 'assistant_run_metadata',
    receipt_version text NOT NULL DEFAULT 'assistant_receipt_v1',

    storage_policy text NOT NULL DEFAULT 'metadata_only_by_default',
    raw_content_stored boolean NOT NULL DEFAULT false,
    prompt_stored boolean NOT NULL DEFAULT false,
    draft_stored boolean NOT NULL DEFAULT false,

    -- Snapshot fields (metadata-only).
    run_status text NOT NULL,
    review_status text NOT NULL,
    review_decision text NULL,

    input_sha256 text NOT NULL,
    output_sha256 text NULL,

    mode text NOT NULL,
    contract_version text NOT NULL,
    workflow_origin text NOT NULL,

    pii_detected boolean NOT NULL,
    pii_types jsonb NOT NULL DEFAULT '[]'::jsonb,
    safety_flags jsonb NOT NULL DEFAULT '[]'::jsonb,
    refusal_reason_codes jsonb NOT NULL DEFAULT '[]'::jsonb,

    model_provider text NULL,
    model_name text NULL,

    assistant_run_created_at timestamptz NOT NULL,
    assistant_run_reviewed_at timestamptz NULL,
    assistant_run_reviewed_by_user_id uuid NULL,

    receipt_created_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_assistant_run_receipts_clinic_run
    ON public.assistant_run_receipts (clinic_id, assistant_run_id);

CREATE INDEX IF NOT EXISTS idx_assistant_run_receipts_clinic_created_at
    ON public.assistant_run_receipts (clinic_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_assistant_run_receipts_assistant_run_id
    ON public.assistant_run_receipts (assistant_run_id);

-- Storage policy CHECK guards (idempotent).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'assistant_run_receipts_metadata_only_check'
    ) THEN
        ALTER TABLE public.assistant_run_receipts
            ADD CONSTRAINT assistant_run_receipts_metadata_only_check
            CHECK (
                raw_content_stored = false
                AND prompt_stored = false
                AND draft_stored = false
                AND storage_policy = 'metadata_only_by_default'
            );
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'assistant_run_receipts_review_status_check'
    ) THEN
        ALTER TABLE public.assistant_run_receipts
            ADD CONSTRAINT assistant_run_receipts_review_status_check
            CHECK (review_status IN (
                'reviewed_approved',
                'reviewed_rejected',
                'reviewed_needs_edit'
            ));
    END IF;
END
$$;

-- Enable + force RLS.
ALTER TABLE public.assistant_run_receipts ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'assistant_run_receipts'
          AND policyname = 'rls_assistant_run_receipts_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_assistant_run_receipts_tenant
            ON public.assistant_run_receipts
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

ALTER TABLE public.assistant_run_receipts FORCE ROW LEVEL SECURITY;

COMMIT;
