-- ============================================================
-- 20260705_04_sustainability_schema.sql
--
-- M6-S - Sustainability Governance & Evidence Module (schema only).
-- Code-wise completion under the 2026-07-05 founder code-completion
-- decision record (docs/operations/). No real clinic operational data
-- is authorised; this is structure, not activation.
--
-- Roadmap v2.6 Section 8 schema corrections - applied here:
--   1. Rolling 12-month view aggregates energy, waste, and footprint
--      SEPARATELY (per-stream CTEs) before joining on month.
--   2. Every RLS policy carries USING and WITH CHECK.
--   3. User references use the live clinic_users(user_id) model.
--   4. Clinic-controlled supplier_label; supplier_display_name is not
--      used anywhere.
--   5. Amendment/supersession: evidence rows use void-with-reason
--      (learning_completions precedent); reports carry superseded_at /
--      superseded_by_report_id.
--   6. Table named sustainability_workflow_footprint_estimates.
--   7. Factor provenance is simple factor_source_text in v1; a full
--      provenance table remains future work.
--
-- Metadata-only doctrine: operational quantities (kWh, kg, kg CO2e),
-- dates, clinic-controlled labels, and aggregate report payloads only.
-- No clinical content, no client data, no patient data.
--
-- This migration must remain idempotent and boot-safe.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- M6-S.a - sustainability_config (RLS + FORCE; one row per clinic)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.sustainability_config (
    config_id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    clinic_id            uuid        NOT NULL UNIQUE
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    reporting_enabled    boolean     NOT NULL DEFAULT false,
    baseline_year        integer     NULL
        CHECK (baseline_year IS NULL OR (baseline_year >= 2000 AND baseline_year <= 2100)),
    electricity_factor_g_co2e_per_kwh numeric(12,4) NULL
        CHECK (electricity_factor_g_co2e_per_kwh IS NULL OR electricity_factor_g_co2e_per_kwh >= 0),
    gas_factor_g_co2e_per_kwh         numeric(12,4) NULL
        CHECK (gas_factor_g_co2e_per_kwh IS NULL OR gas_factor_g_co2e_per_kwh >= 0),
    waste_factor_g_co2e_per_kg        numeric(12,4) NULL
        CHECK (waste_factor_g_co2e_per_kg IS NULL OR waste_factor_g_co2e_per_kg >= 0),
    factor_source_text   text        NULL,
    updated_by_user_id   uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.sustainability_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sustainability_config FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'sustainability_config'
          AND policyname = 'rls_sustainability_config_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_sustainability_config_tenant
            ON public.sustainability_config
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- ------------------------------------------------------------
-- M6-S.b - sustainability_energy_readings (RLS + FORCE)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.sustainability_energy_readings (
    reading_id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    clinic_id            uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    recorded_by_user_id  uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,

    energy_type          text        NOT NULL
        CHECK (energy_type IN ('electricity', 'gas', 'other')),
    period_start         date        NOT NULL,
    period_end           date        NOT NULL,
    consumption_kwh      numeric(14,3) NOT NULL CHECK (consumption_kwh >= 0),
    supplier_label       text        NULL,

    is_voided            boolean     NOT NULL DEFAULT false,
    void_reason          text        NULL,
    voided_at            timestamptz NULL,
    voided_by_user_id    uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,

    created_at           timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT sustainability_energy_period_valid
        CHECK (period_end >= period_start)
);

CREATE INDEX IF NOT EXISTS idx_sustainability_energy_clinic_period
    ON public.sustainability_energy_readings (clinic_id, period_start DESC);

ALTER TABLE public.sustainability_energy_readings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sustainability_energy_readings FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'sustainability_energy_readings'
          AND policyname = 'rls_sustainability_energy_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_sustainability_energy_tenant
            ON public.sustainability_energy_readings
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- ------------------------------------------------------------
-- M6-S.c - sustainability_waste_events (RLS + FORCE)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.sustainability_waste_events (
    waste_event_id       uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    clinic_id            uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    recorded_by_user_id  uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,

    waste_stream         text        NOT NULL
        CHECK (waste_stream IN (
            'clinical', 'offensive', 'domestic', 'recycling', 'other'
        )),
    occurred_on          date        NOT NULL,
    weight_kg            numeric(12,3) NOT NULL CHECK (weight_kg >= 0),
    supplier_label       text        NULL,

    is_voided            boolean     NOT NULL DEFAULT false,
    void_reason          text        NULL,
    voided_at            timestamptz NULL,
    voided_by_user_id    uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,

    created_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sustainability_waste_clinic_date
    ON public.sustainability_waste_events (clinic_id, occurred_on DESC);

ALTER TABLE public.sustainability_waste_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sustainability_waste_events FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'sustainability_waste_events'
          AND policyname = 'rls_sustainability_waste_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_sustainability_waste_tenant
            ON public.sustainability_waste_events
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- ------------------------------------------------------------
-- M6-S.d - sustainability_workflow_footprint_estimates (RLS + FORCE)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.sustainability_workflow_footprint_estimates (
    estimate_id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    clinic_id            uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    recorded_by_user_id  uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,

    workflow_label       text        NOT NULL,
    period_start         date        NOT NULL,
    period_end           date        NOT NULL,
    estimated_kg_co2e    numeric(14,3) NOT NULL CHECK (estimated_kg_co2e >= 0),
    factor_source_text   text        NULL,

    is_voided            boolean     NOT NULL DEFAULT false,
    void_reason          text        NULL,
    voided_at            timestamptz NULL,
    voided_by_user_id    uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,

    created_at           timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT sustainability_footprint_period_valid
        CHECK (period_end >= period_start)
);

CREATE INDEX IF NOT EXISTS idx_sustainability_footprint_clinic_period
    ON public.sustainability_workflow_footprint_estimates (clinic_id, period_start DESC);

ALTER TABLE public.sustainability_workflow_footprint_estimates ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sustainability_workflow_footprint_estimates FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'sustainability_workflow_footprint_estimates'
          AND policyname = 'rls_sustainability_footprint_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_sustainability_footprint_tenant
            ON public.sustainability_workflow_footprint_estimates
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- ------------------------------------------------------------
-- M6-S.e - sustainability_reports (RLS + FORCE; supersession fields)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.sustainability_reports (
    report_id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    clinic_id            uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    generated_by_user_id uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,

    report_version       integer     NOT NULL CHECK (report_version >= 1),
    period_start         date        NOT NULL,
    period_end           date        NOT NULL,
    energy_kwh_total     numeric(16,3) NOT NULL DEFAULT 0 CHECK (energy_kwh_total >= 0),
    waste_kg_total       numeric(16,3) NOT NULL DEFAULT 0 CHECK (waste_kg_total >= 0),
    estimated_kg_co2e_total numeric(16,3) NOT NULL DEFAULT 0 CHECK (estimated_kg_co2e_total >= 0),
    report_payload       jsonb       NOT NULL,
    report_hash          text        NOT NULL,

    superseded_at        timestamptz NULL,
    superseded_by_report_id uuid     NULL
        REFERENCES public.sustainability_reports(report_id) ON DELETE SET NULL,

    generated_at         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT sustainability_reports_period_valid
        CHECK (period_end >= period_start),
    CONSTRAINT sustainability_reports_version_unique
        UNIQUE (clinic_id, report_version)
);

CREATE INDEX IF NOT EXISTS idx_sustainability_reports_clinic
    ON public.sustainability_reports (clinic_id, generated_at DESC);

ALTER TABLE public.sustainability_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sustainability_reports FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'sustainability_reports'
          AND policyname = 'rls_sustainability_reports_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_sustainability_reports_tenant
            ON public.sustainability_reports
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- ------------------------------------------------------------
-- M6-S.f - rolling 12-month view (correction #1: aggregate each
-- stream separately BEFORE joining on month)
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW public.v_sustainability_rolling_12m AS
WITH energy AS (
    SELECT clinic_id,
           date_trunc('month', period_start)::date AS month,
           SUM(consumption_kwh) AS energy_kwh
    FROM public.sustainability_energy_readings
    WHERE is_voided = false
      AND period_start >= (now() - interval '12 months')::date
    GROUP BY clinic_id, date_trunc('month', period_start)::date
),
waste AS (
    SELECT clinic_id,
           date_trunc('month', occurred_on)::date AS month,
           SUM(weight_kg) AS waste_kg
    FROM public.sustainability_waste_events
    WHERE is_voided = false
      AND occurred_on >= (now() - interval '12 months')::date
    GROUP BY clinic_id, date_trunc('month', occurred_on)::date
),
footprint AS (
    SELECT clinic_id,
           date_trunc('month', period_start)::date AS month,
           SUM(estimated_kg_co2e) AS estimated_kg_co2e
    FROM public.sustainability_workflow_footprint_estimates
    WHERE is_voided = false
      AND period_start >= (now() - interval '12 months')::date
    GROUP BY clinic_id, date_trunc('month', period_start)::date
)
SELECT
    COALESCE(e.clinic_id, w.clinic_id, f.clinic_id) AS clinic_id,
    COALESCE(e.month, w.month, f.month)             AS month,
    e.energy_kwh,
    w.waste_kg,
    f.estimated_kg_co2e
FROM energy e
FULL OUTER JOIN waste w
    ON w.clinic_id = e.clinic_id AND w.month = e.month
FULL OUTER JOIN footprint f
    ON f.clinic_id = COALESCE(e.clinic_id, w.clinic_id)
   AND f.month = COALESCE(e.month, w.month);

COMMIT;
