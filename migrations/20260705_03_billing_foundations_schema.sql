-- ============================================================
-- 20260705_03_billing_foundations_schema.sql
--
-- M5.8 - Billing and Activation Foundations (schema only,
-- sandbox-only). Code-wise completion under the 2026-07-05 founder
-- code-completion decision record (docs/operations/).
--
-- Creates two objects:
--   * billing_plans        - GLOBAL plan catalogue. NOT clinic-scoped.
--                            No RLS. Prices are deliberately NULL:
--                            pilot pricing is a founder decision and
--                            no price is published or implied here.
--   * clinic_billing_state - per-clinic activation posture.
--                            RLS ENABLED + FORCED.
--
-- Hard boundaries (sandbox-only doctrine):
--   * No live billing. No charge capability. No card / bank / payment
--     instrument fields exist or may be added here.
--   * stripe_mode is constrained to 'disabled' or 'test' at the schema
--     level - a 'live' value is impossible to store.
--   * activation_status values 'active_limited' / 'active_verified'
--     exist in the model (Roadmap v2.6 M5.8) but the API refuses to
--     set them; they require the security + legal gates.
--
-- This migration must remain idempotent and boot-safe.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- M5.8.a - billing_plans: GLOBAL catalogue (NO RLS)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.billing_plans (
    plan_id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_slug           text        NOT NULL UNIQUE,
    version             text        NOT NULL,
    title               text        NOT NULL,
    summary             text        NOT NULL,
    monthly_price_pence integer     NULL CHECK (monthly_price_pence >= 0),
    currency            text        NOT NULL DEFAULT 'GBP',
    is_active           boolean     NOT NULL DEFAULT true,
    display_order       integer     NOT NULL DEFAULT 0,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_billing_plans_active
    ON public.billing_plans (is_active, display_order);

-- ------------------------------------------------------------
-- M5.8.b - clinic_billing_state: per-clinic posture (RLS + FORCE)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.clinic_billing_state (
    billing_state_id   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id          uuid        NOT NULL UNIQUE
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,

    plan_slug          text        NOT NULL DEFAULT 'internal_demo',
    activation_status  text        NOT NULL DEFAULT 'internal_demo'
        CHECK (activation_status IN (
            'internal_demo', 'pilot_candidate',
            'active_limited', 'active_verified'
        )),
    billing_readiness  text        NOT NULL DEFAULT 'not_ready'
        CHECK (billing_readiness IN (
            'not_ready', 'sandbox_only', 'ready_pending_gates'
        )),
    stripe_mode        text        NOT NULL DEFAULT 'disabled'
        CHECK (stripe_mode IN ('disabled', 'test')),

    updated_by_user_id uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.clinic_billing_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_billing_state FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'clinic_billing_state'
          AND policyname = 'rls_clinic_billing_state_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_clinic_billing_state_tenant
            ON public.clinic_billing_state
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- ------------------------------------------------------------
-- M5.8.c - plan catalogue seed (prices deliberately NULL)
-- ------------------------------------------------------------
INSERT INTO public.billing_plans (
    plan_slug, version, title, summary,
    monthly_price_pence, currency, is_active, display_order
) VALUES (
    'internal_demo',
    '1.0.0',
    'Internal Demo',
    'Internal demonstration and walkthrough use. Not a commercial offer.',
    NULL, 'GBP', true, 1
)
ON CONFLICT (plan_slug) DO NOTHING;

INSERT INTO public.billing_plans (
    plan_slug, version, title, summary,
    monthly_price_pence, currency, is_active, display_order
) VALUES (
    'pilot',
    '1.0.0',
    'Pilot',
    'Structure for a future pilot arrangement. Pricing is not set here and no offer is made.',
    NULL, 'GBP', true, 2
)
ON CONFLICT (plan_slug) DO NOTHING;

COMMIT;
