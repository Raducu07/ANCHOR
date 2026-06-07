-- =========================
-- ANCHOR security.sql
-- Apply manually (NOT during Render startup).
-- Purpose:
--  - Safe login lookup without leaking clinic data
--  - RLS enable + tenant policies for portal tables
--  - Optional grants for runtime role anchor_app
--
-- Notes:
--  - Requires app_current_clinic_id() to exist (created in schema.sql)
--  - Do NOT run from app boot migrations if Render keeps failing
--
-- 2A-D.1 Patch 4A / 5B — HISTORICAL / MANUAL REFERENCE.
-- The replayable legacy RLS policy source for the clinic-scoped tables
-- (clinics, clinic_users, clinic_user_invites, clinic_policies,
-- clinic_policy_state, clinic_privacy_profile, clinic_governance_events,
-- ops_metrics_events) now lives in:
--     migrations/10014_legacy_rls_policies.sql
-- The admin_audit_events ENABLE + FORCE RLS + tenant policy now lives in:
--     migrations/10015_admin_audit_events_rls.sql
-- Both migrations are idempotent and applied automatically at startup
-- by app/migrate.py. This file is retained for historical reference and
-- for the `clinics_public` view + `resolve_clinic_id_by_slug` function
-- + role grants below, which are still applied manually.
--
-- CORRECTION (Patch 5B, supersedes the Patch 4A note in this header):
-- The earlier note here described `rls_admin_audit_tenant` as dead-weight.
-- That was a misreading. `public.admin_audit_events` is CLINIC-scoped
-- (schema.sql:456 — `clinic_id uuid NOT NULL REFERENCES clinics(...)`).
-- Every writer reaches the INSERT via Depends(get_db), which sets
-- app.clinic_id RLS context before the handler body runs, so the policy
-- in section 5 below is both appropriate and active. Patch 5B promotes
-- it to a versioned migration and adds FORCE RLS for defence-in-depth.
-- `public.platform_admin_audit_events` (a separate table with no
-- clinic_id) remains platform-scoped and intentionally outside clinic
-- RLS — not touched by either migration.
-- =========================

-- 1) Safe public view for login (slug + active only)
CREATE OR REPLACE VIEW public.clinics_public AS
SELECT clinic_slug, active_status
FROM public.clinics;

-- 2) Safe resolver function for login (returns clinic_id only)
-- SECURITY DEFINER lets it bypass RLS on clinics safely.
CREATE OR REPLACE FUNCTION public.resolve_clinic_id_by_slug(p_slug text)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
  SELECT clinic_id
  FROM public.clinics
  WHERE clinic_slug = p_slug::citext
    AND active_status = true
  LIMIT 1
$$;

-- 3) Lock down function execution (no DO blocks)
REVOKE ALL ON FUNCTION public.resolve_clinic_id_by_slug(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.resolve_clinic_id_by_slug(text) TO anchor_app;

-- 4) Enable RLS (no FORCE here)
ALTER TABLE public.clinics ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_user_invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_policy_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_privacy_profile ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_governance_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ops_metrics_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_audit_events ENABLE ROW LEVEL SECURITY;

-- 5) Tenant policies (clinic_id must match session setting)

DROP POLICY IF EXISTS rls_clinics_tenant ON public.clinics;
CREATE POLICY rls_clinics_tenant ON public.clinics
  USING (clinic_id = public.app_current_clinic_id())
  WITH CHECK (clinic_id = public.app_current_clinic_id());

DROP POLICY IF EXISTS rls_clinic_users_tenant ON public.clinic_users;
CREATE POLICY rls_clinic_users_tenant ON public.clinic_users
  USING (clinic_id = public.app_current_clinic_id())
  WITH CHECK (clinic_id = public.app_current_clinic_id());

DROP POLICY IF EXISTS rls_clinic_invites_tenant ON public.clinic_user_invites;
CREATE POLICY rls_clinic_invites_tenant ON public.clinic_user_invites
  USING (clinic_id = public.app_current_clinic_id())
  WITH CHECK (clinic_id = public.app_current_clinic_id());

DROP POLICY IF EXISTS rls_clinic_policies_tenant ON public.clinic_policies;
CREATE POLICY rls_clinic_policies_tenant ON public.clinic_policies
  USING (clinic_id = public.app_current_clinic_id())
  WITH CHECK (clinic_id = public.app_current_clinic_id());

DROP POLICY IF EXISTS rls_clinic_policy_state_tenant ON public.clinic_policy_state;
CREATE POLICY rls_clinic_policy_state_tenant ON public.clinic_policy_state
  USING (clinic_id = public.app_current_clinic_id())
  WITH CHECK (clinic_id = public.app_current_clinic_id());

DROP POLICY IF EXISTS rls_privacy_profile_tenant ON public.clinic_privacy_profile;
CREATE POLICY rls_privacy_profile_tenant ON public.clinic_privacy_profile
  USING (clinic_id = public.app_current_clinic_id())
  WITH CHECK (clinic_id = public.app_current_clinic_id());

DROP POLICY IF EXISTS rls_clinic_gov_events_tenant ON public.clinic_governance_events;
CREATE POLICY rls_clinic_gov_events_tenant ON public.clinic_governance_events
  USING (clinic_id = public.app_current_clinic_id())
  WITH CHECK (clinic_id = public.app_current_clinic_id());

DROP POLICY IF EXISTS rls_ops_metrics_tenant ON public.ops_metrics_events;
CREATE POLICY rls_ops_metrics_tenant ON public.ops_metrics_events
  USING (clinic_id = public.app_current_clinic_id())
  WITH CHECK (clinic_id = public.app_current_clinic_id());

DROP POLICY IF EXISTS rls_admin_audit_tenant ON public.admin_audit_events;
CREATE POLICY rls_admin_audit_tenant ON public.admin_audit_events
  USING (clinic_id = public.app_current_clinic_id())
  WITH CHECK (clinic_id = public.app_current_clinic_id());

-- 6) Grants (RLS-scoped reads)
GRANT SELECT ON public.clinics_public TO anchor_app;
GRANT SELECT ON public.clinics TO anchor_app;

