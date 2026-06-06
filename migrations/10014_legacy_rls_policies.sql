-- ============================================================
-- 10014_legacy_rls_policies.sql
--
-- 2A-D.1 Patch 4A — Legacy RLS Policy Replayability.
--
-- Background:
-- The legacy clinic-scoped CREATE POLICY block historically lived in
-- app/security.sql and was applied manually (NOT during Render startup).
-- Migrations 10010 / 10013 enable + FORCE RLS on these tables, but the
-- policies themselves were not in any versioned migration. A clean DB,
-- DR restore, or fresh local env therefore had FORCE RLS on with no
-- matching policy — effectively deny-all — until someone re-ran
-- app/security.sql by hand.
--
-- This migration promotes the legacy CREATE POLICY block into a versioned,
-- idempotent migration that is replayable on a clean database.
--
-- Doctrine:
-- - Every tenant-scoped policy enforces clinic_id = app_current_clinic_id()
--   on BOTH sides (USING + WITH CHECK). USING-only would allow tenant
--   forging on INSERT / UPDATE.
-- - public.clinic_slug_lookup is INTENTIONALLY RLS-off (pre-auth slug
--   resolution, per migrations/10002_clinic_slug_lookup_rls_off.sql) —
--   NOT included here.
-- - public.admin_audit_events is platform-scoped — NOT included here.
--   The pre-existing rls_admin_audit_tenant policy in app/security.sql
--   is dead-weight (FORCE RLS is not on that table, and writes happen
--   outside a clinic context). Cleanup of that policy is a separate
--   patch (Patch 5 candidate).
-- - public.governance_events (v0) is a dormant legacy table — NOT
--   touched here. Cleanup is Patch 6 housekeeping.
-- - Existing migrations are not retroactively edited.
--
-- Safety:
-- - DROP POLICY IF EXISTS before each CREATE POLICY so this migration
--   is safe to replay (e.g. on a DB that already has policies applied
--   from a prior manual run of app/security.sql).
-- - ENABLE ROW LEVEL SECURITY is idempotent in Postgres.
-- - FORCE RLS is asserted separately by 10010 / 10013 — not duplicated
--   here.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- 1) public.clinics
-- ------------------------------------------------------------
ALTER TABLE IF EXISTS public.clinics
    ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_clinics_tenant ON public.clinics;
CREATE POLICY rls_clinics_tenant ON public.clinics
    FOR ALL
    USING (clinic_id = public.app_current_clinic_id())
    WITH CHECK (clinic_id = public.app_current_clinic_id());

-- ------------------------------------------------------------
-- 2) public.clinic_users
-- ------------------------------------------------------------
ALTER TABLE IF EXISTS public.clinic_users
    ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_clinic_users_tenant ON public.clinic_users;
CREATE POLICY rls_clinic_users_tenant ON public.clinic_users
    FOR ALL
    USING (clinic_id = public.app_current_clinic_id())
    WITH CHECK (clinic_id = public.app_current_clinic_id());

-- ------------------------------------------------------------
-- 3) public.clinic_user_invites
-- ------------------------------------------------------------
ALTER TABLE IF EXISTS public.clinic_user_invites
    ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_clinic_invites_tenant ON public.clinic_user_invites;
CREATE POLICY rls_clinic_invites_tenant ON public.clinic_user_invites
    FOR ALL
    USING (clinic_id = public.app_current_clinic_id())
    WITH CHECK (clinic_id = public.app_current_clinic_id());

-- ------------------------------------------------------------
-- 4) public.clinic_policies
-- ------------------------------------------------------------
ALTER TABLE IF EXISTS public.clinic_policies
    ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_clinic_policies_tenant ON public.clinic_policies;
CREATE POLICY rls_clinic_policies_tenant ON public.clinic_policies
    FOR ALL
    USING (clinic_id = public.app_current_clinic_id())
    WITH CHECK (clinic_id = public.app_current_clinic_id());

-- ------------------------------------------------------------
-- 5) public.clinic_policy_state
-- ------------------------------------------------------------
ALTER TABLE IF EXISTS public.clinic_policy_state
    ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_clinic_policy_state_tenant ON public.clinic_policy_state;
CREATE POLICY rls_clinic_policy_state_tenant ON public.clinic_policy_state
    FOR ALL
    USING (clinic_id = public.app_current_clinic_id())
    WITH CHECK (clinic_id = public.app_current_clinic_id());

-- ------------------------------------------------------------
-- 6) public.clinic_privacy_profile
-- ------------------------------------------------------------
ALTER TABLE IF EXISTS public.clinic_privacy_profile
    ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_privacy_profile_tenant ON public.clinic_privacy_profile;
CREATE POLICY rls_privacy_profile_tenant ON public.clinic_privacy_profile
    FOR ALL
    USING (clinic_id = public.app_current_clinic_id())
    WITH CHECK (clinic_id = public.app_current_clinic_id());

-- ------------------------------------------------------------
-- 7) public.clinic_governance_events
--    (Migration 10010 already creates a policy here when missing.
--    We DROP + CREATE so the replayable shape is deterministic and
--    matches the same shape as the rest of the legacy tables.)
-- ------------------------------------------------------------
ALTER TABLE IF EXISTS public.clinic_governance_events
    ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_clinic_gov_events_tenant ON public.clinic_governance_events;
DROP POLICY IF EXISTS rls_clinic_governance_events_tenant ON public.clinic_governance_events;
CREATE POLICY rls_clinic_gov_events_tenant ON public.clinic_governance_events
    FOR ALL
    USING (clinic_id = public.app_current_clinic_id())
    WITH CHECK (clinic_id = public.app_current_clinic_id());

-- ------------------------------------------------------------
-- 8) public.ops_metrics_events
-- ------------------------------------------------------------
ALTER TABLE IF EXISTS public.ops_metrics_events
    ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_ops_metrics_tenant ON public.ops_metrics_events;
CREATE POLICY rls_ops_metrics_tenant ON public.ops_metrics_events
    FOR ALL
    USING (clinic_id = public.app_current_clinic_id())
    WITH CHECK (clinic_id = public.app_current_clinic_id());

COMMIT;
