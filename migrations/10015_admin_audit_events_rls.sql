-- ============================================================
-- 10015_admin_audit_events_rls.sql
--
-- 2A-D.1 Patch 5B — admin_audit_events RLS replayability + FORCE RLS.
--
-- Background:
-- Pass-2 audit finding F-5 was a misreading. There are TWO distinct
-- audit tables in this schema:
--
--   * public.admin_audit_events           — CLINIC-SCOPED.
--     `clinic_id uuid NOT NULL REFERENCES clinics(clinic_id)`.
--     Written from clinic-context routes (portal_submit override,
--     assistant_policy update, governance_policy publish/retire/attest-
--     void, client_transparency publish/retire, self_assessment lifecycle,
--     incident_near_miss close/void). Every writer reaches the INSERT via
--     Depends(get_db) which sets app.clinic_id RLS context before the
--     handler body runs. Every writer binds clinic_id matching that
--     context. The rls_admin_audit_tenant policy is appropriate and
--     ACTIVE (RLS is ENABLED via app/security.sql).
--
--   * public.platform_admin_audit_events  — PLATFORM-SCOPED.
--     No clinic_id column. Written by app.admin_auth.write_admin_audit_
--     event. Intentionally outside clinic RLS. NOT touched by this
--     migration.
--
-- Patch 4A (migrations/10014_legacy_rls_policies.sql) deliberately
-- excluded public.admin_audit_events based on the (incorrect) Pass-2
-- classification. This migration corrects that gap:
--
--   1) Promote the existing rls_admin_audit_tenant policy from
--      app/security.sql into the versioned, replayable migration stream.
--      A clean DB / DR restore / fresh local env will now have the
--      policy applied automatically at startup by app/migrate.py.
--   2) Add FORCE ROW LEVEL SECURITY so the policy is enforced even
--      against a table-owner / superuser session (defence-in-depth —
--      brings admin_audit_events in line with every other clinic-scoped
--      audit / governance table in the system).
--
-- Doctrine:
-- - clinic_id = public.app_current_clinic_id() on BOTH sides
--   (USING + WITH CHECK). USING-only would allow tenant forging on
--   INSERT / UPDATE.
-- - Existing migrations are not retroactively edited. 10014's header
--   comment misclassification of admin_audit_events stands as historical
--   record; the correct classification is documented here and in the
--   corrected Patch 4A comment block in app/security.sql.
--
-- Safety:
-- - DROP POLICY IF EXISTS before CREATE POLICY → idempotent replay.
-- - ALTER TABLE ... ENABLE / FORCE ROW LEVEL SECURITY is idempotent in
--   Postgres.
-- - This migration intentionally does NOT touch:
--     * public.platform_admin_audit_events  (platform-scoped)
--     * public.governance_events            (v0 dormant — Patch 6)
--     * public.clinics, public.clinic_users, public.clinic_user_invites,
--       public.clinic_policies, public.clinic_policy_state,
--       public.clinic_privacy_profile, public.clinic_governance_events,
--       public.ops_metrics_events           (already handled by 10014)
-- ============================================================

BEGIN;

-- 1) Ensure RLS is enabled on admin_audit_events.
ALTER TABLE IF EXISTS public.admin_audit_events
    ENABLE ROW LEVEL SECURITY;

-- 2) FORCE RLS so the policy is enforced even against table-owner /
--    superuser sessions. All in-codebase writers and readers reach the
--    table via Depends(get_db) under the anchor_app runtime role with
--    app.clinic_id already set, so FORCE has no impact on the
--    application path; it only closes the table-owner bypass.
ALTER TABLE IF EXISTS public.admin_audit_events
    FORCE ROW LEVEL SECURITY;

-- 3) Replayable tenant policy. DROP POLICY IF EXISTS first so this
--    migration is safe to re-apply on a DB that already had the
--    policy installed manually from app/security.sql.
DROP POLICY IF EXISTS rls_admin_audit_tenant ON public.admin_audit_events;
CREATE POLICY rls_admin_audit_tenant ON public.admin_audit_events
    FOR ALL
    USING (clinic_id = public.app_current_clinic_id())
    WITH CHECK (clinic_id = public.app_current_clinic_id());

COMMIT;
