-- ============================================================
-- 10010_force_rls_clinic_governance_events.sql
--
-- Final M3 close-out:
-- Ensure clinic_governance_events is protected by FORCE RLS.
--
-- Why:
-- - Self-test showed relrowsecurity = true but relforcerowsecurity = false
-- - clinic_governance_events is a core tenant-scoped table
-- - governance receipts / metadata audit surfaces must be tenant-hard
--
-- Notes:
-- - Keeps existing policies if already present
-- - Adds a tenant policy only if the table has no policy yet
-- - Uses app_current_clinic_id() in line with ANCHOR tenant model
-- ============================================================

BEGIN;

-- 1) Ensure RLS is enabled
ALTER TABLE IF EXISTS public.clinic_governance_events
    ENABLE ROW LEVEL SECURITY;

-- 2) Ensure there is at least one tenant policy
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'clinic_governance_events'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_clinic_governance_events_tenant
            ON public.clinic_governance_events
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

-- 3) Force RLS so even table owner context cannot bypass normal tenant policy behavior
ALTER TABLE IF EXISTS public.clinic_governance_events
    FORCE ROW LEVEL SECURITY;

COMMIT;
