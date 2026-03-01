-- ============================================================
-- FORCE RLS on all clinic-scoped tables (safe / idempotent)
-- - Applies FORCE RLS only if the table exists
-- - Avoids deploy failures in mixed-schema environments
-- ============================================================

DO $$
DECLARE
  t text;
  tables text[] := ARRAY[
    'public.clinics',
    'public.clinic_users',
    'public.governance_events',
    'public.ops_metrics_events',
    'public.clinic_policies',
    'public.clinic_policy_state',
    'public.clinic_privacy_profile'
  ];
BEGIN
  FOREACH t IN ARRAY tables LOOP
    IF to_regclass(t) IS NOT NULL THEN
      EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', t);
    END IF;
  END LOOP;
END $$;
