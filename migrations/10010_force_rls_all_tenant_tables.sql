-- ============================================================
-- FORCE RLS on all clinic-scoped tables
-- Governance-grade tenant isolation hardening
-- ============================================================

-- Core identity
ALTER TABLE public.clinics                 FORCE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_users            FORCE ROW LEVEL SECURITY;

-- Governance
ALTER TABLE public.governance_events       FORCE ROW LEVEL SECURITY;

-- Ops / telemetry (if tenant-scoped)
ALTER TABLE public.ops_metrics_events      FORCE ROW LEVEL SECURITY;

-- Policy system
ALTER TABLE public.clinic_policies         FORCE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_policy_state     FORCE ROW LEVEL SECURITY;

-- Privacy profile
ALTER TABLE public.clinic_privacy_profile  FORCE ROW LEVEL SECURITY;

-- Any additional tenant tables below:
-- ALTER TABLE public.<table_name> FORCE ROW LEVEL SECURITY;
