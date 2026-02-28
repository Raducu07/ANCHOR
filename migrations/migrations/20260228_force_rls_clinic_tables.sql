-- FORCE RLS so even table owners cannot bypass policies.
-- This is required if your app role owns the tables.

BEGIN;

ALTER TABLE public.clinics      FORCE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_users FORCE ROW LEVEL SECURITY;

COMMIT;
