-- clinic_slug_lookup must be readable BEFORE tenant context exists.
-- Keep it unscoped (no RLS) and allow SELECT.

ALTER TABLE public.clinic_slug_lookup DISABLE ROW LEVEL SECURITY;

GRANT SELECT ON public.clinic_slug_lookup TO PUBLIC;
