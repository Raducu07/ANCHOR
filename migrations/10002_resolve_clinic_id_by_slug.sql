-- ============================================================
-- 10002_resolve_clinic_id_by_slug.sql
-- SECURITY DEFINER resolver for clinic slug -> clinic_id
-- Uses public.clinic_slug_lookup so it works even when
-- FORCE RLS is enabled on public.clinics.
-- ============================================================

CREATE OR REPLACE FUNCTION public.resolve_clinic_id_by_slug(p_slug text)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT l.clinic_id
  FROM public.clinic_slug_lookup l
  WHERE l.clinic_slug = lower(trim(p_slug))
    AND l.active_status = true
  LIMIT 1
$$;

-- Lock down direct table access; callers should use the function.
REVOKE ALL ON TABLE public.clinic_slug_lookup FROM PUBLIC;

-- Allow the app role to execute the resolver function.
-- (Adjust role name if yours differs.)
GRANT EXECUTE ON FUNCTION public.resolve_clinic_id_by_slug(text) TO PUBLIC;
