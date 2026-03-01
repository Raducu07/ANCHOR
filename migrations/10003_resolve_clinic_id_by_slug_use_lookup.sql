CREATE OR REPLACE FUNCTION public.resolve_clinic_id_by_slug(p_slug text)
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT csl.clinic_id
  FROM public.clinic_slug_lookup csl
  WHERE csl.clinic_slug = lower(trim(p_slug))
    AND csl.active_status = true
  LIMIT 1
$$;

REVOKE ALL ON FUNCTION public.resolve_clinic_id_by_slug(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.resolve_clinic_id_by_slug(text) TO PUBLIC;
