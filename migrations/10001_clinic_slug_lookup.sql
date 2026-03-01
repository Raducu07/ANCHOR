-- ============================================================
-- 10001_clinic_slug_lookup.sql
-- Unscoped lookup table to resolve clinic_id by slug even when
-- FORCE RLS is enabled on public.clinics.
-- Stores only: slug -> clinic_id + active flag (no PII).
-- ============================================================

CREATE TABLE IF NOT EXISTS public.clinic_slug_lookup (
  clinic_slug    text PRIMARY KEY,
  clinic_id      uuid NOT NULL UNIQUE,
  active_status  boolean NOT NULL DEFAULT true,
  updated_at     timestamptz NOT NULL DEFAULT now()
);

-- Backfill from existing clinics
INSERT INTO public.clinic_slug_lookup (clinic_slug, clinic_id, active_status)
SELECT c.clinic_slug, c.clinic_id, COALESCE(c.active_status, true)
FROM public.clinics c
ON CONFLICT (clinic_slug) DO UPDATE
SET clinic_id = EXCLUDED.clinic_id,
    active_status = EXCLUDED.active_status,
    updated_at = now();

CREATE INDEX IF NOT EXISTS idx_clinic_slug_lookup_active
  ON public.clinic_slug_lookup (active_status);

-- Keep lookup in sync when clinics change
CREATE OR REPLACE FUNCTION public.trg_sync_clinic_slug_lookup()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO public.clinic_slug_lookup (clinic_slug, clinic_id, active_status, updated_at)
  VALUES (NEW.clinic_slug, NEW.clinic_id, COALESCE(NEW.active_status, true), now())
  ON CONFLICT (clinic_slug) DO UPDATE
  SET clinic_id = EXCLUDED.clinic_id,
      active_status = EXCLUDED.active_status,
      updated_at = now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_clinics_sync_slug_lookup ON public.clinics;

CREATE TRIGGER trg_clinics_sync_slug_lookup
AFTER INSERT OR UPDATE OF clinic_slug, active_status
ON public.clinics
FOR EACH ROW
EXECUTE FUNCTION public.trg_sync_clinic_slug_lookup();
