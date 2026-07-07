-- ============================================================
-- 20260706_01_ambient_boundary_check_hardening.sql
--
-- M6.13 boundary adoption, rule 13 (founder decision 2026-07-06,
-- docs/operations/2026-07-06_m6_13_boundary_adoption_decision.md):
-- schema-level CHECK hardening so the API-layer content guards on
-- ambient_governance_events are also literal at the database layer.
--
--   * source_label: single line, at most 200 characters. A tool label
--     can never carry pasted transcript text past the schema.
--   * workflow_reference_hash: exactly a SHA-256 hex digest (or NULL).
--     The only external pointer can never smuggle content.
--
-- This is a NEW migration; 20260705_05 is not edited (doctrine:
-- existing migrations are never retroactively edited). Both
-- constraints are added inside pg_constraint guards (idempotent,
-- boot-safe). No rows can pre-violate these constraints: the table is
-- unreleased and all writes to date have gone through the stricter
-- API-layer validators.
-- ============================================================

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ambient_source_label_single_line'
          AND conrelid = 'public.ambient_governance_events'::regclass
    ) THEN
        ALTER TABLE public.ambient_governance_events
        ADD CONSTRAINT ambient_source_label_single_line
        CHECK (
            char_length(source_label) <= 200
            AND source_label !~ '[\n\r]'
        );
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ambient_reference_hash_sha256_shape'
          AND conrelid = 'public.ambient_governance_events'::regclass
    ) THEN
        ALTER TABLE public.ambient_governance_events
        ADD CONSTRAINT ambient_reference_hash_sha256_shape
        CHECK (
            workflow_reference_hash IS NULL
            OR workflow_reference_hash ~ '^[a-f0-9]{64}$'
        );
    END IF;
END
$$;

COMMIT;
