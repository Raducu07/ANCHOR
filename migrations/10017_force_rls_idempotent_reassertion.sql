-- ============================================================
-- 10017_force_rls_idempotent_reassertion.sql
--
-- 2A-D.1 Patch 6B — Forward migration carrying the safer FORCE RLS
-- wrapper that used to live (incorrectly) inside the edited
-- migrations/10010_force_rls_all_tenant_tables.sql.
--
-- Background:
-- - The original migrations/10010_force_rls_all_tenant_tables.sql
--   (commit b759efb, 2026-03-01) issued bare
--   `ALTER TABLE public.<t> FORCE ROW LEVEL SECURITY;` statements for
--   seven clinic-scoped tables.
-- - That file was later edited in place (commit 48149b0, same day) to
--   wrap the statements in a DO $$ block that skips missing tables via
--   `to_regclass`. The in-place edit violated the "existing migrations
--   are never retroactively edited" doctrine.
-- - Patch 6 checksum verification surfaced the edit on a prod boot.
-- - Patch 6B restored migrations/10010_force_rls_all_tenant_tables.sql
--   to its applied content (b759efb) and moved the safer wrapper here.
--
-- Effect on existing environments:
-- - On production (where 10010 already applied FORCE RLS to the seven
--   tables): this migration is a NO-OP. Postgres treats repeated
--   `ALTER TABLE ... FORCE ROW LEVEL SECURITY` as idempotent.
-- - On a clean DB / DR restore / fresh local env: this migration adds
--   the mixed-schema safety net so a missing optional table does NOT
--   fail the boot. Migration 10010 still runs first (bare ALTERs);
--   that path already works against the canonical schema. This
--   migration is the belt-and-braces follow-up for partial schemas.
--
-- Doctrine:
-- - This file must never be retroactively edited.
-- - Mirrors the same seven-table set the edited 10010 listed; no
--   broadening of scope.
-- - No raw clinical content, no policy change, no schema column change.
--
-- Safety:
-- - DO $$ ... END $$ block: each ALTER runs only if `to_regclass(t)`
--   resolves the table, so a missing optional table is skipped rather
--   than raising.
-- - Repeated application is idempotent at the Postgres layer.
-- - Wrapped in BEGIN; / COMMIT; so a mid-block failure does not leave
--   the run partially-applied.
-- ============================================================

BEGIN;

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

COMMIT;
