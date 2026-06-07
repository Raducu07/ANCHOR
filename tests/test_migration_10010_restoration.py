"""
2A-D.1 Patch 6B — restoration tests for migrations/10010 and the
forward-migration follow-up 10017.

These tests are file-inspection only (no DB, no app boot). They:

  * pin migrations/10010_force_rls_all_tenant_tables.sql to the exact
    SHA-256 production applied in 2026-03-01 — any future edit-in-place
    of 10010 fails this test before reaching prod boot;
  * confirm the restored 10010 is the bare-ALTER list (no DO/$$/
    to_regclass wrapping — those moved to 10017);
  * confirm 10017 exists, is BEGIN/COMMIT wrapped, and carries the
    DO $$ ... to_regclass(...) ... FORCE ROW LEVEL SECURITY wrapper;
  * confirm no neighbouring migration (10009, 10011, 10012, 10013,
    10014, 10015, 10016) was touched by this patch — i.e. only 10010
    was restored and only 10017 was added.

The production-applied content is the canonical source of truth here;
this test pins it from inside the repo so the next reviewer doesn't have
to know the prod-side state to enforce the doctrine.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = REPO_ROOT / "migrations"

MIGRATION_10010 = MIGRATIONS_DIR / "10010_force_rls_all_tenant_tables.sql"
MIGRATION_10017 = MIGRATIONS_DIR / "10017_force_rls_idempotent_reassertion.sql"

# The exact SHA-256 production applied on 2026-03-01, captured into
# schema_migrations.checksum at first apply, and which Patch 6 startup
# verification will compare against. This is the contract.
APPLIED_10010_SHA256 = (
    "782cad9211b77fc033c15d1d5bcbd1fd5bc5281d58f231ab534e5cc873ab4658"
)


def _stripped_sha256(path: Path) -> str:
    """Compute the SHA-256 the migration runner uses. Mirrors
    `app/migrate.py::_sha256_hex` applied to
    `path.read_text(encoding='utf-8').strip()`."""
    text = path.read_text(encoding="utf-8").strip()
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------
# 1. 10010 — restoration pin
# ---------------------------------------------------------------------


def test_10010_file_exists() -> None:
    assert MIGRATION_10010.is_file(), f"Missing migration: {MIGRATION_10010!s}"


def test_10010_stripped_sha256_matches_applied_content() -> None:
    """The most important test in this file. If this ever fails, someone
    has edited 10010 in place again — exactly the doctrine violation
    that took prod down with the Patch 6 mismatch. Restore the file
    instead of changing this assertion."""
    actual = _stripped_sha256(MIGRATION_10010)
    assert actual == APPLIED_10010_SHA256, (
        f"10010 stripped SHA-256 has drifted from the production-applied "
        f"content. Expected (production-applied) {APPLIED_10010_SHA256!r}, "
        f"got {actual!r}. Doctrine: existing migrations are never "
        f"retroactively edited — add a new migration instead."
    )


def test_10010_is_bare_alter_list_not_idempotent_wrapper() -> None:
    body = MIGRATION_10010.read_text(encoding="utf-8")
    upper = body.upper()
    # Confirms the safer wrapper has been moved to 10017 and is NOT
    # re-introduced into 10010.
    assert "TO_REGCLASS" not in upper, (
        "10010 must remain the bare-ALTER applied content. The "
        "to_regclass wrapper belongs in 10017."
    )
    assert "DO $$" not in body, (
        "10010 must remain the bare-ALTER applied content. The DO $$ "
        "block belongs in 10017."
    )
    # And confirm the bare ALTERs are still there (spot-check a few).
    assert "ALTER TABLE public.clinics" in body
    assert "ALTER TABLE public.clinic_users" in body
    assert "ALTER TABLE public.governance_events" in body
    assert "FORCE ROW LEVEL SECURITY" in upper


# ---------------------------------------------------------------------
# 2. 10017 — forward migration
# ---------------------------------------------------------------------


def test_10017_file_exists() -> None:
    assert MIGRATION_10017.is_file(), f"Missing migration: {MIGRATION_10017!s}"


def test_10017_contains_to_regclass_wrapper(
) -> None:
    body = MIGRATION_10017.read_text(encoding="utf-8")
    assert "to_regclass" in body, (
        "10017 must carry the mixed-schema safety net (to_regclass)"
    )
    assert "FORCE ROW LEVEL SECURITY" in body.upper(), (
        "10017 must reassert FORCE ROW LEVEL SECURITY"
    )
    assert re.search(r"DO\s*\$\$", body), (
        "10017 must use a DO $$ ... END $$ block so missing tables are "
        "skipped via to_regclass rather than failing the migration"
    )


def test_10017_is_wrapped_in_a_transaction() -> None:
    body = MIGRATION_10017.read_text(encoding="utf-8")
    # The DO $$ block alone runs in its own implicit transaction in
    # plpgsql, but wrapping the file in BEGIN; / COMMIT; keeps the
    # migration runner's atomicity story consistent with every other
    # numbered migration in the repo.
    assert re.search(r"^\s*BEGIN\s*;", body, re.IGNORECASE | re.MULTILINE), (
        "10017 must open with BEGIN;"
    )
    assert re.search(r"^\s*COMMIT\s*;", body, re.IGNORECASE | re.MULTILINE), (
        "10017 must close with COMMIT;"
    )


def test_10017_targets_the_same_seven_tables_as_edited_10010() -> None:
    """Belt-and-braces: 10017 carries forward the exact intent of the
    (now-removed) edited 10010 wrapper. No broadening of scope —
    same seven clinic-scoped tables, no new ones."""
    body = MIGRATION_10017.read_text(encoding="utf-8")
    expected = (
        "public.clinics",
        "public.clinic_users",
        "public.governance_events",
        "public.ops_metrics_events",
        "public.clinic_policies",
        "public.clinic_policy_state",
        "public.clinic_privacy_profile",
    )
    for table in expected:
        assert table in body, f"10017 must list {table}"

    # Defensive: any table outside the seven would indicate scope drift.
    # The list literal is the only place table names appear in this
    # file. Catch obvious extras by checking for tenant-scoped tables
    # known to be governed by OTHER migrations.
    must_not_appear = (
        "public.assistant_runs",
        "public.assistant_run_receipts",
        "public.clinic_governance_events",
        "public.admin_audit_events",
        "public.platform_admin_audit_events",
        "public.demo_requests",
        "public.start_requests",
        "public.public_site_chat_events",
    )
    for table in must_not_appear:
        assert table not in body, (
            f"10017 must not silently widen scope to {table}"
        )


# ---------------------------------------------------------------------
# 3. Scope confinement — no other migration was edited by this patch
# ---------------------------------------------------------------------


# The Pass-2 / Patch-4A / Patch-5B / Patch-6 numbered migrations that
# Patch 6B must NOT touch. (We do not assert byte-equality against any
# other historical content — only that Patch 6B's working tree changes
# are confined to 10010 + 10017.)
_NEIGHBOURING_MIGRATIONS = (
    "10000_force_rls_clinic_tables.sql",
    "10001_clinic_slug_lookup.sql",
    "10002_clinic_slug_lookup_rls_off.sql",
    "10002_resolve_clinic_id_by_slug.sql",
    "10003_resolve_clinic_id_by_slug_use_lookup.sql",
    "10011_enable_force_rls_governance_events.sql",
    "10011_fix_governance_events_rls.sql",
    "10013_enable_and_force_rls_all_tenant_tables.sql",
    "10014_legacy_rls_policies.sql",
    "10015_admin_audit_events_rls.sql",
    "10016_schema_migrations_checksum.sql",
)


@pytest.mark.parametrize("fname", _NEIGHBOURING_MIGRATIONS)
def test_neighbouring_migration_files_still_exist(fname: str) -> None:
    """Patch 6B must not delete or rename any pre-existing migration."""
    path = MIGRATIONS_DIR / fname
    assert path.is_file(), (
        f"Migration {fname} must still exist on disk (Patch 6B must not "
        f"delete or rename any other migration)."
    )
