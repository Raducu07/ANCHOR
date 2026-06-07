"""
2A-D.1 Patch 5B — admin_audit_events RLS replayability migration tests.

File-inspection only (no live DB). Verifies that
`migrations/10015_admin_audit_events_rls.sql`:

  * exists and is wrapped in BEGIN; / COMMIT;
  * ENABLE + FORCE ROW LEVEL SECURITY on public.admin_audit_events
  * DROP POLICY IF EXISTS rls_admin_audit_tenant before CREATE POLICY
  * Tenant context (clinic_id = public.app_current_clinic_id()) on BOTH
    USING and WITH CHECK sides
  * Does NOT touch public.platform_admin_audit_events (platform-scoped)
  * Does NOT touch public.governance_events (v0 dormant — Patch 6)
  * Does NOT re-touch any of the legacy tables already handled by 10014
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = REPO_ROOT / "migrations" / "10015_admin_audit_events_rls.sql"

TARGET_TABLE = "public.admin_audit_events"
POLICY_NAME = "rls_admin_audit_tenant"

PLATFORM_TABLE = "public.platform_admin_audit_events"
V0_DORMANT_TABLE = "public.governance_events"

# Already covered by migrations/10014_legacy_rls_policies.sql — must not
# be re-altered here.
TABLES_OWNED_BY_10014 = (
    "public.clinics",
    "public.clinic_users",
    "public.clinic_user_invites",
    "public.clinic_policies",
    "public.clinic_policy_state",
    "public.clinic_privacy_profile",
    "public.clinic_governance_events",
    "public.ops_metrics_events",
)


# ---------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------

@pytest.fixture(scope="module")
def migration_sql() -> str:
    assert MIGRATION_PATH.is_file(), f"Missing migration: {MIGRATION_PATH!s}"
    return MIGRATION_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------
# 1. File presence
# ---------------------------------------------------------------------

def test_migration_file_exists() -> None:
    assert MIGRATION_PATH.is_file(), f"Missing migration: {MIGRATION_PATH!s}"


def test_migration_file_is_not_empty(migration_sql: str) -> None:
    assert len(migration_sql.strip()) > 0


# ---------------------------------------------------------------------
# 2. Transaction wrapper
# ---------------------------------------------------------------------

def test_migration_is_wrapped_in_a_transaction(migration_sql: str) -> None:
    assert re.search(
        r"^\s*BEGIN\s*;", migration_sql, re.IGNORECASE | re.MULTILINE
    ), "Expected leading BEGIN;"
    assert re.search(
        r"^\s*COMMIT\s*;", migration_sql, re.IGNORECASE | re.MULTILINE
    ), "Expected trailing COMMIT;"


# ---------------------------------------------------------------------
# 3. ENABLE / FORCE ROW LEVEL SECURITY on admin_audit_events
# ---------------------------------------------------------------------

def test_migration_enables_rls_on_admin_audit_events(migration_sql: str) -> None:
    pattern = re.compile(
        rf"ALTER\s+TABLE\s+IF\s+EXISTS\s+{re.escape(TARGET_TABLE)}\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY",
        re.IGNORECASE,
    )
    assert pattern.search(migration_sql), (
        "Expected ALTER TABLE IF EXISTS public.admin_audit_events ENABLE ROW LEVEL SECURITY"
    )


def test_migration_forces_rls_on_admin_audit_events(migration_sql: str) -> None:
    pattern = re.compile(
        rf"ALTER\s+TABLE\s+IF\s+EXISTS\s+{re.escape(TARGET_TABLE)}\s+FORCE\s+ROW\s+LEVEL\s+SECURITY",
        re.IGNORECASE,
    )
    assert pattern.search(migration_sql), (
        "Expected ALTER TABLE IF EXISTS public.admin_audit_events FORCE ROW LEVEL SECURITY"
    )


# ---------------------------------------------------------------------
# 4. Policy presence (DROP IF EXISTS + CREATE)
# ---------------------------------------------------------------------

def test_migration_drops_policy_if_exists(migration_sql: str) -> None:
    pattern = re.compile(
        rf"DROP\s+POLICY\s+IF\s+EXISTS\s+{re.escape(POLICY_NAME)}\s+ON\s+{re.escape(TARGET_TABLE)}\b",
        re.IGNORECASE,
    )
    assert pattern.search(migration_sql), (
        f"Expected DROP POLICY IF EXISTS {POLICY_NAME} ON {TARGET_TABLE}"
    )


def test_migration_creates_policy(migration_sql: str) -> None:
    pattern = re.compile(
        rf"CREATE\s+POLICY\s+{re.escape(POLICY_NAME)}\s+ON\s+{re.escape(TARGET_TABLE)}\b",
        re.IGNORECASE,
    )
    assert pattern.search(migration_sql), (
        f"Expected CREATE POLICY {POLICY_NAME} ON {TARGET_TABLE}"
    )


# ---------------------------------------------------------------------
# 5. USING + WITH CHECK with tenant context
# ---------------------------------------------------------------------

def _policy_block(migration_sql: str) -> str:
    """Return the substring from CREATE POLICY ... up to the next
    semicolon."""
    create_re = re.compile(
        rf"CREATE\s+POLICY\s+{re.escape(POLICY_NAME)}\s+ON\s+{re.escape(TARGET_TABLE)}\b(.*?)(?=;|\Z)",
        re.IGNORECASE | re.DOTALL,
    )
    match = create_re.search(migration_sql)
    assert match, f"Could not locate CREATE POLICY block for {POLICY_NAME}"
    return match.group(1)


def test_policy_using_clause_uses_tenant_context(migration_sql: str) -> None:
    body = _policy_block(migration_sql)
    pattern = re.compile(
        r"USING\s*\(\s*clinic_id\s*=\s*public\.app_current_clinic_id\s*\(\s*\)\s*\)",
        re.IGNORECASE,
    )
    assert pattern.search(body), (
        "Policy must USING (clinic_id = public.app_current_clinic_id())"
    )


def test_policy_with_check_clause_uses_tenant_context(migration_sql: str) -> None:
    body = _policy_block(migration_sql)
    pattern = re.compile(
        r"WITH\s+CHECK\s*\(\s*clinic_id\s*=\s*public\.app_current_clinic_id\s*\(\s*\)\s*\)",
        re.IGNORECASE,
    )
    assert pattern.search(body), (
        "Policy must WITH CHECK (clinic_id = public.app_current_clinic_id())"
    )


# ---------------------------------------------------------------------
# 6. Forbidden tables: platform / v0 dormant / 10014-owned legacy set
# ---------------------------------------------------------------------

def _table_is_touched(migration_sql: str, table: str) -> bool:
    """Return True if the migration alters or creates a policy on `table`.
    Whole-word match on the qualified name so comments referencing a
    table do not trigger a false positive."""
    create_policy = re.compile(
        rf"CREATE\s+POLICY\s+\w+\s+ON\s+{re.escape(table)}\b",
        re.IGNORECASE,
    )
    alter_table = re.compile(
        rf"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?{re.escape(table)}\b",
        re.IGNORECASE,
    )
    return bool(create_policy.search(migration_sql) or alter_table.search(migration_sql))


def test_migration_does_not_touch_platform_admin_audit_events(
    migration_sql: str,
) -> None:
    assert not _table_is_touched(migration_sql, PLATFORM_TABLE), (
        f"{PLATFORM_TABLE} is platform-scoped and must not be altered here"
    )


def test_migration_does_not_touch_governance_events_v0(migration_sql: str) -> None:
    assert not _table_is_touched(migration_sql, V0_DORMANT_TABLE), (
        f"{V0_DORMANT_TABLE} is the v0 dormant table and is out of scope"
    )


@pytest.mark.parametrize("table", TABLES_OWNED_BY_10014)
def test_migration_does_not_re_touch_10014_legacy_table(
    table: str, migration_sql: str
) -> None:
    assert not _table_is_touched(migration_sql, table), (
        f"{table} is already handled by migrations/10014_legacy_rls_policies.sql"
    )
