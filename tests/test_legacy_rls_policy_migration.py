"""
2A-D.1 Patch 4A — legacy RLS policy replayability migration tests.

These tests inspect the contents of
`migrations/10014_legacy_rls_policies.sql` without touching the database.

They verify:
  * The migration file exists at the expected path.
  * It declares ENABLE ROW LEVEL SECURITY and a CREATE POLICY for each of
    the eight legacy clinic-scoped tables.
  * Every CREATE POLICY block names public.app_current_clinic_id() in
    both a USING and a WITH CHECK clause (no USING-only policy).
  * Every CREATE POLICY uses DROP POLICY IF EXISTS first (idempotent
    replay).
  * The migration does NOT touch public.admin_audit_events (platform-
    scoped — out of scope for Patch 4A).
  * The migration does NOT touch public.clinic_slug_lookup (intentionally
    RLS-off).
  * The migration does NOT touch public.governance_events (v0 legacy
    table — Patch 6 housekeeping).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = REPO_ROOT / "migrations" / "10014_legacy_rls_policies.sql"


# ---------------------------------------------------------------------
# Expected tables and the policy names they should carry.
# ---------------------------------------------------------------------

EXPECTED_TABLES: Tuple[str, ...] = (
    "public.clinics",
    "public.clinic_users",
    "public.clinic_user_invites",
    "public.clinic_policies",
    "public.clinic_policy_state",
    "public.clinic_privacy_profile",
    "public.clinic_governance_events",
    "public.ops_metrics_events",
)

# Names sourced from the historical app/security.sql block.
EXPECTED_POLICIES: Dict[str, str] = {
    "public.clinics": "rls_clinics_tenant",
    "public.clinic_users": "rls_clinic_users_tenant",
    "public.clinic_user_invites": "rls_clinic_invites_tenant",
    "public.clinic_policies": "rls_clinic_policies_tenant",
    "public.clinic_policy_state": "rls_clinic_policy_state_tenant",
    "public.clinic_privacy_profile": "rls_privacy_profile_tenant",
    "public.clinic_governance_events": "rls_clinic_gov_events_tenant",
    "public.ops_metrics_events": "rls_ops_metrics_tenant",
}

FORBIDDEN_TABLES: Tuple[str, ...] = (
    "public.admin_audit_events",
    "public.clinic_slug_lookup",
    "public.governance_events",  # v0 legacy table — out of scope
)


# ---------------------------------------------------------------------
# Fixture — read the file once per test session.
# ---------------------------------------------------------------------

@pytest.fixture(scope="module")
def migration_sql() -> str:
    assert MIGRATION_PATH.is_file(), (
        f"Expected migration file at {MIGRATION_PATH!s}"
    )
    return MIGRATION_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------
# Helpers — parse CREATE POLICY blocks.
# ---------------------------------------------------------------------

# Match: CREATE POLICY <name> ON <schema.table> ... USING (...) WITH CHECK (...)
# Multiline, case-insensitive. The inner `(.*?)` for USING / WITH CHECK is
# greedy-enough because each clause is bounded by the next SQL keyword or
# semicolon. We do not parse SQL; we just check substrings inside each
# CREATE POLICY block.
_CREATE_POLICY_RE = re.compile(
    r"CREATE\s+POLICY\s+(\w+)\s+ON\s+(public\.\w+)\b(.*?)(?=;|\Z)",
    re.IGNORECASE | re.DOTALL,
)


def _parse_policy_blocks(sql: str) -> List[Dict[str, str]]:
    """Return a list of {name, table, body} dicts, one per CREATE POLICY
    statement in the migration."""
    out: List[Dict[str, str]] = []
    for match in _CREATE_POLICY_RE.finditer(sql):
        name = match.group(1).lower()
        table = match.group(2).lower()
        body = match.group(3)
        out.append({"name": name, "table": table, "body": body})
    return out


# ---------------------------------------------------------------------
# 1. File presence
# ---------------------------------------------------------------------

def test_migration_file_exists() -> None:
    assert MIGRATION_PATH.is_file(), f"Missing migration: {MIGRATION_PATH!s}"


def test_migration_file_is_not_empty(migration_sql: str) -> None:
    assert len(migration_sql.strip()) > 0


# ---------------------------------------------------------------------
# 2. Each expected table is enabled and has a policy
# ---------------------------------------------------------------------

@pytest.mark.parametrize("table", EXPECTED_TABLES)
def test_each_expected_table_is_enabled(table: str, migration_sql: str) -> None:
    pattern = re.compile(
        rf"ALTER\s+TABLE\s+IF\s+EXISTS\s+{re.escape(table)}\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY",
        re.IGNORECASE,
    )
    assert pattern.search(migration_sql), (
        f"Expected ENABLE ROW LEVEL SECURITY on {table}"
    )


@pytest.mark.parametrize("table", EXPECTED_TABLES)
def test_each_expected_table_has_a_create_policy(
    table: str, migration_sql: str
) -> None:
    blocks = _parse_policy_blocks(migration_sql)
    tables_with_policy: Set[str] = {b["table"] for b in blocks}
    assert table.lower() in tables_with_policy, (
        f"No CREATE POLICY found for {table}"
    )


@pytest.mark.parametrize("table,policy_name", EXPECTED_POLICIES.items())
def test_each_expected_table_has_named_policy(
    table: str, policy_name: str, migration_sql: str
) -> None:
    blocks = _parse_policy_blocks(migration_sql)
    matched = [
        b for b in blocks if b["table"] == table.lower() and b["name"] == policy_name.lower()
    ]
    assert matched, (
        f"Expected CREATE POLICY {policy_name} ON {table} not found"
    )


# ---------------------------------------------------------------------
# 3. Every policy is replayable and tenant-tight on BOTH sides
# ---------------------------------------------------------------------

@pytest.mark.parametrize("table,policy_name", EXPECTED_POLICIES.items())
def test_each_policy_is_preceded_by_drop_policy_if_exists(
    table: str, policy_name: str, migration_sql: str
) -> None:
    """A replayable migration must drop the existing policy first so it
    is safe to run on a DB that already has the policy from a prior
    manual apply of app/security.sql."""
    pattern = re.compile(
        rf"DROP\s+POLICY\s+IF\s+EXISTS\s+{re.escape(policy_name)}\s+ON\s+{re.escape(table)}\b",
        re.IGNORECASE,
    )
    assert pattern.search(migration_sql), (
        f"Expected DROP POLICY IF EXISTS {policy_name} ON {table} before CREATE POLICY"
    )


@pytest.mark.parametrize("table,policy_name", EXPECTED_POLICIES.items())
def test_each_policy_uses_tenant_context_in_using_clause(
    table: str, policy_name: str, migration_sql: str
) -> None:
    blocks = _parse_policy_blocks(migration_sql)
    block = next(
        b for b in blocks
        if b["table"] == table.lower() and b["name"] == policy_name.lower()
    )
    using_pattern = re.compile(
        r"USING\s*\(\s*clinic_id\s*=\s*public\.app_current_clinic_id\s*\(\s*\)\s*\)",
        re.IGNORECASE,
    )
    assert using_pattern.search(block["body"]), (
        f"{policy_name} on {table} must USING (clinic_id = public.app_current_clinic_id())"
    )


@pytest.mark.parametrize("table,policy_name", EXPECTED_POLICIES.items())
def test_each_policy_uses_tenant_context_in_with_check_clause(
    table: str, policy_name: str, migration_sql: str
) -> None:
    blocks = _parse_policy_blocks(migration_sql)
    block = next(
        b for b in blocks
        if b["table"] == table.lower() and b["name"] == policy_name.lower()
    )
    with_check_pattern = re.compile(
        r"WITH\s+CHECK\s*\(\s*clinic_id\s*=\s*public\.app_current_clinic_id\s*\(\s*\)\s*\)",
        re.IGNORECASE,
    )
    assert with_check_pattern.search(block["body"]), (
        f"{policy_name} on {table} must WITH CHECK (clinic_id = public.app_current_clinic_id())"
    )


def test_no_policy_is_using_only(migration_sql: str) -> None:
    """Belt-and-braces: every CREATE POLICY block in this migration must
    carry BOTH a USING and a WITH CHECK clause. USING-only would allow
    tenant forging on INSERT / UPDATE."""
    blocks = _parse_policy_blocks(migration_sql)
    assert blocks, "Expected at least one CREATE POLICY block"
    for block in blocks:
        body = block["body"]
        assert re.search(r"\bUSING\s*\(", body, re.IGNORECASE), (
            f"Policy {block['name']} on {block['table']} missing USING clause"
        )
        assert re.search(r"\bWITH\s+CHECK\s*\(", body, re.IGNORECASE), (
            f"Policy {block['name']} on {block['table']} missing WITH CHECK clause"
        )


# ---------------------------------------------------------------------
# 4. Forbidden tables are NOT included
# ---------------------------------------------------------------------

@pytest.mark.parametrize("table", FORBIDDEN_TABLES)
def test_forbidden_table_is_not_touched(table: str, migration_sql: str) -> None:
    """admin_audit_events / clinic_slug_lookup / governance_events are
    explicitly out of scope for Patch 4A — see migration header comments."""
    # Match the table name only when preceded by a SQL verb that would
    # imply a CREATE POLICY / ALTER TABLE on that exact object. We match
    # whole-word to avoid spurious hits on substrings inside comments
    # referencing the table name as context.
    create_policy_pattern = re.compile(
        rf"CREATE\s+POLICY\s+\w+\s+ON\s+{re.escape(table)}\b",
        re.IGNORECASE,
    )
    alter_table_pattern = re.compile(
        rf"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?{re.escape(table)}\b",
        re.IGNORECASE,
    )
    assert not create_policy_pattern.search(migration_sql), (
        f"{table} must NOT have a CREATE POLICY in this Patch 4A migration"
    )
    assert not alter_table_pattern.search(migration_sql), (
        f"{table} must NOT be altered by this Patch 4A migration"
    )


# ---------------------------------------------------------------------
# 5. Migration is wrapped in a transaction
# ---------------------------------------------------------------------

def test_migration_is_wrapped_in_a_transaction(migration_sql: str) -> None:
    assert re.search(r"^\s*BEGIN\s*;", migration_sql, re.IGNORECASE | re.MULTILINE)
    assert re.search(r"^\s*COMMIT\s*;", migration_sql, re.IGNORECASE | re.MULTILINE)
