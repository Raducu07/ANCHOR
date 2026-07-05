"""M4.6 - Learn Maturity schema migration tests.

Static assertions over migrations/20260705_01_learn_maturity_schema.sql
and 20260705_02_learn_maturity_seed.sql:

  * clinic-scoped tables (learning_check_attempts,
    learning_renewal_policies) ENABLE + FORCE row level security and
    carry a tenant policy with BOTH `USING` and `WITH CHECK` clauses
  * global catalogue tables carry no clinic_id column and no RLS
  * non-certifying doctrine: no pass/fail, grade, certificate, or
    competence column exists; attempts store aggregate counts only
    (no per-question answer column)
  * seed content (non-comment lines) makes no accreditation /
    certification / compliance claim
  * migrations never edit existing files (they are additive-only by
    filename)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SCHEMA_SQL = (
    REPO_ROOT / "migrations" / "20260705_01_learn_maturity_schema.sql"
).read_text(encoding="utf-8")
SEED_SQL = (
    REPO_ROOT / "migrations" / "20260705_02_learn_maturity_seed.sql"
).read_text(encoding="utf-8")


def _non_comment(sql: str) -> str:
    return "\n".join(
        line
        for line in sql.splitlines()
        if not line.strip().startswith("--")
    )


def test_creates_expected_tables() -> None:
    for table in (
        "learning_module_checks",
        "learning_check_attempts",
        "learning_role_paths",
        "learning_renewal_policies",
    ):
        assert f"CREATE TABLE IF NOT EXISTS public.{table}" in SCHEMA_SQL


def test_clinic_scoped_tables_enable_and_force_rls() -> None:
    for table in ("learning_check_attempts", "learning_renewal_policies"):
        assert (
            f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY"
            in SCHEMA_SQL
        ), f"{table} missing ENABLE RLS"
        assert (
            f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY"
            in SCHEMA_SQL
        ), f"{table} missing FORCE RLS"


def test_tenant_policies_have_using_and_with_check() -> None:
    for policy in (
        "rls_learning_check_attempts_tenant",
        "rls_learning_renewal_policies_tenant",
    ):
        block_match = re.search(
            rf"CREATE POLICY {policy}.*?\$policy\$",
            SCHEMA_SQL,
            flags=re.DOTALL,
        )
        assert block_match, f"policy {policy} not found"
        block = block_match.group(0)
        assert "USING (clinic_id = app_current_clinic_id())" in block
        assert "WITH CHECK (clinic_id = app_current_clinic_id())" in block


def test_global_tables_are_not_clinic_scoped() -> None:
    for table in ("learning_module_checks", "learning_role_paths"):
        ddl = re.search(
            rf"CREATE TABLE IF NOT EXISTS public\.{table} \((.*?)\);",
            SCHEMA_SQL,
            flags=re.DOTALL,
        )
        assert ddl, f"{table} DDL not found"
        assert "clinic_id" not in ddl.group(1)
        assert f"ALTER TABLE public.{table} ENABLE" not in SCHEMA_SQL


def test_non_certifying_schema_columns() -> None:
    body = _non_comment(SCHEMA_SQL).lower()
    for forbidden in (
        "pass_fail",
        "passed",
        "grade",
        "certificate",
        "certified",
        "competence",
        "accredited",
    ):
        assert forbidden not in body, f"forbidden column marker: {forbidden}"


def test_attempts_store_aggregates_only() -> None:
    ddl = re.search(
        r"CREATE TABLE IF NOT EXISTS public\.learning_check_attempts \((.*?)\);",
        SCHEMA_SQL,
        flags=re.DOTALL,
    )
    assert ddl
    cols = ddl.group(1).lower()
    assert "questions_total" in cols
    assert "questions_correct" in cols
    # No per-question answers, no free text.
    assert "selected_option" not in cols
    assert "answer" not in cols
    assert "free_text" not in cols
    assert "notes" not in cols


def test_seed_makes_no_claims() -> None:
    body = _non_comment(SEED_SQL).lower()
    for forbidden in (
        "rcvs-accredited",
        "rcvs accredited",
        "certified",
        "accredited cpd",
        "regulator-approved",
        "regulator approved",
        "compliant",
        "guarantees",
    ):
        assert forbidden not in body, f"claim wording in seed: {forbidden}"


def test_seed_is_idempotent() -> None:
    assert SEED_SQL.count("ON CONFLICT (check_slug) DO NOTHING") == 10
    assert SEED_SQL.count("ON CONFLICT (path_slug) DO NOTHING") == 2


def test_seed_references_only_existing_module_slugs() -> None:
    module_seed = (
        REPO_ROOT / "migrations" / "20260528_02_learn_module_seed.sql"
    ).read_text(encoding="utf-8")
    known_slugs = set(re.findall(r"'([a-z0-9-]+-v1)'", module_seed))
    referenced = set(
        re.findall(r"module_slug = '([a-z0-9-]+-v1)'", SEED_SQL)
    )
    assert referenced, "seed references no modules"
    missing = referenced - known_slugs
    assert not missing, f"seed references unknown modules: {missing}"
