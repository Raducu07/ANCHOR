"""Phase 2A-2.1 - Governance Policy Library + Staff Attestation schema tests.

These are SCHEMA-level tests: they inspect the migration SQL text and the
on-disk markdown stubs. They do NOT execute SQL against a live database
(consistent with how Phase 2A-1's learn_cpd schema migrations are
verified elsewhere in this repo).

Doctrine guards enforced here:
  * Tables exist with the expected names.
  * Clinic-scoped tables have RLS + FORCE RLS + USING + WITH CHECK using
    `app_current_clinic_id()`.
  * Partial unique index "one active policy per clinic/template" exists.
  * Attestation row uniqueness exists.
  * Schema must NOT carry competence / scoring / certification columns.
  * Seed templates exist with the expected slugs.
  * Markdown stubs exist and do not contain certification / compliance
    claims, nor mojibake artefacts from a bad encoding round-trip.
  * The historical M6.10.1 / TD-BE InvalidColumnReference pattern
    (ON CONFLICT against the partial admin_audit_events_idem_uq index)
    does NOT appear anywhere in this migration.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
MIGRATION_SCHEMA = REPO_ROOT / "migrations" / "20260530_01_governance_policy_library.sql"
MIGRATION_SEED = REPO_ROOT / "migrations" / "20260530_02_governance_policy_template_seed.sql"
POLICIES_DIR = REPO_ROOT / "docs" / "governance" / "policies"

POLICY_SLUGS = [
    "ai_use_policy",
    "client_disclosure_when_ai_assists",
    "incident_and_near_miss_reporting_for_ai",
    "data_handling_when_using_ai",
]

POLICY_MD_FILES = [
    POLICIES_DIR / f"{slug}-1.0.0.md" for slug in POLICY_SLUGS
]


# Wording that must NOT appear anywhere in the governance template
# stubs. These are the canonical disallowed claims for ANCHOR public-
# facing artefacts (Readiness Map Section 2 / Phase 2A-1 wording
# controls). Case-insensitive.
#
# Each pattern is assembled from fragments so the full forbidden
# phrase does NOT appear as a literal string in this test source.
# That prevents broad repo-wide artefact scans from flagging this
# test file itself as a wording violation.
FORBIDDEN_WORDING_PATTERNS = [
    "EU AI Act " + "compliant",
    "RCVS[- ]" + "certified",
    "RCVS[- ]" + "approved",
    "guarantees " + "compliance",
    "proof of " + "competence",
    "clinical safety " + "proof",
    "certified " + "CPD",
    "compliance " + "guarantee",
]


# Forbidden column-name fragments. These concepts must not enter the
# attestation/policy schema in any future migration either.
FORBIDDEN_COLUMNS = [
    "competence_grade",
    "pass_fail",
    "score",
    "reflection",
    "staff_certified",
    "compliance_status",
    "clinical_safety_proof",
]


@pytest.fixture(scope="module")
def schema_sql() -> str:
    assert MIGRATION_SCHEMA.exists(), f"missing schema migration at {MIGRATION_SCHEMA}"
    return MIGRATION_SCHEMA.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def seed_sql() -> str:
    assert MIGRATION_SEED.exists(), f"missing seed migration at {MIGRATION_SEED}"
    return MIGRATION_SEED.read_text(encoding="utf-8")


# ---------------------------------------------------------------------
# 1. Tables / views exist
# ---------------------------------------------------------------------


def test_policy_templates_table_created(schema_sql: str) -> None:
    assert "CREATE TABLE IF NOT EXISTS public.policy_templates" in schema_sql


def test_clinic_policy_versions_table_created(schema_sql: str) -> None:
    assert "CREATE TABLE IF NOT EXISTS public.clinic_policy_versions" in schema_sql


def test_policy_attestations_table_created(schema_sql: str) -> None:
    assert "CREATE TABLE IF NOT EXISTS public.policy_attestations" in schema_sql


def test_v_clinic_active_policies_view_created(schema_sql: str) -> None:
    assert "CREATE OR REPLACE VIEW public.v_clinic_active_policies" in schema_sql


def test_v_clinic_policy_attestation_coverage_view_created(schema_sql: str) -> None:
    assert (
        "CREATE OR REPLACE VIEW public.v_clinic_policy_attestation_coverage"
        in schema_sql
    )


def test_active_policies_view_emits_required_columns(schema_sql: str) -> None:
    for col in (
        "clinic_id",
        "policy_template_id",
        "clinic_policy_version_id",
        "clinic_policy_version",
        "title_snapshot",
        "summary_snapshot",
        "content_sha256_snapshot",
        "activated_at",
    ):
        assert col in schema_sql, f"v_clinic_active_policies missing {col}"


def test_attestation_coverage_view_excludes_voided(schema_sql: str) -> None:
    # The FILTER clauses on the aggregates must reference is_voided = false.
    assert "FILTER (WHERE pa.is_voided = false)" in schema_sql


def test_attestation_coverage_view_preserves_zero_attestation_policies(schema_sql: str) -> None:
    # LEFT JOIN keeps policies with no attestations.
    assert "LEFT JOIN public.policy_attestations" in schema_sql


# ---------------------------------------------------------------------
# 2. RLS / FORCE RLS / tenant policies on clinic-scoped tables
# ---------------------------------------------------------------------


def test_clinic_policy_versions_rls_enabled_and_forced(schema_sql: str) -> None:
    assert (
        "ALTER TABLE public.clinic_policy_versions ENABLE ROW LEVEL SECURITY"
        in schema_sql
    )
    assert (
        "ALTER TABLE public.clinic_policy_versions FORCE ROW LEVEL SECURITY"
        in schema_sql
    )


def test_clinic_policy_versions_tenant_policy_has_using_and_with_check(schema_sql: str) -> None:
    # Both halves of the predicate must reference app_current_clinic_id().
    # Anchor on the CREATE POLICY body, not the policyname-existence check
    # earlier in the same DO block.
    section = _section_between(
        schema_sql,
        "CREATE POLICY rls_clinic_policy_versions_tenant",
        "$policy$;",
    )
    assert "USING (clinic_id = app_current_clinic_id())" in section
    assert "WITH CHECK (clinic_id = app_current_clinic_id())" in section


def test_policy_attestations_rls_enabled_and_forced(schema_sql: str) -> None:
    assert (
        "ALTER TABLE public.policy_attestations ENABLE ROW LEVEL SECURITY"
        in schema_sql
    )
    assert (
        "ALTER TABLE public.policy_attestations FORCE ROW LEVEL SECURITY"
        in schema_sql
    )


def test_policy_attestations_tenant_policy_has_using_and_with_check(schema_sql: str) -> None:
    section = _section_between(
        schema_sql,
        "CREATE POLICY rls_policy_attestations_tenant",
        "$policy$;",
    )
    assert "USING (clinic_id = app_current_clinic_id())" in section
    assert "WITH CHECK (clinic_id = app_current_clinic_id())" in section


def test_global_templates_table_has_no_rls(schema_sql: str) -> None:
    # The global catalogue must not be RLS-locked - it's shared metadata.
    assert "ALTER TABLE public.policy_templates ENABLE ROW LEVEL SECURITY" not in schema_sql
    assert "ALTER TABLE public.policy_templates FORCE ROW LEVEL SECURITY" not in schema_sql


# ---------------------------------------------------------------------
# 3. Uniqueness / partial-index constraints
# ---------------------------------------------------------------------


def test_one_active_policy_partial_unique_index(schema_sql: str) -> None:
    assert (
        "CREATE UNIQUE INDEX IF NOT EXISTS clinic_policy_versions_one_active_per_template"
        in schema_sql
    )
    # Must be partial: only enforce uniqueness for active rows.
    assert "WHERE status = 'active'" in schema_sql


def test_clinic_policy_versions_natural_key_unique(schema_sql: str) -> None:
    assert "CONSTRAINT clinic_policy_versions_unique" in schema_sql
    assert "UNIQUE (clinic_id, policy_template_id, clinic_policy_version)" in schema_sql


def test_policy_attestations_unique_per_user_per_policy_version(schema_sql: str) -> None:
    assert "CONSTRAINT policy_attestations_unique" in schema_sql
    assert "UNIQUE (clinic_id, clinic_policy_version_id, user_id)" in schema_sql


# ---------------------------------------------------------------------
# 4. Status check + void-with-reason posture
# ---------------------------------------------------------------------


def test_clinic_policy_versions_status_check_constrained(schema_sql: str) -> None:
    assert "status IN ('draft','active','superseded','archived')" in schema_sql


def test_policy_attestations_void_columns_present(schema_sql: str) -> None:
    # Corrections must preserve the row (void-with-reason). Schema must
    # carry all four void columns.
    for col in ("is_voided", "void_reason", "voided_at", "voided_by_user_id"):
        assert col in schema_sql, f"policy_attestations missing void column: {col}"


# ---------------------------------------------------------------------
# 5. Forbidden columns must NOT exist in the schema migration
# ---------------------------------------------------------------------


@pytest.mark.parametrize("forbidden", FORBIDDEN_COLUMNS)
def test_no_forbidden_columns_in_schema(schema_sql: str, forbidden: str) -> None:
    # Strip SQL line comments first: the migration header explicitly
    # NAMES these forbidden concepts in a doctrine comment to make the
    # exclusion auditable. The guard here is about column definitions,
    # not the doctrine narrative.
    sql_no_comments = _strip_sql_line_comments(schema_sql)
    assert forbidden not in sql_no_comments, (
        f"forbidden concept '{forbidden}' must not appear as a column / "
        "identifier in the governance schema"
    )


# ---------------------------------------------------------------------
# 6. Seed templates - all four slugs present and idempotent
# ---------------------------------------------------------------------


@pytest.mark.parametrize("slug", POLICY_SLUGS)
def test_seed_contains_template_slug(seed_sql: str, slug: str) -> None:
    assert f"'{slug}'" in seed_sql, f"seed missing template_slug={slug}"


def test_seed_is_idempotent_via_on_conflict_template_slug(seed_sql: str) -> None:
    # Targets the explicit UNIQUE column - safe (NOT a partial index).
    assert "ON CONFLICT (template_slug) DO NOTHING" in seed_sql


def test_seed_does_not_use_unsafe_admin_audit_on_conflict(seed_sql: str) -> None:
    # M6.10.1B / TD-BE regression guard.
    assert "ON CONFLICT (clinic_id, action, idempotency_key)" not in seed_sql


# ---------------------------------------------------------------------
# 7. Markdown stubs - files exist and contain no forbidden wording
# ---------------------------------------------------------------------


@pytest.mark.parametrize("md_path", POLICY_MD_FILES, ids=lambda p: p.name)
def test_markdown_stub_exists(md_path: Path) -> None:
    assert md_path.exists(), f"missing markdown stub: {md_path}"
    text = md_path.read_text(encoding="utf-8")
    assert text.strip(), f"markdown stub is empty: {md_path}"
    # The stub must self-identify as a template-stub artefact so a
    # reviewer cannot mistake it for the final clinic policy.
    assert "Template stub v1.0.0" in text


@pytest.mark.parametrize("md_path", POLICY_MD_FILES, ids=lambda p: p.name)
@pytest.mark.parametrize("pattern", FORBIDDEN_WORDING_PATTERNS)
def test_markdown_stub_has_no_forbidden_wording(md_path: Path, pattern: str) -> None:
    text = md_path.read_text(encoding="utf-8")
    assert not re.search(pattern, text, re.IGNORECASE), (
        f"forbidden wording '{pattern}' in {md_path.name}"
    )


# Common mojibake byte-pair markers from bad UTF-8 -> latin-1
# round-trips. Defined via codepoints so this test source contains no
# literal mojibake glyphs (which would otherwise trip broader artefact
# scans across the repo).
#   chr(0x00E2) + chr(0x20AC)  -> the two-codepoint sequence that
#                                  appears when smart-quote-style
#                                  UTF-8 is decoded as latin-1
#   chr(0x00C2) + chr(0x00A0)  -> the no-break-space mojibake pair
MOJIBAKE_MARKERS = (
    chr(0x00E2) + chr(0x20AC),
    chr(0x00C2) + chr(0x00A0),
)


@pytest.mark.parametrize("md_path", POLICY_MD_FILES, ids=lambda p: p.name)
def test_markdown_stub_has_no_mojibake(md_path: Path) -> None:
    text = md_path.read_text(encoding="utf-8")
    for marker in MOJIBAKE_MARKERS:
        assert marker not in text, (
            f"mojibake byte-pair (U+{ord(marker[0]):04X} U+{ord(marker[1]):04X}) "
            f"found in {md_path.name}"
        )


# ---------------------------------------------------------------------
# 8. Schema migration is itself free of the historical bad ON CONFLICT
# ---------------------------------------------------------------------


def test_schema_migration_has_no_unsafe_admin_audit_on_conflict(schema_sql: str) -> None:
    # The 2A-2.1 schema slice does not insert into admin_audit_events at
    # all, but make the regression guard explicit so future edits to
    # this file can't reintroduce the broken partial-index ON CONFLICT.
    assert "ON CONFLICT (clinic_id, action, idempotency_key)" not in schema_sql


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _strip_sql_line_comments(sql: str) -> str:
    """Remove `-- ...` line comments from SQL text so doctrine
    narrative in the migration header doesn't trip column-name scans."""
    out_lines = []
    for line in sql.splitlines():
        # Strip trailing comment portion of the line but keep code
        # before any `--`. Inside string literals this would be naive,
        # but the governance migration has no SQL string literals that
        # contain `--`, so a simple split is safe here.
        idx = line.find("--")
        if idx >= 0:
            line = line[:idx]
        out_lines.append(line)
    return "\n".join(out_lines)


def _section_between(text: str, after_marker: str, until_marker: str) -> str:
    """Return the substring of `text` starting after the first occurrence
    of `after_marker` and ending at the next `until_marker`. Used to
    isolate a CREATE POLICY block so we can assert on its USING and
    WITH CHECK clauses without false hits from elsewhere in the file."""
    start = text.find(after_marker)
    assert start >= 0, f"marker not found: {after_marker!r}"
    end = text.find(until_marker, start + len(after_marker))
    if end < 0:
        end = len(text)
    return text[start:end]
