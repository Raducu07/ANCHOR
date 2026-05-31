"""Phase 2A-3.1 - RCVS-aligned AI Governance Self-Assessment schema tests.

These are SCHEMA-level tests: they inspect the migration SQL text and the
on-disk markdown stubs. They do NOT execute SQL against a live database
(consistent with how Phase 2A-1 learn_cpd and Phase 2A-2 governance
policy schema migrations are verified elsewhere in this repo).

Doctrine guards enforced here:
  * Schema + seed migration files exist.
  * Global catalogue tables (self_assessment_templates,
    self_assessment_questions) exist with the expected names and are
    NOT RLS-locked.
  * Clinic-scoped tables (clinic_self_assessments,
    clinic_self_assessment_answers) have RLS + FORCE RLS + USING +
    WITH CHECK using `app_current_clinic_id()`.
  * Partial unique index "one draft per clinic/template" exists.
  * Answer enum is bounded to {yes, partial, planned, no,
    not_applicable}.
  * Schema must NOT carry scoring / competence / certification /
    free-text columns.
  * Seed contains the expected template slug and ten question slugs.
  * Markdown stubs exist and do not contain certification /
    compliance claims, nor mojibake artefacts from a bad encoding
    round-trip.
  * The historical M6.10.1 / TD-BE InvalidColumnReference pattern
    (ON CONFLICT against the partial admin_audit_events_idem_uq
    index) does NOT appear anywhere in this migration.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
MIGRATION_SCHEMA = REPO_ROOT / "migrations" / "20260531_01_self_assessment_schema.sql"
MIGRATION_SEED = REPO_ROOT / "migrations" / "20260531_02_self_assessment_template_seed.sql"
SA_DIR = REPO_ROOT / "docs" / "governance" / "self_assessment"

TEMPLATE_SLUG = "rcvs_ai_governance_self_assessment"

QUESTION_SLUGS = [
    "governance_owner_named",
    "ai_use_policy_active",
    "staff_ai_literacy_recorded",
    "staff_acknowledged_policy",
    "human_review_required",
    "data_handling_boundaries_set",
    "client_transparency_practice",
    "incident_reporting_path",
    "tool_vendor_inventory",
    "evidence_audit_ready",
]

ANSWER_ENUM_VALUES = ["yes", "partial", "planned", "no", "not_applicable"]

THEME_VALUES = [
    "governance_ownership",
    "policy_availability",
    "staff_literacy",
    "staff_acknowledgement",
    "human_review",
    "data_handling",
    "transparency_to_clients",
    "incident_readiness",
    "tool_vendor_awareness",
    "evidence_audit_readiness",
]

STUB_FILES = [SA_DIR / f"{TEMPLATE_SLUG}-1.0.0.md"] + [
    SA_DIR / f"{slug}-1.0.0.md" for slug in QUESTION_SLUGS
]


# Wording that must NOT appear in any product / migration / seed /
# docs file. Each pattern is assembled from fragments so the full
# forbidden phrase does not appear as a literal string in this test
# source. That prevents broad repo-wide artefact scans from flagging
# this test file itself as a wording violation.
FORBIDDEN_WORDING_PATTERNS = [
    "EU AI Act " + "compliant",
    "RCVS[- ]" + "certified",
    "RCVS[- ]" + "approved",
    "guarantees " + "compliance",
    "proof of " + "competence",
    "clinical safety " + "proof",
    "certified " + "CPD",
    "compliance " + "guarantee",
    "legally complete " + "audit trail",
    "staff " + "certified",
    "approved by " + "RCVS",
    "compliance " + "proof",
    "certified " + "audit",
]


# Forbidden column-name fragments. These concepts must not enter the
# self-assessment schema in any future migration either.
FORBIDDEN_COLUMNS = [
    "score",
    "pass_fail",
    "competence_grade",
    "compliance_status",
    "clinical_safety_proof",
    "staff_certified",
    "legal_approval",
    "notes",
    "free_text",
    "reflection",
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
# 1. Migration files / tables / views exist
# ---------------------------------------------------------------------


def test_schema_migration_file_exists() -> None:
    assert MIGRATION_SCHEMA.exists()


def test_seed_migration_file_exists() -> None:
    assert MIGRATION_SEED.exists()


def test_self_assessment_templates_table_created(schema_sql: str) -> None:
    assert "CREATE TABLE IF NOT EXISTS public.self_assessment_templates" in schema_sql


def test_self_assessment_questions_table_created(schema_sql: str) -> None:
    assert "CREATE TABLE IF NOT EXISTS public.self_assessment_questions" in schema_sql


def test_clinic_self_assessments_table_created(schema_sql: str) -> None:
    assert "CREATE TABLE IF NOT EXISTS public.clinic_self_assessments" in schema_sql


def test_clinic_self_assessment_answers_table_created(schema_sql: str) -> None:
    assert (
        "CREATE TABLE IF NOT EXISTS public.clinic_self_assessment_answers"
        in schema_sql
    )


def test_v_clinic_latest_self_assessment_view_created(schema_sql: str) -> None:
    assert "CREATE OR REPLACE VIEW public.v_clinic_latest_self_assessment" in schema_sql


def test_latest_view_excludes_draft_and_archived(schema_sql: str) -> None:
    section = _section_between(
        schema_sql,
        "CREATE OR REPLACE VIEW public.v_clinic_latest_self_assessment",
        "ORDER BY",
    )
    assert "status IN ('submitted','superseded')" in section


# ---------------------------------------------------------------------
# 2. RLS / FORCE RLS on clinic-scoped tables; none on globals
# ---------------------------------------------------------------------


def test_clinic_self_assessments_rls_enabled_and_forced(schema_sql: str) -> None:
    assert (
        "ALTER TABLE public.clinic_self_assessments ENABLE ROW LEVEL SECURITY"
        in schema_sql
    )
    assert (
        "ALTER TABLE public.clinic_self_assessments FORCE ROW LEVEL SECURITY"
        in schema_sql
    )


def test_clinic_self_assessments_tenant_policy_has_using_and_with_check(
    schema_sql: str,
) -> None:
    section = _section_between(
        schema_sql,
        "CREATE POLICY rls_clinic_self_assessments_tenant",
        "$policy$;",
    )
    assert "USING (clinic_id = app_current_clinic_id())" in section
    assert "WITH CHECK (clinic_id = app_current_clinic_id())" in section


def test_clinic_self_assessment_answers_rls_enabled_and_forced(schema_sql: str) -> None:
    assert (
        "ALTER TABLE public.clinic_self_assessment_answers ENABLE ROW LEVEL SECURITY"
        in schema_sql
    )
    assert (
        "ALTER TABLE public.clinic_self_assessment_answers FORCE ROW LEVEL SECURITY"
        in schema_sql
    )


def test_clinic_self_assessment_answers_tenant_policy_has_using_and_with_check(
    schema_sql: str,
) -> None:
    section = _section_between(
        schema_sql,
        "CREATE POLICY rls_clinic_self_assessment_answers_tenant",
        "$policy$;",
    )
    assert "USING (clinic_id = app_current_clinic_id())" in section
    assert "WITH CHECK (clinic_id = app_current_clinic_id())" in section


def test_global_templates_table_has_no_rls(schema_sql: str) -> None:
    assert (
        "ALTER TABLE public.self_assessment_templates ENABLE ROW LEVEL SECURITY"
        not in schema_sql
    )
    assert (
        "ALTER TABLE public.self_assessment_templates FORCE ROW LEVEL SECURITY"
        not in schema_sql
    )


def test_global_questions_table_has_no_rls(schema_sql: str) -> None:
    assert (
        "ALTER TABLE public.self_assessment_questions ENABLE ROW LEVEL SECURITY"
        not in schema_sql
    )
    assert (
        "ALTER TABLE public.self_assessment_questions FORCE ROW LEVEL SECURITY"
        not in schema_sql
    )


def test_global_tables_have_no_clinic_id_column(schema_sql: str) -> None:
    """The global catalogue tables must not carry clinic_id; that would
    imply tenant-scoping that the no-RLS posture would silently break."""
    sql_no_comments = _strip_sql_line_comments(schema_sql)
    tmpl_section = _section_between(
        sql_no_comments,
        "CREATE TABLE IF NOT EXISTS public.self_assessment_templates",
        ");",
    )
    qst_section = _section_between(
        sql_no_comments,
        "CREATE TABLE IF NOT EXISTS public.self_assessment_questions",
        ");",
    )
    assert "clinic_id" not in tmpl_section
    assert "clinic_id" not in qst_section


# ---------------------------------------------------------------------
# 3. Uniqueness / partial-index constraints
# ---------------------------------------------------------------------


def test_one_draft_per_clinic_template_partial_unique_index(schema_sql: str) -> None:
    assert (
        "CREATE UNIQUE INDEX IF NOT EXISTS clinic_self_assessments_one_draft_per_template"
        in schema_sql
    )
    assert "WHERE status = 'draft'" in schema_sql


def test_clinic_self_assessments_natural_key_unique(schema_sql: str) -> None:
    assert "CONSTRAINT clinic_self_assessments_unique" in schema_sql
    assert "UNIQUE (clinic_id, template_id, clinic_assessment_version)" in schema_sql


def test_clinic_self_assessment_answers_unique_per_question(schema_sql: str) -> None:
    assert "CONSTRAINT clinic_self_assessment_answers_unique" in schema_sql
    assert "UNIQUE (assessment_id, question_id)" in schema_sql


def test_templates_slug_version_unique(schema_sql: str) -> None:
    assert "CONSTRAINT self_assessment_templates_slug_version_unique" in schema_sql


def test_questions_template_slug_unique(schema_sql: str) -> None:
    assert "CONSTRAINT self_assessment_questions_template_slug_unique" in schema_sql


def test_questions_template_order_unique(schema_sql: str) -> None:
    assert "CONSTRAINT self_assessment_questions_template_order_unique" in schema_sql


# ---------------------------------------------------------------------
# 4. Status check + bounded answer enum + theme enum
# ---------------------------------------------------------------------


def test_clinic_self_assessments_status_check_constrained(schema_sql: str) -> None:
    assert "status IN ('draft','submitted','superseded','archived')" in schema_sql


def test_answer_enum_bounded(schema_sql: str) -> None:
    expected = "answer_value IN (\n            'yes','partial','planned','no','not_applicable'\n        )"
    # Be tolerant of whitespace variation; assert each enum value
    # individually and assert no other quoted answer-shaped value
    # leaks into the answer_value CHECK section.
    section = _section_between(schema_sql, "answer_value", "evidence_links")
    for v in ANSWER_ENUM_VALUES:
        assert f"'{v}'" in section, f"answer enum missing {v}"
    # Guard: no free-text-shaped escape values inside the enum.
    for forbidden in ("'free_text'", "'notes'", "'other'", "'partial_with_notes'"):
        assert forbidden not in section


@pytest.mark.parametrize("theme", THEME_VALUES)
def test_theme_enum_includes_all_themes(schema_sql: str, theme: str) -> None:
    section = _section_between(schema_sql, "theme                      text", "prompt_text")
    assert f"'{theme}'" in section


# ---------------------------------------------------------------------
# 5. Forbidden columns must NOT exist in the schema migration
# ---------------------------------------------------------------------


@pytest.mark.parametrize("forbidden", FORBIDDEN_COLUMNS)
def test_no_forbidden_columns_in_schema(schema_sql: str, forbidden: str) -> None:
    # Strip SQL line comments first: the migration header explicitly
    # NAMES these forbidden concepts in a doctrine comment to make
    # the exclusion auditable. The guard here is about column
    # definitions, not the doctrine narrative.
    sql_no_comments = _strip_sql_line_comments(schema_sql)
    assert forbidden not in sql_no_comments, (
        f"forbidden concept '{forbidden}' must not appear as a column / "
        "identifier in the self-assessment schema"
    )


# ---------------------------------------------------------------------
# 6. Seed - template + 10 question slugs present; idempotency safe
# ---------------------------------------------------------------------


def test_seed_contains_template_slug(seed_sql: str) -> None:
    assert f"'{TEMPLATE_SLUG}'" in seed_sql


@pytest.mark.parametrize("slug", QUESTION_SLUGS)
def test_seed_contains_question_slug(seed_sql: str, slug: str) -> None:
    assert f"'{slug}'" in seed_sql, f"seed missing question_slug={slug}"


def test_seed_template_insert_idempotent_via_unique_template_slug(seed_sql: str) -> None:
    # Targets the explicit UNIQUE column on self_assessment_templates -
    # safe (NOT a partial index).
    assert "ON CONFLICT (template_slug) DO NOTHING" in seed_sql


def test_seed_question_inserts_idempotent_via_explicit_constraint(seed_sql: str) -> None:
    # Targets the explicit named UNIQUE constraint - safe
    # (NOT a partial index, NOT the partial draft-index).
    assert (
        "ON CONFLICT ON CONSTRAINT self_assessment_questions_template_slug_unique DO NOTHING"
        in seed_sql
    )


def test_seed_does_not_target_partial_draft_index(seed_sql: str) -> None:
    # The partial unique index is for runtime clinic data; seeds must
    # never use it as a conflict target.
    assert "clinic_self_assessments_one_draft_per_template" not in seed_sql


def test_seed_does_not_use_unsafe_admin_audit_on_conflict(seed_sql: str) -> None:
    # M6.10.1B / TD-BE regression guard.
    assert "ON CONFLICT (clinic_id, action, idempotency_key)" not in seed_sql


def test_schema_migration_has_no_unsafe_admin_audit_on_conflict(schema_sql: str) -> None:
    assert "ON CONFLICT (clinic_id, action, idempotency_key)" not in schema_sql


# ---------------------------------------------------------------------
# 7. Markdown stubs - files exist, no forbidden wording, no mojibake
# ---------------------------------------------------------------------


@pytest.mark.parametrize("md_path", STUB_FILES, ids=lambda p: p.name)
def test_markdown_stub_exists(md_path: Path) -> None:
    assert md_path.exists(), f"missing markdown stub: {md_path}"
    text = md_path.read_text(encoding="utf-8")
    assert text.strip(), f"markdown stub is empty: {md_path}"
    assert "Template stub v1.0.0" in text


@pytest.mark.parametrize("md_path", STUB_FILES, ids=lambda p: p.name)
@pytest.mark.parametrize("pattern", FORBIDDEN_WORDING_PATTERNS)
def test_markdown_stub_has_no_forbidden_wording(md_path: Path, pattern: str) -> None:
    text = md_path.read_text(encoding="utf-8")
    assert not re.search(pattern, text, re.IGNORECASE), (
        f"forbidden wording '{pattern}' in {md_path.name}"
    )


# Common mojibake byte-pair markers from bad UTF-8 -> latin-1
# round-trips. Defined via codepoints so this test source contains no
# literal mojibake glyphs.
MOJIBAKE_MARKERS = (
    chr(0x00E2) + chr(0x20AC),
    chr(0x00C2) + chr(0x00A0),
)


@pytest.mark.parametrize("md_path", STUB_FILES, ids=lambda p: p.name)
def test_markdown_stub_has_no_mojibake(md_path: Path) -> None:
    text = md_path.read_text(encoding="utf-8")
    for marker in MOJIBAKE_MARKERS:
        assert marker not in text, (
            f"mojibake byte-pair (U+{ord(marker[0]):04X} U+{ord(marker[1]):04X}) "
            f"found in {md_path.name}"
        )


# ---------------------------------------------------------------------
# 8. Product copy in migration + seed must not carry forbidden wording
# ---------------------------------------------------------------------


@pytest.mark.parametrize("pattern", FORBIDDEN_WORDING_PATTERNS)
def test_schema_sql_has_no_forbidden_wording(schema_sql: str, pattern: str) -> None:
    assert not re.search(pattern, schema_sql, re.IGNORECASE), (
        f"forbidden wording '{pattern}' in schema migration"
    )


@pytest.mark.parametrize("pattern", FORBIDDEN_WORDING_PATTERNS)
def test_seed_sql_has_no_forbidden_wording(seed_sql: str, pattern: str) -> None:
    assert not re.search(pattern, seed_sql, re.IGNORECASE), (
        f"forbidden wording '{pattern}' in seed migration"
    )


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _strip_sql_line_comments(sql: str) -> str:
    """Remove `-- ...` line comments from SQL text so doctrine
    narrative in the migration header doesn't trip column-name scans."""
    out_lines = []
    for line in sql.splitlines():
        idx = line.find("--")
        if idx >= 0:
            line = line[:idx]
        out_lines.append(line)
    return "\n".join(out_lines)


def _section_between(text: str, after_marker: str, until_marker: str) -> str:
    """Return the substring of `text` starting after the first occurrence
    of `after_marker` and ending at the next `until_marker`. Used to
    isolate a CREATE POLICY / CREATE TABLE block so we can assert on
    its contents without false hits from elsewhere in the file."""
    start = text.find(after_marker)
    assert start >= 0, f"marker not found: {after_marker!r}"
    end = text.find(until_marker, start + len(after_marker))
    if end < 0:
        end = len(text)
    return text[start:end]
