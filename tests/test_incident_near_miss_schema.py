"""Phase 2A-5.1 - Basic Incident / Near-Miss Logging schema tests.

Schema-level tests: inspect the migration SQL text. No live DB run
(consistent with `test_governance_policy_schema.py`,
`test_self_assessment_schema.py`, `test_client_transparency_schema.py`).

Doctrine guards enforced here:
  * Single clinic-scoped table `ai_incident_near_miss_records` exists.
  * RLS + FORCE RLS + USING + WITH CHECK bound to
    `app_current_clinic_id()`.
  * Schema is metadata-only by construction: NO free-text columns,
    NO narrative columns, NO identifier columns, NO claim/insurance/
    negligence/malpractice columns.
  * Every documented enum value appears in the migration text.
  * Optional metadata-only links reference real existing table PKs.
  * Migration does not write seed data, does not insert into
    admin_audit_events, does not contain the broken partial-index
    ON CONFLICT (M6.10.1B / TD-BE regression guard).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
MIGRATION = (
    REPO_ROOT / "migrations" / "20260603_03_incident_near_miss_schema.sql"
)


# ---------------------------------------------------------------------
# Enum vocabularies (must all appear in migration SQL)
# ---------------------------------------------------------------------

STATUS_VALUES = ("open", "in_review", "actioned", "closed", "voided")
SEVERITY_VALUES = ("low", "moderate", "high", "critical")
CATEGORY_VALUES = (
    "misleading_output",
    "inaccurate_output",
    "unsafe_suggestion",
    "privacy_or_identifier_risk",
    "overconfident_output",
    "missing_human_review",
    "policy_boundary_issue",
    "inappropriate_client_communication",
    "workflow_confusion",
    "other",
)
SOURCE_VALUES = (
    "assistant_workspace",
    "external_ai_tool",
    "ambient_or_scribe",
    "client_communication",
    "internal_summary",
    "clinical_note_support",
    "other",
)
OUTCOME_VALUES = (
    "caught_before_use",
    "corrected_before_use",
    "used_with_correction",
    "escalated_for_review",
    "client_communication_delayed",
    "clinical_team_reviewed",
    "other",
)
ACTION_TAKEN_VALUES = (
    "no_action_required",
    "additional_review",
    "staff_briefing",
    "policy_review",
    "process_change",
    "vendor_followup",
    "other",
)
VOID_REASON_VALUES = (
    "duplicate",
    "wrong_clinic_record",
    "test_data",
    "incorrect_metadata",
    "other",
)


# Column-name fragments that must NOT appear in the schema migration
# OUTSIDE comment lines.  These are the metadata-only / no-clinical /
# no-identifier / no-narrative / no-legal-claim doctrine guards.
FORBIDDEN_COLUMN_FRAGMENTS = (
    "summary",
    "note",
    "description",
    "narrative",
    "comment",
    "free_text",
    "clinical_content",
    "client_identifier",
    "patient_identifier",
    "staff_identifier",
    "raw_prompt",
    "raw_output",
    "transcript",
    "case_material",
    "consent_text",
    "legal_consent",
    "claim",
    "insurance",
    "negligence",
    "malpractice",
)


# ---------------------------------------------------------------------
# Fragment-assembled wording markers (so this test source does not
# itself trip broader repo-level wording scans).
# ---------------------------------------------------------------------

_FORBIDDEN_WORDING_PATTERNS = [
    "EU AI Act " + "compliant",
    "RCVS[- ]" + "certified",
    "RCVS[- ]" + "approved",
    "guarantees " + "compliance",
    "certified " + "CPD",
    "proof of " + "competence",
    "clinical safety " + "proof",
    "compliance " + "guarantee",
    "compliance " + "proof",
    "certified " + "audit",
    "insurance" + "-ready record",
    "proves safe " + "AI use",
    "guarantees " + "protection",
    "RCVS" + "-approved reporting",
    "VDS" + "-approved record",
    "adverse event " + "submission",
    "regulator" + "-approved report",
]


@pytest.fixture(scope="module")
def schema_sql() -> str:
    assert MIGRATION.exists(), f"missing migration at {MIGRATION}"
    return MIGRATION.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def schema_sql_no_comments(schema_sql: str) -> str:
    return _strip_sql_line_comments(schema_sql)


# ---------------------------------------------------------------------
# 1. Migration file presence
# ---------------------------------------------------------------------


def test_migration_file_exists() -> None:
    assert MIGRATION.exists()


# ---------------------------------------------------------------------
# 2. Table + primary key + clinic_id FK
# ---------------------------------------------------------------------


def test_table_created(schema_sql: str) -> None:
    assert (
        "CREATE TABLE IF NOT EXISTS public.ai_incident_near_miss_records"
        in schema_sql
    )


def test_primary_key_incident_id(schema_sql_no_comments: str) -> None:
    assert "incident_id" in schema_sql_no_comments
    assert "PRIMARY KEY" in schema_sql_no_comments


def test_clinic_id_foreign_key(schema_sql_no_comments: str) -> None:
    assert "clinic_id" in schema_sql_no_comments
    # FK to clinics(clinic_id) ON DELETE RESTRICT, matching other
    # clinic-scoped tables in this repo.
    assert (
        "REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT"
        in schema_sql_no_comments
    )


# ---------------------------------------------------------------------
# 3. Actor UUID metadata fields
# ---------------------------------------------------------------------


@pytest.mark.parametrize("col", (
    "created_by_user_id",
    "reviewed_by_user_id",
    "closed_by_user_id",
    "voided_by_user_id",
))
def test_actor_uuid_column_present(schema_sql_no_comments: str, col: str) -> None:
    assert col in schema_sql_no_comments
    # All actor columns must FK to clinic_users(user_id). The PK column
    # on clinic_users (per app/schema.sql) is `user_id`, NOT
    # `clinic_user_id`.
    assert "REFERENCES public.clinic_users(user_id)" in schema_sql_no_comments


def test_created_by_user_id_is_non_null(schema_sql_no_comments: str) -> None:
    # The creator must always be recorded.
    pattern = re.compile(r"created_by_user_id\s+uuid\s+NOT\s+NULL")
    assert pattern.search(schema_sql_no_comments) is not None


@pytest.mark.parametrize("col", (
    "reviewed_by_user_id",
    "closed_by_user_id",
    "voided_by_user_id",
))
def test_nullable_actor_columns_use_set_null(
    schema_sql_no_comments: str, col: str,
) -> None:
    # When a clinic_user is removed, the historical actor reference
    # nulls out but the incident record itself remains.
    pattern = re.compile(
        rf"{col}\s+uuid\s+NULL\s+REFERENCES\s+public\.clinic_users\(user_id\)\s+ON\s+DELETE\s+SET\s+NULL",
        re.DOTALL,
    )
    assert pattern.search(schema_sql_no_comments) is not None, (
        f"{col} should ON DELETE SET NULL"
    )


# ---------------------------------------------------------------------
# 4. Controlled-vocabulary columns + every enum value
# ---------------------------------------------------------------------


def _has_check_clause(sql: str, column: str) -> bool:
    # Find any `CHECK (... <column> IN (...))` after the column name.
    pat = re.compile(
        rf"\b{re.escape(column)}\b.*?CHECK\s*\([^)]*\bIN\s*\(",
        re.DOTALL,
    )
    return pat.search(sql) is not None


@pytest.mark.parametrize("col", (
    "status", "severity", "category", "source", "outcome",
    "action_taken_category", "void_reason_category",
))
def test_controlled_vocabulary_column_has_check(
    schema_sql_no_comments: str, col: str,
) -> None:
    assert _has_check_clause(schema_sql_no_comments, col), (
        f"controlled-vocabulary column missing CHECK IN: {col}"
    )


@pytest.mark.parametrize("value", STATUS_VALUES)
def test_status_enum_value_present(schema_sql_no_comments: str, value: str) -> None:
    assert f"'{value}'" in schema_sql_no_comments


@pytest.mark.parametrize("value", SEVERITY_VALUES)
def test_severity_enum_value_present(schema_sql_no_comments: str, value: str) -> None:
    assert f"'{value}'" in schema_sql_no_comments


@pytest.mark.parametrize("value", CATEGORY_VALUES)
def test_category_enum_value_present(schema_sql_no_comments: str, value: str) -> None:
    assert f"'{value}'" in schema_sql_no_comments


@pytest.mark.parametrize("value", SOURCE_VALUES)
def test_source_enum_value_present(schema_sql_no_comments: str, value: str) -> None:
    assert f"'{value}'" in schema_sql_no_comments


@pytest.mark.parametrize("value", OUTCOME_VALUES)
def test_outcome_enum_value_present(schema_sql_no_comments: str, value: str) -> None:
    assert f"'{value}'" in schema_sql_no_comments


@pytest.mark.parametrize("value", ACTION_TAKEN_VALUES)
def test_action_taken_category_value_present(
    schema_sql_no_comments: str, value: str,
) -> None:
    assert f"'{value}'" in schema_sql_no_comments


@pytest.mark.parametrize("value", VOID_REASON_VALUES)
def test_void_reason_category_value_present(
    schema_sql_no_comments: str, value: str,
) -> None:
    assert f"'{value}'" in schema_sql_no_comments


def test_action_taken_category_nullable_check(schema_sql_no_comments: str) -> None:
    # The "is null or in (...)" form keeps nullable columns valid.
    assert (
        "action_taken_category IS NULL OR action_taken_category IN"
        in schema_sql_no_comments
    )


def test_void_reason_category_nullable_check(schema_sql_no_comments: str) -> None:
    assert (
        "void_reason_category IS NULL OR void_reason_category IN"
        in schema_sql_no_comments
    )


# ---------------------------------------------------------------------
# 5. Reflective booleans
# ---------------------------------------------------------------------


@pytest.mark.parametrize("col", (
    "learning_recommended",
    "policy_review_recommended",
    "client_communication_review_recommended",
))
def test_reflective_boolean_present_with_default_false(
    schema_sql_no_comments: str, col: str,
) -> None:
    pattern = re.compile(
        rf"{col}\s+boolean\s+NOT\s+NULL\s+DEFAULT\s+false",
        re.DOTALL,
    )
    assert pattern.search(schema_sql_no_comments) is not None, (
        f"reflective boolean missing or wrong default: {col}"
    )


# ---------------------------------------------------------------------
# 6. Timestamps
# ---------------------------------------------------------------------


@pytest.mark.parametrize("col", (
    "occurred_at", "detected_at", "reported_at",
    "reviewed_at", "closed_at", "voided_at",
    "created_at", "updated_at",
))
def test_timestamp_column_present(schema_sql_no_comments: str, col: str) -> None:
    assert col in schema_sql_no_comments


def test_reported_at_defaults_to_now(schema_sql_no_comments: str) -> None:
    pattern = re.compile(
        r"reported_at\s+timestamptz\s+NOT\s+NULL\s+DEFAULT\s+now\(\)",
    )
    assert pattern.search(schema_sql_no_comments) is not None


# ---------------------------------------------------------------------
# 7. Optional metadata-only link columns with real FK targets
# ---------------------------------------------------------------------


def test_linked_receipt_fk(schema_sql_no_comments: str) -> None:
    pattern = re.compile(
        r"linked_receipt_id\s+uuid\s+NULL\s+REFERENCES\s+"
        r"public\.assistant_run_receipts\(id\)\s+ON\s+DELETE\s+SET\s+NULL",
        re.DOTALL,
    )
    assert pattern.search(schema_sql_no_comments) is not None


def test_linked_governance_event_fk(schema_sql_no_comments: str) -> None:
    pattern = re.compile(
        r"linked_governance_event_id\s+uuid\s+NULL\s+REFERENCES\s+"
        r"public\.clinic_governance_events\(event_id\)\s+ON\s+DELETE\s+SET\s+NULL",
        re.DOTALL,
    )
    assert pattern.search(schema_sql_no_comments) is not None


def test_linked_assistant_run_fk(schema_sql_no_comments: str) -> None:
    pattern = re.compile(
        r"linked_assistant_run_id\s+uuid\s+NULL\s+REFERENCES\s+"
        r"public\.assistant_runs\(id\)\s+ON\s+DELETE\s+SET\s+NULL",
        re.DOTALL,
    )
    assert pattern.search(schema_sql_no_comments) is not None


def test_linked_clinic_policy_version_fk(schema_sql_no_comments: str) -> None:
    pattern = re.compile(
        r"linked_clinic_policy_version_id\s+uuid\s+NULL\s+REFERENCES\s+"
        r"public\.clinic_policy_versions\(clinic_policy_version_id\)\s+"
        r"ON\s+DELETE\s+SET\s+NULL",
        re.DOTALL,
    )
    assert pattern.search(schema_sql_no_comments) is not None


# ---------------------------------------------------------------------
# 8. Forbidden columns absent
# ---------------------------------------------------------------------


@pytest.mark.parametrize("fragment", FORBIDDEN_COLUMN_FRAGMENTS)
def test_no_forbidden_column_fragment(
    schema_sql_no_comments: str, fragment: str,
) -> None:
    """No free-text / clinical / identifier / legal-claim COLUMN may
    appear in the DDL.

    Comments and single-quoted string literals (enum values inside
    `CHECK ('...')` clauses) are stripped first so:
      * Doctrine narrative in the migration header does not
        false-positive.
      * Enum values like `'internal_summary'` or
        `'clinical_note_support'` are not mistaken for column
        definitions.
    """
    scrubbed = _strip_sql_string_literals(schema_sql_no_comments)
    assert fragment not in scrubbed, (
        f"forbidden column-name fragment '{fragment}' appears in DDL"
    )


# ---------------------------------------------------------------------
# 9. Indexes (mandatory + partial)
# ---------------------------------------------------------------------


@pytest.mark.parametrize("expected_columns", (
    "(clinic_id, status)",
    "(clinic_id, severity)",
    "(clinic_id, category)",
    "(clinic_id, source)",
    "(clinic_id, reported_at DESC)",
    "(clinic_id, created_by_user_id)",
))
def test_index_present(schema_sql_no_comments: str, expected_columns: str) -> None:
    assert expected_columns in schema_sql_no_comments, (
        f"missing index on {expected_columns}"
    )


@pytest.mark.parametrize("link_col", (
    "linked_receipt_id",
    "linked_governance_event_id",
    "linked_assistant_run_id",
))
def test_partial_index_for_optional_link(
    schema_sql_no_comments: str, link_col: str,
) -> None:
    # Partial index "WHERE <col> IS NOT NULL" must appear.
    pattern = re.compile(
        rf"\({link_col}\s+IS\s+NOT\s+NULL\)|WHERE\s+{link_col}\s+IS\s+NOT\s+NULL",
        re.IGNORECASE,
    )
    assert pattern.search(schema_sql_no_comments) is not None, (
        f"partial index for {link_col} not present"
    )


# ---------------------------------------------------------------------
# 10. RLS + FORCE RLS + policy
# ---------------------------------------------------------------------


def test_rls_enabled(schema_sql: str) -> None:
    assert (
        "ALTER TABLE public.ai_incident_near_miss_records ENABLE ROW LEVEL SECURITY"
        in schema_sql
    )


def test_force_rls(schema_sql: str) -> None:
    assert (
        "ALTER TABLE public.ai_incident_near_miss_records FORCE ROW LEVEL SECURITY"
        in schema_sql
    )


def test_policy_exists_with_using_and_with_check(schema_sql: str) -> None:
    section = _section_between(
        schema_sql,
        "CREATE POLICY rls_ai_incident_near_miss_records_tenant",
        "$policy$;",
    )
    assert "USING (clinic_id = app_current_clinic_id())" in section
    assert "WITH CHECK (clinic_id = app_current_clinic_id())" in section


def test_policy_idempotent_guard(schema_sql: str) -> None:
    # The DO $$ pg_policies guard is the repo's idempotent pattern.
    assert "FROM pg_policies" in schema_sql
    assert "'rls_ai_incident_near_miss_records_tenant'" in schema_sql


# ---------------------------------------------------------------------
# 11. Slice-scope guards
# ---------------------------------------------------------------------


def test_migration_does_not_create_seed_data(schema_sql_no_comments: str) -> None:
    # No INSERTs in this slice.
    assert "INSERT INTO" not in schema_sql_no_comments


def test_migration_does_not_insert_admin_audit_events(
    schema_sql_no_comments: str,
) -> None:
    assert "INSERT INTO admin_audit_events" not in schema_sql_no_comments


def test_migration_does_not_create_endpoints(schema_sql: str) -> None:
    # SQL migrations can't create FastAPI routes - but defence in
    # depth: ensure nothing here resembles HTTP/router work.
    for marker in ("APIRouter", "FastAPI", "include_router", "@router."):
        assert marker not in schema_sql


def test_migration_does_not_modify_trust_logic(schema_sql_no_comments: str) -> None:
    for marker in (
        "trust_snapshot",
        "build_trust_snapshot",
        "build_pack_response",
        "trust_pack",
    ):
        assert marker not in schema_sql_no_comments


def test_no_unsafe_admin_audit_on_conflict(schema_sql_no_comments: str) -> None:
    # M6.10.1B / TD-BE regression guard. Assemble fragments so this
    # test source itself contains no literal forbidden string.
    fragment = (
        "ON CONFLICT (clinic_id, " + "action, " + "idempotency_key)"
    )
    assert fragment not in schema_sql_no_comments


# ---------------------------------------------------------------------
# 12. Wording / hygiene
# ---------------------------------------------------------------------


@pytest.mark.parametrize("pattern", _FORBIDDEN_WORDING_PATTERNS)
def test_migration_has_no_high_risk_wording(
    schema_sql_no_comments: str, pattern: str,
) -> None:
    assert not re.search(pattern, schema_sql_no_comments, re.IGNORECASE), (
        f"forbidden wording '{pattern}' in migration (non-comment text)"
    )


MOJIBAKE_MARKERS = (
    chr(0x00E2) + chr(0x20AC),
    chr(0x00C2) + chr(0x00A0),
)


def test_migration_has_no_mojibake() -> None:
    text = MIGRATION.read_text(encoding="utf-8")
    for marker in MOJIBAKE_MARKERS:
        assert marker not in text, (
            f"mojibake byte-pair (U+{ord(marker[0]):04X} U+{ord(marker[1]):04X}) "
            f"in {MIGRATION.name}"
        )


def test_migration_has_no_merge_markers() -> None:
    text = MIGRATION.read_text(encoding="utf-8")
    for marker in ("<<<<<<<", "=======", ">>>>>>>"):
        # The DDL must not carry git merge artefacts. The migration
        # uses `-- ---` separators (not `-- ===`) so seven-equals runs
        # would not legitimately appear.
        assert marker not in text, f"merge marker {marker!r} in migration"


def test_migration_is_pure_ascii() -> None:
    text = MIGRATION.read_text(encoding="utf-8")
    for ln, line in enumerate(text.splitlines(), 1):
        for col, ch in enumerate(line):
            if ord(ch) > 127:
                raise AssertionError(
                    f"non-ASCII char U+{ord(ch):04X} at line {ln} col {col}"
                )


def test_migration_is_wrapped_in_transaction(schema_sql: str) -> None:
    # The repo's migration runner expects an explicit transaction so
    # partial failures roll back.
    assert "BEGIN;" in schema_sql
    assert "COMMIT;" in schema_sql


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _strip_sql_string_literals(sql: str) -> str:
    """Remove `'...'` single-quoted string literals so enum values
    inside `CHECK (col IN ('a','b',...))` clauses do not collide with
    column-name scans. This is a small heuristic - the migration uses
    only simple single-quoted literals without embedded quotes."""
    return re.sub(r"'[^']*'", "''", sql)


def _strip_sql_line_comments(sql: str) -> str:
    """Remove `-- ...` line comments so doctrine narrative in the
    migration header does not trip column-name / wording scans."""
    out_lines = []
    for line in sql.splitlines():
        idx = line.find("--")
        if idx >= 0:
            line = line[:idx]
        out_lines.append(line)
    return "\n".join(out_lines)


def _section_between(text: str, after_marker: str, until_marker: str) -> str:
    start = text.find(after_marker)
    assert start >= 0, f"marker not found: {after_marker!r}"
    end = text.find(until_marker, start + len(after_marker))
    if end < 0:
        end = len(text)
    return text[start:end]
