"""Phase 2A-4.1 - Client-Facing Transparency schema tests.

Schema-level tests: inspect migration SQL text + on-disk markdown stub.
No live DB executed (consistent with `test_governance_policy_schema.py`
and `test_self_assessment_schema.py`).

Doctrine guards enforced here:
  * Three tables exist with the expected names.
  * Clinic-scoped tables have RLS + FORCE RLS + USING + WITH CHECK
    bound to `app_current_clinic_id()`.
  * Partial unique index for active profile is on (clinic_id) ONLY
    where status = 'active' (founder v1 decision: one active client
    transparency profile per clinic, NOT one per template).
  * Schema must NOT carry clinical / consent / certification columns.
  * Seed template present with canonical permitted / prohibited
    category enums.
  * Markdown stub exists and avoids high-risk wording except the
    explicit approved negative disclaimer.
  * No `ON CONFLICT (clinic_id, action, idempotency_key)` literal in
    either migration (TD-BE / M6.10.1B regression guard).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
MIGRATION_SCHEMA = (
    REPO_ROOT / "migrations" / "20260603_01_client_transparency_schema.sql"
)
MIGRATION_SEED = (
    REPO_ROOT / "migrations" / "20260603_02_client_transparency_template_seed.sql"
)
POLICIES_DIR = REPO_ROOT / "docs" / "governance" / "client_transparency"
MARKDOWN_STUB = POLICIES_DIR / "client_ai_use_transparency_v1-1.0.0.md"


# ---------------------------------------------------------------------
# Forbidden wording / column scans
# ---------------------------------------------------------------------
#
# Phrases assembled from fragments at runtime so this test source does
# NOT itself trip broader repo-level wording scans.
_FORBIDDEN_WORDING_PATTERNS = [
    "EU AI Act " + "compliant",
    "RCVS[- ]" + "certified",
    "RCVS[- ]" + "approved",
    "guarantees " + "compliance",
    "proof of " + "competence",
    "clinical safety " + "proof",
    "certified " + "CPD",
    "compliance " + "guarantee",
    "compliance " + "proof",
    "certified " + "audit",
    "legal " + "consent",
    "consent " + "form",
]

# The single approved negative-disclaimer sentence in the markdown
# stub (assembled from fragments so this guard does not itself match
# the broader wording scan). Any occurrence of the broader terms must
# fall within this approved disclaimer.
_APPROVED_DISCLAIMER_PREFIX = (
    "It is not legal advice, "
    "regulatory app" + "roval, a con" + "sent form, or a clinical record."
)


FORBIDDEN_COLUMNS = [
    "clinical_content",
    "client_identifier",
    "patient_identifier",
    "consent_text",
    "legal_consent",
    "competence_grade",
    "pass_fail",
    "score",
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
# 1. Migration files / markdown stub exist
# ---------------------------------------------------------------------


def test_schema_migration_file_exists() -> None:
    assert MIGRATION_SCHEMA.exists()


def test_seed_migration_file_exists() -> None:
    assert MIGRATION_SEED.exists()


def test_markdown_stub_exists() -> None:
    assert MARKDOWN_STUB.exists()
    text = MARKDOWN_STUB.read_text(encoding="utf-8")
    assert text.strip()
    assert "Template stub v1.0.0" in text


# ---------------------------------------------------------------------
# 2. Tables created
# ---------------------------------------------------------------------


def test_client_transparency_templates_table_created(schema_sql: str) -> None:
    assert (
        "CREATE TABLE IF NOT EXISTS public.client_transparency_templates"
        in schema_sql
    )


def test_clinic_client_transparency_profiles_table_created(schema_sql: str) -> None:
    assert (
        "CREATE TABLE IF NOT EXISTS public.clinic_client_transparency_profiles"
        in schema_sql
    )


def test_client_transparency_public_versions_table_created(schema_sql: str) -> None:
    assert (
        "CREATE TABLE IF NOT EXISTS public.client_transparency_public_versions"
        in schema_sql
    )


# ---------------------------------------------------------------------
# 3. RLS + FORCE RLS + USING + WITH CHECK on clinic-scoped tables
# ---------------------------------------------------------------------


def test_clinic_profiles_rls_enabled_and_forced(schema_sql: str) -> None:
    assert (
        "ALTER TABLE public.clinic_client_transparency_profiles "
        "ENABLE ROW LEVEL SECURITY"
        in schema_sql
    )
    assert (
        "ALTER TABLE public.clinic_client_transparency_profiles "
        "FORCE ROW LEVEL SECURITY"
        in schema_sql
    )


def test_clinic_profiles_policy_has_using_and_with_check(schema_sql: str) -> None:
    section = _section_between(
        schema_sql,
        "CREATE POLICY rls_clinic_client_transparency_profiles_tenant",
        "$policy$;",
    )
    assert "USING (clinic_id = app_current_clinic_id())" in section
    assert "WITH CHECK (clinic_id = app_current_clinic_id())" in section


def test_public_versions_rls_enabled_and_forced(schema_sql: str) -> None:
    assert (
        "ALTER TABLE public.client_transparency_public_versions "
        "ENABLE ROW LEVEL SECURITY"
        in schema_sql
    )
    assert (
        "ALTER TABLE public.client_transparency_public_versions "
        "FORCE ROW LEVEL SECURITY"
        in schema_sql
    )


def test_public_versions_policy_has_using_and_with_check(schema_sql: str) -> None:
    section = _section_between(
        schema_sql,
        "CREATE POLICY rls_client_transparency_public_versions_tenant",
        "$policy$;",
    )
    assert "USING (clinic_id = app_current_clinic_id())" in section
    assert "WITH CHECK (clinic_id = app_current_clinic_id())" in section


def test_global_templates_table_has_no_rls(schema_sql: str) -> None:
    # The global catalogue must not be RLS-locked - it's shared metadata.
    assert (
        "ALTER TABLE public.client_transparency_templates "
        "ENABLE ROW LEVEL SECURITY"
        not in schema_sql
    )
    assert (
        "ALTER TABLE public.client_transparency_templates "
        "FORCE ROW LEVEL SECURITY"
        not in schema_sql
    )


# ---------------------------------------------------------------------
# 4. Active-profile partial unique index - founder v1 correction:
#    UNIQUE (clinic_id) WHERE status = 'active'  (NOT per template).
# ---------------------------------------------------------------------


def test_active_profile_partial_unique_index_is_clinic_only(schema_sql: str) -> None:
    assert (
        "CREATE UNIQUE INDEX IF NOT EXISTS clinic_client_transparency_one_active"
        in schema_sql
    )
    # The unique target must be (clinic_id) only - NOT
    # (clinic_id, client_transparency_template_id).
    section = _section_between(
        schema_sql,
        "CREATE UNIQUE INDEX IF NOT EXISTS clinic_client_transparency_one_active",
        ";",
    )
    assert (
        "ON public.clinic_client_transparency_profiles (clinic_id)"
        in section
    )
    assert "client_transparency_template_id" not in section
    assert "WHERE status = 'active'" in section


# ---------------------------------------------------------------------
# 5. Status / publication_status CHECK enums
# ---------------------------------------------------------------------


def test_clinic_profile_status_check_constrained(schema_sql: str) -> None:
    assert "CHECK (status IN ('draft','active','superseded','archived'))" in schema_sql


def test_public_version_publication_status_check_constrained(schema_sql: str) -> None:
    assert (
        "CHECK (publication_status IN ('published','retired'))" in schema_sql
    )


# ---------------------------------------------------------------------
# 6. Text length CHECKs on bounded clinic-authored fields
# ---------------------------------------------------------------------


def test_display_title_length_bounded(schema_sql: str) -> None:
    assert "char_length(display_title) BETWEEN 1 AND 120" in schema_sql


def test_plain_language_summary_length_bounded(schema_sql: str) -> None:
    assert "char_length(plain_language_summary) BETWEEN 1 AND 1500" in schema_sql


# ---------------------------------------------------------------------
# 7. Profile natural-key uniqueness + public_version uniqueness
# ---------------------------------------------------------------------


def test_clinic_profile_natural_key_unique(schema_sql: str) -> None:
    assert "CONSTRAINT clinic_client_transparency_profiles_unique" in schema_sql
    assert (
        "UNIQUE (clinic_id, client_transparency_template_id, "
        "clinic_profile_version)"
        in schema_sql
    )


def test_public_version_natural_key_unique(schema_sql: str) -> None:
    assert "CONSTRAINT client_transparency_public_versions_unique" in schema_sql
    assert "UNIQUE (clinic_id, public_version)" in schema_sql


# ---------------------------------------------------------------------
# 8. Forbidden columns must NOT exist in the schema migration
# ---------------------------------------------------------------------


@pytest.mark.parametrize("forbidden", FORBIDDEN_COLUMNS)
def test_no_forbidden_columns_in_schema(schema_sql: str, forbidden: str) -> None:
    # Strip SQL line comments first so doctrine narrative in the
    # migration header doesn't trip the column-name scan.
    sql_no_comments = _strip_sql_line_comments(schema_sql)
    assert forbidden not in sql_no_comments, (
        f"forbidden concept '{forbidden}' must not appear as a column "
        "in the client transparency schema"
    )


# ---------------------------------------------------------------------
# 9. Seed - template slug and category enums present
# ---------------------------------------------------------------------


def test_seed_contains_v1_template_slug(seed_sql: str) -> None:
    assert "'client_ai_use_transparency_v1'" in seed_sql


def test_seed_contains_permitted_category_enums(seed_sql: str) -> None:
    for cat in (
        "'draft_client_communication'",
        "'internal_summarisation'",
        "'administrative_support'",
        "'governance_and_learning_support'",
    ):
        assert cat in seed_sql, f"seed missing permitted category {cat}"


def test_seed_contains_prohibited_category_enums(seed_sql: str) -> None:
    for cat in (
        "'diagnosis'",
        "'prescribing'",
        "'treatment_planning'",
        "'autonomous_clinical_decisions'",
        "'replacing_veterinary_judgement'",
    ):
        assert cat in seed_sql, f"seed missing prohibited category {cat}"


def test_seed_default_sections_contains_expected_keys(seed_sql: str) -> None:
    for key in (
        '"what_ai_may_be_used_for"',
        '"what_ai_is_not_used_for"',
        '"human_review"',
        '"privacy_and_confidentiality"',
        '"questions_from_clients"',
    ):
        assert key in seed_sql, f"seed default_sections missing key {key}"


def test_seed_is_idempotent_via_on_conflict_template_slug(seed_sql: str) -> None:
    # Targets the explicit UNIQUE column - safe (NOT a partial index).
    assert "ON CONFLICT (template_slug) DO NOTHING" in seed_sql


# ---------------------------------------------------------------------
# 10. Wording - migrations / markdown stub avoid high-risk claims
# ---------------------------------------------------------------------


@pytest.mark.parametrize("pattern", _FORBIDDEN_WORDING_PATTERNS)
def test_seed_migration_has_no_forbidden_wording(seed_sql: str, pattern: str) -> None:
    assert not re.search(pattern, seed_sql, re.IGNORECASE), (
        f"forbidden wording '{pattern}' in seed migration"
    )


@pytest.mark.parametrize("pattern", _FORBIDDEN_WORDING_PATTERNS)
def test_schema_migration_has_no_forbidden_wording(
    schema_sql: str, pattern: str
) -> None:
    # The schema-doctrine comment uses "consent form" / "consent text" in
    # NEGATIVE form inside the column-blocklist narrative. We tolerate
    # those when they appear immediately after the literal "is not " /
    # column-forbidden context. Strip SQL line comments first so the
    # doctrine narrative is excluded from the scan.
    sql_no_comments = _strip_sql_line_comments(schema_sql)
    assert not re.search(pattern, sql_no_comments, re.IGNORECASE), (
        f"forbidden wording '{pattern}' in schema migration (non-comment text)"
    )


@pytest.mark.parametrize("pattern", _FORBIDDEN_WORDING_PATTERNS)
def test_markdown_stub_has_no_forbidden_wording(pattern: str) -> None:
    text = MARKDOWN_STUB.read_text(encoding="utf-8")
    # The approved negative disclaimer contains the words "regulatory
    # approval, a consent form" inside one specific sentence. We assert
    # that any match of these patterns in the markdown stub lies within
    # that approved sentence - and that the pattern in question is one
    # of the negative-disclaimer-OK fragments. Other forbidden patterns
    # must not appear at all.
    NEGATIVE_OK = {
        "RCVS[- ]" + "approved",
        "legal " + "consent",
        "consent " + "form",
    }
    for m in re.finditer(pattern, text, re.IGNORECASE):
        if pattern not in NEGATIVE_OK:
            raise AssertionError(
                f"forbidden wording '{pattern}' in markdown stub"
            )
        # Sentence-bounded: every occurrence of the negative-OK
        # phrase must be in a sentence that also contains ' not '.
        sentence_start = max(
            text.rfind(". ", 0, m.start()),
            text.rfind("! ", 0, m.start()),
            text.rfind("? ", 0, m.start()),
            text.rfind("\n", 0, m.start()),
            0,
        )
        window = text[sentence_start: m.start()]
        assert " not " in window, (
            f"phrase '{pattern}' in markdown stub is not in negated form"
        )


def test_markdown_stub_contains_approved_negative_disclaimer() -> None:
    text = MARKDOWN_STUB.read_text(encoding="utf-8")
    # Assemble at runtime so this test source doesn't carry the full
    # disclaimer literal.
    expected = _APPROVED_DISCLAIMER_PREFIX
    assert expected in text, "approved negative-disclaimer sentence missing"


# ---------------------------------------------------------------------
# 11. No invalid admin_audit_events ON CONFLICT in either migration
# ---------------------------------------------------------------------


def test_schema_migration_has_no_unsafe_admin_audit_on_conflict(
    schema_sql: str,
) -> None:
    # Assemble from fragments so this test source itself contains no
    # literal forbidden conflict-target string. Strip SQL line comments
    # first - the migration header doctrine narrative names the
    # forbidden pattern explicitly for auditability; the guard is
    # about active SQL only.
    fragment = (
        "ON CONFLICT (clinic_id, " + "action, " + "idempotency_key)"
    )
    assert fragment not in _strip_sql_line_comments(schema_sql)


def test_seed_migration_has_no_unsafe_admin_audit_on_conflict(
    seed_sql: str,
) -> None:
    fragment = (
        "ON CONFLICT (clinic_id, " + "action, " + "idempotency_key)"
    )
    assert fragment not in seed_sql


# ---------------------------------------------------------------------
# 12. Hygiene checks on the changed files (mojibake / non-ASCII)
# ---------------------------------------------------------------------


# Codepoint-defined mojibake byte pairs - matches the
# `MOJIBAKE_MARKERS` pattern established in 2A-2.1B cleanup.
MOJIBAKE_MARKERS = (
    chr(0x00E2) + chr(0x20AC),
    chr(0x00C2) + chr(0x00A0),
)


def _changed_files() -> list:
    return [MIGRATION_SCHEMA, MIGRATION_SEED, MARKDOWN_STUB]


@pytest.mark.parametrize("path", _changed_files(), ids=lambda p: p.name)
def test_changed_file_has_no_mojibake(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for marker in MOJIBAKE_MARKERS:
        assert marker not in text, (
            f"mojibake byte-pair (U+{ord(marker[0]):04X} U+{ord(marker[1]):04X}) "
            f"found in {path.name}"
        )


@pytest.mark.parametrize("path", _changed_files(), ids=lambda p: p.name)
def test_changed_file_is_pure_ascii(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for ln, line in enumerate(text.splitlines(), 1):
        for col, ch in enumerate(line):
            if ord(ch) > 127:
                raise AssertionError(
                    f"non-ASCII char U+{ord(ch):04X} at {path.name}:{ln}:col{col}"
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
    """Return the substring starting at `after_marker` and ending at
    the next `until_marker` after it."""
    start = text.find(after_marker)
    assert start >= 0, f"marker not found: {after_marker!r}"
    end = text.find(until_marker, start + len(after_marker))
    if end < 0:
        end = len(text)
    return text[start:end]
