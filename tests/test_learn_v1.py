from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SCHEMA_MIGRATION = REPO_ROOT / "migrations" / "20260528_01_learn_cpd_schema.sql"
SEED_MIGRATION = REPO_ROOT / "migrations" / "20260528_02_learn_module_seed.sql"
MODULES_DIR = REPO_ROOT / "docs" / "learn" / "modules"

MODULE_SLUGS = [
    "ai-literacy-foundations-v1",
    "bias-detection-in-ai-outputs-v1",
    "ethical-and-safe-ai-use-v1",
    "confidentiality-and-ai-v1",
    "explaining-ai-to-clients-v1",
]

# Audience tags treated as METADATA only (decision: not access-control roles).
AUDIENCE_TAGS = {"vet", "nurse", "practice_manager", "admin", "reception", "locum"}
# The real access-control role enum, which this slice must NOT alter.
ACCESS_CONTROL_ROLES = {"admin", "staff"}


def _read(path: Path) -> str:
    assert path.exists(), f"missing file: {path}"
    return path.read_text(encoding="utf-8")


def _normalize(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip()


def _schema_sql_lower() -> str:
    return _normalize(_read(SCHEMA_MIGRATION)).lower()


def _seed_sql_lower() -> str:
    return _normalize(_read(SEED_MIGRATION)).lower()


# ------------------------------------------------------------
# Seed: rows exist / active selectable
# ------------------------------------------------------------
def test_seed_inserts_all_five_modules() -> None:
    seed = _read(SEED_MIGRATION)
    for slug in MODULE_SLUGS:
        assert f"'{slug}'" in seed, f"seed missing module slug: {slug}"


def test_seed_modules_are_active() -> None:
    # Each INSERT block ends "...true ) ON CONFLICT (module_slug) DO NOTHING".
    seed = _seed_sql_lower()
    insert_blocks = re.findall(
        r"insert into public\.learning_modules.*?on conflict",
        seed,
        flags=re.DOTALL,
    )
    assert len(insert_blocks) == len(MODULE_SLUGS), (
        f"expected {len(MODULE_SLUGS)} INSERT blocks, found {len(insert_blocks)}"
    )
    # is_active is the final value before the conflict clause; must be true, never false.
    for block in insert_blocks:
        assert " true ) on conflict" in block or " true) on conflict" in block, (
            "each seeded module must be inserted with is_active = true"
        )
    assert " false ) on conflict" not in seed and " false) on conflict" not in seed


def test_seed_is_idempotent() -> None:
    # Every INSERT block must carry the idempotent conflict clause. Counted per
    # INSERT statement (not raw substring count) so comment text cannot inflate it.
    seed = _seed_sql_lower()
    insert_blocks = re.findall(
        r"insert into public\.learning_modules.*?do nothing",
        seed,
        flags=re.DOTALL,
    )
    assert len(insert_blocks) == len(MODULE_SLUGS), (
        f"expected {len(MODULE_SLUGS)} idempotent INSERT blocks, found {len(insert_blocks)}"
    )
    for block in insert_blocks:
        assert "on conflict (module_slug) do nothing" in block


# ------------------------------------------------------------
# role_applicability behaves as metadata tags (NOT access-control roles)
# ------------------------------------------------------------
def test_role_applicability_is_text_array_column() -> None:
    schema = _schema_sql_lower()
    assert "role_applicability text[] not null" in schema


def test_role_applicability_seeded_as_audience_tags() -> None:
    seed = _seed_sql_lower()
    # All six audience tags must appear in the seeded role_applicability arrays.
    for tag in AUDIENCE_TAGS:
        assert f"'{tag}'" in seed, f"audience tag not seeded: {tag}"


def test_role_applicability_not_constrained_to_access_control_roles() -> None:
    # Doctrine guard: this slice must not redefine the access-control role enum,
    # and must not constrain role_applicability to ('admin','staff').
    schema = _schema_sql_lower()
    assert "check (role in ('admin','staff'))" not in schema
    assert "alter table public.clinic_users" not in schema
    # Audience-only tags (which are NOT valid access-control roles) are present
    # in the seed, proving role_applicability is a separate metadata vocabulary.
    seed = _seed_sql_lower()
    audience_only = AUDIENCE_TAGS - ACCESS_CONTROL_ROLES
    for tag in audience_only:
        assert f"'{tag}'" in seed, f"expected audience-only tag in seed: {tag}"


# ------------------------------------------------------------
# category filter data exists, especially bias_detection
# ------------------------------------------------------------
def test_category_column_and_bias_detection_present() -> None:
    schema = _schema_sql_lower()
    assert "category text not null" in schema
    assert "'bias_detection'" in schema  # allowed-value CHECK list
    seed = _seed_sql_lower()
    assert "'bias_detection'" in seed  # at least one seeded module in this category


def test_all_seed_categories_are_valid() -> None:
    seeded_categories = {
        "literacy",
        "bias_detection",
        "ethical_use",
        "confidentiality",
        "transparency",
    }
    seed = _seed_sql_lower()
    for cat in seeded_categories:
        assert f"'{cat}'" in seed, f"expected seeded category: {cat}"


# ------------------------------------------------------------
# learning_completions RLS + FORCE RLS
# ------------------------------------------------------------
def test_learning_completions_rls_enabled_and_forced() -> None:
    schema = _schema_sql_lower()
    assert "alter table public.learning_completions enable row level security" in schema
    assert "alter table public.learning_completions force row level security" in schema


def test_learning_completions_policy_uses_app_current_clinic_id() -> None:
    schema = _schema_sql_lower()
    assert "create policy rls_learning_completions_tenant" in schema
    assert "on public.learning_completions" in schema
    # Both USING and WITH CHECK must reference the repo helper, not raw current_setting.
    assert "using (clinic_id = app_current_clinic_id())" in schema
    assert "with check (clinic_id = app_current_clinic_id())" in schema


# ------------------------------------------------------------
# cpd_exports RLS + FORCE RLS
# ------------------------------------------------------------
def test_cpd_exports_rls_enabled_and_forced() -> None:
    schema = _schema_sql_lower()
    assert "alter table public.cpd_exports enable row level security" in schema
    assert "alter table public.cpd_exports force row level security" in schema


def test_cpd_exports_policy_uses_app_current_clinic_id() -> None:
    schema = _schema_sql_lower()
    assert "create policy rls_cpd_exports_tenant" in schema
    assert "on public.cpd_exports" in schema
    assert "using (clinic_id = app_current_clinic_id())" in schema
    assert "with check (clinic_id = app_current_clinic_id())" in schema


# ------------------------------------------------------------
# RLS helper convention: repo helper, NOT raw current_setting cast
# ------------------------------------------------------------
def test_rls_policies_do_not_use_raw_current_setting() -> None:
    schema = _schema_sql_lower()
    assert "current_setting('app.clinic_id')::uuid" not in schema
    assert "current_setting(\"app.clinic_id\")" not in schema


def test_learning_modules_has_no_rls() -> None:
    # Global catalogue is intentionally NOT clinic-scoped and must not enable RLS.
    schema = _schema_sql_lower()
    assert "alter table public.learning_modules enable row level security" not in schema
    assert "alter table public.learning_modules force row level security" not in schema


# ------------------------------------------------------------
# v_cpd_records excludes voided completions
# ------------------------------------------------------------
def test_v_cpd_records_excludes_voided() -> None:
    schema = _schema_sql_lower()
    assert "create or replace view public.v_cpd_records" in schema
    assert "where is_voided = false" in schema


# ------------------------------------------------------------
# Duplicate completion uniqueness
# ------------------------------------------------------------
def test_learning_completions_unique_constraint() -> None:
    schema = _schema_sql_lower()
    assert "unique (clinic_id, user_id, module_id, module_version)" in schema


# ------------------------------------------------------------
# Metadata-only doctrine: no raw content columns
# ------------------------------------------------------------
def test_learning_modules_uses_content_reference_not_raw_content() -> None:
    schema = _schema_sql_lower()
    assert "content_reference text not null" in schema
    m = re.search(
        r"create table if not exists public\.learning_modules \((.*?)\);",
        schema,
        flags=re.DOTALL,
    )
    assert m, "learning_modules CREATE TABLE block not found"
    body = f" {m.group(1)} "
    for forbidden in (" content ", " body ", " module_content ", " raw_content ", " markdown "):
        assert forbidden not in body, f"learning_modules must not store raw content: {forbidden.strip()}"


def test_module_markdown_stubs_exist() -> None:
    for slug in MODULE_SLUGS:
        path = MODULES_DIR / f"{slug}.md"
        assert path.exists(), f"missing module stub: {path}"
        assert "to be written" in path.read_text(encoding="utf-8").lower()
