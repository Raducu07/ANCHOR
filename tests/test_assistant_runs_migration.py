from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

MIGRATION_PATH = (
    REPO_ROOT / "migrations" / "20260515_01_assistant_runs.sql"
)


def _migration_sql() -> str:
    assert MIGRATION_PATH.exists(), f"missing migration: {MIGRATION_PATH}"
    return MIGRATION_PATH.read_text(encoding="utf-8")


def _normalize(sql: str) -> str:
    # Collapse whitespace to make matching robust against formatting.
    return re.sub(r"\s+", " ", sql).strip()


def test_assistant_runs_no_raw_content_columns() -> None:
    sql = _normalize(_migration_sql()).lower()

    # Find the CREATE TABLE assistant_runs ( ... ) block and inspect only its body.
    m = re.search(
        r"create table if not exists public\.assistant_runs \((.*?)\);",
        sql,
        flags=re.DOTALL,
    )
    assert m, "assistant_runs CREATE TABLE block not found"
    body = m.group(1)

    forbidden_columns = [
        " input ",
        " raw_input ",
        " input_text ",
        " output ",
        " raw_output ",
        " output_text ",
        " prompt ",
        " prompt_text ",
        " response_text ",
        " content ",
        " clinical_content ",
        " patient_data ",
    ]
    for col in forbidden_columns:
        assert col not in f" {body} ", (
            f"assistant_runs must not declare a raw-content column: {col.strip()}"
        )


def test_assistant_runs_has_clinic_id_fk() -> None:
    sql = _normalize(_migration_sql()).lower()

    # clinic_id FK -> public.clinics(clinic_id) ON DELETE RESTRICT
    assert "clinic_id uuid not null" in sql
    assert "references public.clinics(clinic_id) on delete restrict" in sql

    # clinic_user_id FK -> public.clinic_users(user_id) ON DELETE RESTRICT
    assert "clinic_user_id uuid not null" in sql
    assert "references public.clinic_users(user_id) on delete restrict" in sql


def test_assistant_runs_rls_enabled() -> None:
    sql = _normalize(_migration_sql()).lower()
    assert "alter table public.assistant_runs enable row level security" in sql


def test_assistant_runs_force_rls() -> None:
    sql = _normalize(_migration_sql()).lower()
    assert "alter table public.assistant_runs force row level security" in sql


def test_assistant_runs_clinic_isolation() -> None:
    sql = _normalize(_migration_sql()).lower()

    # Tenant policy must exist and reference app_current_clinic_id().
    assert "create policy rls_assistant_runs_tenant" in sql
    assert "on public.assistant_runs" in sql
    assert "using (clinic_id = app_current_clinic_id())" in sql
    assert "with check (clinic_id = app_current_clinic_id())" in sql


def test_assistant_runs_required_metadata_columns_present() -> None:
    sql = _normalize(_migration_sql()).lower()

    required = [
        "id uuid primary key",
        "mode text not null",
        "contract_version text not null",
        "workflow_origin text not null default 'anchor_assistant'",
        "input_sha256 text not null",
        "output_sha256 text null",
        "input_field_keys jsonb not null default '[]'::jsonb",
        "pii_detected boolean not null default false",
        "pii_types jsonb not null default '[]'::jsonb",
        "safety_flags jsonb not null default '[]'::jsonb",
        "refusal_reason_codes jsonb not null default '[]'::jsonb",
        "review_status text not null default 'not_reviewed'",
        "receipt_id uuid null",
        "governance_event_id uuid null",
        "model_provider text null",
        "model_name text null",
        "created_at timestamptz not null default now()",
        "updated_at timestamptz not null default now()",
    ]
    for fragment in required:
        assert fragment in sql, f"assistant_runs missing column declaration: {fragment}"
