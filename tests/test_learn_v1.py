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


# ============================================================
# Slice 2 — behavioural endpoint tests (in-memory fake DB; no live Postgres)
# ============================================================
import hashlib  # noqa: E402

from tests._learn_test_helpers import (  # noqa: E402
    ADMIN_USER,
    CLINIC_A,
    CLINIC_B,
    MOD_BIAS,
    MOD_CONF,
    MOD_ETHICS,
    MOD_INACTIVE,
    MOD_LITERACY,
    OTHER_USER,
    STAFF_USER,
    LearnFakeDB,
    build_learn_app,
    build_trust_app,
    client_for,
)


# ---- modules ----
def test_list_modules_returns_active_only() -> None:
    fake = LearnFakeDB()
    c = client_for(build_learn_app(fake))
    resp = c.get("/v1/learn/modules")
    assert resp.status_code == 200
    ids = {m["module_id"] for m in resp.json()}
    assert MOD_INACTIVE not in ids
    assert MOD_LITERACY in ids
    assert len(resp.json()) == 5


def test_list_modules_filter_by_category() -> None:
    fake = LearnFakeDB()
    c = client_for(build_learn_app(fake))
    resp = c.get("/v1/learn/modules", params={"category": "bias_detection"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["module_id"] == MOD_BIAS


def test_list_modules_filter_by_role_applicability_tag() -> None:
    fake = LearnFakeDB()
    c = client_for(build_learn_app(fake))
    # MOD_ETHICS is tagged only {vet, nurse}; reception must exclude it.
    resp = c.get("/v1/learn/modules", params={"role": "reception"})
    ids = {m["module_id"] for m in resp.json()}
    assert MOD_ETHICS not in ids
    assert MOD_LITERACY in ids
    # vet tag includes the ethics module.
    resp2 = c.get("/v1/learn/modules", params={"role": "vet"})
    assert MOD_ETHICS in {m["module_id"] for m in resp2.json()}


def test_module_detail_returns_full_metadata() -> None:
    fake = LearnFakeDB()
    c = client_for(build_learn_app(fake))
    resp = c.get(f"/v1/learn/modules/{MOD_LITERACY}")
    assert resp.status_code == 200
    m = resp.json()
    for key in (
        "module_id", "module_slug", "version", "title", "summary",
        "learning_objectives", "role_applicability", "cpd_minutes", "category",
        "rcvs_principle_mappings", "eu_ai_act_article_mappings",
        "content_reference", "is_active",
    ):
        assert key in m


# ---- completions ----
def test_record_completion_creates_row() -> None:
    fake = LearnFakeDB()
    c = client_for(build_learn_app(fake))
    resp = c.post("/v1/learn/completions", json={"module_id": MOD_LITERACY})
    assert resp.status_code == 201
    assert resp.json()["module_id"] == MOD_LITERACY
    assert len(fake.completions) == 1


def test_record_completion_snapshots_version_and_minutes() -> None:
    fake = LearnFakeDB()
    c = client_for(build_learn_app(fake))
    resp = c.post("/v1/learn/completions", json={"module_id": MOD_LITERACY})
    body = resp.json()
    assert body["module_version"] == fake.modules[MOD_LITERACY]["version"]
    assert body["cpd_minutes_credited"] == fake.modules[MOD_LITERACY]["cpd_minutes"]


def test_record_completion_duplicate_same_version_rejected() -> None:
    fake = LearnFakeDB()
    c = client_for(build_learn_app(fake))
    assert c.post("/v1/learn/completions", json={"module_id": MOD_LITERACY}).status_code == 201
    dup = c.post("/v1/learn/completions", json={"module_id": MOD_LITERACY})
    assert dup.status_code == 409


def test_record_completion_new_version_allowed() -> None:
    fake = LearnFakeDB()
    c = client_for(build_learn_app(fake))
    assert c.post("/v1/learn/completions", json={"module_id": MOD_LITERACY}).status_code == 201
    fake.modules[MOD_LITERACY]["version"] = "2.0.0"
    again = c.post("/v1/learn/completions", json={"module_id": MOD_LITERACY})
    assert again.status_code == 201
    assert again.json()["module_version"] == "2.0.0"
    assert len(fake.completions) == 2


def test_record_completion_inactive_module_rejected() -> None:
    fake = LearnFakeDB()
    c = client_for(build_learn_app(fake))
    resp = c.post("/v1/learn/completions", json={"module_id": MOD_INACTIVE})
    assert resp.status_code == 400


def test_list_my_completions() -> None:
    fake = LearnFakeDB()
    c = client_for(build_learn_app(fake, user_id=ADMIN_USER))
    c.post("/v1/learn/completions", json={"module_id": MOD_LITERACY})
    resp = c.get("/v1/learn/completions/me")
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["user_id"] == ADMIN_USER


def test_admin_can_view_another_users_completions() -> None:
    fake = LearnFakeDB()
    fake.add_completion(user_id=OTHER_USER, module_id=MOD_LITERACY)
    c = client_for(build_learn_app(fake, role="admin"))
    resp = c.get(f"/v1/learn/completions/users/{OTHER_USER}")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_non_admin_cannot_view_another_users_completions() -> None:
    fake = LearnFakeDB()
    fake.add_completion(user_id=OTHER_USER, module_id=MOD_LITERACY)
    c = client_for(build_learn_app(fake, user_id=STAFF_USER, role="staff"))
    resp = c.get(f"/v1/learn/completions/users/{OTHER_USER}")
    assert resp.status_code == 403


def test_void_completion_requires_reason_and_preserves_row() -> None:
    fake = LearnFakeDB()
    c = client_for(build_learn_app(fake, role="admin"))
    created = c.post("/v1/learn/completions", json={"module_id": MOD_LITERACY}).json()
    cid = created["completion_id"]
    # Missing reason -> validation error.
    assert c.post(f"/v1/learn/completions/{cid}/void", json={}).status_code == 422
    # With reason -> voided, row preserved.
    voided = c.post(
        f"/v1/learn/completions/{cid}/void", json={"void_reason": "entered in error"}
    )
    assert voided.status_code == 200
    assert voided.json()["is_voided"] is True
    assert len(fake.completions) == 1
    assert fake.completions[0]["void_reason"] == "entered in error"


def test_non_admin_cannot_void() -> None:
    fake = LearnFakeDB()
    fake.add_completion(user_id=OTHER_USER, module_id=MOD_LITERACY)
    cid = fake.completions[0]["completion_id"]
    c = client_for(build_learn_app(fake, role="staff"))
    resp = c.post(f"/v1/learn/completions/{cid}/void", json={"void_reason": "nope"})
    assert resp.status_code == 403


# ---- CPD record ----
def test_cpd_record_excludes_voided_and_totals_correct() -> None:
    fake = LearnFakeDB()
    c = client_for(build_learn_app(fake, user_id=ADMIN_USER, role="admin"))
    c.post("/v1/learn/completions", json={"module_id": MOD_LITERACY})  # 30
    c.post("/v1/learn/completions", json={"module_id": MOD_CONF})      # 20
    rec = c.get("/v1/learn/cpd/me").json()
    assert rec["total_modules_completed"] == 2
    assert rec["total_cpd_minutes"] == 50
    # Void one and re-check.
    cid = fake.completions[0]["completion_id"]
    c.post(f"/v1/learn/completions/{cid}/void", json={"void_reason": "duplicate entry"})
    rec2 = c.get("/v1/learn/cpd/me").json()
    assert rec2["total_modules_completed"] == 1
    assert rec2["total_cpd_minutes"] == 20
    assert all(not comp["is_voided"] for comp in rec2["completions"])


def test_admin_cpd_record_for_user() -> None:
    fake = LearnFakeDB()
    fake.add_completion(user_id=OTHER_USER, module_id=MOD_BIAS)  # 25
    c = client_for(build_learn_app(fake, role="admin"))
    rec = c.get(f"/v1/learn/cpd/users/{OTHER_USER}").json()
    assert rec["total_modules_completed"] == 1
    assert rec["total_cpd_minutes"] == 25


# ---- exports ----
def _forbidden_payload_keys(payload: dict) -> None:
    allowed_top = {
        "export_version", "clinic_id", "user_id", "generated_by_user_id",
        "generated_at", "cpd_summary", "completions",
    }
    assert set(payload.keys()) == allowed_top
    allowed_completion = {
        "module_id", "module_version", "completed_at", "cpd_minutes_credited",
        "acknowledgement_provided",
    }
    for comp in payload["completions"]:
        assert set(comp.keys()) == allowed_completion


def test_create_export_metadata_only_payload() -> None:
    fake = LearnFakeDB()
    fake.add_completion(user_id=OTHER_USER, module_id=MOD_LITERACY)
    c = client_for(build_learn_app(fake, role="admin"))
    created = c.post(f"/v1/learn/cpd/users/{OTHER_USER}/exports")
    assert created.status_code == 201
    eid = created.json()["export_id"]
    payload = c.get(f"/v1/learn/cpd/exports/{eid}/payload").json()
    _forbidden_payload_keys(payload)


def test_export_hash_matches_sha256_of_canonical_payload() -> None:
    from app.learn_v1 import _canonical_json

    fake = LearnFakeDB()
    fake.add_completion(user_id=OTHER_USER, module_id=MOD_LITERACY)
    c = client_for(build_learn_app(fake, role="admin"))
    created = c.post(f"/v1/learn/cpd/users/{OTHER_USER}/exports").json()
    payload = c.get(f"/v1/learn/cpd/exports/{created['export_id']}/payload").json()
    recomputed = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
    assert created["export_hash"] == recomputed


def test_export_payload_immutable_after_later_completion() -> None:
    fake = LearnFakeDB()
    fake.add_completion(user_id=OTHER_USER, module_id=MOD_LITERACY)
    c = client_for(build_learn_app(fake, role="admin"))
    created = c.post(f"/v1/learn/cpd/users/{OTHER_USER}/exports").json()
    eid = created["export_id"]
    payload_before = c.get(f"/v1/learn/cpd/exports/{eid}/payload").json()
    # A later completion for the same user must NOT alter the existing export.
    fake.add_completion(user_id=OTHER_USER, module_id=MOD_BIAS)
    payload_after = c.get(f"/v1/learn/cpd/exports/{eid}/payload").json()
    assert payload_before == payload_after
    meta = c.get(f"/v1/learn/cpd/exports/{eid}").json()
    assert meta["export_hash"] == created["export_hash"]


# ---- tenant isolation ----
def test_tenant_isolation_completions() -> None:
    fake = LearnFakeDB()
    fake.add_completion(user_id=ADMIN_USER, module_id=MOD_LITERACY, clinic_id=CLINIC_A)
    # Same user id, different clinic context -> must not see clinic A's row.
    c_b = client_for(build_learn_app(fake, clinic_id=CLINIC_B, user_id=ADMIN_USER))
    assert c_b.get("/v1/learn/completions/me").json() == []
    # Clinic A context sees it.
    c_a = client_for(build_learn_app(fake, clinic_id=CLINIC_A, user_id=ADMIN_USER))
    assert len(c_a.get("/v1/learn/completions/me").json()) == 1


# ---- trust learning-delta ----
def test_trust_learning_delta_aggregate_only(monkeypatch) -> None:
    fake = LearnFakeDB()
    fake.add_completion(user_id=ADMIN_USER, module_id=MOD_LITERACY)  # 30, literacy
    fake.add_completion(user_id=OTHER_USER, module_id=MOD_BIAS)      # 25, bias
    c = client_for(build_trust_app(fake, monkeypatch))
    resp = c.get("/v1/portal/trust/posture/learning-delta")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_staff_with_completions"] == 2
    assert data["total_cpd_minutes_delivered"] == 55
    assert data["module_catalogue_count"] == 5
    assert data["last_completion_at"] is not None
    assert data["role_basis"] == "access_control_role"
    # Aggregate only — keyed on access-control roles, no per-user fields.
    assert set(data["completion_rate_by_role"].keys()) <= {"admin", "staff"}
    assert "user_id" not in data and "completions" not in data


def test_trust_learning_delta_bias_counted_distinctly(monkeypatch) -> None:
    fake = LearnFakeDB()
    fake.add_completion(user_id=ADMIN_USER, module_id=MOD_LITERACY)
    fake.add_completion(user_id=ADMIN_USER, module_id=MOD_BIAS)
    fake.add_completion(user_id=OTHER_USER, module_id=MOD_CONF)
    c = client_for(build_trust_app(fake, monkeypatch))
    data = c.get("/v1/portal/trust/posture/learning-delta").json()
    assert data["bias_detection_completions"] == 1
