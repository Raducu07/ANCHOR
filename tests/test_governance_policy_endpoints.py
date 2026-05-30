"""Phase 2A-2.2 - Governance Policy Library endpoint tests.

Coverage:
  * Templates: list / get-by-slug, include_inactive admin gate, 404 for
    missing slugs and inactive-to-staff, governance_note in envelope.
  * Clinic policies: create (admin only), list (staff visible), list
    active (staff visible), activate (admin only, supersedes prior
    active, idempotent on already-active), archive (admin only,
    rejects active, idempotent on already-archived).
  * Tenant scoping: every SQL bind carries clinic_id; cross-clinic
    UUIDs return 404 (modelled by the FakeDB).
  * Auth: unauthenticated requests return 401.
  * Audit: admin_audit_events insert is metadata-only and contains
    no raw policy body / forbidden field markers; no `ON CONFLICT
    (clinic_id, action, idempotency_key)` regression.
  * Response shape doctrine: no policy_body / policy_text / score /
    compliance_status / competence_grade / staff_certified /
    clinical_safety_proof / legal_approval keys ever appear.

These tests use an in-memory FakeDB that interprets the SQL the
governance_policy router issues. No live Postgres needed.
"""
from __future__ import annotations

import json
import re
import sys
import uuid as _uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


CLINIC_A = "11111111-1111-4111-8111-111111111111"
CLINIC_B = "33333333-3333-4333-8333-333333333333"
ADMIN_USER = "22222222-2222-4222-8222-222222222222"
STAFF_USER = "44444444-4444-4444-8444-444444444444"

# Deterministic template ids.
TPL_AI_USE = "aaaaaaaa-0000-4000-8000-000000000001"
TPL_DISCLOSURE = "aaaaaaaa-0000-4000-8000-000000000002"
TPL_RETIRED = "aaaaaaaa-0000-4000-8000-000000000099"

ALL_AUDIENCE = ["vet", "nurse", "practice_manager", "admin", "reception", "locum"]


# Doctrine markers that must NEVER appear as keys/fields in any
# response or in the audit `meta` JSON.
FORBIDDEN_RESPONSE_KEYS = {
    "policy_body",
    "policy_text",
    "policy_content",
    "score",
    "pass_fail",
    "compliance_status",
    "competence_grade",
    "staff_certified",
    "clinical_safety_proof",
    "legal_approval",
    "reflection",
    "transcript",
}


def _template(
    template_id: str,
    slug: str,
    title: str,
    category: str,
    *,
    is_active: bool = True,
    template_version: str = "1.0.0",
    role_applicability: Optional[List[str]] = None,
) -> Dict[str, Any]:
    now = datetime(2026, 5, 30, 10, 0, 0, tzinfo=timezone.utc)
    return {
        "template_id": _uuid.UUID(template_id),
        "template_slug": slug,
        "template_version": template_version,
        "title": title,
        "summary": f"Summary for {title}.",
        "category": category,
        "role_applicability": list(role_applicability or ALL_AUDIENCE),
        "jurisdiction_tags": ["UK_RCVS", "EU_AI_ACT_READINESS"],
        "source_basis": ["RCVS_AI_literacy"],
        "content_reference": f"docs/governance/policies/{slug}-1.0.0.md",
        "content_sha256": None,
        "is_active": is_active,
        "superseded_by": None,
        "created_at": now,
        "updated_at": now,
    }


class _Result:
    def __init__(
        self,
        row: Optional[Dict[str, Any]] = None,
        rows: Optional[List[Dict[str, Any]]] = None,
    ):
        self._row = row
        self._rows = rows

    def mappings(self) -> "_Result":
        return self

    def first(self) -> Optional[Dict[str, Any]]:
        return self._row

    def fetchone(self) -> Optional[Dict[str, Any]]:
        return self._row

    def all(self) -> List[Dict[str, Any]]:
        return list(self._rows or [])


class GovernanceFakeDB:
    """In-memory fake that interprets the SQL governance_policy emits.

    Carries a `current_clinic` set per-request from the auth override
    so cross-clinic cases (CLINIC_A user trying to fetch a CLINIC_B row)
    behave like FORCE RLS in production: not found.
    """

    def __init__(self) -> None:
        self.current_clinic: str = CLINIC_A
        self.templates: Dict[str, Dict[str, Any]] = {
            TPL_AI_USE: _template(
                TPL_AI_USE, "ai_use_policy",
                "AI Use Policy for Veterinary Teams", "ai_use_policy",
            ),
            TPL_DISCLOSURE: _template(
                TPL_DISCLOSURE, "client_disclosure_when_ai_assists",
                "Client Disclosure When AI Assists", "transparency",
            ),
            TPL_RETIRED: _template(
                TPL_RETIRED, "retired_policy",
                "Retired Policy Template", "ai_use_policy",
                is_active=False,
            ),
        }
        self.clinic_policy_versions: List[Dict[str, Any]] = []
        self.audit_events: List[Dict[str, Any]] = []
        self.committed = False
        self.rolled_back = False
        self.calls: List[tuple] = []

    # -- session shape --
    def begin(self) -> None:
        return None

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        return None

    # -- helpers --
    def _by_slug(
        self, slug: str, version: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        for t in self.templates.values():
            if t["template_slug"] != slug:
                continue
            if version is not None and t["template_version"] != version:
                continue
            return t
        return None

    def _scoped_cpvs(self) -> List[Dict[str, Any]]:
        return [c for c in self.clinic_policy_versions
                if c["clinic_id"] == self.current_clinic]

    # -- main interpreter --
    def execute(self, statement: Any, params: Optional[Dict[str, Any]] = None) -> _Result:
        sql = str(getattr(statement, "text", statement))
        p = dict(params or {})
        self.calls.append((sql, p))

        # ---- policy_templates: list ----
        if "FROM policy_templates" in sql and "ORDER BY title" in sql:
            rows = list(self.templates.values())
            if "is_active = true" in sql:
                rows = [t for t in rows if t["is_active"]]
            if "category = :category" in sql and "category" in p:
                rows = [t for t in rows if t["category"] == p["category"]]
            rows = sorted(rows, key=lambda t: t["title"])
            return _Result(rows=rows)

        # ---- policy_templates: by slug (get/create-fetch) ----
        if "FROM policy_templates" in sql and "template_slug = :template_slug" in sql:
            version = p.get("template_version")
            return _Result(row=self._by_slug(p["template_slug"], version))

        # ---- MAX(clinic_policy_version) for create ----
        if "MAX(clinic_policy_version)" in sql and "clinic_policy_versions" in sql:
            vs = [
                int(c["clinic_policy_version"]) for c in self._scoped_cpvs()
                if str(c["policy_template_id"]) == p["policy_template_id"]
            ]
            return _Result(row={"v": max(vs) if vs else 0})

        # ---- clinic_policy_versions: INSERT ----
        if "INSERT INTO clinic_policy_versions" in sql:
            now = datetime.now(timezone.utc)
            row = {
                "clinic_policy_version_id": _uuid.uuid4(),
                "clinic_id": p["clinic_id"],
                "policy_template_id": _uuid.UUID(p["policy_template_id"]),
                "template_version_snapshot": p["template_version_snapshot"],
                "clinic_policy_version": int(p["clinic_policy_version"]),
                "status": "draft",
                "title_snapshot": p["title_snapshot"],
                "summary_snapshot": p["summary_snapshot"],
                "content_sha256_snapshot": p.get("content_sha256_snapshot"),
                "effective_from": None,
                "created_by_user_id": _uuid.UUID(p["created_by_user_id"]),
                "activated_by_user_id": None,
                "activated_at": None,
                "superseded_at": None,
                "created_at": now,
                "updated_at": now,
            }
            self.clinic_policy_versions.append(row)
            return _Result(row=row)

        # ---- clinic_policy_versions: SELECT one by id ----
        if (
            "FROM clinic_policy_versions" in sql
            and "clinic_policy_version_id = CAST(:cpv_id AS uuid)" in sql
            and "UPDATE" not in sql
        ):
            for c in self._scoped_cpvs():
                if str(c["clinic_policy_version_id"]) == p["cpv_id"]:
                    return _Result(row=c)
            return _Result(row=None)

        # ---- supersede prior active (UPDATE no RETURNING) ----
        if "UPDATE clinic_policy_versions" in sql and "status = 'superseded'" in sql:
            for c in self._scoped_cpvs():
                if (
                    str(c["policy_template_id"]) == p["policy_template_id"]
                    and c["status"] == "active"
                ):
                    c["status"] = "superseded"
                    c["superseded_at"] = datetime.now(timezone.utc)
                    c["updated_at"] = datetime.now(timezone.utc)
            return _Result(row=None)

        # ---- activate target draft (UPDATE RETURNING) ----
        if (
            "UPDATE clinic_policy_versions" in sql
            and "status = 'active'" in sql
            and "RETURNING" in sql
        ):
            for c in self._scoped_cpvs():
                if (
                    str(c["clinic_policy_version_id"]) == p["cpv_id"]
                    and c["status"] == "draft"
                ):
                    now = datetime.now(timezone.utc)
                    c["status"] = "active"
                    c["activated_by_user_id"] = _uuid.UUID(p["actor"])
                    c["activated_at"] = now
                    if c["effective_from"] is None:
                        c["effective_from"] = now
                    c["updated_at"] = now
                    return _Result(row=c)
            return _Result(row=None)

        # ---- archive (UPDATE RETURNING) ----
        if (
            "UPDATE clinic_policy_versions" in sql
            and "status = 'archived'" in sql
            and "RETURNING" in sql
        ):
            for c in self._scoped_cpvs():
                if (
                    str(c["clinic_policy_version_id"]) == p["cpv_id"]
                    and c["status"] in ("draft", "superseded")
                ):
                    c["status"] = "archived"
                    c["updated_at"] = datetime.now(timezone.utc)
                    return _Result(row=c)
            return _Result(row=None)

        # ---- clinic_policy_versions: list-active (no JOIN) ----
        if (
            "FROM clinic_policy_versions" in sql
            and "status = 'active'" in sql
            and "ORDER BY activated_at DESC" in sql
            and "UPDATE" not in sql
        ):
            rows = [c for c in self._scoped_cpvs() if c["status"] == "active"]
            rows = sorted(
                rows,
                key=lambda c: c["activated_at"] or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True,
            )
            return _Result(rows=rows)

        # ---- clinic_policy_versions: list with optional filters (LEFT JOIN) ----
        if (
            "FROM clinic_policy_versions cpv" in sql
            and "ORDER BY cpv.created_at DESC" in sql
        ):
            rows = list(self._scoped_cpvs())
            if "cpv.status = :status" in sql and "status" in p:
                rows = [c for c in rows if c["status"] == p["status"]]
            if "pt.template_slug = :template_slug" in sql and "template_slug" in p:
                tpl = self._by_slug(p["template_slug"])
                if tpl is None:
                    rows = []
                else:
                    rows = [
                        c for c in rows
                        if str(c["policy_template_id"]) == str(tpl["template_id"])
                    ]
            rows = sorted(rows, key=lambda c: c["created_at"], reverse=True)
            rows = rows[: int(p.get("limit", 25))]
            return _Result(rows=rows)

        # ---- admin_audit_events: INSERT ----
        if "INSERT INTO admin_audit_events" in sql:
            meta = p["meta"]
            if isinstance(meta, str):
                meta = json.loads(meta)
            self.audit_events.append({
                "clinic_id": p["clinic_id"],
                "admin_user_id": p["admin_user_id"],
                "action": p["action"],
                "target_id": p["target_id"],
                "ip_hash": p.get("ip_hash"),
                "meta": meta,
                "created_at": datetime.now(timezone.utc),
            })
            return _Result(row=None)

        return _Result(row=None)


def build_app(
    *,
    authenticated: bool = True,
    clinic_id: str = CLINIC_A,
    user_id: str = ADMIN_USER,
    role: str = "admin",
) -> tuple:
    from app.auth_and_rls import require_clinic_user
    from app.db import get_db
    from app.governance_policy import router

    app = FastAPI()
    app.include_router(router)
    fake = GovernanceFakeDB()

    def _fake_db_dep(request: Request):
        fake.current_clinic = getattr(request.state, "clinic_id", clinic_id)
        yield fake
        fake.commit()

    app.dependency_overrides[get_db] = _fake_db_dep

    if authenticated:
        def _fake_auth(request: Request) -> Dict[str, str]:
            request.state.clinic_id = clinic_id
            request.state.clinic_user_id = user_id
            request.state.role = role
            request.state.ip_hash = "test_ip_hash"
            return {
                "clinic_id": clinic_id,
                "clinic_user_id": user_id,
                "role": role,
            }
        app.dependency_overrides[require_clinic_user] = _fake_auth

    return app, fake


def auth_headers() -> Dict[str, str]:
    return {"Authorization": "Bearer test-token"}


def client_for(app: FastAPI) -> TestClient:
    return TestClient(app)


def _assert_no_forbidden_keys(payload: Any, *, where: str = "response") -> None:
    """Recursively walk a JSON-like structure asserting no doctrine-
    forbidden keys appear (defends against future field-bleed)."""
    if isinstance(payload, dict):
        leaked = set(payload.keys()) & FORBIDDEN_RESPONSE_KEYS
        assert not leaked, f"forbidden keys leaked in {where}: {leaked}"
        for k, v in payload.items():
            _assert_no_forbidden_keys(v, where=f"{where}.{k}")
    elif isinstance(payload, list):
        for i, v in enumerate(payload):
            _assert_no_forbidden_keys(v, where=f"{where}[{i}]")


# ---------------------------------------------------------------------
# 1-2. Templates
# ---------------------------------------------------------------------


def test_list_templates_returns_active_templates_to_staff() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).get(
        "/v1/governance/policy/templates", headers=auth_headers()
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    slugs = {t["template_slug"] for t in body["templates"]}
    assert "ai_use_policy" in slugs
    assert "client_disclosure_when_ai_assists" in slugs
    # Inactive templates excluded by default.
    assert "retired_policy" not in slugs
    assert "governance_note" in body
    _assert_no_forbidden_keys(body)


def test_list_templates_filter_by_category() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).get(
        "/v1/governance/policy/templates?category=transparency",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert all(t["category"] == "transparency" for t in body["templates"])


def test_list_templates_include_inactive_requires_admin() -> None:
    # Staff cannot see retired templates.
    app, fake = build_app(role="staff")
    resp = client_for(app).get(
        "/v1/governance/policy/templates?include_inactive=true",
        headers=auth_headers(),
    )
    assert resp.status_code == 403
    assert resp.json().get("detail") == "forbidden_not_admin"

    # Admin can.
    app, fake = build_app(role="admin")
    resp = client_for(app).get(
        "/v1/governance/policy/templates?include_inactive=true",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    slugs = {t["template_slug"] for t in resp.json()["templates"]}
    assert "retired_policy" in slugs


def test_get_template_by_slug_success() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).get(
        "/v1/governance/policy/templates/ai_use_policy",
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["template_slug"] == "ai_use_policy"
    assert body["template_version"] == "1.0.0"
    _assert_no_forbidden_keys(body)


def test_get_template_missing_returns_404() -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).get(
        "/v1/governance/policy/templates/no_such_template",
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "governance_policy_template_not_found"


def test_get_inactive_template_hidden_from_staff() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).get(
        "/v1/governance/policy/templates/retired_policy",
        headers=auth_headers(),
    )
    # 404 deliberately - same envelope as "not found" so the inactive
    # set isn't enumerable by staff.
    assert resp.status_code == 404
    assert resp.json().get("detail") == "governance_policy_template_not_found"


def test_get_inactive_template_visible_to_admin() -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).get(
        "/v1/governance/policy/templates/retired_policy",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["template_slug"] == "retired_policy"


# ---------------------------------------------------------------------
# 3. Create clinic policy
# ---------------------------------------------------------------------


@pytest.mark.parametrize("role", ["admin", "owner", "practice_manager"])
def test_admin_tier_can_create_clinic_policy(role: str) -> None:
    app, fake = build_app(role=role)
    resp = client_for(app).post(
        "/v1/governance/policy/clinic-policies",
        json={"template_slug": "ai_use_policy"},
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    p = body["policy"]
    assert p["status"] == "draft"
    assert p["clinic_policy_version"] == 1
    assert p["template_version_snapshot"] == "1.0.0"
    assert p["title_snapshot"] == "AI Use Policy for Veterinary Teams"
    _assert_no_forbidden_keys(body)


@pytest.mark.parametrize("role", ["staff", "clinic_user", "reader"])
def test_non_admin_cannot_create_clinic_policy(role: str) -> None:
    app, fake = build_app(role=role)
    resp = client_for(app).post(
        "/v1/governance/policy/clinic-policies",
        json={"template_slug": "ai_use_policy"},
        headers=auth_headers(),
    )
    assert resp.status_code == 403
    assert resp.json().get("detail") == "forbidden_not_admin"
    assert fake.clinic_policy_versions == []


def test_create_rejects_unknown_template_slug() -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).post(
        "/v1/governance/policy/clinic-policies",
        json={"template_slug": "no_such_template"},
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "governance_policy_template_not_found"


def test_create_rejects_inactive_template() -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).post(
        "/v1/governance/policy/clinic-policies",
        json={"template_slug": "retired_policy"},
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "governance_policy_template_inactive"


def test_create_rejects_unknown_fields_via_extra_forbid() -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).post(
        "/v1/governance/policy/clinic-policies",
        json={
            "template_slug": "ai_use_policy",
            "policy_body": "anything",
            "compliance_status": "ok",
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 422
    assert fake.clinic_policy_versions == []


def test_create_increments_clinic_policy_version_per_template() -> None:
    app, fake = build_app(role="admin")
    for expected_v in (1, 2, 3):
        resp = client_for(app).post(
            "/v1/governance/policy/clinic-policies",
            json={"template_slug": "ai_use_policy"},
            headers=auth_headers(),
        )
        assert resp.status_code == 201
        assert resp.json()["policy"]["clinic_policy_version"] == expected_v


def test_create_writes_metadata_only_audit_event() -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).post(
        "/v1/governance/policy/clinic-policies",
        json={"template_slug": "ai_use_policy"},
        headers=auth_headers(),
    )
    assert resp.status_code == 201
    assert len(fake.audit_events) == 1
    ev = fake.audit_events[0]
    assert ev["action"] == "governance_policy_created"
    assert ev["clinic_id"] == CLINIC_A
    assert ev["admin_user_id"] == ADMIN_USER
    # Metadata-only: only safe keys.
    assert set(ev["meta"].keys()) == {
        "template_slug", "template_version_snapshot",
        "clinic_policy_version", "status",
    }
    _assert_no_forbidden_keys(ev["meta"], where="audit.meta")


# ---------------------------------------------------------------------
# 4. List clinic policies
# ---------------------------------------------------------------------


def _seed_drafts(fake: GovernanceFakeDB, n: int = 3) -> List[Dict[str, Any]]:
    out = []
    for _ in range(n):
        now = datetime.now(timezone.utc)
        row = {
            "clinic_policy_version_id": _uuid.uuid4(),
            "clinic_id": CLINIC_A,
            "policy_template_id": _uuid.UUID(TPL_AI_USE),
            "template_version_snapshot": "1.0.0",
            "clinic_policy_version": len(fake.clinic_policy_versions) + 1,
            "status": "draft",
            "title_snapshot": "AI Use Policy for Veterinary Teams",
            "summary_snapshot": "Summary.",
            "content_sha256_snapshot": None,
            "effective_from": None,
            "created_by_user_id": _uuid.UUID(ADMIN_USER),
            "activated_by_user_id": None,
            "activated_at": None,
            "superseded_at": None,
            "created_at": now,
            "updated_at": now,
        }
        fake.clinic_policy_versions.append(row)
        out.append(row)
    return out


@pytest.mark.parametrize("role", ["staff", "clinic_user", "reader", "admin"])
def test_list_clinic_policies_visible_to_all_roles(role: str) -> None:
    app, fake = build_app(role=role)
    _seed_drafts(fake, n=2)
    resp = client_for(app).get(
        "/v1/governance/policy/clinic-policies", headers=auth_headers()
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["policies"]) == 2
    _assert_no_forbidden_keys(body)


def test_list_clinic_policies_status_filter() -> None:
    app, fake = build_app(role="admin")
    rows = _seed_drafts(fake, n=2)
    rows[0]["status"] = "active"
    resp = client_for(app).get(
        "/v1/governance/policy/clinic-policies?status=active",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["policies"]) == 1
    assert body["policies"][0]["status"] == "active"


def test_list_clinic_policies_invalid_status_400() -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).get(
        "/v1/governance/policy/clinic-policies?status=bogus",
        headers=auth_headers(),
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------
# 5. List active clinic policies
# ---------------------------------------------------------------------


@pytest.mark.parametrize("role", ["staff", "clinic_user", "reader", "admin"])
def test_list_active_policies_visible_to_all_roles(role: str) -> None:
    app, fake = build_app(role=role)
    rows = _seed_drafts(fake, n=2)
    rows[0]["status"] = "active"
    rows[0]["activated_at"] = datetime.now(timezone.utc)
    resp = client_for(app).get(
        "/v1/governance/policy/clinic-policies/active",
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["policies"]) == 1
    assert body["policies"][0]["status"] == "active"


# ---------------------------------------------------------------------
# 6. Activate
# ---------------------------------------------------------------------


def test_admin_can_activate_draft_policy() -> None:
    app, fake = build_app(role="admin")
    draft = _seed_drafts(fake, n=1)[0]
    cpv_id = str(draft["clinic_policy_version_id"])
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv_id}/activate",
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["policy"]["status"] == "active"
    assert resp.json()["policy"]["activated_by_user_id"] == ADMIN_USER


def test_activate_supersedes_previous_active_for_same_template() -> None:
    app, fake = build_app(role="admin")
    drafts = _seed_drafts(fake, n=2)
    # First, activate draft #0.
    cpv0 = str(drafts[0]["clinic_policy_version_id"])
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv0}/activate",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    # Now activate draft #1 - draft #0 should be superseded.
    cpv1 = str(drafts[1]["clinic_policy_version_id"])
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv1}/activate",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    statuses = {str(c["clinic_policy_version_id"]): c["status"]
                for c in fake.clinic_policy_versions}
    assert statuses[cpv0] == "superseded"
    assert statuses[cpv1] == "active"


def test_activate_already_active_is_idempotent() -> None:
    app, fake = build_app(role="admin")
    draft = _seed_drafts(fake, n=1)[0]
    cpv_id = str(draft["clinic_policy_version_id"])
    # Activate once.
    client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv_id}/activate",
        headers=auth_headers(),
    )
    # Activate again - should be 200, no extra audit row beyond the first.
    audit_count_before = len(fake.audit_events)
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv_id}/activate",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["policy"]["status"] == "active"
    assert len(fake.audit_events) == audit_count_before, (
        "idempotent re-activate must NOT write a duplicate audit event"
    )


def test_activate_writes_metadata_only_audit_event() -> None:
    app, fake = build_app(role="admin")
    draft = _seed_drafts(fake, n=1)[0]
    cpv_id = str(draft["clinic_policy_version_id"])
    client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv_id}/activate",
        headers=auth_headers(),
    )
    activated = [e for e in fake.audit_events
                 if e["action"] == "governance_policy_activated"]
    assert len(activated) == 1
    ev = activated[0]
    assert set(ev["meta"].keys()) == {
        "policy_template_id",
        "clinic_policy_version",
        "template_version_snapshot",
        "status",
        "previous_status",
    }
    _assert_no_forbidden_keys(ev["meta"], where="audit.meta")


def test_staff_cannot_activate_policy() -> None:
    app, fake = build_app(role="staff")
    draft = _seed_drafts(fake, n=1)[0]
    cpv_id = str(draft["clinic_policy_version_id"])
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv_id}/activate",
        headers=auth_headers(),
    )
    assert resp.status_code == 403
    assert resp.json().get("detail") == "forbidden_not_admin"


def test_activate_unknown_id_returns_404() -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{_uuid.uuid4()}/activate",
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "governance_policy_version_not_found"


def test_activate_cross_clinic_returns_404() -> None:
    app, fake = build_app(role="admin", clinic_id=CLINIC_A)
    # Plant a row that belongs to CLINIC_B - CLINIC_A admin must not see it.
    other = _seed_drafts(fake, n=1)[0]
    other["clinic_id"] = CLINIC_B
    cpv_id = str(other["clinic_policy_version_id"])
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv_id}/activate",
        headers=auth_headers(),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------
# 7. Archive
# ---------------------------------------------------------------------


def test_admin_can_archive_draft_policy() -> None:
    app, fake = build_app(role="admin")
    draft = _seed_drafts(fake, n=1)[0]
    cpv_id = str(draft["clinic_policy_version_id"])
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv_id}/archive",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["policy"]["status"] == "archived"


def test_admin_can_archive_superseded_policy() -> None:
    app, fake = build_app(role="admin")
    draft = _seed_drafts(fake, n=1)[0]
    draft["status"] = "superseded"
    cpv_id = str(draft["clinic_policy_version_id"])
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv_id}/archive",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["policy"]["status"] == "archived"


def test_archive_rejects_active_policy() -> None:
    app, fake = build_app(role="admin")
    draft = _seed_drafts(fake, n=1)[0]
    draft["status"] = "active"
    draft["activated_at"] = datetime.now(timezone.utc)
    cpv_id = str(draft["clinic_policy_version_id"])
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv_id}/archive",
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "governance_policy_active_archive_not_allowed"


def test_archive_already_archived_is_idempotent() -> None:
    app, fake = build_app(role="admin")
    draft = _seed_drafts(fake, n=1)[0]
    draft["status"] = "archived"
    cpv_id = str(draft["clinic_policy_version_id"])
    audit_count_before = len(fake.audit_events)
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv_id}/archive",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["policy"]["status"] == "archived"
    assert len(fake.audit_events) == audit_count_before


def test_archive_writes_metadata_only_audit_event() -> None:
    app, fake = build_app(role="admin")
    draft = _seed_drafts(fake, n=1)[0]
    cpv_id = str(draft["clinic_policy_version_id"])
    client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv_id}/archive",
        headers=auth_headers(),
    )
    archived = [e for e in fake.audit_events
                if e["action"] == "governance_policy_archived"]
    assert len(archived) == 1
    ev = archived[0]
    assert set(ev["meta"].keys()) == {
        "policy_template_id",
        "clinic_policy_version",
        "previous_status",
        "status",
    }
    _assert_no_forbidden_keys(ev["meta"], where="audit.meta")


def test_staff_cannot_archive() -> None:
    app, fake = build_app(role="staff")
    draft = _seed_drafts(fake, n=1)[0]
    cpv_id = str(draft["clinic_policy_version_id"])
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv_id}/archive",
        headers=auth_headers(),
    )
    assert resp.status_code == 403


def test_archive_unknown_id_returns_404() -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{_uuid.uuid4()}/archive",
        headers=auth_headers(),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------
# 8. Tenant scoping / cross-clinic / unauth
# ---------------------------------------------------------------------


def test_clinic_scoped_sql_always_binds_clinic_id() -> None:
    app, fake = build_app(role="admin")
    _seed_drafts(fake, n=1)
    # Touch a few endpoints.
    client_for(app).get(
        "/v1/governance/policy/clinic-policies", headers=auth_headers()
    )
    client_for(app).get(
        "/v1/governance/policy/clinic-policies/active", headers=auth_headers()
    )
    client_for(app).post(
        "/v1/governance/policy/clinic-policies",
        json={"template_slug": "ai_use_policy"},
        headers=auth_headers(),
    )
    # Every SQL statement that touches clinic_policy_versions must
    # carry :clinic_id bound to the caller's clinic.
    for sql, params in fake.calls:
        if "clinic_policy_versions" in sql:
            assert params.get("clinic_id") == CLINIC_A, (sql, params)


def test_unauthenticated_request_returns_401() -> None:
    app, fake = build_app(authenticated=False)
    resp = TestClient(app).get("/v1/governance/policy/templates")
    assert resp.status_code == 401


# ---------------------------------------------------------------------
# 9. Regression / doctrine guards
# ---------------------------------------------------------------------


def test_no_invalid_partial_index_on_conflict_in_governance_module() -> None:
    """M6.10.1B / TD-BE regression: the broken admin_audit_events
    partial-index conflict target must never appear in this module."""
    import inspect
    from app import governance_policy
    src = inspect.getsource(governance_policy)
    assert "ON CONFLICT (clinic_id, action, idempotency_key)" not in src


def test_module_does_not_import_assistant_runtime_policy() -> None:
    """Conflation guard: the governance module must not silently couple
    itself to the Assistant runtime policy module. They are deliberately
    separate surfaces."""
    import inspect
    from app import governance_policy
    src = inspect.getsource(governance_policy)
    assert "from app.assistant_policy" not in src
    assert "import assistant_policy" not in src


def test_all_response_envelopes_metadata_only() -> None:
    """Light sweep across the main responses to confirm no forbidden
    field name appears in any response body."""
    app, fake = build_app(role="admin")
    draft = _seed_drafts(fake, n=1)[0]
    cpv_id = str(draft["clinic_policy_version_id"])

    for url in (
        "/v1/governance/policy/templates",
        "/v1/governance/policy/templates/ai_use_policy",
        "/v1/governance/policy/clinic-policies",
        "/v1/governance/policy/clinic-policies/active",
    ):
        resp = client_for(app).get(url, headers=auth_headers())
        assert resp.status_code == 200, (url, resp.text)
        _assert_no_forbidden_keys(resp.json(), where=url)

    # Activate then assert response.
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv_id}/activate",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    _assert_no_forbidden_keys(resp.json(), where="activate")
