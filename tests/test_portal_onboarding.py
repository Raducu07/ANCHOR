"""M5.7 - Assisted Onboarding foundations tests (gated).

Coverage:
  * checklist: done/count semantics per item, informational item
    honest-zero handling, soft-fail on a single unavailable surface
    (200 with available=false, never a 500)
  * checklist: every SQL bind carries the caller's clinic_id
  * invites: admin-only (staff 403), status derivation
    pending/used/expired, token material never present in responses
  * auth: unauthenticated requests return 401
  * doctrine: no forbidden keys (scores, compliance status, policy
    bodies, token hashes) in any response

Uses an in-memory FakeDB interpreting the SQL the router emits.
No live Postgres needed.
"""
from __future__ import annotations

import json
import sys
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import os

os.environ.setdefault("DATABASE_URL", "postgresql://x:y@localhost:5432/z")
os.environ.setdefault("RATE_LIMIT_ENABLED", "0")
os.environ.setdefault("ANCHOR_JWT_SECRET", "test")


CLINIC_A = "11111111-1111-4111-8111-111111111111"
ADMIN_USER = "22222222-2222-4222-8222-222222222222"
STAFF_USER = "44444444-4444-4444-8444-444444444444"

_NOW = datetime(2026, 7, 5, 12, 0, 0, tzinfo=timezone.utc)

FORBIDDEN_RESPONSE_KEYS = {
    "token_hash",
    "invite_token",
    "password_hash",
    "score",
    "pass_fail",
    "compliance_status",
    "competence_grade",
    "staff_certified",
    "policy_body",
    "policy_text",
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

    def all(self) -> List[Dict[str, Any]]:
        return list(self._rows or [])


class OnboardingFakeDB:
    """Interprets the SQL app/portal_onboarding.py emits, keyed by
    table name. `counts` maps table markers to the count returned;
    a table listed in `broken_tables` raises instead (soft-fail path)."""

    def __init__(self) -> None:
        self.counts: Dict[str, int] = {
            "clinic_users": 1,
            "clinic_user_invites": 3,
            "clinic_policy_versions": 1,
            "policy_attestations": 4,
            "learning_completions": 2,
            "clinic_self_assessments": 1,
            "client_transparency_public_versions": 1,
            "assistant_policy_settings": 1,
            "ai_incidents": 0,
        }
        self.broken_tables: set = set()
        self.invite_rows: List[Dict[str, Any]] = []
        self.seen_params: List[Dict[str, Any]] = []

    def execute(self, clause: Any, params: Optional[Dict[str, Any]] = None):
        sql = str(getattr(clause, "text", clause))
        self.seen_params.append(dict(params or {}))

        for marker in self.broken_tables:
            if marker in sql:
                raise RuntimeError(f"simulated failure for {marker}")

        if "SELECT invite_id, email, role" in sql:
            return _Result(rows=self.invite_rows)

        for marker, count in self.counts.items():
            if f"FROM {marker}" in sql:
                return _Result(row={"c": count})
        raise AssertionError(f"unexpected SQL: {sql}")

    def commit(self) -> None:
        pass


def _invite(
    *,
    used_at: Optional[datetime] = None,
    expires_at: Optional[datetime] = None,
    email: str = "vet@example.invalid",
    role: str = "staff",
) -> Dict[str, Any]:
    return {
        "invite_id": _uuid.uuid4(),
        "email": email,
        "role": role,
        "created_at": _NOW - timedelta(days=1),
        "expires_at": expires_at or (_NOW + timedelta(days=6)),
        "used_at": used_at,
        # Deliberately include a token_hash column value: the router
        # must never select or surface it, but if it ever did, the
        # forbidden-key sweep below would catch it.
        "token_hash": "should-never-appear",
    }


def _build_app(
    *,
    authenticated: bool = True,
    role: str = "admin",
) -> tuple:
    from app.auth_and_rls import require_clinic_user
    from app.db import get_db
    from app.portal_onboarding import router

    app = FastAPI()
    app.include_router(router)
    fake = OnboardingFakeDB()

    def _fake_db_dep(request: Request):
        yield fake
        fake.commit()

    app.dependency_overrides[get_db] = _fake_db_dep

    if authenticated:
        user_id = ADMIN_USER if role == "admin" else STAFF_USER

        def _fake_auth(request: Request) -> Dict[str, str]:
            request.state.clinic_id = CLINIC_A
            request.state.clinic_user_id = user_id
            request.state.role = role
            return {
                "clinic_id": CLINIC_A,
                "clinic_user_id": user_id,
                "role": role,
            }

        app.dependency_overrides[require_clinic_user] = _fake_auth

    return app, fake


def _sweep_forbidden(payload: Any) -> None:
    blob = json.dumps(payload)
    for key in FORBIDDEN_RESPONSE_KEYS:
        assert f'"{key}"' not in blob, f"forbidden key {key} in response"
    assert "should-never-appear" not in blob


# ---------------------------------------------------------------------
# Checklist
# ---------------------------------------------------------------------

def test_checklist_happy_path() -> None:
    app, fake = _build_app()
    resp = TestClient(app).get("/v1/portal/onboarding/checklist")
    assert resp.status_code == 200
    body = resp.json()

    items = {i["key"]: i for i in body["items"]}
    assert body["total_count"] == 9
    assert items["ai_use_policy_active"]["done"] is True
    assert items["ai_use_policy_active"]["count"] == 1
    assert items["staff_attestations_recorded"]["count"] == 4
    # Informational item: zero incidents is an honest zero, still done.
    assert items["incident_reporting_ready"]["done"] is True
    assert items["incident_reporting_ready"]["count"] == 0
    assert body["completed_count"] == 9
    assert "governance_note" in body
    _sweep_forbidden(body)


def test_checklist_incomplete_items_report_not_done() -> None:
    app, fake = _build_app()
    fake.counts["clinic_policy_versions"] = 0
    fake.counts["clinic_self_assessments"] = 0
    resp = TestClient(app).get("/v1/portal/onboarding/checklist")
    body = resp.json()
    items = {i["key"]: i for i in body["items"]}
    assert items["ai_use_policy_active"]["done"] is False
    assert items["self_assessment_submitted"]["done"] is False
    assert body["completed_count"] == 7


def test_checklist_soft_fails_single_surface() -> None:
    app, fake = _build_app()
    fake.broken_tables.add("clinic_self_assessments")
    resp = TestClient(app).get("/v1/portal/onboarding/checklist")
    assert resp.status_code == 200
    items = {i["key"]: i for i in resp.json()["items"]}
    broken = items["self_assessment_submitted"]
    assert broken["available"] is False
    assert broken["done"] is False
    assert broken["count"] is None
    # The other items are unaffected.
    assert items["ai_use_policy_active"]["done"] is True


def test_checklist_binds_caller_clinic_id() -> None:
    app, fake = _build_app()
    TestClient(app).get("/v1/portal/onboarding/checklist")
    assert fake.seen_params, "no SQL executed"
    for params in fake.seen_params:
        assert params.get("clinic_id") == CLINIC_A


def test_checklist_requires_auth() -> None:
    app, _ = _build_app(authenticated=False)
    resp = TestClient(app).get("/v1/portal/onboarding/checklist")
    assert resp.status_code == 401


# ---------------------------------------------------------------------
# Invites
# ---------------------------------------------------------------------

def test_invites_admin_only() -> None:
    app, _ = _build_app(role="staff")
    resp = TestClient(app).get("/v1/portal/onboarding/invites")
    assert resp.status_code == 403
    assert resp.json()["detail"] == "forbidden_not_admin"


def test_invites_status_derivation_and_no_token_material() -> None:
    app, fake = _build_app()
    fake.invite_rows = [
        _invite(),  # pending
        _invite(used_at=_NOW - timedelta(hours=2)),  # used
        _invite(expires_at=_NOW - timedelta(days=30)),  # expired
    ]
    resp = TestClient(app).get("/v1/portal/onboarding/invites")
    assert resp.status_code == 200
    body = resp.json()

    statuses = sorted(i["status"] for i in body["invites"])
    assert statuses == ["expired", "pending", "used"]
    assert body["pending_count"] == 1
    assert body["used_count"] == 1
    assert body["expired_count"] == 1
    _sweep_forbidden(body)


def test_invites_requires_auth() -> None:
    app, _ = _build_app(authenticated=False)
    resp = TestClient(app).get("/v1/portal/onboarding/invites")
    assert resp.status_code == 401


# ---------------------------------------------------------------------
# Route mounting
# ---------------------------------------------------------------------

def test_router_mounted_in_main_app() -> None:
    from app.main import app as main_app

    paths = {getattr(r, "path", None) for r in main_app.routes}
    assert "/v1/portal/onboarding/checklist" in paths
    assert "/v1/portal/onboarding/invites" in paths
