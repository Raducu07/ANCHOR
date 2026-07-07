"""M4.6 - Learn Maturity endpoint tests (non-certifying).

Coverage:
  * self-check list never exposes correct answers or explanations
  * attempt marking: counts, per-question feedback, aggregate-only
    insert (no per-question answers persisted)
  * attempt validation: incomplete set, duplicate answers, bad option
    index, unknown module
  * role paths: per-user progress computation
  * renewals: current / due_soon / overdue derivation, clinic policy
    months honoured, default 12 when unset
  * leadership overview + renewal policy PUT are admin-only
  * every response carries the non-certifying self_check_note and no
    forbidden competence/certification keys

Uses an in-memory FakeDB interpreting the SQL the router emits.
No live Postgres needed.
"""
from __future__ import annotations

import json
import os
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

os.environ.setdefault("DATABASE_URL", "postgresql://x:y@localhost:5432/z")
os.environ.setdefault("RATE_LIMIT_ENABLED", "0")
os.environ.setdefault("ANCHOR_JWT_SECRET", "test")

CLINIC_A = "11111111-1111-4111-8111-111111111111"
ADMIN_USER = "22222222-2222-4222-8222-222222222222"
STAFF_USER = "44444444-4444-4444-8444-444444444444"

MODULE_ID = "aaaaaaaa-1111-4111-8111-000000000001"
CHECK_1 = "bbbbbbbb-1111-4111-8111-000000000001"
CHECK_2 = "bbbbbbbb-1111-4111-8111-000000000002"

_NOW = datetime.now(timezone.utc)

FORBIDDEN_KEYS = {
    "score",
    "pass_fail",
    "passed",
    "grade",
    "certificate",
    "certified",
    "competence_grade",
    "staff_certified",
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


class LearnMaturityFakeDB:
    def __init__(self) -> None:
        self.module_row: Optional[Dict[str, Any]] = {
            "version": "1.0.0",
            "is_active": True,
        }
        self.check_rows: List[Dict[str, Any]] = [
            {
                "check_id": _uuid.UUID(CHECK_1),
                "check_slug": "check-one-v1",
                "kind": "knowledge_check",
                "prompt": "Prompt one?",
                "options": ["a", "b", "c"],
                "correct_option_index": 1,
                "explanation": "Because review is required.",
                "display_order": 1,
            },
            {
                "check_id": _uuid.UUID(CHECK_2),
                "check_slug": "check-two-v1",
                "kind": "scenario",
                "prompt": "Prompt two?",
                "options": ["a", "b"],
                "correct_option_index": 0,
                "explanation": "Because policy applies.",
                "display_order": 2,
            },
        ]
        self.renewal_policy_row: Optional[Dict[str, Any]] = None
        self.path_rows: List[Dict[str, Any]] = []
        self.completed_slug_rows: List[Dict[str, Any]] = []
        self.my_renewal_rows: List[Dict[str, Any]] = []
        self.overview_rows: List[Dict[str, Any]] = []
        self.attempt_inserts: List[Dict[str, Any]] = []
        self.policy_upserts: List[Dict[str, Any]] = []
        self.audit_inserts: List[Dict[str, Any]] = []

    def execute(self, clause: Any, params: Optional[Dict[str, Any]] = None):
        sql = str(getattr(clause, "text", clause))
        p = dict(params or {})

        if "INSERT INTO admin_audit_events" in sql:
            self.audit_inserts.append(p)
            return _Result()
        if "SELECT version, is_active FROM learning_modules" in sql:
            return _Result(row=self.module_row)
        if "correct_option_index, explanation" in sql:
            return _Result(
                rows=[
                    {
                        "check_id": r["check_id"],
                        "options": r["options"],
                        "correct_option_index": r["correct_option_index"],
                        "explanation": r["explanation"],
                    }
                    for r in self.check_rows
                ]
            )
        if "SELECT check_id, check_slug, kind, prompt, options" in sql:
            return _Result(
                rows=[
                    {
                        k: r[k]
                        for k in (
                            "check_id",
                            "check_slug",
                            "kind",
                            "prompt",
                            "options",
                            "display_order",
                        )
                    }
                    for r in self.check_rows
                ]
            )
        if "INSERT INTO learning_check_attempts" in sql:
            self.attempt_inserts.append(p)
            return _Result(
                row={"attempt_id": _uuid.uuid4(), "completed_at": _NOW}
            )
        if "SELECT renewal_months FROM learning_renewal_policies" in sql:
            return _Result(row=self.renewal_policy_row)
        if "INSERT INTO learning_renewal_policies" in sql:
            self.policy_upserts.append(p)
            return _Result(
                row={
                    "renewal_months": p.get("renewal_months"),
                    "updated_at": _NOW,
                }
            )
        if "SELECT path_id, path_slug" in sql:
            return _Result(rows=self.path_rows)
        if "SELECT DISTINCT lm.module_slug" in sql:
            return _Result(rows=self.completed_slug_rows)
        if "SELECT lc.module_id, lm.module_slug, lm.title" in sql:
            return _Result(rows=self.my_renewal_rows)
        if "SELECT lc.user_id, lc.module_id" in sql:
            return _Result(rows=self.overview_rows)
        raise AssertionError(f"unexpected SQL: {sql}")

    def commit(self) -> None:
        pass


def _build_app(*, authenticated: bool = True, role: str = "staff") -> tuple:
    from app.auth_and_rls import require_clinic_user
    from app.db import get_db
    from app.learn_maturity import router

    app = FastAPI()
    app.include_router(router)
    fake = LearnMaturityFakeDB()

    def _fake_db_dep(request: Request):
        yield fake
        fake.commit()

    app.dependency_overrides[get_db] = _fake_db_dep

    if authenticated:
        user_id = ADMIN_USER if role in ("admin", "owner") else STAFF_USER

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


def _sweep(payload: Any) -> None:
    blob = json.dumps(payload)
    for key in FORBIDDEN_KEYS:
        assert f'"{key}"' not in blob, f"forbidden key {key} in response"


# ---------------------------------------------------------------------
# Self-check list
# ---------------------------------------------------------------------

def test_check_list_hides_answers_and_explanations() -> None:
    app, _ = _build_app()
    resp = TestClient(app).get(f"/v1/learn/checks/modules/{MODULE_ID}")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["questions"]) == 2
    blob = json.dumps(body)
    assert "correct_option_index" not in blob
    assert "explanation" not in blob
    assert "Because review is required." not in blob
    assert body["self_check_note"].startswith("Self-check reinforcement")
    _sweep(body)


def test_check_list_unknown_module_404() -> None:
    app, fake = _build_app()
    fake.module_row = None
    resp = TestClient(app).get(f"/v1/learn/checks/modules/{MODULE_ID}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------
# Attempts
# ---------------------------------------------------------------------

def _answers(idx1: int, idx2: int) -> Dict[str, Any]:
    return {
        "answers": [
            {"check_id": CHECK_1, "selected_option_index": idx1},
            {"check_id": CHECK_2, "selected_option_index": idx2},
        ]
    }


def test_attempt_marking_and_aggregate_only_insert() -> None:
    app, fake = _build_app()
    resp = TestClient(app).post(
        f"/v1/learn/checks/modules/{MODULE_ID}/attempts",
        json=_answers(1, 1),  # first correct, second wrong
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["questions_total"] == 2
    assert body["questions_correct"] == 1
    feedback = {f["check_id"]: f for f in body["feedback"]}
    assert feedback[CHECK_1]["correct"] is True
    assert feedback[CHECK_2]["correct"] is False
    assert feedback[CHECK_2]["explanation"] == "Because policy applies."
    assert body["self_check_note"].startswith("Self-check reinforcement")
    _sweep(body)

    # Aggregate-only persistence: the insert carries counts, never the
    # selected answers.
    assert len(fake.attempt_inserts) == 1
    ins = fake.attempt_inserts[0]
    assert ins["clinic_id"] == CLINIC_A
    assert ins["questions_total"] == 2
    assert ins["questions_correct"] == 1
    assert "selected_option_index" not in ins
    assert not any("answer" in k for k in ins)


def test_attempt_incomplete_set_rejected() -> None:
    app, fake = _build_app()
    resp = TestClient(app).post(
        f"/v1/learn/checks/modules/{MODULE_ID}/attempts",
        json={
            "answers": [
                {"check_id": CHECK_1, "selected_option_index": 0}
            ]
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "incomplete_self_check"
    assert fake.attempt_inserts == []


def test_attempt_duplicate_answers_rejected() -> None:
    app, fake = _build_app()
    resp = TestClient(app).post(
        f"/v1/learn/checks/modules/{MODULE_ID}/attempts",
        json={
            "answers": [
                {"check_id": CHECK_1, "selected_option_index": 0},
                {"check_id": CHECK_1, "selected_option_index": 1},
            ]
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "duplicate_check_answer"


def test_attempt_invalid_option_index_rejected() -> None:
    app, fake = _build_app()
    resp = TestClient(app).post(
        f"/v1/learn/checks/modules/{MODULE_ID}/attempts",
        json=_answers(9, 0),
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "invalid_option_index"
    assert fake.attempt_inserts == []


# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------

def test_paths_progress() -> None:
    app, fake = _build_app()
    fake.path_rows = [
        {
            "path_id": _uuid.uuid4(),
            "path_slug": "clinical-team-ai-foundations-v1",
            "version": "1.0.0",
            "title": "Clinical Team AI Foundations",
            "summary": "Recommended sequence.",
            "role_applicability": ["vet", "nurse"],
            "module_slugs": ["mod-a-v1", "mod-b-v1", "mod-c-v1"],
            "display_order": 1,
        }
    ]
    fake.completed_slug_rows = [
        {"module_slug": "mod-a-v1"},
        {"module_slug": "mod-c-v1"},
        {"module_slug": "unrelated-v1"},
    ]
    resp = TestClient(app).get("/v1/learn/paths")
    assert resp.status_code == 200
    path = resp.json()["paths"][0]
    assert path["completed_count"] == 2
    assert path["total_count"] == 3
    assert sorted(path["completed_module_slugs"]) == ["mod-a-v1", "mod-c-v1"]
    _sweep(resp.json())


# ---------------------------------------------------------------------
# Renewals
# ---------------------------------------------------------------------

def _renewal_row(module_slug: str, completed_days_ago: int) -> Dict[str, Any]:
    return {
        "module_id": _uuid.uuid4(),
        "module_slug": module_slug,
        "title": module_slug,
        "latest_completed_at": _NOW - timedelta(days=completed_days_ago),
    }


def test_my_renewals_status_derivation() -> None:
    app, fake = _build_app()
    fake.my_renewal_rows = [
        _renewal_row("fresh-v1", 10),        # current
        _renewal_row("aging-v1", 330),       # due soon (12m policy)
        _renewal_row("stale-v1", 800),       # overdue
    ]
    resp = TestClient(app).get("/v1/learn/renewals/me")
    assert resp.status_code == 200
    body = resp.json()
    assert body["renewal_months"] == 12
    statuses = {e["module_slug"]: e["status"] for e in body["entries"]}
    assert statuses["fresh-v1"] == "current"
    assert statuses["aging-v1"] == "due_soon"
    assert statuses["stale-v1"] == "overdue"
    _sweep(body)


def test_my_renewals_honours_clinic_policy_months() -> None:
    app, fake = _build_app()
    fake.renewal_policy_row = {"renewal_months": 6}
    fake.my_renewal_rows = [_renewal_row("aging-v1", 330)]  # > 6 months
    resp = TestClient(app).get("/v1/learn/renewals/me")
    body = resp.json()
    assert body["renewal_months"] == 6
    assert body["entries"][0]["status"] == "overdue"


def test_overview_admin_only() -> None:
    app, _ = _build_app(role="staff")
    resp = TestClient(app).get("/v1/learn/renewals/overview")
    assert resp.status_code == 403


def test_overview_aggregates() -> None:
    app, fake = _build_app(role="admin")
    user_a = str(_uuid.uuid4())
    user_b = str(_uuid.uuid4())
    fake.overview_rows = [
        {
            "user_id": user_a,
            "module_id": _uuid.uuid4(),
            "latest_completed_at": _NOW - timedelta(days=10),
        },
        {
            "user_id": user_a,
            "module_id": _uuid.uuid4(),
            "latest_completed_at": _NOW - timedelta(days=800),
        },
        {
            "user_id": user_b,
            "module_id": _uuid.uuid4(),
            "latest_completed_at": _NOW - timedelta(days=330),
        },
    ]
    resp = TestClient(app).get("/v1/learn/renewals/overview")
    assert resp.status_code == 200
    body = resp.json()
    users = {u["user_id"]: u for u in body["users"]}
    assert users[user_a]["modules_completed"] == 2
    assert users[user_a]["overdue_count"] == 1
    assert users[user_a]["current_count"] == 1
    assert users[user_b]["due_soon_count"] == 1
    assert body["total_overdue"] == 1
    assert body["total_due_soon"] == 1
    assert body["total_current"] == 1
    _sweep(body)


def test_renewal_policy_put_admin_only_and_upserts() -> None:
    app_staff, _ = _build_app(role="staff")
    resp = TestClient(app_staff).put(
        "/v1/learn/renewal-policy", json={"renewal_months": 6}
    )
    assert resp.status_code == 403

    app_admin, fake = _build_app(role="admin")
    resp = TestClient(app_admin).put(
        "/v1/learn/renewal-policy", json={"renewal_months": 6}
    )
    assert resp.status_code == 200
    assert resp.json()["renewal_months"] == 6
    assert fake.policy_upserts[0]["clinic_id"] == CLINIC_A

    # Bounds enforced by the model.
    resp = TestClient(app_admin).put(
        "/v1/learn/renewal-policy", json={"renewal_months": 0}
    )
    assert resp.status_code == 422


def test_renewal_policy_put_writes_audit_event() -> None:
    """Pre-merge FIX 2 (5 July audit): renewal-policy updates write an
    append-only admin_audit_events row, M6.10 precedent."""
    import json as _json

    app, fake = _build_app(role="admin")
    resp = TestClient(app).put(
        "/v1/learn/renewal-policy", json={"renewal_months": 9}
    )
    assert resp.status_code == 200
    assert len(fake.audit_inserts) == 1
    audit = fake.audit_inserts[0]
    assert audit["action"] == "learn_renewal_policy_updated"
    assert audit["clinic_id"] == CLINIC_A
    assert _json.loads(audit["meta"]) == {"renewal_months": 9}

    # Refused (staff) updates write nothing.
    app_staff, fake_staff = _build_app(role="staff")
    TestClient(app_staff).put(
        "/v1/learn/renewal-policy", json={"renewal_months": 9}
    )
    assert fake_staff.audit_inserts == []


def test_requires_auth() -> None:
    app, _ = _build_app(authenticated=False)
    client = TestClient(app)
    assert client.get("/v1/learn/paths").status_code == 401
    assert client.get("/v1/learn/renewals/me").status_code == 401


def test_router_mounted_in_main_app() -> None:
    from app.main import app as main_app

    paths = {getattr(r, "path", None) for r in main_app.routes}
    assert "/v1/learn/checks/modules/{module_id}" in paths
    assert "/v1/learn/paths" in paths
    assert "/v1/learn/renewals/overview" in paths
