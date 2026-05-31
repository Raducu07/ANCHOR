"""Phase 2A-3.2 - RCVS-aligned AI Governance Self-Assessment endpoint tests.

Coverage (mirrors tests/test_governance_policy_endpoints.py):
  * Templates: list (any clinic user) + get (with ordered questions).
  * Create draft: admin-only, idempotent for existing draft, server
    derives clinic_id / created_by_user_id.
  * Upsert answer: admin-only, `extra="forbid"` rejects unknown
    fields, bounded enum rejection for answer_value /
    evidence_links, blocked after submit.
  * Submit: requires all questions answered, freezes aggregate
    snapshots, supersedes prior submitted assessment for the same
    (clinic, template).
  * Latest: reads v_clinic_latest_self_assessment metadata, returns
    safe empty when none.
  * Archive: draft success; current submitted blocked.
  * Tenant isolation: clinic B cannot read clinic A or write an
    answer onto clinic A's assessment.
  * Audit: append-only metadata-only rows written for create / answer
    upsert / submit / archive; no forbidden response keys leak.

These tests use an in-memory FakeDB that interprets the SQL the
self_assessment router issues. No live Postgres needed.
"""
from __future__ import annotations

import json
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
ADMIN_USER_B = "55555555-5555-4555-8555-555555555555"
STAFF_USER = "44444444-4444-4444-8444-444444444444"

TPL_ID = "aaaaaaaa-0000-4000-8000-000000000001"
TEMPLATE_SLUG = "rcvs_ai_governance_self_assessment"
TEMPLATE_VERSION = "1.0.0"

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

THEMES = [
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


FORBIDDEN_RESPONSE_KEYS = {
    "notes",
    "free_text",
    "reflection",
    "score",
    "pass_fail",
    "competence_grade",
    "compliance_status",
    "staff_certified",
    "clinical_safety_proof",
    "legal_approval",
}


def _now() -> datetime:
    return datetime(2026, 5, 31, 12, 0, 0, tzinfo=timezone.utc)


def _template_row() -> Dict[str, Any]:
    return {
        "template_id": _uuid.UUID(TPL_ID),
        "template_slug": TEMPLATE_SLUG,
        "template_version": TEMPLATE_VERSION,
        "title": "RCVS-aligned AI Governance Self-Assessment",
        "summary": "Structured self-assessment of AI governance posture.",
        "rcvs_principle_mappings": ["RCVS_AI_literacy", "RCVS_accountability"],
        "eu_ai_act_article_mappings": ["EU_AI_Act_Article_4"],
        "is_active": True,
        "superseded_by": None,
        "created_at": _now(),
        "updated_at": _now(),
    }


def _seed_questions(template_id: _uuid.UUID) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for i, slug in enumerate(QUESTION_SLUGS, start=1):
        rows.append(
            {
                "question_id": _uuid.UUID(
                    f"bbbbbbbb-0000-4000-8000-{i:012d}"
                ),
                "template_id": template_id,
                "question_slug": slug,
                "question_order": i,
                "theme": THEMES[i - 1],
                "prompt_text": f"Prompt for {slug}",
                "guidance_reference": (
                    f"docs/governance/self_assessment/{slug}-1.0.0.md"
                ),
                "evidence_link_hints": ["manual_review"],
                "rcvs_principle_mappings": ["RCVS_accountability"],
                "eu_ai_act_article_mappings": ["EU_AI_Act_Article_26"],
                "created_at": _now(),
            }
        )
    return rows


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


class SelfAssessmentFakeDB:
    """In-memory fake that interprets the SQL self_assessment.py emits.

    `current_clinic` is reset by the get_db dependency override on each
    request, so cross-clinic tests behave like FORCE RLS in production:
    not found.
    """

    def __init__(self) -> None:
        self.current_clinic: str = CLINIC_A
        self.templates: Dict[str, Dict[str, Any]] = {TPL_ID: _template_row()}
        self.questions: List[Dict[str, Any]] = _seed_questions(
            _uuid.UUID(TPL_ID)
        )
        self.assessments: List[Dict[str, Any]] = []
        self.answers: List[Dict[str, Any]] = []
        self.audit_events: List[Dict[str, Any]] = []
        self.committed = False
        self.rolled_back = False
        self.calls: List[tuple] = []

    # session shape
    def begin(self) -> None:
        return None

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        return None

    def _scoped_assessments(self) -> List[Dict[str, Any]]:
        return [a for a in self.assessments if str(a["clinic_id"]) == self.current_clinic]

    def _scoped_answers(self) -> List[Dict[str, Any]]:
        return [a for a in self.answers if str(a["clinic_id"]) == self.current_clinic]

    def _template_by_slug(
        self, slug: str, version: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        for t in self.templates.values():
            if t["template_slug"] != slug:
                continue
            if version is not None and t["template_version"] != version:
                continue
            return t
        return None

    def _template_by_id(self, tid: str) -> Optional[Dict[str, Any]]:
        return self.templates.get(str(tid))

    def _questions_for_template(self, tid: str) -> List[Dict[str, Any]]:
        return [q for q in self.questions if str(q["template_id"]) == str(tid)]

    def _question_by_slug(
        self, tid: str, slug: str
    ) -> Optional[Dict[str, Any]]:
        for q in self.questions:
            if str(q["template_id"]) == str(tid) and q["question_slug"] == slug:
                return q
        return None

    def execute(self, statement: Any, params: Optional[Dict[str, Any]] = None) -> _Result:
        sql = str(getattr(statement, "text", statement))
        p = dict(params or {})
        self.calls.append((sql, p))

        # ---- list templates ----
        if (
            "FROM self_assessment_templates" in sql
            and "ORDER BY title" in sql
        ):
            rows = [t for t in self.templates.values() if t["is_active"]]
            rows = sorted(rows, key=lambda t: t["title"])
            return _Result(rows=rows)

        # ---- get template by id ----
        if (
            "FROM self_assessment_templates" in sql
            and "template_id = CAST(:template_id AS uuid)" in sql
        ):
            return _Result(row=self._template_by_id(p["template_id"]))

        # ---- get template by slug ----
        if (
            "FROM self_assessment_templates" in sql
            and "template_slug = :template_slug" in sql
        ):
            tpl = self._template_by_slug(
                p["template_slug"], p.get("template_version")
            )
            return _Result(row=tpl)

        # ---- list questions for template ----
        if (
            "FROM self_assessment_questions" in sql
            and "template_id = CAST(:template_id AS uuid)" in sql
            and "question_slug = :question_slug" not in sql
        ):
            qs = self._questions_for_template(p["template_id"])
            qs = sorted(qs, key=lambda q: q["question_order"])
            return _Result(rows=qs)

        # ---- get question by (template_id, slug) ----
        if (
            "FROM self_assessment_questions" in sql
            and "question_slug = :question_slug" in sql
        ):
            return _Result(row=self._question_by_slug(
                p["template_id"], p["question_slug"]
            ))

        # ---- existing draft for (clinic, template) ----
        if (
            "FROM clinic_self_assessments" in sql
            and "status = 'draft'" in sql
            and "template_id = CAST(:template_id AS uuid)" in sql
            and "RETURNING" not in sql
            and "UPDATE" not in sql
        ):
            for a in self._scoped_assessments():
                if (
                    str(a["template_id"]) == p["template_id"]
                    and a["status"] == "draft"
                ):
                    return _Result(row=a)
            return _Result(row=None)

        # ---- MAX(clinic_assessment_version) ----
        if (
            "MAX(clinic_assessment_version)" in sql
            and "clinic_self_assessments" in sql
        ):
            vs = [
                int(a["clinic_assessment_version"])
                for a in self._scoped_assessments()
                if str(a["template_id"]) == p["template_id"]
            ]
            return _Result(row={"v": max(vs) if vs else 0})

        # ---- INSERT clinic_self_assessments (draft) ----
        if "INSERT INTO clinic_self_assessments" in sql:
            now = datetime.now(timezone.utc)
            row = {
                "assessment_id": _uuid.uuid4(),
                "clinic_id": _uuid.UUID(p["clinic_id"]),
                "template_id": _uuid.UUID(p["template_id"]),
                "template_version_snapshot": p["template_version_snapshot"],
                "clinic_assessment_version": int(p["clinic_assessment_version"]),
                "status": "draft",
                "created_by_user_id": _uuid.UUID(p["created_by_user_id"]),
                "submitted_by_user_id": None,
                "submitted_at": None,
                "superseded_at": None,
                "total_questions_snapshot": None,
                "answered_questions_snapshot": None,
                "readiness_summary_snapshot": None,
                "linked_evidence_counts_snapshot": None,
                "created_at": now,
                "updated_at": now,
            }
            self.assessments.append(row)
            return _Result(row=row)

        # ---- v_clinic_latest_self_assessment ----
        if "v_clinic_latest_self_assessment" in sql:
            buckets: Dict[str, Dict[str, Any]] = {}
            for a in self._scoped_assessments():
                if a["status"] not in ("submitted", "superseded"):
                    continue
                key = str(a["template_id"])
                cur = buckets.get(key)
                if cur is None or (
                    (a.get("submitted_at") or datetime.min.replace(tzinfo=timezone.utc))
                    > (cur.get("submitted_at") or datetime.min.replace(tzinfo=timezone.utc))
                ):
                    buckets[key] = a
            return _Result(rows=list(buckets.values()))

        # ---- SELECT one assessment by id ----
        if (
            "FROM clinic_self_assessments" in sql
            and "assessment_id = CAST(:assessment_id AS uuid)" in sql
            and "UPDATE" not in sql
            and "RETURNING" not in sql
        ):
            for a in self._scoped_assessments():
                if str(a["assessment_id"]) == p["assessment_id"]:
                    return _Result(row=a)
            return _Result(row=None)

        # ---- list assessments ----
        if (
            "FROM clinic_self_assessments" in sql
            and "ORDER BY created_at DESC" in sql
        ):
            rows = list(self._scoped_assessments())
            if "status = :status" in sql and "status" in p:
                rows = [a for a in rows if a["status"] == p["status"]]
            if "status <> 'draft'" in sql:
                rows = [a for a in rows if a["status"] != "draft"]
            rows = sorted(rows, key=lambda a: a["created_at"], reverse=True)
            rows = rows[: int(p.get("limit", 25))]
            return _Result(rows=rows)

        # ---- SELECT answers for an assessment ----
        if (
            "FROM clinic_self_assessment_answers" in sql
            and "ORDER BY answered_at ASC" in sql
        ):
            rows = [
                a for a in self._scoped_answers()
                if str(a["assessment_id"]) == p["assessment_id"]
            ]
            rows = sorted(rows, key=lambda a: a["answered_at"])
            return _Result(rows=rows)

        # ---- UPDATE answer (upsert RETURNING) ----
        if (
            "UPDATE clinic_self_assessment_answers" in sql
            and "RETURNING" in sql
        ):
            for a in self._scoped_answers():
                if (
                    str(a["assessment_id"]) == p["assessment_id"]
                    and str(a["question_id"]) == p["question_id"]
                ):
                    a["answer_value"] = p["answer_value"]
                    a["evidence_links"] = list(p["evidence_links"])
                    a["answered_by_user_id"] = _uuid.UUID(p["actor"])
                    a["answered_at"] = datetime.now(timezone.utc)
                    a["updated_at"] = a["answered_at"]
                    return _Result(row=a)
            return _Result(row=None)

        # ---- INSERT answer ----
        if "INSERT INTO clinic_self_assessment_answers" in sql:
            now = datetime.now(timezone.utc)
            row = {
                "answer_id": _uuid.uuid4(),
                "clinic_id": _uuid.UUID(p["clinic_id"]),
                "assessment_id": _uuid.UUID(p["assessment_id"]),
                "question_id": _uuid.UUID(p["question_id"]),
                "question_slug_snapshot": p["question_slug_snapshot"],
                "theme_snapshot": p["theme_snapshot"],
                "answer_value": p["answer_value"],
                "evidence_links": list(p["evidence_links"]),
                "answered_by_user_id": _uuid.UUID(p["actor"]),
                "answered_at": now,
                "updated_at": now,
            }
            self.answers.append(row)
            return _Result(row=row)

        # ---- UPDATE supersede prior submitted ----
        if (
            "UPDATE clinic_self_assessments" in sql
            and "status = 'superseded'" in sql
            and "RETURNING" not in sql
        ):
            for a in self._scoped_assessments():
                if (
                    str(a["template_id"]) == p["template_id"]
                    and a["status"] == "submitted"
                ):
                    a["status"] = "superseded"
                    a["superseded_at"] = datetime.now(timezone.utc)
                    a["updated_at"] = a["superseded_at"]
            return _Result(row=None)

        # ---- UPDATE submit (RETURNING) ----
        if (
            "UPDATE clinic_self_assessments" in sql
            and "status = 'submitted'" in sql
            and "RETURNING" in sql
        ):
            for a in self._scoped_assessments():
                if (
                    str(a["assessment_id"]) == p["assessment_id"]
                    and a["status"] == "draft"
                ):
                    now = datetime.now(timezone.utc)
                    a["status"] = "submitted"
                    a["submitted_by_user_id"] = _uuid.UUID(p["actor"])
                    a["submitted_at"] = now
                    a["total_questions_snapshot"] = int(p["total_questions"])
                    a["answered_questions_snapshot"] = int(
                        p["answered_questions"]
                    )
                    a["readiness_summary_snapshot"] = json.loads(p["readiness"])
                    a["linked_evidence_counts_snapshot"] = json.loads(
                        p["evidence"]
                    )
                    a["updated_at"] = now
                    return _Result(row=a)
            return _Result(row=None)

        # ---- UPDATE archive (RETURNING) ----
        if (
            "UPDATE clinic_self_assessments" in sql
            and "status = 'archived'" in sql
            and "RETURNING" in sql
        ):
            for a in self._scoped_assessments():
                if (
                    str(a["assessment_id"]) == p["assessment_id"]
                    and a["status"] in ("draft", "superseded")
                ):
                    now = datetime.now(timezone.utc)
                    a["status"] = "archived"
                    a["updated_at"] = now
                    return _Result(row=a)
            return _Result(row=None)

        # ---- admin_audit_events INSERT ----
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
    fake: Optional[SelfAssessmentFakeDB] = None,
    clinic_id: str = CLINIC_A,
    user_id: str = ADMIN_USER,
    role: str = "admin",
) -> tuple:
    from app.auth_and_rls import require_clinic_user
    from app.db import get_db
    from app.self_assessment import router

    app = FastAPI()
    app.include_router(router)
    fake = fake or SelfAssessmentFakeDB()

    def _fake_db_dep(request: Request):
        fake.current_clinic = getattr(request.state, "clinic_id", clinic_id)
        yield fake
        fake.commit()

    app.dependency_overrides[get_db] = _fake_db_dep

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
    if isinstance(payload, dict):
        leaked = set(payload.keys()) & FORBIDDEN_RESPONSE_KEYS
        assert not leaked, f"forbidden keys leaked in {where}: {leaked}"
        for k, v in payload.items():
            _assert_no_forbidden_keys(v, where=f"{where}.{k}")
    elif isinstance(payload, list):
        for i, v in enumerate(payload):
            _assert_no_forbidden_keys(v, where=f"{where}[{i}]")


def _create_draft(client: TestClient) -> Dict[str, Any]:
    resp = client.post(
        "/v1/governance/self-assessment/assessments",
        json={"template_slug": TEMPLATE_SLUG},
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["assessment"]


def _answer_all(client: TestClient, assessment_id: str, value: str = "yes") -> None:
    for slug in QUESTION_SLUGS:
        r = client.put(
            f"/v1/governance/self-assessment/assessments/"
            f"{assessment_id}/answers/{slug}",
            json={"answer_value": value, "evidence_links": ["manual_review"]},
            headers=auth_headers(),
        )
        assert r.status_code == 200, r.text


# ---------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------


def test_list_templates_visible_to_clinic_user() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).get(
        "/v1/governance/self-assessment/templates", headers=auth_headers()
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    slugs = {t["template_slug"] for t in body["templates"]}
    assert TEMPLATE_SLUG in slugs
    assert "governance_note" in body
    _assert_no_forbidden_keys(body)


def test_get_template_returns_ordered_questions() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).get(
        f"/v1/governance/self-assessment/templates/{TEMPLATE_SLUG}",
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["template"]["template_slug"] == TEMPLATE_SLUG
    qs = body["questions"]
    assert [q["question_slug"] for q in qs] == QUESTION_SLUGS
    assert [q["question_order"] for q in qs] == list(range(1, 11))
    _assert_no_forbidden_keys(body)


def test_get_template_questions_endpoint() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).get(
        f"/v1/governance/self-assessment/templates/{TEMPLATE_SLUG}/questions",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert [q["question_slug"] for q in resp.json()["questions"]] == QUESTION_SLUGS


# ---------------------------------------------------------------------
# Create draft
# ---------------------------------------------------------------------


@pytest.mark.parametrize("role", ["admin", "owner", "practice_manager"])
def test_create_draft_admin_success(role: str) -> None:
    app, fake = build_app(role=role)
    body = _create_draft(client_for(app))
    assert body["status"] == "draft"
    assert body["clinic_assessment_version"] == 1
    assert body["template_version_snapshot"] == TEMPLATE_VERSION
    # Server-derived fields.
    assert body["clinic_id"] == CLINIC_A
    assert body["created_by_user_id"] == ADMIN_USER
    _assert_no_forbidden_keys(body)


@pytest.mark.parametrize("role", ["staff", "reader", "clinic_user"])
def test_create_draft_requires_admin_role(role: str) -> None:
    app, fake = build_app(role=role)
    resp = client_for(app).post(
        "/v1/governance/self-assessment/assessments",
        json={"template_slug": TEMPLATE_SLUG},
        headers=auth_headers(),
    )
    assert resp.status_code == 403
    assert resp.json().get("detail") == "forbidden_not_admin"
    assert fake.assessments == []


def test_create_draft_duplicate_returns_existing() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    first = _create_draft(c)
    resp2 = c.post(
        "/v1/governance/self-assessment/assessments",
        json={"template_slug": TEMPLATE_SLUG},
        headers=auth_headers(),
    )
    assert resp2.status_code == 201, resp2.text
    second = resp2.json()["assessment"]
    assert second["assessment_id"] == first["assessment_id"]
    assert len(fake.assessments) == 1


def test_create_rejects_unknown_template_slug() -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).post(
        "/v1/governance/self-assessment/assessments",
        json={"template_slug": "no_such"},
        headers=auth_headers(),
    )
    assert resp.status_code == 404


def test_create_rejects_caller_supplied_clinic_id() -> None:
    """`extra='forbid'` rejects any attempt to send clinic_id / user_id."""
    app, fake = build_app(role="admin")
    resp = client_for(app).post(
        "/v1/governance/self-assessment/assessments",
        json={
            "template_slug": TEMPLATE_SLUG,
            "clinic_id": CLINIC_B,
            "created_by_user_id": STAFF_USER,
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------
# Upsert answer
# ---------------------------------------------------------------------


def test_upsert_answer_requires_admin_role() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    draft = _create_draft(c)

    app2, fake2 = build_app(fake=fake, role="staff")
    resp = client_for(app2).put(
        f"/v1/governance/self-assessment/assessments/"
        f"{draft['assessment_id']}/answers/{QUESTION_SLUGS[0]}",
        json={"answer_value": "yes", "evidence_links": []},
        headers=auth_headers(),
    )
    assert resp.status_code == 403


def test_upsert_answer_rejects_unknown_fields() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    draft = _create_draft(c)
    for forbidden in ("notes", "free_text", "score", "reflection",
                      "compliance_status", "competence_grade"):
        resp = c.put(
            f"/v1/governance/self-assessment/assessments/"
            f"{draft['assessment_id']}/answers/{QUESTION_SLUGS[0]}",
            json={
                "answer_value": "yes",
                "evidence_links": [],
                forbidden: "anything",
            },
            headers=auth_headers(),
        )
        assert resp.status_code == 422, (forbidden, resp.text)


def test_upsert_answer_rejects_invalid_answer_value() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    draft = _create_draft(c)
    resp = c.put(
        f"/v1/governance/self-assessment/assessments/"
        f"{draft['assessment_id']}/answers/{QUESTION_SLUGS[0]}",
        json={"answer_value": "maybe", "evidence_links": []},
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "self_assessment_invalid_answer_value"


def test_upsert_answer_rejects_invalid_evidence_link() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    draft = _create_draft(c)
    resp = c.put(
        f"/v1/governance/self-assessment/assessments/"
        f"{draft['assessment_id']}/answers/{QUESTION_SLUGS[0]}",
        json={
            "answer_value": "yes",
            "evidence_links": ["clinical_record"],
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "self_assessment_invalid_evidence_link"


def test_upsert_answer_success_and_snapshot_fields() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    draft = _create_draft(c)
    resp = c.put(
        f"/v1/governance/self-assessment/assessments/"
        f"{draft['assessment_id']}/answers/{QUESTION_SLUGS[0]}",
        json={
            "answer_value": "partial",
            "evidence_links": ["policy_library", "manual_review"],
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["answer_value"] == "partial"
    assert set(body["evidence_links"]) == {"policy_library", "manual_review"}
    assert body["question_slug_snapshot"] == QUESTION_SLUGS[0]
    assert body["theme_snapshot"] == THEMES[0]
    assert body["answered_by_user_id"] == ADMIN_USER
    _assert_no_forbidden_keys(body)


def test_upsert_answer_idempotent_overwrite() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    draft = _create_draft(c)
    aid = draft["assessment_id"]
    for v in ("yes", "partial", "planned"):
        r = c.put(
            f"/v1/governance/self-assessment/assessments/{aid}/answers/"
            f"{QUESTION_SLUGS[0]}",
            json={"answer_value": v, "evidence_links": ["manual_review"]},
            headers=auth_headers(),
        )
        assert r.status_code == 200, r.text
    # Only one row should exist for this (assessment, question).
    rows = [
        a for a in fake.answers
        if str(a["assessment_id"]) == aid
        and a["question_slug_snapshot"] == QUESTION_SLUGS[0]
    ]
    assert len(rows) == 1
    assert rows[0]["answer_value"] == "planned"


def test_upsert_answer_blocked_after_submit() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    draft = _create_draft(c)
    aid = draft["assessment_id"]
    _answer_all(c, aid)
    sub = c.post(
        f"/v1/governance/self-assessment/assessments/{aid}/submit",
        headers=auth_headers(),
    )
    assert sub.status_code == 200, sub.text

    resp = c.put(
        f"/v1/governance/self-assessment/assessments/{aid}/answers/"
        f"{QUESTION_SLUGS[0]}",
        json={"answer_value": "no", "evidence_links": []},
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "self_assessment_not_in_draft"


# ---------------------------------------------------------------------
# Submit
# ---------------------------------------------------------------------


def test_submit_requires_all_questions_answered() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    draft = _create_draft(c)
    # Answer only the first 3 questions.
    for slug in QUESTION_SLUGS[:3]:
        r = c.put(
            f"/v1/governance/self-assessment/assessments/"
            f"{draft['assessment_id']}/answers/{slug}",
            json={"answer_value": "yes", "evidence_links": []},
            headers=auth_headers(),
        )
        assert r.status_code == 200
    sub = c.post(
        f"/v1/governance/self-assessment/assessments/"
        f"{draft['assessment_id']}/submit",
        headers=auth_headers(),
    )
    assert sub.status_code == 400
    assert sub.json().get("detail") == "self_assessment_unanswered_questions"


def test_submit_success_freezes_snapshots() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    draft = _create_draft(c)
    aid = draft["assessment_id"]
    # Mix of answer values + evidence links for non-trivial aggregates.
    for i, slug in enumerate(QUESTION_SLUGS):
        v = ["yes", "partial", "planned", "no", "not_applicable"][i % 5]
        ev = ["manual_review"] if i % 2 == 0 else ["policy_library", "learn_cpd"]
        r = c.put(
            f"/v1/governance/self-assessment/assessments/{aid}/answers/{slug}",
            json={"answer_value": v, "evidence_links": ev},
            headers=auth_headers(),
        )
        assert r.status_code == 200
    sub = c.post(
        f"/v1/governance/self-assessment/assessments/{aid}/submit",
        headers=auth_headers(),
    )
    assert sub.status_code == 200, sub.text
    a = sub.json()["assessment"]
    assert a["status"] == "submitted"
    assert a["submitted_by_user_id"] == ADMIN_USER
    assert a["submitted_at"] is not None
    assert a["total_questions_snapshot"] == 10
    assert a["answered_questions_snapshot"] == 10
    rs = a["readiness_summary_snapshot"]
    assert sum(rs.values()) == 10
    assert set(rs.keys()) == {"yes", "partial", "planned", "no", "not_applicable"}
    es = a["linked_evidence_counts_snapshot"]
    assert set(es.keys()) == {
        "policy_library", "staff_attestation", "learn_cpd",
        "assistant_receipts", "trust_posture", "manual_review",
    }
    assert es["manual_review"] == 5
    assert es["policy_library"] == 5
    assert es["learn_cpd"] == 5
    _assert_no_forbidden_keys(sub.json())


def test_submit_supersedes_prior_submitted_assessment() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    # Cycle 1.
    d1 = _create_draft(c)
    _answer_all(c, d1["assessment_id"])
    s1 = c.post(
        f"/v1/governance/self-assessment/assessments/"
        f"{d1['assessment_id']}/submit",
        headers=auth_headers(),
    )
    assert s1.status_code == 200
    assert s1.json()["assessment"]["status"] == "submitted"

    # Cycle 2 - a new draft + submit.
    d2 = _create_draft(c)
    assert d2["assessment_id"] != d1["assessment_id"]
    assert d2["clinic_assessment_version"] == 2
    _answer_all(c, d2["assessment_id"])
    s2 = c.post(
        f"/v1/governance/self-assessment/assessments/"
        f"{d2['assessment_id']}/submit",
        headers=auth_headers(),
    )
    assert s2.status_code == 200

    # The cycle-1 row must now be superseded.
    prior = next(
        a for a in fake.assessments
        if str(a["assessment_id"]) == d1["assessment_id"]
    )
    assert prior["status"] == "superseded"
    assert prior["superseded_at"] is not None


# ---------------------------------------------------------------------
# Latest
# ---------------------------------------------------------------------


def test_latest_empty_when_no_submitted_assessment() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).get(
        "/v1/governance/self-assessment/assessments/latest",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["latest"] == []


def test_latest_returns_latest_submitted_assessment() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    d = _create_draft(c)
    _answer_all(c, d["assessment_id"])
    c.post(
        f"/v1/governance/self-assessment/assessments/{d['assessment_id']}/submit",
        headers=auth_headers(),
    )
    resp = c.get(
        "/v1/governance/self-assessment/assessments/latest",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    entries = resp.json()["latest"]
    assert len(entries) == 1
    e = entries[0]
    assert e["assessment_id"] == d["assessment_id"]
    assert e["status"] == "submitted"
    assert e["total_questions_snapshot"] == 10
    _assert_no_forbidden_keys(resp.json())


def test_latest_excludes_draft_and_archived() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    _create_draft(c)  # draft only
    resp = c.get(
        "/v1/governance/self-assessment/assessments/latest",
        headers=auth_headers(),
    )
    assert resp.json()["latest"] == []


# ---------------------------------------------------------------------
# Archive
# ---------------------------------------------------------------------


def test_archive_draft_success() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    d = _create_draft(c)
    resp = c.post(
        f"/v1/governance/self-assessment/assessments/"
        f"{d['assessment_id']}/archive",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["assessment"]["status"] == "archived"


def test_archive_current_submitted_blocked() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    d = _create_draft(c)
    _answer_all(c, d["assessment_id"])
    c.post(
        f"/v1/governance/self-assessment/assessments/{d['assessment_id']}/submit",
        headers=auth_headers(),
    )
    resp = c.post(
        f"/v1/governance/self-assessment/assessments/"
        f"{d['assessment_id']}/archive",
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert (
        resp.json().get("detail")
        == "self_assessment_submitted_archive_not_allowed"
    )


# ---------------------------------------------------------------------
# Tenant isolation (modelled by FakeDB.current_clinic scoping)
# ---------------------------------------------------------------------


def test_cross_clinic_assessment_read_blocked() -> None:
    fake = SelfAssessmentFakeDB()
    # Clinic A admin creates a draft.
    app_a, _ = build_app(fake=fake, clinic_id=CLINIC_A, role="admin")
    draft = _create_draft(client_for(app_a))

    # Clinic B admin tries to read it.
    app_b, _ = build_app(
        fake=fake, clinic_id=CLINIC_B, user_id=ADMIN_USER_B, role="admin"
    )
    resp = client_for(app_b).get(
        f"/v1/governance/self-assessment/assessments/{draft['assessment_id']}",
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "self_assessment_not_found"


def test_cross_clinic_answer_write_blocked() -> None:
    fake = SelfAssessmentFakeDB()
    app_a, _ = build_app(fake=fake, clinic_id=CLINIC_A, role="admin")
    draft = _create_draft(client_for(app_a))

    app_b, _ = build_app(
        fake=fake, clinic_id=CLINIC_B, user_id=ADMIN_USER_B, role="admin"
    )
    resp = client_for(app_b).put(
        f"/v1/governance/self-assessment/assessments/"
        f"{draft['assessment_id']}/answers/{QUESTION_SLUGS[0]}",
        json={"answer_value": "yes", "evidence_links": []},
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    # No answer should have been recorded.
    assert all(
        str(a["clinic_id"]) == CLINIC_A or str(a["clinic_id"]) == CLINIC_B
        for a in fake.answers
    )
    assert len(fake.answers) == 0


# ---------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------


def test_audit_events_written_for_admin_actions() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    d = _create_draft(c)
    aid = d["assessment_id"]
    _answer_all(c, aid)
    c.post(
        f"/v1/governance/self-assessment/assessments/{aid}/submit",
        headers=auth_headers(),
    )
    # Spawn a fresh draft cycle so we have a draft to archive.
    d2 = _create_draft(c)
    c.post(
        f"/v1/governance/self-assessment/assessments/"
        f"{d2['assessment_id']}/archive",
        headers=auth_headers(),
    )

    actions = [e["action"] for e in fake.audit_events]
    assert "self_assessment_created" in actions
    assert "self_assessment_answer_upserted" in actions
    assert "self_assessment_submitted" in actions
    assert "self_assessment_archived" in actions

    # Audit meta is metadata-only - no raw clinical content / forbidden
    # keys ever leaked into the meta blob.
    for e in fake.audit_events:
        _assert_no_forbidden_keys(e["meta"], where=f"audit({e['action']}).meta")


# ---------------------------------------------------------------------
# Response shape doctrine
# ---------------------------------------------------------------------


def test_no_raw_or_forbidden_fields_in_responses() -> None:
    app, fake = build_app(role="admin")
    c = client_for(app)
    d = _create_draft(c)
    _answer_all(c, d["assessment_id"])
    c.post(
        f"/v1/governance/self-assessment/assessments/{d['assessment_id']}/submit",
        headers=auth_headers(),
    )

    for url in (
        "/v1/governance/self-assessment/templates",
        f"/v1/governance/self-assessment/templates/{TEMPLATE_SLUG}",
        f"/v1/governance/self-assessment/templates/{TEMPLATE_SLUG}/questions",
        "/v1/governance/self-assessment/assessments",
        "/v1/governance/self-assessment/assessments/latest",
        f"/v1/governance/self-assessment/assessments/{d['assessment_id']}",
    ):
        resp = c.get(url, headers=auth_headers())
        assert resp.status_code == 200, (url, resp.text)
        _assert_no_forbidden_keys(resp.json(), where=url)
