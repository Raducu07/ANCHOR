"""Phase 2A-4.2 - Client-Facing Transparency endpoint tests.

Covers the nine endpoints under /v1/governance/client-transparency
(templates + clinic profile CRUD; publish is deferred to 2A-4.3).

Doctrine guards asserted here:
  * Templates list active-only by default; include_inactive=true
    requires admin tier.
  * Profile create is admin-tier only; categories must be subsets of
    the template's canonical defaults; text passes the blocklist.
  * The three "*_statement_enabled" booleans are LOCKED TRUE at the
    handler layer even when the request sends false.
  * Profile list is clinic-scoped (cross-clinic UUIDs are not found).
  * Activate supersedes ANY existing active row for the clinic (v1
    "one active per clinic" founder rule) - including across template
    boundaries.
  * Activate is idempotent on already-active rows; archive is
    idempotent on already-archived rows; both write no duplicate
    audit events on idempotent re-call.
  * Archive rejects active profiles.
  * Audit events are append-only metadata-only and contain no raw
    free text / no clinical content / no client identifiers.
  * Responses recursively contain no forbidden raw-content keys.
  * No `ON CONFLICT (clinic_id, action, idempotency_key)` literal in
    the module source (TD-BE / M6.10.1B regression guard).
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
STAFF_USER = "44444444-4444-4444-8444-444444444444"

TPL_V1 = "aaaaaaaa-0000-4000-8000-000000000001"
TPL_V2 = "aaaaaaaa-0000-4000-8000-000000000002"
TPL_RETIRED = "aaaaaaaa-0000-4000-8000-000000000099"


# Forbidden response keys that must never appear in any response
# envelope or audit meta.
FORBIDDEN_RESPONSE_KEYS = {
    "raw_prompt", "raw_output", "raw_input",
    "prompt", "draft", "input_text", "output_text",
    "transcript", "clinical_content", "case_material",
    "client_identifier", "patient_identifier",
    "consent_text", "legal_consent",
    "compliance_status", "competence_grade", "score",
    "pass_fail", "staff_certified", "clinical_safety_proof",
    "legal_approval", "reflection", "staff_reflection",
    "email", "first_name", "last_name", "user_email", "reviewer_email",
}


# ---------------------------------------------------------------------
# Test data helpers
# ---------------------------------------------------------------------


def _template(
    template_id: str,
    *,
    slug: str = "client_ai_use_transparency_v1",
    template_version: str = "1.0.0",
    title: str = "Client AI Use Transparency Statement",
    is_active: bool = True,
    permitted: Optional[List[str]] = None,
    prohibited: Optional[List[str]] = None,
) -> Dict[str, Any]:
    now = datetime(2026, 6, 3, 10, 0, 0, tzinfo=timezone.utc)
    return {
        "template_id": _uuid.UUID(template_id),
        "template_slug": slug,
        "template_version": template_version,
        "title": title,
        "summary": "Plain-language client-facing explanation.",
        "default_sections": {
            "sections": [
                {"key": "what_ai_may_be_used_for", "heading": "What AI may be used for"},
                {"key": "what_ai_is_not_used_for", "heading": "What AI is not used for"},
                {"key": "human_review", "heading": "Human review"},
                {"key": "privacy_and_confidentiality", "heading": "Privacy and confidentiality"},
                {"key": "questions_from_clients", "heading": "Questions from clients"},
            ],
        },
        "default_permitted_categories": list(permitted or [
            "draft_client_communication",
            "internal_summarisation",
            "administrative_support",
            "governance_and_learning_support",
        ]),
        "default_prohibited_categories": list(prohibited or [
            "diagnosis",
            "prescribing",
            "treatment_planning",
            "autonomous_clinical_decisions",
            "replacing_veterinary_judgement",
        ]),
        "rcvs_principle_mappings": ["RCVS_transparency"],
        "eu_ai_act_article_mappings": ["EU_AI_Act_Article_50"],
        "content_reference": f"docs/governance/client_transparency/{slug}-{template_version}.md",
        "content_sha256": None,
        "is_active": is_active,
        "superseded_by": None,
        "created_at": now,
        "updated_at": now,
    }


def _valid_create_body(**overrides: Any) -> Dict[str, Any]:
    body = {
        "template_slug": "client_ai_use_transparency_v1",
        "display_title": "How we use AI at the clinic",
        "plain_language_summary": (
            "We use AI to help with drafting client communications "
            "from facts our team confirms. The veterinary team reviews "
            "everything before it is used. AI is never used for "
            "diagnosis, prescribing, or treatment decisions."
        ),
        "permitted_use_categories": [
            "draft_client_communication", "administrative_support",
        ],
        "prohibited_use_categories": [
            "diagnosis", "prescribing", "autonomous_clinical_decisions",
        ],
    }
    body.update(overrides)
    return body


# ---------------------------------------------------------------------
# FakeDB
# ---------------------------------------------------------------------


class _Result:
    def __init__(self, row=None, rows=None):
        self._row = row
        self._rows = rows

    def mappings(self):
        return self

    def first(self):
        return self._row

    def all(self):
        return list(self._rows or [])


class ClientTransparencyFakeDB:
    """In-memory fake interpreting the client_transparency module's SQL."""

    def __init__(self) -> None:
        self.current_clinic: str = CLINIC_A
        self.templates: Dict[str, Dict[str, Any]] = {
            TPL_V1: _template(TPL_V1, slug="client_ai_use_transparency_v1"),
            TPL_V2: _template(
                TPL_V2, slug="client_ai_use_transparency_v2",
                template_version="2.0.0", title="Newer template",
            ),
            TPL_RETIRED: _template(
                TPL_RETIRED, slug="retired_transparency_template",
                is_active=False,
            ),
        }
        self.profiles: List[Dict[str, Any]] = []
        self.audit_events: List[Dict[str, Any]] = []
        self.committed = False
        self.rolled_back = False
        self.calls: List[tuple] = []

    # session shape
    def begin(self): return None
    def commit(self): self.committed = True
    def rollback(self): self.rolled_back = True
    def close(self): return None

    # helpers
    def _by_slug(self, slug, version=None):
        for t in self.templates.values():
            if t["template_slug"] != slug:
                continue
            if version is not None and t["template_version"] != version:
                continue
            return t
        return None

    def _scoped_profiles(self) -> List[Dict[str, Any]]:
        return [p for p in self.profiles
                if p["clinic_id"] == self.current_clinic]

    def execute(self, statement, params=None):
        sql = str(getattr(statement, "text", statement))
        p = dict(params or {})
        self.calls.append((sql, p))

        # ---- templates: list ----
        if (
            "FROM client_transparency_templates" in sql
            and "ORDER BY title" in sql
        ):
            rows = list(self.templates.values())
            if "is_active = true" in sql:
                rows = [t for t in rows if t["is_active"]]
            rows = sorted(rows, key=lambda t: t["title"])
            return _Result(rows=rows)

        # ---- templates: by template_id (used by PUT category validation) ----
        if (
            "FROM client_transparency_templates" in sql
            and "template_id = CAST(:template_id AS uuid)" in sql
        ):
            tid = p["template_id"]
            for t in self.templates.values():
                if str(t["template_id"]) == tid:
                    return _Result(row=t)
            return _Result(row=None)

        # ---- templates: by slug ----
        if (
            "FROM client_transparency_templates" in sql
            and "template_slug = :template_slug" in sql
        ):
            return _Result(row=self._by_slug(
                p["template_slug"], p.get("template_version"),
            ))

        # ---- MAX(clinic_profile_version) for create ----
        if (
            "MAX(clinic_profile_version)" in sql
            and "clinic_client_transparency_profiles" in sql
        ):
            vs = [
                int(pp["clinic_profile_version"])
                for pp in self._scoped_profiles()
                if str(pp["client_transparency_template_id"]) == p["template_id"]
            ]
            return _Result(row={"v": max(vs) if vs else 0})

        # ---- INSERT profile ----
        if "INSERT INTO clinic_client_transparency_profiles" in sql:
            now = datetime.now(timezone.utc)
            row = {
                "clinic_profile_id": _uuid.uuid4(),
                "clinic_id": p["clinic_id"],
                "client_transparency_template_id": _uuid.UUID(p["template_id"]),
                "template_version_snapshot": p["template_version_snapshot"],
                "clinic_profile_version": int(p["clinic_profile_version"]),
                "status": "draft",
                "display_title": p["display_title"],
                "plain_language_summary": p["plain_language_summary"],
                "permitted_use_categories": list(p["permitted_use_categories"]),
                "prohibited_use_categories": list(p["prohibited_use_categories"]),
                # Booleans are hardcoded TRUE in the INSERT SQL regardless
                # of payload - reflect that here.
                "human_review_statement_enabled": True,
                "privacy_statement_enabled": True,
                "client_explanation_statement_enabled": True,
                "content_sha256_snapshot": p.get("content_sha256_snapshot"),
                "created_by_user_id": _uuid.UUID(p["created_by_user_id"]),
                "activated_by_user_id": None,
                "activated_at": None,
                "superseded_at": None,
                "effective_from": None,
                "created_at": now,
                "updated_at": now,
            }
            self.profiles.append(row)
            return _Result(row=row)

        # ---- SELECT profile by id (clinic-scoped) ----
        if (
            "FROM clinic_client_transparency_profiles" in sql
            and "clinic_profile_id = CAST(:clinic_profile_id AS uuid)" in sql
            and "UPDATE" not in sql
        ):
            for pp in self._scoped_profiles():
                if str(pp["clinic_profile_id"]) == p["clinic_profile_id"]:
                    return _Result(row=pp)
            return _Result(row=None)

        # ---- supersede prior active for THIS CLINIC (any template) ----
        if (
            "UPDATE clinic_client_transparency_profiles" in sql
            and "status = 'superseded'" in sql
        ):
            for pp in self._scoped_profiles():
                if pp["status"] == "active":
                    pp["status"] = "superseded"
                    pp["superseded_at"] = datetime.now(timezone.utc)
                    pp["updated_at"] = datetime.now(timezone.utc)
            return _Result(row=None)

        # ---- activate draft ----
        if (
            "UPDATE clinic_client_transparency_profiles" in sql
            and "status = 'active'" in sql
            and "RETURNING" in sql
        ):
            for pp in self._scoped_profiles():
                if (
                    str(pp["clinic_profile_id"]) == p["clinic_profile_id"]
                    and pp["status"] == "draft"
                ):
                    now = datetime.now(timezone.utc)
                    pp["status"] = "active"
                    pp["activated_by_user_id"] = _uuid.UUID(p["actor"])
                    pp["activated_at"] = now
                    if pp["effective_from"] is None:
                        pp["effective_from"] = now
                    pp["updated_at"] = now
                    return _Result(row=pp)
            return _Result(row=None)

        # ---- archive draft/superseded ----
        if (
            "UPDATE clinic_client_transparency_profiles" in sql
            and "status = 'archived'" in sql
            and "RETURNING" in sql
        ):
            for pp in self._scoped_profiles():
                if (
                    str(pp["clinic_profile_id"]) == p["clinic_profile_id"]
                    and pp["status"] in ("draft", "superseded")
                ):
                    pp["status"] = "archived"
                    pp["updated_at"] = datetime.now(timezone.utc)
                    return _Result(row=pp)
            return _Result(row=None)

        # ---- PUT update (draft only) ----
        if (
            "UPDATE clinic_client_transparency_profiles" in sql
            and "RETURNING" in sql
            and "SET updated_at = now()" in sql
        ):
            for pp in self._scoped_profiles():
                if (
                    str(pp["clinic_profile_id"]) == p["clinic_profile_id"]
                    and pp["status"] == "draft"
                ):
                    if "display_title" in p:
                        pp["display_title"] = p["display_title"]
                    if "plain_language_summary" in p:
                        pp["plain_language_summary"] = p["plain_language_summary"]
                    if "permitted_use_categories" in p:
                        pp["permitted_use_categories"] = list(
                            p["permitted_use_categories"]
                        )
                    if "prohibited_use_categories" in p:
                        pp["prohibited_use_categories"] = list(
                            p["prohibited_use_categories"]
                        )
                    pp["updated_at"] = datetime.now(timezone.utc)
                    return _Result(row=pp)
            return _Result(row=None)

        # ---- active profile lookup ----
        if (
            "FROM clinic_client_transparency_profiles" in sql
            and "status = 'active'" in sql
            and "ORDER BY" not in sql
            and "RETURNING" not in sql
            and "UPDATE" not in sql
        ):
            for pp in self._scoped_profiles():
                if pp["status"] == "active":
                    return _Result(row=pp)
            return _Result(row=None)

        # ---- list profiles (clinic-scoped) ----
        if (
            "FROM clinic_client_transparency_profiles" in sql
            and "ORDER BY created_at DESC" in sql
        ):
            rows = list(self._scoped_profiles())
            if "status = :status" in sql and "status" in p:
                rows = [pp for pp in rows if pp["status"] == p["status"]]
            rows = sorted(rows, key=lambda pp: pp["created_at"], reverse=True)
            return _Result(rows=rows[: int(p.get("limit", 25))])

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
    authenticated: bool = True,
    clinic_id: str = CLINIC_A,
    user_id: str = ADMIN_USER,
    role: str = "admin",
) -> tuple:
    from app.auth_and_rls import require_clinic_user
    from app.db import get_db
    from app.client_transparency import router

    app = FastAPI()
    app.include_router(router)
    fake = ClientTransparencyFakeDB()

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
    if isinstance(payload, dict):
        leaked = set(payload.keys()) & FORBIDDEN_RESPONSE_KEYS
        assert not leaked, f"forbidden keys leaked in {where}: {leaked}"
        for k, v in payload.items():
            _assert_no_forbidden_keys(v, where=f"{where}.{k}")
    elif isinstance(payload, list):
        for i, v in enumerate(payload):
            _assert_no_forbidden_keys(v, where=f"{where}[{i}]")


# ---------------------------------------------------------------------
# 1 / 2. Templates
# ---------------------------------------------------------------------


def test_list_templates_returns_active_seed_template() -> None:
    app, _fake = build_app(role="staff")
    resp = client_for(app).get(
        "/v1/governance/client-transparency/templates",
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    slugs = {t["template_slug"] for t in body["templates"]}
    assert "client_ai_use_transparency_v1" in slugs
    assert "retired_transparency_template" not in slugs
    assert "governance_note" in body
    _assert_no_forbidden_keys(body)


def test_non_admin_cannot_use_include_inactive() -> None:
    app, _fake = build_app(role="staff")
    resp = client_for(app).get(
        "/v1/governance/client-transparency/templates?include_inactive=true",
        headers=auth_headers(),
    )
    assert resp.status_code == 403
    assert resp.json().get("detail") == "forbidden_not_admin"


def test_admin_include_inactive_returns_retired_template() -> None:
    app, _fake = build_app(role="admin")
    resp = client_for(app).get(
        "/v1/governance/client-transparency/templates?include_inactive=true",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    slugs = {t["template_slug"] for t in resp.json()["templates"]}
    assert "retired_transparency_template" in slugs


def test_get_template_by_slug_success() -> None:
    app, _fake = build_app(role="staff")
    resp = client_for(app).get(
        "/v1/governance/client-transparency/templates/client_ai_use_transparency_v1",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["template"]["template_slug"] == "client_ai_use_transparency_v1"
    assert body["template"]["template_version"] == "1.0.0"
    assert isinstance(body["template"]["default_sections"], dict)
    _assert_no_forbidden_keys(body)


def test_get_template_missing_returns_404() -> None:
    app, _fake = build_app(role="admin")
    resp = client_for(app).get(
        "/v1/governance/client-transparency/templates/no_such_template",
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "client_transparency_template_not_found"


def test_inactive_template_hidden_from_staff() -> None:
    app, _fake = build_app(role="staff")
    resp = client_for(app).get(
        "/v1/governance/client-transparency/templates/retired_transparency_template",
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "client_transparency_template_not_found"


def test_inactive_template_visible_to_admin() -> None:
    app, _fake = build_app(role="admin")
    resp = client_for(app).get(
        "/v1/governance/client-transparency/templates/retired_transparency_template",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["template"]["template_slug"] == "retired_transparency_template"


# ---------------------------------------------------------------------
# 3. Create draft profile
# ---------------------------------------------------------------------


@pytest.mark.parametrize("role", ["admin", "owner", "practice_manager"])
def test_admin_tier_can_create_draft(role: str) -> None:
    app, fake = build_app(role=role)
    resp = client_for(app).post(
        "/v1/governance/client-transparency/profiles",
        json=_valid_create_body(),
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    p = body["profile"]
    assert p["status"] == "draft"
    assert p["clinic_profile_version"] == 1
    assert p["display_title"] == "How we use AI at the clinic"
    _assert_no_forbidden_keys(body)


@pytest.mark.parametrize("role", ["staff", "clinic_user", "reader"])
def test_non_admin_cannot_create_draft(role: str) -> None:
    app, fake = build_app(role=role)
    resp = client_for(app).post(
        "/v1/governance/client-transparency/profiles",
        json=_valid_create_body(),
        headers=auth_headers(),
    )
    assert resp.status_code == 403
    assert resp.json().get("detail") == "forbidden_not_admin"
    assert fake.profiles == []


def test_create_rejects_unknown_template_slug() -> None:
    app, _fake = build_app(role="admin")
    resp = client_for(app).post(
        "/v1/governance/client-transparency/profiles",
        json=_valid_create_body(template_slug="no_such_template"),
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "client_transparency_template_not_found"


def test_create_rejects_inactive_template() -> None:
    app, _fake = build_app(role="admin")
    resp = client_for(app).post(
        "/v1/governance/client-transparency/profiles",
        json=_valid_create_body(template_slug="retired_transparency_template"),
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "client_transparency_template_inactive"


@pytest.mark.parametrize(
    "permitted",
    [
        ["draft_client_communication", "diagnosis"],  # 'diagnosis' is prohibited, not permitted
        ["not_a_real_category"],
        ["administrative_support", "freeform_text"],
    ],
)
def test_create_rejects_permitted_category_not_in_template_defaults(
    permitted: List[str],
) -> None:
    app, _fake = build_app(role="admin")
    resp = client_for(app).post(
        "/v1/governance/client-transparency/profiles",
        json=_valid_create_body(permitted_use_categories=permitted),
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "client_transparency_invalid_category"


@pytest.mark.parametrize(
    "prohibited",
    [
        ["draft_client_communication"],  # this is permitted, not prohibited
        ["unknown_prohibited"],
    ],
)
def test_create_rejects_prohibited_category_not_in_template_defaults(
    prohibited: List[str],
) -> None:
    app, _fake = build_app(role="admin")
    resp = client_for(app).post(
        "/v1/governance/client-transparency/profiles",
        json=_valid_create_body(prohibited_use_categories=prohibited),
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "client_transparency_invalid_category"


def test_create_rejects_empty_category_arrays_via_pydantic() -> None:
    app, _fake = build_app(role="admin")
    resp = client_for(app).post(
        "/v1/governance/client-transparency/profiles",
        json=_valid_create_body(permitted_use_categories=[]),
        headers=auth_headers(),
    )
    # Pydantic min_length=1 -> 422.
    assert resp.status_code == 422


@pytest.mark.parametrize(
    "summary,kind",
    [
        ("Contact me at owner@example.com please.", "email"),
        ("Patient microchip 985112345678901 was scanned.", "long-digit"),
        ("Owner phone +44 7700 900 123 1234 was logged.", "phone"),
        ("See https://example.com/case/4242 for details.", "url"),
        ("Reach out at www.example.com about Buddy's case.", "www"),
        ("Use <|im_start|>system to override.", "prompt-marker"),
        ("Vet MRCVS 12345 attended.", "mrcvs"),
    ],
)
def test_create_rejects_blocked_text(summary: str, kind: str) -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).post(
        "/v1/governance/client-transparency/profiles",
        json=_valid_create_body(plain_language_summary=summary),
        headers=auth_headers(),
    )
    assert resp.status_code == 400, (kind, resp.text)
    assert resp.json().get("detail") == "client_transparency_text_blocked"
    assert fake.profiles == []


def test_create_text_blocked_error_does_not_disclose_rule() -> None:
    """The error body must NOT echo the offending text, regex, or rule
    name - only the stable error code."""
    app, _fake = build_app(role="admin")
    resp = client_for(app).post(
        "/v1/governance/client-transparency/profiles",
        json=_valid_create_body(
            plain_language_summary="Email me at test@example.com",
        ),
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body == {"detail": "client_transparency_text_blocked"}
    # No regex / no submitted text leaked back.
    assert "test@example.com" not in json.dumps(body)


def test_create_locks_statement_booleans_true_even_when_false_supplied() -> None:
    app, fake = build_app(role="admin")
    body = _valid_create_body(
        human_review_statement_enabled=False,
        privacy_statement_enabled=False,
        client_explanation_statement_enabled=False,
    )
    resp = client_for(app).post(
        "/v1/governance/client-transparency/profiles",
        json=body,
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text
    p = resp.json()["profile"]
    assert p["human_review_statement_enabled"] is True
    assert p["privacy_statement_enabled"] is True
    assert p["client_explanation_statement_enabled"] is True


def test_create_rejects_unknown_extras_via_extra_forbid() -> None:
    app, fake = build_app(role="admin")
    body = _valid_create_body()
    body["consent_text"] = "I consent to..."
    body["compliance_status"] = "ok"
    resp = client_for(app).post(
        "/v1/governance/client-transparency/profiles",
        json=body,
        headers=auth_headers(),
    )
    assert resp.status_code == 422
    assert fake.profiles == []


def test_create_writes_metadata_only_audit_event() -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).post(
        "/v1/governance/client-transparency/profiles",
        json=_valid_create_body(),
        headers=auth_headers(),
    )
    assert resp.status_code == 201
    assert len(fake.audit_events) == 1
    ev = fake.audit_events[0]
    assert ev["action"] == "governance_client_transparency_profile_created"
    assert ev["clinic_id"] == CLINIC_A
    # Audit meta carries IDs + counts only, no raw text.
    meta = ev["meta"]
    assert set(meta.keys()) == {
        "template_slug",
        "template_version_snapshot",
        "clinic_profile_version",
        "status",
        "permitted_category_count",
        "prohibited_category_count",
    }
    meta_str = json.dumps(meta)
    assert "How we use AI at the clinic" not in meta_str
    assert "veterinary team" not in meta_str  # plain_language_summary not in audit
    _assert_no_forbidden_keys(meta, where="audit.meta")


# ---------------------------------------------------------------------
# 4. List clinic profiles
# ---------------------------------------------------------------------


def _seed_draft(fake: ClientTransparencyFakeDB,
                *, clinic_id: str = CLINIC_A,
                template_id: str = TPL_V1,
                clinic_profile_version: int = 1,
                status: str = "draft") -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    row = {
        "clinic_profile_id": _uuid.uuid4(),
        "clinic_id": clinic_id,
        "client_transparency_template_id": _uuid.UUID(template_id),
        "template_version_snapshot": "1.0.0",
        "clinic_profile_version": clinic_profile_version,
        "status": status,
        "display_title": "How we use AI",
        "plain_language_summary": "Bounded, human-reviewed AI use.",
        "permitted_use_categories": ["draft_client_communication"],
        "prohibited_use_categories": ["diagnosis"],
        "human_review_statement_enabled": True,
        "privacy_statement_enabled": True,
        "client_explanation_statement_enabled": True,
        "content_sha256_snapshot": None,
        "created_by_user_id": _uuid.UUID(ADMIN_USER),
        "activated_by_user_id": None,
        "activated_at": None,
        "superseded_at": None,
        "effective_from": None,
        "created_at": now,
        "updated_at": now,
    }
    fake.profiles.append(row)
    return row


@pytest.mark.parametrize("role", ["staff", "clinic_user", "reader", "admin"])
def test_list_profiles_visible_to_all_roles(role: str) -> None:
    app, fake = build_app(role=role)
    _seed_draft(fake)
    _seed_draft(fake, clinic_profile_version=2)
    resp = client_for(app).get(
        "/v1/governance/client-transparency/profiles",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert len(resp.json()["profiles"]) == 2


def test_list_profiles_status_filter() -> None:
    app, fake = build_app(role="admin")
    rows = [_seed_draft(fake), _seed_draft(fake, clinic_profile_version=2)]
    rows[0]["status"] = "active"
    resp = client_for(app).get(
        "/v1/governance/client-transparency/profiles?status=active",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["profiles"]) == 1
    assert body["profiles"][0]["status"] == "active"


def test_list_profiles_invalid_status_400() -> None:
    app, _fake = build_app(role="admin")
    resp = client_for(app).get(
        "/v1/governance/client-transparency/profiles?status=bogus",
        headers=auth_headers(),
    )
    assert resp.status_code == 400


def test_list_profiles_clinic_scoped() -> None:
    app, fake = build_app(role="admin", clinic_id=CLINIC_A)
    other = _seed_draft(fake, clinic_id=CLINIC_B)
    resp = client_for(app).get(
        "/v1/governance/client-transparency/profiles",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    ids = [pp["clinic_profile_id"] for pp in resp.json()["profiles"]]
    assert str(other["clinic_profile_id"]) not in ids


# ---------------------------------------------------------------------
# 5. /profiles/active
# ---------------------------------------------------------------------


def test_active_profile_returns_404_before_activation() -> None:
    app, fake = build_app(role="staff")
    _seed_draft(fake)
    resp = client_for(app).get(
        "/v1/governance/client-transparency/profiles/active",
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "client_transparency_profile_not_found"


def test_active_profile_returns_active_row() -> None:
    app, fake = build_app(role="staff")
    row = _seed_draft(fake)
    row["status"] = "active"
    row["activated_at"] = datetime.now(timezone.utc)
    resp = client_for(app).get(
        "/v1/governance/client-transparency/profiles/active",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["profile"]["status"] == "active"


# ---------------------------------------------------------------------
# 6. Get profile by id
# ---------------------------------------------------------------------


def test_get_profile_unknown_id_404() -> None:
    app, _fake = build_app(role="admin")
    resp = client_for(app).get(
        f"/v1/governance/client-transparency/profiles/{_uuid.uuid4()}",
        headers=auth_headers(),
    )
    assert resp.status_code == 404


def test_get_profile_cross_clinic_404() -> None:
    app, fake = build_app(role="admin", clinic_id=CLINIC_A)
    other = _seed_draft(fake, clinic_id=CLINIC_B)
    resp = client_for(app).get(
        f"/v1/governance/client-transparency/profiles/{other['clinic_profile_id']}",
        headers=auth_headers(),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------
# 7. PUT update draft
# ---------------------------------------------------------------------


def test_update_draft_works() -> None:
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    resp = client_for(app).put(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}",
        json={"display_title": "Updated title for our clinic"},
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["profile"]["display_title"] == "Updated title for our clinic"


def test_update_non_draft_rejected() -> None:
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    row["status"] = "active"
    resp = client_for(app).put(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}",
        json={"display_title": "Should not apply"},
        headers=auth_headers(),
    )
    assert resp.status_code == 409
    assert resp.json().get("detail") == "client_transparency_profile_not_draft"


def test_update_requires_admin() -> None:
    app, fake = build_app(role="staff")
    row = _seed_draft(fake)
    resp = client_for(app).put(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}",
        json={"display_title": "Should be 403"},
        headers=auth_headers(),
    )
    assert resp.status_code == 403


def test_update_rejects_empty_body() -> None:
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    resp = client_for(app).put(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}",
        json={},
        headers=auth_headers(),
    )
    # No editable fields supplied -> 400.
    assert resp.status_code == 400
    assert resp.json().get("detail") == "client_transparency_update_empty"


def test_update_rejects_blocked_text() -> None:
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    resp = client_for(app).put(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}",
        json={"display_title": "Email owner@example.com"},
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "client_transparency_text_blocked"


def test_update_rejects_invalid_category() -> None:
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    resp = client_for(app).put(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}",
        json={"permitted_use_categories": ["diagnosis"]},  # this is prohibited
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "client_transparency_invalid_category"


def test_update_locks_statement_booleans_true() -> None:
    """PUT may submit the locked booleans but they are ignored - the
    DB never receives a false value for them in this slice."""
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    resp = client_for(app).put(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}",
        json={
            "display_title": "Still updating",
            "human_review_statement_enabled": False,
            "privacy_statement_enabled": False,
            "client_explanation_statement_enabled": False,
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    p = resp.json()["profile"]
    assert p["human_review_statement_enabled"] is True
    assert p["privacy_statement_enabled"] is True
    assert p["client_explanation_statement_enabled"] is True
    # Confirm no SET clause for any locked boolean was issued (the
    # RETURNING clause carries those column names but only the SET
    # clause writes; isolate the SET region for the assertion).
    for sql, _params in fake.calls:
        if (
            "UPDATE clinic_client_transparency_profiles" in sql
            and "RETURNING" in sql
            and "SET " in sql
        ):
            set_region = sql.split("SET ", 1)[1].split("WHERE", 1)[0]
            assert "human_review_statement_enabled" not in set_region
            assert "privacy_statement_enabled" not in set_region
            assert "client_explanation_statement_enabled" not in set_region


# ---------------------------------------------------------------------
# 8. Activate
# ---------------------------------------------------------------------


def test_admin_can_activate_draft() -> None:
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    resp = client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}/activate",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    p = resp.json()["profile"]
    assert p["status"] == "active"
    assert p["activated_by_user_id"] == ADMIN_USER


def test_activate_supersedes_any_existing_active_for_clinic() -> None:
    """v1 founder rule: ONE active profile per clinic, even if it
    adopts a different template. Activating a draft must supersede
    the active row across template boundaries."""
    app, fake = build_app(role="admin")
    first = _seed_draft(fake)
    first["status"] = "active"
    first["activated_at"] = datetime.now(timezone.utc)
    # Second draft adopting a DIFFERENT template.
    second = _seed_draft(
        fake, template_id=TPL_V2, clinic_profile_version=1,
    )
    resp = client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{second['clinic_profile_id']}/activate",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    statuses = {str(pp["clinic_profile_id"]): pp["status"]
                for pp in fake.profiles}
    assert statuses[str(first["clinic_profile_id"])] == "superseded"
    assert statuses[str(second["clinic_profile_id"])] == "active"


def test_activate_idempotent_when_already_active() -> None:
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    # Activate once.
    client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}/activate",
        headers=auth_headers(),
    )
    audit_count_before = len(fake.audit_events)
    # Activate again.
    resp = client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}/activate",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["profile"]["status"] == "active"
    assert len(fake.audit_events) == audit_count_before


def test_activate_writes_audit_event() -> None:
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}/activate",
        headers=auth_headers(),
    )
    activated = [
        e for e in fake.audit_events
        if e["action"] == "governance_client_transparency_profile_activated"
    ]
    assert len(activated) == 1
    meta = activated[0]["meta"]
    assert set(meta.keys()) == {
        "client_transparency_template_id",
        "clinic_profile_version",
        "template_version_snapshot",
        "status",
        "previous_status",
    }
    _assert_no_forbidden_keys(meta, where="audit.meta")


def test_staff_cannot_activate() -> None:
    app, fake = build_app(role="staff")
    row = _seed_draft(fake)
    resp = client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}/activate",
        headers=auth_headers(),
    )
    assert resp.status_code == 403


def test_activate_unknown_id_404() -> None:
    app, _fake = build_app(role="admin")
    resp = client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{_uuid.uuid4()}/activate",
        headers=auth_headers(),
    )
    assert resp.status_code == 404


def test_activate_superseded_or_archived_rejected() -> None:
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    row["status"] = "superseded"
    resp = client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}/activate",
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "client_transparency_profile_not_in_draft"


# ---------------------------------------------------------------------
# 9. Archive
# ---------------------------------------------------------------------


def test_admin_can_archive_draft() -> None:
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    resp = client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}/archive",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["profile"]["status"] == "archived"


def test_admin_can_archive_superseded() -> None:
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    row["status"] = "superseded"
    resp = client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}/archive",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["profile"]["status"] == "archived"


def test_archive_active_rejected() -> None:
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    row["status"] = "active"
    resp = client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}/archive",
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "client_transparency_active_profile_cannot_be_archived"


def test_archive_already_archived_idempotent_no_duplicate_audit() -> None:
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    row["status"] = "archived"
    audit_count_before = len(fake.audit_events)
    resp = client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}/archive",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert len(fake.audit_events) == audit_count_before


def test_archive_writes_audit_event() -> None:
    app, fake = build_app(role="admin")
    row = _seed_draft(fake)
    client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}/archive",
        headers=auth_headers(),
    )
    archived = [
        e for e in fake.audit_events
        if e["action"] == "governance_client_transparency_profile_archived"
    ]
    assert len(archived) == 1
    meta = archived[0]["meta"]
    assert set(meta.keys()) == {
        "client_transparency_template_id",
        "clinic_profile_version",
        "previous_status",
        "status",
    }


def test_staff_cannot_archive() -> None:
    app, fake = build_app(role="staff")
    row = _seed_draft(fake)
    resp = client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{row['clinic_profile_id']}/archive",
        headers=auth_headers(),
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------
# 10. Doctrine guards / regression
# ---------------------------------------------------------------------


def test_unauthenticated_returns_401() -> None:
    app, _fake = build_app(authenticated=False)
    paths = [
        "/v1/governance/client-transparency/templates",
        "/v1/governance/client-transparency/profiles",
        "/v1/governance/client-transparency/profiles/active",
    ]
    for path in paths:
        resp = TestClient(app).get(path)
        assert resp.status_code == 401, path


def test_no_invalid_partial_index_on_conflict_in_module() -> None:
    """M6.10.1B / TD-BE regression - assemble the forbidden literal at
    runtime so this test source itself doesn't carry it."""
    import inspect
    from app import client_transparency
    fragment = (
        "ON CONFLICT (clinic_id, " + "action, " + "idempotency_key)"
    )
    assert fragment not in inspect.getsource(client_transparency)


def test_module_does_not_import_assistant_or_policy_modules() -> None:
    """Conflation guard: client transparency is a deliberately
    separate surface from Assistant runtime policy and governance
    policy library."""
    import inspect
    from app import client_transparency
    src = inspect.getsource(client_transparency)
    assert "from app.assistant_policy" not in src
    assert "from app.governance_policy" not in src


def test_module_does_not_import_learn_or_cpd_paths() -> None:
    import inspect
    from app import client_transparency
    src = inspect.getsource(client_transparency)
    assert "from app.learn_v1" not in src
    assert "learning_completions" not in src
    assert "cpd_exports" not in src


def test_no_publish_endpoints_yet() -> None:
    """2A-4.3 will add /publish endpoints. They must not exist yet."""
    from app.client_transparency import router
    paths = {r.path for r in router.routes}
    assert not any("/publish" in p for p in paths), (
        f"publish endpoints unexpectedly registered: {paths}"
    )
    assert not any("/public/" in p for p in paths), (
        f"public-version endpoints unexpectedly registered: {paths}"
    )


def test_router_registers_exactly_nine_endpoints() -> None:
    from app.client_transparency import router
    # Count distinct (method, path) pairs.
    pairs = set()
    for r in router.routes:
        methods = getattr(r, "methods", None) or set()
        for m in methods:
            if m in ("HEAD", "OPTIONS"):
                continue
            pairs.add((m, r.path))
    assert len(pairs) == 9, sorted(pairs)


def test_all_response_envelopes_metadata_only() -> None:
    app, fake = build_app(role="admin")
    # Create draft.
    resp = client_for(app).post(
        "/v1/governance/client-transparency/profiles",
        json=_valid_create_body(),
        headers=auth_headers(),
    )
    assert resp.status_code == 201
    cpid = resp.json()["profile"]["clinic_profile_id"]

    for url in (
        "/v1/governance/client-transparency/templates",
        "/v1/governance/client-transparency/templates/client_ai_use_transparency_v1",
        "/v1/governance/client-transparency/profiles",
        f"/v1/governance/client-transparency/profiles/{cpid}",
    ):
        r = client_for(app).get(url, headers=auth_headers())
        assert r.status_code == 200, (url, r.text)
        _assert_no_forbidden_keys(r.json(), where=url)

    # Activate then assert.
    r = client_for(app).post(
        f"/v1/governance/client-transparency/profiles/{cpid}/activate",
        headers=auth_headers(),
    )
    assert r.status_code == 200
    _assert_no_forbidden_keys(r.json(), where="activate")
