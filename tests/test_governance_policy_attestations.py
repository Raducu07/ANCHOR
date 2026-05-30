"""Phase 2A-2.3 - Staff Attestation endpoint tests.

Covers:
  * GET /me/outstanding (self, clinic-scoped)
  * POST /clinic-policies/{cpv_id}/attest (self, idempotent, 409 on
    previously-voided)
  * GET /me/attestations (self only, include_voided gate)
  * GET /attestations (admin tier, filters + clinic-scoping)
  * POST /attestations/{attestation_id}/void (admin tier, audit row,
    idempotent re-void)

The test file subclasses GovernanceFakeDB from the 2A-2.2 endpoint
tests to add `policy_attestations` SQL handling. The base file is
otherwise unchanged.

Doctrine guards asserted here:
  * Attestation surface stores no policy_body / policy_text /
    competence_grade / score / pass_fail / staff_reflection /
    compliance_status / clinical_safety_proof / legal_approval.
  * Self-attestation does NOT write admin_audit_events.
  * Admin void writes exactly one audit event with metadata-only
    `meta` (no free-text reflection, no policy body).
  * Attestation does NOT call Learn / CPD code paths.
  * No invalid partial-index `ON CONFLICT` against
    admin_audit_events anywhere in the module source.
"""
from __future__ import annotations

import json
import sys
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Reuse the 2A-2.2 helpers / FakeDB / constants.
from tests.test_governance_policy_endpoints import (  # noqa: E402
    ADMIN_USER,
    ALL_AUDIENCE,
    CLINIC_A,
    CLINIC_B,
    FORBIDDEN_RESPONSE_KEYS,
    GovernanceFakeDB,
    STAFF_USER,
    TPL_AI_USE,
    TPL_DISCLOSURE,
    _Result,
    _assert_no_forbidden_keys,
    auth_headers,
    client_for,
)


OTHER_USER = "55555555-5555-4555-8555-555555555555"


# ---------------------------------------------------------------------
# FakeDB extension: policy_attestations SQL handling
# ---------------------------------------------------------------------


class AttestationFakeDB(GovernanceFakeDB):
    """Extends the 2A-2.2 FakeDB with policy_attestations + outstanding
    + admin-listing JOIN handling."""

    def __init__(self) -> None:
        super().__init__()
        self.policy_attestations: List[Dict[str, Any]] = []

    def _scoped_attestations(self) -> List[Dict[str, Any]]:
        return [a for a in self.policy_attestations
                if a["clinic_id"] == self.current_clinic]

    def _template_by_id(self, template_id: str) -> Optional[Dict[str, Any]]:
        for t in self.templates.values():
            if str(t["template_id"]) == template_id:
                return t
        return None

    def execute(self, statement, params=None):
        sql = str(getattr(statement, "text", statement))
        p = dict(params or {})

        # ---- outstanding: active cpvs NOT EXISTS attestation ----
        if (
            "FROM clinic_policy_versions cpv" in sql
            and "NOT EXISTS" in sql
            and "FROM policy_attestations pa" in sql
        ):
            self.calls.append((sql, p))
            user_id = p["user_id"]
            existing_keys = {
                (str(a["clinic_policy_version_id"]), str(a["user_id"]))
                for a in self._scoped_attestations()
            }
            rows = []
            for c in self._scoped_cpvs():
                if c["status"] != "active":
                    continue
                if (str(c["clinic_policy_version_id"]), user_id) in existing_keys:
                    continue
                rows.append(c)
            rows = sorted(
                rows,
                key=lambda c: c["activated_at"]
                or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True,
            )
            return _Result(rows=rows)

        # ---- SELECT attestation for (clinic, cpv, user) lookup ----
        if (
            "FROM policy_attestations" in sql
            and "clinic_policy_version_id = CAST(:cpv_id AS uuid)" in sql
            and "user_id = CAST(:user_id AS uuid)" in sql
            and "INSERT" not in sql
            and "UPDATE" not in sql
        ):
            self.calls.append((sql, p))
            for a in self._scoped_attestations():
                if (
                    str(a["clinic_policy_version_id"]) == p["cpv_id"]
                    and str(a["user_id"]) == p["user_id"]
                ):
                    return _Result(row=a)
            return _Result(row=None)

        # ---- INSERT attestation ----
        if "INSERT INTO policy_attestations" in sql:
            self.calls.append((sql, p))
            now = datetime.now(timezone.utc)
            row = {
                "attestation_id": _uuid.uuid4(),
                "clinic_id": p["clinic_id"],
                "clinic_policy_version_id": _uuid.UUID(p["cpv_id"]),
                "user_id": _uuid.UUID(p["user_id"]),
                "attestation_statement_version": p[
                    "attestation_statement_version"
                ],
                "acknowledged_at": now,
                "acknowledgement_method": p["acknowledgement_method"],
                "policy_content_sha256_snapshot": p.get(
                    "policy_content_sha256_snapshot"
                ),
                "ip_hash": p.get("ip_hash"),
                "is_voided": False,
                "void_reason": None,
                "voided_at": None,
                "voided_by_user_id": None,
                "created_at": now,
            }
            self.policy_attestations.append(row)
            return _Result(row=row)

        # ---- SELECT attestation by clinic + attestation_id (for void) ----
        if (
            "FROM policy_attestations" in sql
            and "attestation_id = CAST(:attestation_id AS uuid)" in sql
            and "UPDATE" not in sql
        ):
            self.calls.append((sql, p))
            for a in self._scoped_attestations():
                if str(a["attestation_id"]) == p["attestation_id"]:
                    return _Result(row=a)
            return _Result(row=None)

        # ---- UPDATE attestation (void) ----
        if (
            "UPDATE policy_attestations" in sql
            and "is_voided = true" in sql
        ):
            self.calls.append((sql, p))
            for a in self._scoped_attestations():
                if (
                    str(a["attestation_id"]) == p["attestation_id"]
                    and not a["is_voided"]
                ):
                    a["is_voided"] = True
                    a["void_reason"] = p["void_reason"]
                    a["voided_at"] = datetime.now(timezone.utc)
                    a["voided_by_user_id"] = _uuid.UUID(p["actor"])
                    return _Result(row=a)
            return _Result(row=None)

        # ---- self list: clinic + user, no JOIN ----
        if (
            "FROM policy_attestations" in sql
            and "user_id = CAST(:user_id AS uuid)" in sql
            and "ORDER BY acknowledged_at DESC" in sql
            and "JOIN" not in sql
        ):
            self.calls.append((sql, p))
            rows = [a for a in self._scoped_attestations()
                    if str(a["user_id"]) == p["user_id"]]
            if "is_voided = false" in sql:
                rows = [a for a in rows if not a["is_voided"]]
            rows = sorted(rows, key=lambda a: a["acknowledged_at"], reverse=True)
            rows = rows[: int(p.get("limit", 25))]
            return _Result(rows=rows)

        # ---- admin list: JOIN cpv (+ optional template) ----
        if (
            "FROM policy_attestations pa" in sql
            and "JOIN clinic_policy_versions cpv" in sql
        ):
            self.calls.append((sql, p))
            rows = list(self._scoped_attestations())
            if "pa.clinic_policy_version_id = CAST(:cpv_id AS uuid)" in sql:
                rows = [a for a in rows
                        if str(a["clinic_policy_version_id"]) == p["cpv_id"]]
            if "pa.user_id = CAST(:user_id AS uuid)" in sql:
                rows = [a for a in rows
                        if str(a["user_id"]) == p["user_id"]]
            if "pa.is_voided = false" in sql:
                rows = [a for a in rows if not a["is_voided"]]
            if "pt.template_slug = :template_slug" in sql:
                # JOIN through cpv -> template.
                cpv_by_id = {
                    str(c["clinic_policy_version_id"]): c
                    for c in self._scoped_cpvs()
                }
                filtered = []
                for a in rows:
                    c = cpv_by_id.get(str(a["clinic_policy_version_id"]))
                    if not c:
                        continue
                    t = self._template_by_id(str(c["policy_template_id"]))
                    if t and t["template_slug"] == p["template_slug"]:
                        filtered.append(a)
                rows = filtered

            # Hydrate join fields.
            cpv_by_id = {
                str(c["clinic_policy_version_id"]): c
                for c in self._scoped_cpvs()
            }
            hydrated = []
            for a in rows:
                c = cpv_by_id.get(str(a["clinic_policy_version_id"]))
                t = (
                    self._template_by_id(str(c["policy_template_id"]))
                    if c else None
                )
                hydrated.append({
                    **a,
                    "policy_title_snapshot": c["title_snapshot"] if c else None,
                    "policy_clinic_policy_version": (
                        int(c["clinic_policy_version"]) if c else None
                    ),
                    "template_slug": t["template_slug"] if t else None,
                })
            hydrated = sorted(
                hydrated, key=lambda a: a["acknowledged_at"], reverse=True
            )
            hydrated = hydrated[: int(p.get("limit", 25))]
            return _Result(rows=hydrated)

        # Fall back to the 2A-2.2 FakeDB for non-attestation SQL.
        return super().execute(statement, params)


# ---------------------------------------------------------------------
# Test scaffolding
# ---------------------------------------------------------------------


def build_app(
    *,
    authenticated: bool = True,
    clinic_id: str = CLINIC_A,
    user_id: str = STAFF_USER,
    role: str = "staff",
) -> tuple:
    from app.auth_and_rls import require_clinic_user
    from app.db import get_db
    from app.governance_policy import router

    app = FastAPI()
    app.include_router(router)
    fake = AttestationFakeDB()

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


def _seed_active_cpv(
    fake: AttestationFakeDB,
    *,
    clinic_id: str = CLINIC_A,
    template_id: str = TPL_AI_USE,
    clinic_policy_version: int = 1,
    status: str = "active",
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    row = {
        "clinic_policy_version_id": _uuid.uuid4(),
        "clinic_id": clinic_id,
        "policy_template_id": _uuid.UUID(template_id),
        "template_version_snapshot": "1.0.0",
        "clinic_policy_version": clinic_policy_version,
        "status": status,
        "title_snapshot": "AI Use Policy for Veterinary Teams",
        "summary_snapshot": "Summary.",
        "content_sha256_snapshot": "abc123",
        "effective_from": now if status == "active" else None,
        "created_by_user_id": _uuid.UUID(ADMIN_USER),
        "activated_by_user_id": (
            _uuid.UUID(ADMIN_USER) if status == "active" else None
        ),
        "activated_at": now if status == "active" else None,
        "superseded_at": None,
        "created_at": now,
        "updated_at": now,
    }
    fake.clinic_policy_versions.append(row)
    return row


# ---------------------------------------------------------------------
# 1. /me/outstanding
# ---------------------------------------------------------------------


def test_outstanding_returns_active_policies_without_user_attestation() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    cpv = _seed_active_cpv(fake)
    resp = client_for(app).get(
        "/v1/governance/policy/me/outstanding", headers=auth_headers()
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] == 1
    assert body["policies"][0]["clinic_policy_version_id"] == str(
        cpv["clinic_policy_version_id"]
    )
    _assert_no_forbidden_keys(body)


def test_outstanding_excludes_policies_already_attested() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    cpv = _seed_active_cpv(fake)
    # Plant an existing non-voided attestation.
    fake.policy_attestations.append({
        "attestation_id": _uuid.uuid4(),
        "clinic_id": CLINIC_A,
        "clinic_policy_version_id": cpv["clinic_policy_version_id"],
        "user_id": _uuid.UUID(STAFF_USER),
        "attestation_statement_version": "attestation_statement_v1",
        "acknowledged_at": datetime.now(timezone.utc),
        "acknowledgement_method": "in_app_button_click",
        "policy_content_sha256_snapshot": None,
        "ip_hash": None,
        "is_voided": False,
        "void_reason": None,
        "voided_at": None,
        "voided_by_user_id": None,
        "created_at": datetime.now(timezone.utc),
    })
    resp = client_for(app).get(
        "/v1/governance/policy/me/outstanding", headers=auth_headers()
    )
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_outstanding_documented_behaviour_voided_attestation_blocks_outstanding() -> None:
    """Founder-decided behaviour: a voided row counts as 'user already
    had a turn' under the unique-constraint design. The policy does NOT
    re-surface as outstanding; admin must issue a new clinic policy
    version to require re-attestation."""
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    cpv = _seed_active_cpv(fake)
    fake.policy_attestations.append({
        "attestation_id": _uuid.uuid4(),
        "clinic_id": CLINIC_A,
        "clinic_policy_version_id": cpv["clinic_policy_version_id"],
        "user_id": _uuid.UUID(STAFF_USER),
        "attestation_statement_version": "attestation_statement_v1",
        "acknowledged_at": datetime.now(timezone.utc),
        "acknowledgement_method": "in_app_button_click",
        "policy_content_sha256_snapshot": None,
        "ip_hash": None,
        "is_voided": True,
        "void_reason": "admin_correction",
        "voided_at": datetime.now(timezone.utc),
        "voided_by_user_id": _uuid.UUID(ADMIN_USER),
        "created_at": datetime.now(timezone.utc) - timedelta(days=1),
    })
    resp = client_for(app).get(
        "/v1/governance/policy/me/outstanding", headers=auth_headers()
    )
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_outstanding_only_includes_active_policies() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    _seed_active_cpv(fake, status="draft")
    _seed_active_cpv(fake, status="superseded",
                     template_id=TPL_DISCLOSURE)
    resp = client_for(app).get(
        "/v1/governance/policy/me/outstanding", headers=auth_headers()
    )
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


# ---------------------------------------------------------------------
# 2. POST /clinic-policies/{cpv_id}/attest
# ---------------------------------------------------------------------


def test_staff_can_attest_to_active_policy() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    cpv = _seed_active_cpv(fake)
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv['clinic_policy_version_id']}/attest",
        json={},
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    att = body["attestation"]
    assert att["user_id"] == STAFF_USER
    assert att["acknowledgement_method"] == "in_app_button_click"
    assert att["attestation_statement_version"] == "attestation_statement_v1"
    assert att["is_voided"] is False
    # Doctrine: no admin audit row for self-attestation.
    assert fake.audit_events == []
    _assert_no_forbidden_keys(body)


def test_attest_carries_content_sha256_snapshot() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    cpv = _seed_active_cpv(fake)
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv['clinic_policy_version_id']}/attest",
        json={},
        headers=auth_headers(),
    )
    assert resp.status_code == 201
    assert resp.json()["attestation"]["policy_content_sha256_snapshot"] == "abc123"


@pytest.mark.parametrize("status", ["draft", "superseded", "archived"])
def test_attest_rejects_non_active_policy(status: str) -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    cpv = _seed_active_cpv(fake, status=status)
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv['clinic_policy_version_id']}/attest",
        json={},
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "governance_policy_not_active"
    assert fake.policy_attestations == []


def test_attest_unknown_id_returns_404() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{_uuid.uuid4()}/attest",
        json={},
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "governance_policy_version_not_found"


def test_attest_cross_clinic_returns_404() -> None:
    app, fake = build_app(
        role="admin", user_id=ADMIN_USER, clinic_id=CLINIC_A
    )
    other = _seed_active_cpv(fake)
    other["clinic_id"] = CLINIC_B
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{other['clinic_policy_version_id']}/attest",
        json={},
        headers=auth_headers(),
    )
    assert resp.status_code == 404


def test_attest_idempotent_when_existing_non_voided() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    cpv = _seed_active_cpv(fake)
    resp1 = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv['clinic_policy_version_id']}/attest",
        json={},
        headers=auth_headers(),
    )
    assert resp1.status_code == 201
    first_id = resp1.json()["attestation"]["attestation_id"]

    resp2 = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv['clinic_policy_version_id']}/attest",
        json={},
        headers=auth_headers(),
    )
    assert resp2.status_code == 201, resp2.text
    assert resp2.json()["attestation"]["attestation_id"] == first_id
    # Only one row exists.
    assert len(fake.policy_attestations) == 1


def test_attest_after_void_returns_409_documented_behaviour() -> None:
    """Founder decision: with the current unique constraint and no
    schema migration in this slice, attesting against a previously-
    voided row returns 409. Admin must issue a new clinic policy
    version to require re-attestation."""
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    cpv = _seed_active_cpv(fake)
    fake.policy_attestations.append({
        "attestation_id": _uuid.uuid4(),
        "clinic_id": CLINIC_A,
        "clinic_policy_version_id": cpv["clinic_policy_version_id"],
        "user_id": _uuid.UUID(STAFF_USER),
        "attestation_statement_version": "attestation_statement_v1",
        "acknowledged_at": datetime.now(timezone.utc),
        "acknowledgement_method": "in_app_button_click",
        "policy_content_sha256_snapshot": None,
        "ip_hash": None,
        "is_voided": True,
        "void_reason": "admin_correction",
        "voided_at": datetime.now(timezone.utc),
        "voided_by_user_id": _uuid.UUID(ADMIN_USER),
        "created_at": datetime.now(timezone.utc),
    })
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv['clinic_policy_version_id']}/attest",
        json={},
        headers=auth_headers(),
    )
    assert resp.status_code == 409
    assert resp.json().get("detail") == "attestation_previously_voided"
    assert len(fake.policy_attestations) == 1


@pytest.mark.parametrize(
    "extra_field,value",
    [
        ("competence_grade", "A"),
        ("score", 100),
        ("pass_fail", "pass"),
        ("staff_reflection", "I read the policy"),
        ("policy_body", "anything"),
        ("compliance_status", "ok"),
        ("clinical_safety_proof", True),
        ("legal_approval", True),
    ],
)
def test_attest_rejects_forbidden_extra_fields(extra_field: str, value: Any) -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    cpv = _seed_active_cpv(fake)
    resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv['clinic_policy_version_id']}/attest",
        json={extra_field: value},
        headers=auth_headers(),
    )
    assert resp.status_code == 422
    assert fake.policy_attestations == []


def test_attest_does_not_invoke_learn_or_cpd_paths() -> None:
    """Doctrine: attesting is not a Learn completion. The governance
    module must not call learn_v1 helpers or insert into
    learning_completions / cpd_exports."""
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    cpv = _seed_active_cpv(fake)
    client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv['clinic_policy_version_id']}/attest",
        json={},
        headers=auth_headers(),
    )
    for sql, _params in fake.calls:
        assert "learning_completions" not in sql
        assert "cpd_exports" not in sql
        assert "v_cpd_records" not in sql

    import inspect
    from app import governance_policy
    src = inspect.getsource(governance_policy)
    assert "from app.learn_v1" not in src
    assert "import learn_v1" not in src
    assert "learning_completions" not in src
    assert "cpd_exports" not in src


# ---------------------------------------------------------------------
# 3. /me/attestations
# ---------------------------------------------------------------------


def _seed_attestation(
    fake: AttestationFakeDB,
    *,
    user_id: str,
    cpv_id: _uuid.UUID,
    is_voided: bool = False,
    clinic_id: str = CLINIC_A,
    acknowledged_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    now = acknowledged_at or datetime.now(timezone.utc)
    row = {
        "attestation_id": _uuid.uuid4(),
        "clinic_id": clinic_id,
        "clinic_policy_version_id": cpv_id,
        "user_id": _uuid.UUID(user_id),
        "attestation_statement_version": "attestation_statement_v1",
        "acknowledged_at": now,
        "acknowledgement_method": "in_app_button_click",
        "policy_content_sha256_snapshot": None,
        "ip_hash": None,
        "is_voided": is_voided,
        "void_reason": "admin_correction" if is_voided else None,
        "voided_at": now if is_voided else None,
        "voided_by_user_id": _uuid.UUID(ADMIN_USER) if is_voided else None,
        "created_at": now,
    }
    fake.policy_attestations.append(row)
    return row


def test_me_attestations_returns_only_callers_rows() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    cpv = _seed_active_cpv(fake)
    _seed_attestation(fake, user_id=STAFF_USER,
                      cpv_id=cpv["clinic_policy_version_id"])
    _seed_attestation(fake, user_id=OTHER_USER,
                      cpv_id=cpv["clinic_policy_version_id"])
    resp = client_for(app).get(
        "/v1/governance/policy/me/attestations", headers=auth_headers()
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["attestations"]) == 1
    assert body["attestations"][0]["user_id"] == STAFF_USER


def test_me_attestations_excludes_voided_by_default() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    cpv = _seed_active_cpv(fake)
    _seed_attestation(fake, user_id=STAFF_USER,
                      cpv_id=cpv["clinic_policy_version_id"])
    _seed_attestation(fake, user_id=STAFF_USER,
                      cpv_id=_uuid.uuid4(), is_voided=True)
    resp = client_for(app).get(
        "/v1/governance/policy/me/attestations", headers=auth_headers()
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["attestations"]) == 1
    assert body["attestations"][0]["is_voided"] is False


def test_me_attestations_includes_voided_when_requested() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    cpv = _seed_active_cpv(fake)
    _seed_attestation(fake, user_id=STAFF_USER,
                      cpv_id=cpv["clinic_policy_version_id"])
    _seed_attestation(fake, user_id=STAFF_USER,
                      cpv_id=_uuid.uuid4(), is_voided=True)
    resp = client_for(app).get(
        "/v1/governance/policy/me/attestations?include_voided=true",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert len(resp.json()["attestations"]) == 2


# ---------------------------------------------------------------------
# 4. GET /attestations  (admin tier)
# ---------------------------------------------------------------------


@pytest.mark.parametrize("role", ["admin", "owner", "practice_manager"])
def test_admin_tier_can_list_clinic_attestations(role: str) -> None:
    app, fake = build_app(role=role, user_id=ADMIN_USER)
    cpv = _seed_active_cpv(fake)
    _seed_attestation(fake, user_id=STAFF_USER,
                      cpv_id=cpv["clinic_policy_version_id"])
    _seed_attestation(fake, user_id=OTHER_USER,
                      cpv_id=cpv["clinic_policy_version_id"])
    resp = client_for(app).get(
        "/v1/governance/policy/attestations", headers=auth_headers()
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["attestations"]) == 2
    # Joined metadata hydrated.
    for a in body["attestations"]:
        assert a["template_slug"] == "ai_use_policy"
        assert a["policy_clinic_policy_version"] == 1
        assert a["policy_title_snapshot"]


@pytest.mark.parametrize("role", ["staff", "clinic_user", "reader"])
def test_non_admin_cannot_list_clinic_attestations(role: str) -> None:
    app, fake = build_app(role=role, user_id=STAFF_USER)
    resp = client_for(app).get(
        "/v1/governance/policy/attestations", headers=auth_headers()
    )
    assert resp.status_code == 403
    assert resp.json().get("detail") == "forbidden_not_admin"


def test_admin_listing_filter_by_cpv_id() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    cpv_a = _seed_active_cpv(fake)
    cpv_b = _seed_active_cpv(fake, template_id=TPL_DISCLOSURE,
                             clinic_policy_version=1)
    _seed_attestation(fake, user_id=STAFF_USER,
                      cpv_id=cpv_a["clinic_policy_version_id"])
    _seed_attestation(fake, user_id=OTHER_USER,
                      cpv_id=cpv_b["clinic_policy_version_id"])
    cpv_a_id = cpv_a["clinic_policy_version_id"]
    resp = client_for(app).get(
        f"/v1/governance/policy/attestations?clinic_policy_version_id={cpv_a_id}",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["attestations"]) == 1
    assert body["attestations"][0]["clinic_policy_version_id"] == str(cpv_a_id)


def test_admin_listing_filter_by_user_id() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    cpv = _seed_active_cpv(fake)
    _seed_attestation(fake, user_id=STAFF_USER,
                      cpv_id=cpv["clinic_policy_version_id"])
    _seed_attestation(fake, user_id=OTHER_USER,
                      cpv_id=cpv["clinic_policy_version_id"])
    resp = client_for(app).get(
        f"/v1/governance/policy/attestations?user_id={STAFF_USER}",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["attestations"]) == 1
    assert body["attestations"][0]["user_id"] == STAFF_USER


def test_admin_listing_filter_by_template_slug() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    cpv_a = _seed_active_cpv(fake)  # ai_use_policy
    cpv_b = _seed_active_cpv(fake, template_id=TPL_DISCLOSURE,
                             clinic_policy_version=1)
    _seed_attestation(fake, user_id=STAFF_USER,
                      cpv_id=cpv_a["clinic_policy_version_id"])
    _seed_attestation(fake, user_id=STAFF_USER,
                      cpv_id=cpv_b["clinic_policy_version_id"])
    resp = client_for(app).get(
        "/v1/governance/policy/attestations?template_slug=client_disclosure_when_ai_assists",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["attestations"]) == 1
    assert body["attestations"][0]["template_slug"] == (
        "client_disclosure_when_ai_assists"
    )


def test_admin_listing_excludes_voided_by_default() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    cpv = _seed_active_cpv(fake)
    _seed_attestation(fake, user_id=STAFF_USER,
                      cpv_id=cpv["clinic_policy_version_id"])
    _seed_attestation(fake, user_id=OTHER_USER,
                      cpv_id=cpv["clinic_policy_version_id"],
                      is_voided=True)
    resp = client_for(app).get(
        "/v1/governance/policy/attestations", headers=auth_headers()
    )
    assert resp.status_code == 200
    assert len(resp.json()["attestations"]) == 1


def test_admin_listing_binds_clinic_id_on_all_sql() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    cpv = _seed_active_cpv(fake)
    _seed_attestation(fake, user_id=STAFF_USER,
                      cpv_id=cpv["clinic_policy_version_id"])
    client_for(app).get(
        "/v1/governance/policy/attestations", headers=auth_headers()
    )
    for sql, params in fake.calls:
        if "policy_attestations" in sql:
            assert params.get("clinic_id") == CLINIC_A, (sql, params)


# ---------------------------------------------------------------------
# 5. POST /attestations/{attestation_id}/void
# ---------------------------------------------------------------------


def test_admin_can_void_attestation() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    cpv = _seed_active_cpv(fake)
    att = _seed_attestation(fake, user_id=STAFF_USER,
                            cpv_id=cpv["clinic_policy_version_id"])
    resp = client_for(app).post(
        f"/v1/governance/policy/attestations/{att['attestation_id']}/void",
        json={"void_reason": "Recorded against the wrong policy version"},
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["attestation"]["is_voided"] is True
    assert body["attestation"]["void_reason"] == (
        "Recorded against the wrong policy version"
    )
    assert body["attestation"]["voided_by_user_id"] == ADMIN_USER


def test_void_writes_metadata_only_audit_event() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    cpv = _seed_active_cpv(fake)
    att = _seed_attestation(fake, user_id=STAFF_USER,
                            cpv_id=cpv["clinic_policy_version_id"])
    client_for(app).post(
        f"/v1/governance/policy/attestations/{att['attestation_id']}/void",
        json={"void_reason": "Recorded against the wrong policy version"},
        headers=auth_headers(),
    )
    assert len(fake.audit_events) == 1
    ev = fake.audit_events[0]
    assert ev["action"] == "governance_policy_attestation_voided"
    assert ev["target_id"] == str(att["attestation_id"])
    assert set(ev["meta"].keys()) == {
        "attestation_id",
        "clinic_policy_version_id",
        "user_id",
        "void_reason_present",
    }
    # Doctrine: no raw void_reason text in audit meta.
    assert "void_reason" not in ev["meta"]
    _assert_no_forbidden_keys(ev["meta"], where="audit.meta")


@pytest.mark.parametrize("bad_reason", ["", "   ", "\n\t"])
def test_void_rejects_empty_void_reason(bad_reason: str) -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    cpv = _seed_active_cpv(fake)
    att = _seed_attestation(fake, user_id=STAFF_USER,
                            cpv_id=cpv["clinic_policy_version_id"])
    resp = client_for(app).post(
        f"/v1/governance/policy/attestations/{att['attestation_id']}/void",
        json={"void_reason": bad_reason},
        headers=auth_headers(),
    )
    # Either 422 (Pydantic min_length=1 after strip_whitespace) or 400
    # (handler-level "void_reason required"). Both acceptable; assert
    # one of them and that no state changed.
    assert resp.status_code in (400, 422)
    assert att["is_voided"] is False
    assert fake.audit_events == []


def test_void_rejects_extra_fields() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    cpv = _seed_active_cpv(fake)
    att = _seed_attestation(fake, user_id=STAFF_USER,
                            cpv_id=cpv["clinic_policy_version_id"])
    resp = client_for(app).post(
        f"/v1/governance/policy/attestations/{att['attestation_id']}/void",
        json={"void_reason": "ok", "compliance_status": "bad"},
        headers=auth_headers(),
    )
    assert resp.status_code == 422


def test_void_unknown_id_returns_404() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    resp = client_for(app).post(
        f"/v1/governance/policy/attestations/{_uuid.uuid4()}/void",
        json={"void_reason": "n/a"},
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "attestation_not_found"


def test_void_cross_clinic_returns_404() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER, clinic_id=CLINIC_A)
    cpv = _seed_active_cpv(fake, clinic_id=CLINIC_B)
    att = _seed_attestation(fake, user_id=STAFF_USER,
                            cpv_id=cpv["clinic_policy_version_id"],
                            clinic_id=CLINIC_B)
    resp = client_for(app).post(
        f"/v1/governance/policy/attestations/{att['attestation_id']}/void",
        json={"void_reason": "cross-clinic test"},
        headers=auth_headers(),
    )
    assert resp.status_code == 404


def test_re_voiding_already_voided_is_idempotent_no_duplicate_audit() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    cpv = _seed_active_cpv(fake)
    att = _seed_attestation(fake, user_id=STAFF_USER,
                            cpv_id=cpv["clinic_policy_version_id"])
    # First void.
    client_for(app).post(
        f"/v1/governance/policy/attestations/{att['attestation_id']}/void",
        json={"void_reason": "first"},
        headers=auth_headers(),
    )
    audits_after_first = len(fake.audit_events)
    # Second void: same row.
    resp = client_for(app).post(
        f"/v1/governance/policy/attestations/{att['attestation_id']}/void",
        json={"void_reason": "second"},
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["attestation"]["is_voided"] is True
    # Idempotent: no extra audit row.
    assert len(fake.audit_events) == audits_after_first


@pytest.mark.parametrize("role", ["staff", "clinic_user", "reader"])
def test_non_admin_cannot_void_attestation(role: str) -> None:
    app, fake = build_app(role=role, user_id=STAFF_USER)
    cpv = _seed_active_cpv(fake)
    att = _seed_attestation(fake, user_id=STAFF_USER,
                            cpv_id=cpv["clinic_policy_version_id"])
    resp = client_for(app).post(
        f"/v1/governance/policy/attestations/{att['attestation_id']}/void",
        json={"void_reason": "should be blocked"},
        headers=auth_headers(),
    )
    assert resp.status_code == 403
    assert att["is_voided"] is False
    assert fake.audit_events == []


# ---------------------------------------------------------------------
# 6. Doctrine / regression guards
# ---------------------------------------------------------------------


def test_unauthenticated_requests_return_401() -> None:
    app, fake = build_app(authenticated=False)
    paths = [
        "/v1/governance/policy/me/outstanding",
        "/v1/governance/policy/me/attestations",
        "/v1/governance/policy/attestations",
    ]
    for path in paths:
        resp = TestClient(app).get(path)
        assert resp.status_code == 401, path


def test_no_invalid_partial_index_on_conflict_in_governance_module() -> None:
    """Belt-and-braces M6.10.1B / TD-BE guard. Avoid hard-coding the
    full literal forbidden string (which would itself trip broader
    artefact scans); build from fragments."""
    import inspect
    from app import governance_policy
    src = inspect.getsource(governance_policy)
    fragment = (
        "ON CONFLICT (clinic_id, " + "action, " + "idempotency_key)"
    )
    assert fragment not in src


def test_response_envelopes_metadata_only_across_attestation_endpoints() -> None:
    """Sweep representative attestation responses for forbidden keys."""
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    cpv = _seed_active_cpv(fake)
    att_resp = client_for(app).post(
        f"/v1/governance/policy/clinic-policies/{cpv['clinic_policy_version_id']}/attest",
        json={},
        headers=auth_headers(),
    )
    assert att_resp.status_code == 201
    _assert_no_forbidden_keys(att_resp.json(), where="attest")

    for url in (
        "/v1/governance/policy/me/outstanding",
        "/v1/governance/policy/me/attestations",
        "/v1/governance/policy/attestations",
    ):
        resp = client_for(app).get(url, headers=auth_headers())
        assert resp.status_code == 200, (url, resp.text)
        _assert_no_forbidden_keys(resp.json(), where=url)
