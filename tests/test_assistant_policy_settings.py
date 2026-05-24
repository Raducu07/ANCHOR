"""Tests for M6.7 — Assistant admin controls / policy tuning.

Doctrine reminders enforced by these tests:
  * Default policy is safe (review required, validation on, generation on).
  * Admin role required for PATCH /policy and GET /policy/history.
  * Hard-doctrine fields (require_human_review, allow_receipts_after_review)
    are NOT modifiable; the endpoint rejects them.
  * validation_profile must be 'standard' or 'conservative' (never 'off').
  * Updates create a new version, deactivate the previous, and audit.
  * Active policy limits override env defaults.
  * Policy can disable client_communication mode and generation.
  * RLS / clinic_id predicate prevents cross-clinic access.
"""
from __future__ import annotations

import json
import re
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest

from tests._assistant_test_helpers import (
    DEFAULT_DRAFT_TEXT,
    DEFAULT_MODEL,
    DEFAULT_PROVIDER,
    TEST_CLINIC_ID,
    TEST_USER_ID,
    auth_headers,
    build_app,
    client_for,
)


def _policy_row(
    *,
    policy_version: int = 1,
    is_active: bool = True,
    validation_profile: str = "standard",
    client_communication_enabled: bool = True,
    generation_enabled: bool = True,
    daily_run_limit_per_clinic: int = 50,
    monthly_run_limit_per_clinic: int = 1000,
    require_human_review: bool = True,
    allow_receipts_after_review: bool = True,
    policy_label: str = "Default Assistant Policy",
    policy_notes: Any = None,
) -> Dict[str, Any]:
    now = datetime(2026, 5, 24, 12, 0, 0, tzinfo=timezone.utc)
    return {
        "id": _uuid.uuid4(),
        "clinic_id": _uuid.UUID(TEST_CLINIC_ID),
        "policy_version": policy_version,
        "is_active": is_active,
        "client_communication_enabled": client_communication_enabled,
        "generation_enabled": generation_enabled,
        "validation_profile": validation_profile,
        "daily_run_limit_per_clinic": daily_run_limit_per_clinic,
        "monthly_run_limit_per_clinic": monthly_run_limit_per_clinic,
        "require_human_review": require_human_review,
        "allow_receipts_after_review": allow_receipts_after_review,
        "policy_label": policy_label,
        "policy_notes": policy_notes,
        "created_by_user_id": _uuid.UUID(TEST_USER_ID),
        "created_at": now,
        "activated_at": now,
        "superseded_at": None,
    }


# ---------------------------------------------------------------------
# 1. Default policy when no row exists
# ---------------------------------------------------------------------

def test_get_policy_returns_safe_default_when_none_exists() -> None:
    app, db = build_app()
    db.select_policy_row = None  # no DB row

    resp = client_for(app).get("/v1/assistant/policy", headers=auth_headers())
    assert resp.status_code == 200, resp.text
    body = resp.json()

    p = body["policy"]
    assert p["is_default"] is True
    assert p["is_active"] is False
    assert p["policy_version"] == 0
    assert p["require_human_review"] is True
    assert p["allow_receipts_after_review"] is True
    assert p["validation_profile"] == "standard"
    assert p["generation_enabled"] is True
    assert p["client_communication_enabled"] is True
    assert p["policy_label"] == "Default Assistant Policy"
    assert "governance_note" in body
    assert "cannot be disabled" in body["governance_note"].lower()


# ---------------------------------------------------------------------
# 2. Admin update creates a new version, deactivates the previous
# ---------------------------------------------------------------------

def test_admin_can_update_policy_creates_new_version() -> None:
    app, db = build_app(auth_role="admin")

    # Active version 1 in the DB.
    db.select_policy_row = _policy_row(policy_version=1)
    db.max_policy_version_value = 1

    # The INSERT RETURNING for the new version 2.
    db.insert_policy_row = _policy_row(
        policy_version=2,
        validation_profile="conservative",
        daily_run_limit_per_clinic=30,
        monthly_run_limit_per_clinic=600,
        policy_label="Conservative — Q3",
    )

    resp = client_for(app).patch(
        "/v1/assistant/policy",
        json={
            "validation_profile": "conservative",
            "daily_run_limit_per_clinic": 30,
            "monthly_run_limit_per_clinic": 600,
            "policy_label": "Conservative — Q3",
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    p = resp.json()["policy"]
    assert p["policy_version"] == 2
    assert p["is_active"] is True
    assert p["validation_profile"] == "conservative"
    assert p["daily_run_limit_per_clinic"] == 30
    assert p["monthly_run_limit_per_clinic"] == 600
    assert p["policy_label"] == "Conservative — Q3"

    # Sequence: deactivate previous + INSERT new + audit insert.
    sql_seq = [s for s, _ in db.calls]
    assert any("UPDATE assistant_policy_settings" in s for s in sql_seq)
    assert any(
        "INSERT INTO assistant_policy_settings" in s for s in sql_seq
    )
    assert any("INSERT INTO admin_audit_events" in s for s in sql_seq)


# ---------------------------------------------------------------------
# 3. Non-admin cannot PATCH
# ---------------------------------------------------------------------

def test_non_admin_cannot_update_policy() -> None:
    app, db = build_app(auth_role="staff")
    db.select_policy_row = _policy_row(policy_version=1)
    db.max_policy_version_value = 1

    resp = client_for(app).patch(
        "/v1/assistant/policy",
        json={"validation_profile": "conservative"},
        headers=auth_headers(),
    )
    assert resp.status_code == 403, resp.text
    assert resp.json().get("detail") == "forbidden_not_admin"

    # No INSERT happened.
    assert not any("INSERT INTO assistant_policy_settings" in s for s, _ in db.calls)


# ---------------------------------------------------------------------
# 4. Invalid validation_profile is rejected
# ---------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["off", "disabled", "permissive", ""])
def test_policy_update_rejects_invalid_validation_profile(bad: str) -> None:
    app, db = build_app(auth_role="admin")
    db.select_policy_row = _policy_row(policy_version=1)
    db.max_policy_version_value = 1

    resp = client_for(app).patch(
        "/v1/assistant/policy",
        json={"validation_profile": bad},
        headers=auth_headers(),
    )
    assert resp.status_code == 400, resp.text
    # No INSERT happened.
    assert not any("INSERT INTO assistant_policy_settings" in s for s, _ in db.calls)


# ---------------------------------------------------------------------
# 5. Cannot disable human review
# ---------------------------------------------------------------------

def test_policy_update_cannot_disable_human_review() -> None:
    app, db = build_app(auth_role="admin")
    db.select_policy_row = _policy_row(policy_version=1)
    db.max_policy_version_value = 1

    resp = client_for(app).patch(
        "/v1/assistant/policy",
        json={"require_human_review": False},
        headers=auth_headers(),
    )
    # extra='forbid' on the request model returns 422 for unknown keys.
    # That is the intended hard-doctrine block.
    assert resp.status_code == 422, resp.text
    assert not any("INSERT INTO assistant_policy_settings" in s for s, _ in db.calls)


def test_policy_update_cannot_disable_receipts_after_review() -> None:
    app, db = build_app(auth_role="admin")
    db.select_policy_row = _policy_row(policy_version=1)
    db.max_policy_version_value = 1

    resp = client_for(app).patch(
        "/v1/assistant/policy",
        json={"allow_receipts_after_review": False},
        headers=auth_headers(),
    )
    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------
# 6. History returns versions newest-first
# ---------------------------------------------------------------------

def test_policy_history_returns_versions() -> None:
    app, db = build_app(auth_role="admin")
    db.select_policy_history_rows = [
        _policy_row(policy_version=2, validation_profile="conservative"),
        _policy_row(
            policy_version=1,
            is_active=False,
            validation_profile="standard",
        ),
    ]

    resp = client_for(app).get(
        "/v1/assistant/policy/history?limit=10", headers=auth_headers()
    )
    assert resp.status_code == 200, resp.text
    items = resp.json()["items"]
    assert len(items) == 2
    assert items[0]["policy_version"] == 2
    assert items[0]["is_active"] is True
    assert items[0]["validation_profile"] == "conservative"
    assert items[1]["policy_version"] == 1
    assert items[1]["is_active"] is False


def test_policy_history_admin_only() -> None:
    app, db = build_app(auth_role="staff")
    db.select_policy_history_rows = []
    resp = client_for(app).get(
        "/v1/assistant/policy/history", headers=auth_headers()
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------
# 7. Run insert stamps active policy version + validation profile
# ---------------------------------------------------------------------

def test_assistant_run_uses_active_policy_version() -> None:
    app, db = build_app()
    db.select_policy_row = _policy_row(
        policy_version=3, validation_profile="conservative"
    )

    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={
            "mode": "client_communication",
            "input": {
                "communication_goal": "Reassure owner about post-op recovery",
                "clinician_confirmed_facts": "Patient is stable. Sutures intact.",
            },
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text

    _, insert_params = db.insert_call
    assert insert_params["assistant_policy_version"] == 3
    assert insert_params["assistant_validation_profile"] == "conservative"
    # assistant_policy_id is passed through as a string (or "" sentinel).
    pid = insert_params["assistant_policy_id"]
    assert isinstance(pid, str) and pid != ""


# ---------------------------------------------------------------------
# 8. Policy can disable client_communication mode
# ---------------------------------------------------------------------

def test_policy_can_disable_client_communication_mode() -> None:
    call_count = {"n": 0}

    def _stub(*, system_prompt: str, user_message: str):
        call_count["n"] += 1
        return DEFAULT_DRAFT_TEXT, DEFAULT_PROVIDER, DEFAULT_MODEL

    app, db = build_app(model_stub=_stub)
    db.select_policy_row = _policy_row(
        policy_version=2, client_communication_enabled=False
    )

    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={
            "mode": "client_communication",
            "input": {
                "communication_goal": "Reassure owner",
                "clinician_confirmed_facts": "Patient is stable.",
            },
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 403, resp.text
    assert resp.json().get("detail") == "assistant_mode_disabled_by_policy"
    assert call_count["n"] == 0
    # No assistant_runs INSERT should have happened.
    assert not any("INSERT INTO assistant_runs" in s for s, _ in db.calls)


# ---------------------------------------------------------------------
# 9. Policy generation_enabled=false does not call model
# ---------------------------------------------------------------------

def test_policy_generation_disabled_does_not_call_model() -> None:
    call_count = {"n": 0}

    def _stub(*, system_prompt: str, user_message: str):
        call_count["n"] += 1
        raise AssertionError("model must not be called when generation disabled")

    app, db = build_app(model_stub=_stub)
    db.select_policy_row = _policy_row(
        policy_version=4, generation_enabled=False
    )

    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={
            "mode": "client_communication",
            "input": {
                "communication_goal": "Reassure owner",
                "clinician_confirmed_facts": "Patient is stable.",
            },
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text
    run = resp.json()["run"]
    assert run["generation_enabled"] is False
    assert run["run_status"] == "generation_refused"
    assert run["refused"] is True
    assert "generation_disabled_by_policy" in run["refusal_reason_codes"]
    assert run["output_sha256"] is None
    assert run["model_provider"] is None
    assert run["model_name"] is None
    assert call_count["n"] == 0


# ---------------------------------------------------------------------
# 10. Policy limits override env defaults via enforce_assistant_run_limits
# ---------------------------------------------------------------------

def test_policy_limits_override_env_defaults() -> None:
    """When the active policy carries a low daily cap and the FakeDB
    count_queue says we're at-or-above it, the endpoint returns 429
    based on the POLICY limit (not the env default)."""
    app, db = build_app()
    db.select_policy_row = _policy_row(
        policy_version=2,
        daily_run_limit_per_clinic=1,
        monthly_run_limit_per_clinic=10,
    )
    # Daily count = 1, monthly = 1 → daily at limit, should 429.
    db.count_queue = [1, 1]

    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={
            "mode": "client_communication",
            "input": {
                "communication_goal": "Reassure owner",
                "clinician_confirmed_facts": "Patient is stable.",
            },
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 429, resp.text
    body = resp.json()
    assert body["detail"] == "assistant_daily_run_limit_exceeded"
    # The response carries the POLICY's limit value, not the env default.
    assert body["limit"] == 1
    assert body["window"] == "day"


# ---------------------------------------------------------------------
# 11. PATCH writes a metadata-only audit event
# ---------------------------------------------------------------------

def test_policy_update_audit_event_metadata_only() -> None:
    app, db = build_app(auth_role="admin")
    db.select_policy_row = _policy_row(policy_version=1)
    db.max_policy_version_value = 1
    db.insert_policy_row = _policy_row(
        policy_version=2, validation_profile="conservative"
    )

    resp = client_for(app).patch(
        "/v1/assistant/policy",
        json={"validation_profile": "conservative"},
        headers=auth_headers(),
    )
    assert resp.status_code == 200

    audit_calls = [
        (s, p) for s, p in db.calls if "INSERT INTO admin_audit_events" in s
    ]
    assert len(audit_calls) == 1, "expected exactly one audit insert"
    _, audit_params = audit_calls[0]
    assert audit_params["clinic_id"] == TEST_CLINIC_ID
    assert audit_params["admin_user_id"] == TEST_USER_ID
    assert audit_params["action"] == "assistant_policy_updated"
    meta = json.loads(audit_params["meta"])
    assert meta["previous_policy_version"] == 1
    assert meta["new_policy_version"] == 2
    assert "validation_profile" in meta["changed_fields"]
    # No raw-content leakage. The audit meta is a tight metadata object.
    for forbidden in ("draft", "prompt", "input_text", "output_text"):
        assert forbidden not in audit_params["meta"]


# ---------------------------------------------------------------------
# 12. Policy SELECT uses clinic_id predicate (RLS / cross-clinic gate)
# ---------------------------------------------------------------------

def test_cross_clinic_policy_not_visible() -> None:
    """The active-policy SELECT must filter by clinic_id from auth state.
    Combined with FORCE RLS in production, this prevents cross-clinic
    reads. Here we just assert the predicate + bound param."""
    app, db = build_app()
    db.select_policy_row = None

    resp = client_for(app).get("/v1/assistant/policy", headers=auth_headers())
    assert resp.status_code == 200

    select_calls = [
        (s, p) for s, p in db.calls
        if "FROM assistant_policy_settings" in s
        and "ORDER BY" not in s
        and "MAX(policy_version)" not in s
    ]
    assert select_calls, "expected active-policy SELECT"
    sql, params = select_calls[-1]
    assert "clinic_id = CAST(:clinic_id AS uuid)" in sql
    assert params["clinic_id"] == TEST_CLINIC_ID


# ---------------------------------------------------------------------
# Bonus: monthly < daily rejected by cross-field validation
# ---------------------------------------------------------------------

def test_policy_update_rejects_monthly_below_daily() -> None:
    app, db = build_app(auth_role="admin")
    db.select_policy_row = _policy_row(
        policy_version=1,
        daily_run_limit_per_clinic=10,
        monthly_run_limit_per_clinic=100,
    )
    db.max_policy_version_value = 1

    resp = client_for(app).patch(
        "/v1/assistant/policy",
        json={"daily_run_limit_per_clinic": 50, "monthly_run_limit_per_clinic": 20},
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "monthly_limit_below_daily_limit"


# ---------------------------------------------------------------------
# Bonus: response shape sanity
# ---------------------------------------------------------------------

def test_policy_response_has_all_required_fields() -> None:
    app, db = build_app()
    db.select_policy_row = _policy_row(policy_version=1)

    resp = client_for(app).get("/v1/assistant/policy", headers=auth_headers())
    assert resp.status_code == 200
    p = resp.json()["policy"]

    required = {
        "id",
        "clinic_id",
        "policy_version",
        "is_active",
        "is_default",
        "client_communication_enabled",
        "generation_enabled",
        "validation_profile",
        "daily_run_limit_per_clinic",
        "monthly_run_limit_per_clinic",
        "require_human_review",
        "allow_receipts_after_review",
        "policy_label",
        "policy_notes",
        "created_by_user_id",
        "created_at",
        "activated_at",
    }
    missing = required - set(p.keys())
    assert not missing, f"missing policy fields: {missing}"
