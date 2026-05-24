"""Tests for M6.8 — Assistant analytics into Intelligence.

The summary endpoint aggregates metadata-only assistant_runs evidence:
counts, rates, funnel, top refusal codes, top safety flags, breakdown by
validation profile, and usage-vs-policy limits. No raw content is ever
read or returned.
"""
from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from tests._assistant_test_helpers import (
    TEST_CLINIC_ID,
    TEST_USER_ID,
    FakeDB,
    auth_headers,
)


# ---------------------------------------------------------------------
# Test app builder. We mount only the Intelligence router and override
# the two dependencies it uses: require_clinic_user (auth) and
# get_clinic_scoped_db (DB session). The FakeDB is the same one used
# everywhere else in this suite.
# ---------------------------------------------------------------------

def build_intel_app(
    *,
    authenticated: bool = True,
) -> Tuple[FastAPI, FakeDB]:
    from app.auth_and_rls import require_clinic_user
    from app.portal_intelligence import (
        get_clinic_scoped_db,
        router as intelligence_router,
    )

    app = FastAPI()
    app.include_router(intelligence_router)

    fake_db = FakeDB()

    def _fake_db_dep(request: Request):
        try:
            yield fake_db
        finally:
            pass

    app.dependency_overrides[get_clinic_scoped_db] = _fake_db_dep

    if authenticated:
        def _fake_require_clinic_user(request: Request) -> Dict[str, str]:
            request.state.clinic_id = TEST_CLINIC_ID
            request.state.clinic_user_id = TEST_USER_ID
            request.state.role = "staff"
            return {
                "clinic_id": TEST_CLINIC_ID,
                "clinic_user_id": TEST_USER_ID,
                "role": "staff",
            }
        app.dependency_overrides[require_clinic_user] = _fake_require_clinic_user

    return app, fake_db


# ---------------------------------------------------------------------
# Extend FakeDB at runtime to handle the new aggregation SQL shapes.
# We do this per-test by stuffing the rows into attributes the helper's
# SQL queries will hit. The matching is by SQL substring.
# ---------------------------------------------------------------------

def _patch_fakedb_for_intel(
    db: FakeDB,
    *,
    summary_row: Optional[Dict[str, Any]] = None,
    refusal_rows: Optional[List[Dict[str, Any]]] = None,
    safety_rows: Optional[List[Dict[str, Any]]] = None,
    profile_rows: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Wrap FakeDB.execute so the four Assistant Intelligence SQLs
    return the rows the test specifies. The original FakeDB.execute is
    preserved for any unrelated SQL (e.g. policy fetches via
    select_policy_row, count_queue for runs_today/month)."""
    original_execute = db.execute

    def patched(statement: Any, params: Optional[Dict[str, Any]] = None):
        sql = str(getattr(statement, "text", statement))
        # Record the call so tests can inspect WHERE clauses / params.
        db.calls.append((sql, dict(params or {})))

        # Summary aggregate (single row with many FILTER counts).
        if "FILTER (WHERE run_status =" in sql and "FROM assistant_runs" in sql:
            from tests._assistant_test_helpers import _FakeResult
            return _FakeResult(row=summary_row or {})

        # Top refusal reasons.
        if "jsonb_array_elements_text(refusal_reason_codes)" in sql:
            from tests._assistant_test_helpers import _FakeResult
            return _FakeResult(rows=list(refusal_rows or []))

        # Top safety flags.
        if "jsonb_array_elements_text(safety_flags)" in sql:
            from tests._assistant_test_helpers import _FakeResult
            return _FakeResult(rows=list(safety_rows or []))

        # By validation profile.
        if (
            "GROUP BY validation_profile" in sql
            and "FROM assistant_runs" in sql
        ):
            from tests._assistant_test_helpers import _FakeResult
            return _FakeResult(rows=list(profile_rows or []))

        # Everything else (policy SELECT, COUNT(*) for runs today/month,
        # etc.) flows through the existing FakeDB branches.
        return original_execute(statement, params)

    db.execute = patched  # type: ignore[assignment]


def _summary(**overrides: int) -> Dict[str, Any]:
    """Helper: build an aggregate-row dict the helper expects."""
    base = {
        "total_runs": 0,
        "draft_generated": 0,
        "refused_before_model_call": 0,
        "output_blocked": 0,
        "generation_failed": 0,
        "generation_disabled_by_policy": 0,
        "pii_detected": 0,
        "reviewed": 0,
        "approved": 0,
        "needs_edit": 0,
        "rejected": 0,
        "receipt_linked": 0,
        "default_policy_runs": 0,
        "policy_versioned_runs": 0,
    }
    base.update({k: int(v) for k, v in overrides.items()})
    return base


def _get(client: TestClient, days: Optional[int] = None):
    url = "/v1/portal/intelligence/assistant-summary"
    if days is not None:
        url += f"?days={days}"
    return client.get(url, headers=auth_headers())


# =====================================================================
# 1. Empty state
# =====================================================================

def test_assistant_intelligence_empty_state() -> None:
    app, db = build_intel_app()
    _patch_fakedb_for_intel(db, summary_row=_summary())
    # runs_today / runs_this_month from FakeDB count_queue → 0/0 by default

    resp = TestClient(app).get(
        "/v1/portal/intelligence/assistant-summary", headers=auth_headers()
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["summary"]["total_runs"] == 0
    for key in (
        "draft_generated_rate",
        "refusal_rate",
        "output_blocked_rate",
        "pii_detected_rate",
        "review_completion_rate",
        "receipt_completion_rate",
        "approval_rate_among_reviewed",
    ):
        assert body["rates"][key] == 0.0, key
    assert "governance_note" in body
    assert "metadata only" in body["governance_note"].lower()
    assert body["funnel"]["submitted"] == 0
    assert body["usage_limits"]["source"] in ("default", "assistant_policy")


# =====================================================================
# 2. Count breakdown by run_status
# =====================================================================

def test_assistant_intelligence_counts_run_statuses() -> None:
    app, db = build_intel_app()
    _patch_fakedb_for_intel(
        db,
        summary_row=_summary(
            total_runs=10,
            draft_generated=5,
            refused_before_model_call=2,
            output_blocked=2,
            generation_failed=1,
        ),
    )
    resp = TestClient(app).get(
        "/v1/portal/intelligence/assistant-summary", headers=auth_headers()
    )
    assert resp.status_code == 200
    s = resp.json()["summary"]
    assert s["draft_generated"] == 5
    assert s["refused_before_model_call"] == 2
    assert s["output_blocked"] == 2
    assert s["generation_failed"] == 1

    rates = resp.json()["rates"]
    assert rates["draft_generated_rate"] == pytest.approx(0.5)
    # Refusal rate counts input refusals + output blocks → (2+2)/10 = 0.4
    assert rates["refusal_rate"] == pytest.approx(0.4)
    assert rates["output_blocked_rate"] == pytest.approx(0.2)

    by_status = resp.json()["by_status"]
    by_status_map = {item["status"]: item["count"] for item in by_status}
    assert by_status_map["draft_generated"] == 5
    assert by_status_map["refused_before_model_call"] == 2
    assert by_status_map["output_blocked"] == 2
    assert by_status_map["generation_failed"] == 1


# =====================================================================
# 3. Review + receipt rates (with safe division)
# =====================================================================

def test_assistant_intelligence_review_and_receipt_rates() -> None:
    app, db = build_intel_app()
    _patch_fakedb_for_intel(
        db,
        summary_row=_summary(
            total_runs=10,
            reviewed=6,
            approved=4,
            needs_edit=1,
            rejected=1,
            receipt_linked=3,
        ),
    )
    resp = TestClient(app).get(
        "/v1/portal/intelligence/assistant-summary", headers=auth_headers()
    )
    body = resp.json()

    assert body["rates"]["review_completion_rate"] == pytest.approx(0.6)
    assert body["rates"]["receipt_completion_rate"] == pytest.approx(0.3)
    # Approval among reviewed: 4/6
    assert body["rates"]["approval_rate_among_reviewed"] == pytest.approx(
        4 / 6, abs=1e-3
    )
    rev = {x["status"]: x["count"] for x in body["by_review_status"]}
    assert rev["approved"] == 4
    assert rev["needs_edit"] == 1
    assert rev["rejected"] == 1
    assert rev["not_reviewed"] == 4  # 10 - 6


def test_assistant_intelligence_safe_division_when_no_reviews() -> None:
    app, db = build_intel_app()
    _patch_fakedb_for_intel(
        db, summary_row=_summary(total_runs=5, reviewed=0, approved=0)
    )
    resp = TestClient(app).get(
        "/v1/portal/intelligence/assistant-summary", headers=auth_headers()
    )
    assert resp.json()["rates"]["approval_rate_among_reviewed"] == 0.0


# =====================================================================
# 4. Top refusal reasons + top safety flags
# =====================================================================

def test_assistant_intelligence_top_refusal_reasons_and_safety_flags() -> None:
    app, db = build_intel_app()
    _patch_fakedb_for_intel(
        db,
        summary_row=_summary(total_runs=10),
        refusal_rows=[
            {"code": "dose_calculation_request", "c": 4},
            {"code": "diagnosis_request", "c": 2},
        ],
        safety_rows=[
            {"code": "output_prescribing_or_dose", "c": 3},
            {"code": "output_diagnosis_language", "c": 1},
        ],
    )
    resp = TestClient(app).get(
        "/v1/portal/intelligence/assistant-summary", headers=auth_headers()
    )
    body = resp.json()
    assert body["top_refusal_reasons"] == [
        {"code": "dose_calculation_request", "count": 4},
        {"code": "diagnosis_request", "count": 2},
    ]
    assert body["top_safety_flags"] == [
        {"code": "output_prescribing_or_dose", "count": 3},
        {"code": "output_diagnosis_language", "count": 1},
    ]


# =====================================================================
# 5. PII rate
# =====================================================================

def test_assistant_intelligence_pii_rate() -> None:
    app, db = build_intel_app()
    _patch_fakedb_for_intel(
        db, summary_row=_summary(total_runs=8, pii_detected=2)
    )
    resp = TestClient(app).get(
        "/v1/portal/intelligence/assistant-summary", headers=auth_headers()
    )
    body = resp.json()
    assert body["summary"]["pii_detected"] == 2
    assert body["rates"]["pii_detected_rate"] == pytest.approx(0.25)


# =====================================================================
# 6. Validation profile breakdown (null → standard)
# =====================================================================

def test_assistant_intelligence_validation_profile_breakdown() -> None:
    """The SQL COALESCEs NULL profiles to 'standard', so by the time
    rows reach the helper, every value is a real string. We assert the
    response surfaces the rows verbatim, in order."""
    app, db = build_intel_app()
    _patch_fakedb_for_intel(
        db,
        summary_row=_summary(total_runs=5),
        profile_rows=[
            {"validation_profile": "standard", "c": 3},
            {"validation_profile": "conservative", "c": 2},
        ],
    )
    resp = TestClient(app).get(
        "/v1/portal/intelligence/assistant-summary", headers=auth_headers()
    )
    items = resp.json()["by_validation_profile"]
    assert items == [
        {"validation_profile": "standard", "count": 3},
        {"validation_profile": "conservative", "count": 2},
    ]


# =====================================================================
# 7. Usage limits from active policy
# =====================================================================

def test_assistant_intelligence_usage_limits_from_active_policy() -> None:
    app, db = build_intel_app()
    _patch_fakedb_for_intel(db, summary_row=_summary())

    db.select_policy_row = {
        "id": _uuid.uuid4(),
        "clinic_id": _uuid.UUID(TEST_CLINIC_ID),
        "policy_version": 2,
        "is_active": True,
        "client_communication_enabled": True,
        "generation_enabled": True,
        "validation_profile": "conservative",
        "daily_run_limit_per_clinic": 25,
        "monthly_run_limit_per_clinic": 500,
        "require_human_review": True,
        "allow_receipts_after_review": True,
        "policy_label": "Test",
        "policy_notes": None,
        "created_by_user_id": _uuid.UUID(TEST_USER_ID),
        "created_at": datetime(2026, 5, 24, 12, 0, 0, tzinfo=timezone.utc),
        "activated_at": datetime(2026, 5, 24, 12, 0, 0, tzinfo=timezone.utc),
        "superseded_at": None,
    }
    db.count_queue = [5, 20]  # runs_today, runs_this_month

    resp = TestClient(app).get(
        "/v1/portal/intelligence/assistant-summary", headers=auth_headers()
    )
    body = resp.json()
    ul = body["usage_limits"]
    assert ul["source"] == "assistant_policy"
    assert ul["daily_limit_per_clinic"] == 25
    assert ul["monthly_limit_per_clinic"] == 500
    assert ul["runs_today"] == 5
    assert ul["runs_this_month"] == 20
    assert ul["daily_utilization_rate"] == pytest.approx(0.2)
    assert ul["monthly_utilization_rate"] == pytest.approx(0.04)


# =====================================================================
# 8. Usage limits default when no policy
# =====================================================================

def test_assistant_intelligence_usage_limits_default_when_no_policy() -> None:
    app, db = build_intel_app()
    _patch_fakedb_for_intel(db, summary_row=_summary())
    db.select_policy_row = None
    db.count_queue = [0, 0]

    resp = TestClient(app).get(
        "/v1/portal/intelligence/assistant-summary", headers=auth_headers()
    )
    body = resp.json()
    ul = body["usage_limits"]
    assert ul["source"] == "default"
    assert isinstance(ul["daily_limit_per_clinic"], int)
    assert isinstance(ul["monthly_limit_per_clinic"], int)
    assert ul["runs_today"] == 0
    assert ul["runs_this_month"] == 0


# =====================================================================
# 9. Window filter parameter is honoured
# =====================================================================

def test_assistant_intelligence_window_filter() -> None:
    """Custom `days` reaches the SQL params and is reflected in the
    response's window block."""
    app, db = build_intel_app()
    _patch_fakedb_for_intel(db, summary_row=_summary(total_runs=2))

    resp = TestClient(app).get(
        "/v1/portal/intelligence/assistant-summary?days=7", headers=auth_headers()
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["window"]["days"] == 7

    # Aggregate SQL params carry the same start_at the response reports.
    agg_calls = [
        (s, p) for s, p in db.calls
        if "FILTER (WHERE run_status =" in s and "FROM assistant_runs" in s
    ]
    assert agg_calls
    _, params = agg_calls[-1]
    assert params["clinic_id"] == TEST_CLINIC_ID
    assert "start_at" in params and "end_at" in params


@pytest.mark.parametrize("bad", ["0", "-1", "500"])
def test_assistant_intelligence_window_filter_validation(bad: str) -> None:
    """FastAPI rejects out-of-range `days` values with 422."""
    app, db = build_intel_app()
    _patch_fakedb_for_intel(db, summary_row=_summary())
    resp = TestClient(app).get(
        f"/v1/portal/intelligence/assistant-summary?days={bad}",
        headers=auth_headers(),
    )
    assert resp.status_code == 422


# =====================================================================
# 10. Clinic isolation — SQL carries the auth clinic_id
# =====================================================================

def test_assistant_intelligence_clinic_isolation() -> None:
    app, db = build_intel_app()
    _patch_fakedb_for_intel(db, summary_row=_summary())

    TestClient(app).get(
        "/v1/portal/intelligence/assistant-summary", headers=auth_headers()
    )

    aggregate_sqls = [
        (s, p) for s, p in db.calls if "FROM assistant_runs" in s
    ]
    assert aggregate_sqls, "expected aggregate SQL"
    for sql, params in aggregate_sqls:
        # Every assistant_runs read filters by clinic_id; the bound value
        # is always the auth context's clinic_id. RLS (FORCE) is the
        # second layer at the DB.
        assert "clinic_id = CAST(:clinic_id AS uuid)" in sql, sql[:80]
        assert params.get("clinic_id") == TEST_CLINIC_ID


# =====================================================================
# 11. No raw content in the response
# =====================================================================

def test_assistant_intelligence_does_not_return_raw_content() -> None:
    """Sentinel substrings that would only be present if raw content
    leaked must not appear in the JSON response. The response surface is
    counts + codes + a fixed governance note — nothing else.

    Note: bare metadata schema words ("draft", "prompt", "input",
    "output") legitimately appear in field names like `draft_generated`,
    `draft_generated_rate`, `output_blocked`, `output_blocked_rate`,
    `top_refusal_reasons`, and the governance note. Only RAW-CONTENT
    column/field names and sample raw values are sentinels."""
    app, db = build_intel_app()
    _patch_fakedb_for_intel(
        db,
        summary_row=_summary(total_runs=3, draft_generated=1, output_blocked=1),
        refusal_rows=[{"code": "dose_calculation_request", "c": 1}],
        safety_rows=[{"code": "output_prescribing_or_dose", "c": 1}],
    )
    resp = TestClient(app).get(
        "/v1/portal/intelligence/assistant-summary", headers=auth_headers()
    )
    text_body = resp.text
    forbidden = (
        "input_text",
        "output_text",
        "raw_input",
        "raw_output",
        "policy_notes",
        "communication_goal",
        "clinician_confirmed_facts",
        "Dear owner",
        "internal-only notes that must NEVER appear",
        "sample raw prompt",
        "sample raw input",
        "sample raw output",
    )
    for needle in forbidden:
        assert needle not in text_body, (
            f"forbidden token {needle!r} appears in intel response"
        )


# =====================================================================
# 12. Auth required
# =====================================================================

def test_assistant_intelligence_requires_auth() -> None:
    app, db = build_intel_app(authenticated=False)
    _patch_fakedb_for_intel(db, summary_row=_summary())

    resp = TestClient(app).get(
        "/v1/portal/intelligence/assistant-summary"
    )
    # Without the bearer header the real require_clinic_user rejects.
    assert resp.status_code == 401
