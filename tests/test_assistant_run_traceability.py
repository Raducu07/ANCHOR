"""Tests for M6.3 — Assistant traceability / evidence surface.

These endpoints return metadata only. They MUST NOT include or imply any
stored raw input, prompt, or draft output. All queries are clinic-scoped
and run under the existing get_db / RLS session pattern.
"""
from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pytest

from tests._assistant_test_helpers import (
    TEST_CLINIC_ID,
    TEST_USER_ID,
    auth_headers,
    build_app,
    client_for,
)


def _make_row(
    *,
    run_id: str | None = None,
    run_status: str = "generation_succeeded",
    pii_detected: bool = False,
    pii_types: List[str] | None = None,
    safety_flags: List[str] | None = None,
    refusal_reason_codes: List[str] | None = None,
    output_sha256: str | None = "a" * 64,
    model_provider: str | None = "anthropic",
    model_name: str | None = "claude-sonnet-4-6",
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> Dict[str, Any]:
    """Shape mirrors what psycopg returns for the SELECT in
    list_assistant_runs / get_assistant_run_detail: jsonb columns are
    already decoded to Python lists; timestamps are tz-aware datetimes."""
    now = created_at or datetime(2026, 5, 23, 12, 0, 0, tzinfo=timezone.utc)
    return {
        "run_id": _uuid.UUID(run_id) if run_id else _uuid.uuid4(),
        "clinic_id": _uuid.UUID(TEST_CLINIC_ID),
        "clinic_user_id": _uuid.UUID(TEST_USER_ID),
        "mode": "client_communication",
        "contract_version": "assistant_contract_v1",
        "workflow_origin": "anchor_assistant",
        "input_sha256": "b" * 64,
        "output_sha256": output_sha256,
        "input_field_keys": ["clinician_confirmed_facts", "communication_goal"],
        "pii_detected": pii_detected,
        "pii_types": pii_types or [],
        "safety_flags": safety_flags or [],
        "refusal_reason_codes": refusal_reason_codes or [],
        "review_status": "not_reviewed",
        "run_status": run_status,
        "receipt_id": None,
        "governance_event_id": None,
        "model_provider": model_provider,
        "model_name": model_name,
        "created_at": now,
        "updated_at": updated_at or now,
    }


# ---------------------------------------------------------------------
# 1. List endpoint returns metadata only
# ---------------------------------------------------------------------

def test_list_recent_assistant_runs_metadata_only() -> None:
    app, db = build_app()
    db.select_list_rows = [
        _make_row(run_status="generation_succeeded"),
        _make_row(
            run_status="generation_refused",
            refusal_reason_codes=["dose_calculation_request"],
            safety_flags=["dose_calculation_request"],
            output_sha256=None,
            model_provider=None,
            model_name=None,
        ),
    ]

    resp = client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert "runs" in body and isinstance(body["runs"], list)
    assert len(body["runs"]) == 2
    assert body["limit"] == 25

    # No raw content fields exist on any item.
    forbidden = {"draft", "input", "input_text", "output_text", "prompt", "user_message", "raw_input", "raw_output"}
    for item in body["runs"]:
        assert not (forbidden & set(item.keys())), (
            f"forbidden raw-content field in list item keys: {set(item.keys()) & forbidden}"
        )

    # Required metadata fields present on each item.
    required = {
        "run_id", "mode", "contract_version", "workflow_origin",
        "input_sha256", "output_sha256", "input_field_keys",
        "pii_detected", "pii_types", "safety_flags", "refusal_reason_codes",
        "review_status", "run_status", "receipt_id", "governance_event_id",
        "model_provider", "model_name", "created_at", "updated_at",
        "clinic_id", "clinic_user_id",
    }
    for item in body["runs"]:
        missing = required - set(item.keys())
        assert not missing, f"missing metadata fields: {missing}"


# ---------------------------------------------------------------------
# 2. Limit default + cap behaviour
# ---------------------------------------------------------------------

def test_list_recent_assistant_runs_limit_default_and_cap() -> None:
    # default limit = 25 (no `limit` query param)
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    assert resp.status_code == 200
    assert resp.json()["limit"] == 25
    # SQL params reflect the default. M6.11.2 binds `fetch_limit = limit + 1`
    # to support has_more detection without a COUNT round-trip.
    select_calls = [
        (s, p) for s, p in db.calls if "FROM assistant_runs" in s and "ORDER BY" in s
    ]
    assert select_calls and select_calls[-1][1]["fetch_limit"] == 26

    # explicit limit honoured
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get("/v1/assistant/runs?limit=10", headers=auth_headers())
    assert resp.status_code == 200
    assert resp.json()["limit"] == 10

    # over-cap rejected by FastAPI Query(le=100) → 422
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get("/v1/assistant/runs?limit=500", headers=auth_headers())
    assert resp.status_code == 422

    # below-min rejected
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get("/v1/assistant/runs?limit=0", headers=auth_headers())
    assert resp.status_code == 422


# ---------------------------------------------------------------------
# 3. run_status filter — recognised values pass; bad values rejected
# ---------------------------------------------------------------------

def test_list_recent_assistant_runs_status_filter() -> None:
    # recognised filter → SQL + params include run_status
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get(
        "/v1/assistant/runs?run_status=generation_refused",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    sql, params = [
        (s, p) for s, p in db.calls if "FROM assistant_runs" in s and "ORDER BY" in s
    ][-1]
    assert "run_status = :run_status" in sql
    assert params["run_status"] == "generation_refused"

    # bad value → 400
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get(
        "/v1/assistant/runs?run_status=bogus",
        headers=auth_headers(),
    )
    assert resp.status_code == 400


def test_list_recent_assistant_runs_mode_filter_rejects_unknown_mode() -> None:
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get(
        "/v1/assistant/runs?mode=discharge_instructions",
        headers=auth_headers(),
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------
# 4. Detail endpoint — metadata only + storage policy assertions
# ---------------------------------------------------------------------

def test_get_assistant_run_detail_metadata_only() -> None:
    row = _make_row()
    app, db = build_app()
    db.select_detail_row = row

    run_id_str = str(row["run_id"])
    resp = client_for(app).get(
        f"/v1/assistant/runs/{run_id_str}",
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["storage_policy"] == "metadata_only_by_default"
    assert body["raw_content_stored"] is False
    assert body["draft_stored"] is False
    assert body["prompt_stored"] is False
    assert "Assistant run records contain metadata only" in body["governance_note"]

    assert "run" in body
    run = body["run"]
    forbidden = {"draft", "input", "input_text", "output_text", "prompt", "raw_input", "raw_output"}
    assert not (forbidden & set(run.keys()))
    assert run["run_id"] == run_id_str


# ---------------------------------------------------------------------
# 5. Detail 404 — also covers cross-clinic non-leakage
# ---------------------------------------------------------------------

def test_get_assistant_run_detail_not_found() -> None:
    app, db = build_app()
    db.select_detail_row = None  # nothing matches clinic_id + run_id

    resp = client_for(app).get(
        f"/v1/assistant/runs/{_uuid.uuid4()}",
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    body = resp.json()
    # Generic detail; does not reveal whether the row exists for another clinic.
    assert body.get("detail") == "assistant_run_not_found"


# ---------------------------------------------------------------------
# 6. Queries use clinic_id and the RLS-bound get_db session
# ---------------------------------------------------------------------

def test_traceability_queries_use_clinic_id_and_rls_session() -> None:
    # list
    app, db = build_app()
    db.select_list_rows = []
    client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    list_sql, list_params = [
        (s, p) for s, p in db.calls if "FROM assistant_runs" in s and "ORDER BY" in s
    ][-1]
    assert "clinic_id = CAST(:clinic_id AS uuid)" in list_sql
    assert list_params["clinic_id"] == TEST_CLINIC_ID

    # detail
    app, db = build_app()
    db.select_detail_row = _make_row()
    rid = str(db.select_detail_row["run_id"])
    client_for(app).get(f"/v1/assistant/runs/{rid}", headers=auth_headers())
    detail_sql, detail_params = [
        (s, p)
        for s, p in db.calls
        if "FROM assistant_runs" in s and "run_id" in p
    ][-1]
    assert "clinic_id = CAST(:clinic_id AS uuid)" in detail_sql
    assert "id = CAST(:run_id AS uuid)" in detail_sql
    assert detail_params["clinic_id"] == TEST_CLINIC_ID

    # Both endpoints used the dependency-injected fake (get_db override).
    assert db.committed is True


# ---------------------------------------------------------------------
# 7. Successful generation row exposes hash but not draft
# ---------------------------------------------------------------------

def test_traceability_response_has_no_draft_even_for_generation_succeeded() -> None:
    row = _make_row(
        run_status="generation_succeeded",
        output_sha256="c" * 64,
    )
    app, db = build_app()
    db.select_detail_row = row

    rid = str(row["run_id"])
    resp = client_for(app).get(
        f"/v1/assistant/runs/{rid}",
        headers=auth_headers(),
    )
    assert resp.status_code == 200

    body = resp.json()
    run = body["run"]
    assert run["output_sha256"] == "c" * 64
    assert "draft" not in run
    assert body["draft_stored"] is False


# ---------------------------------------------------------------------
# 8. Refused run exposes refusal codes + safety flags
# ---------------------------------------------------------------------

def test_traceability_response_has_refusal_codes_for_refused_run() -> None:
    row = _make_row(
        run_status="generation_refused",
        output_sha256=None,
        model_provider=None,
        model_name=None,
        refusal_reason_codes=["dose_calculation_request"],
        safety_flags=["dose_calculation_request"],
    )
    app, db = build_app()
    db.select_detail_row = row

    rid = str(row["run_id"])
    resp = client_for(app).get(
        f"/v1/assistant/runs/{rid}",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    run = resp.json()["run"]
    assert run["run_status"] == "generation_refused"
    assert run["refusal_reason_codes"] == ["dose_calculation_request"]
    assert run["safety_flags"] == ["dose_calculation_request"]
    assert run["output_sha256"] is None
    assert run["model_provider"] is None
    assert run["model_name"] is None


# ---------------------------------------------------------------------
# Bonus: list endpoint sorts by created_at DESC
# ---------------------------------------------------------------------

def test_list_recent_assistant_runs_sorted_by_created_at_desc() -> None:
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    assert resp.status_code == 200

    sql = [
        s for s, _ in db.calls if "FROM assistant_runs" in s and "ORDER BY" in s
    ][-1]
    # M6.11.2 — stable total order: tiebreaker on id keeps cursor
    # pagination correct when many rows share a created_at timestamp.
    assert "ORDER BY ar.created_at DESC, ar.id DESC" in sql


# ---------------------------------------------------------------------
# Bonus: unauthenticated request rejected
# ---------------------------------------------------------------------

def test_traceability_unauthenticated_request_rejected() -> None:
    app, db = build_app(authenticated=False)
    db.select_list_rows = []

    from fastapi.testclient import TestClient
    resp = TestClient(app).get("/v1/assistant/runs")
    assert resp.status_code == 401

    resp = TestClient(app).get(f"/v1/assistant/runs/{_uuid.uuid4()}")
    assert resp.status_code == 401
