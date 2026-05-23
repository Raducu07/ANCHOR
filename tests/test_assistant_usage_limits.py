"""Tests for PR 2D — per-clinic Assistant usage-limit guardrail.

Doctrine:
  * Daily and monthly run caps are enforced BEFORE any assistant_runs
    INSERT and BEFORE any model call.
  * Every assistant_runs row counts toward both windows regardless of
    run_status (created / succeeded / refused / failed).
  * Over-limit responses are 429, carry safe metadata only, and contain
    no raw input.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

import pytest

from tests._assistant_test_helpers import (
    TEST_CLINIC_ID,
    auth_headers,
    build_app,
    client_for,
)


def _safe_input() -> Dict[str, Any]:
    return {
        "communication_goal": "Reassure owner about post-op recovery",
        "clinician_confirmed_facts": "Patient is stable. Sutures intact.",
    }


def _unsafe_dose_input() -> Dict[str, Any]:
    return {
        "communication_goal": "What dose of metacam should I give a 12kg dog?",
        "clinician_confirmed_facts": "Patient is post-op and recovering well.",
    }


def _fail_if_called(*, system_prompt: str, user_message: str):
    raise AssertionError(
        "model stub was invoked but the request should never have reached "
        "the model in this test"
    )


# ---------------------------------------------------------------------
# 1. Under limits → run proceeds (and the count query was used)
# ---------------------------------------------------------------------

def test_under_limits_allows_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANCHOR_ASSISTANT_DAILY_RUN_LIMIT_PER_CLINIC", "10")
    monkeypatch.setenv("ANCHOR_ASSISTANT_MONTHLY_RUN_LIMIT_PER_CLINIC", "100")

    app, db = build_app()  # default success stub
    db.count_queue = [3, 25]  # daily=3, monthly=25 — both under

    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={"mode": "client_communication", "input": _safe_input()},
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text

    # INSERT happened.
    sql, _ = db.insert_call
    assert "INSERT INTO assistant_runs" in sql

    # Both count queries executed.
    assert len(db.count_calls) == 2


# ---------------------------------------------------------------------
# 2. Daily limit blocks BEFORE insert and BEFORE model
# ---------------------------------------------------------------------

def test_daily_limit_blocks_before_insert(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANCHOR_ASSISTANT_DAILY_RUN_LIMIT_PER_CLINIC", "1")
    monkeypatch.setenv("ANCHOR_ASSISTANT_MONTHLY_RUN_LIMIT_PER_CLINIC", "1000")

    app, db = build_app(model_stub=_fail_if_called)
    # daily=1 already at the cap → daily check fails before monthly runs
    db.count_queue = [1, 0]

    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={"mode": "client_communication", "input": _safe_input()},
        headers=auth_headers(),
    )
    assert resp.status_code == 429, resp.text

    body = resp.json()
    assert body["detail"] == "assistant_daily_run_limit_exceeded"
    assert body["limit"] == 1
    assert body["window"] == "day"

    # No assistant_runs INSERT.
    inserts = [sql for sql, _ in db.calls if "INSERT INTO assistant_runs" in sql]
    assert inserts == []

    # No UPDATE either.
    assert db.has_update() is False


# ---------------------------------------------------------------------
# 3. Monthly limit blocks BEFORE insert and BEFORE model
# ---------------------------------------------------------------------

def test_monthly_limit_blocks_before_insert(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANCHOR_ASSISTANT_DAILY_RUN_LIMIT_PER_CLINIC", "10")
    monkeypatch.setenv("ANCHOR_ASSISTANT_MONTHLY_RUN_LIMIT_PER_CLINIC", "1")

    app, db = build_app(model_stub=_fail_if_called)
    # daily=0 under cap → monthly=1 at cap → monthly check fails
    db.count_queue = [0, 1]

    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={"mode": "client_communication", "input": _safe_input()},
        headers=auth_headers(),
    )
    assert resp.status_code == 429, resp.text

    body = resp.json()
    assert body["detail"] == "assistant_monthly_run_limit_exceeded"
    assert body["limit"] == 1
    assert body["window"] == "month"

    # No INSERT.
    inserts = [sql for sql, _ in db.calls if "INSERT INTO assistant_runs" in sql]
    assert inserts == []
    assert db.has_update() is False


# ---------------------------------------------------------------------
# 4. Invalid / missing env values fall back to documented defaults
# ---------------------------------------------------------------------

def test_invalid_env_values_fall_back_to_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.assistant_usage_limits import daily_run_limit, monthly_run_limit

    for invalid in ["", "   ", "not-an-int", "-5", "0", "12.5", "1e3"]:
        monkeypatch.setenv("ANCHOR_ASSISTANT_DAILY_RUN_LIMIT_PER_CLINIC", invalid)
        monkeypatch.setenv("ANCHOR_ASSISTANT_MONTHLY_RUN_LIMIT_PER_CLINIC", invalid)
        assert daily_run_limit() == 50, f"daily default not used for {invalid!r}"
        assert monthly_run_limit() == 1000, f"monthly default not used for {invalid!r}"

    # Unset env vars also fall back.
    monkeypatch.delenv("ANCHOR_ASSISTANT_DAILY_RUN_LIMIT_PER_CLINIC", raising=False)
    monkeypatch.delenv("ANCHOR_ASSISTANT_MONTHLY_RUN_LIMIT_PER_CLINIC", raising=False)
    assert daily_run_limit() == 50
    assert monthly_run_limit() == 1000

    # Valid values are honoured.
    monkeypatch.setenv("ANCHOR_ASSISTANT_DAILY_RUN_LIMIT_PER_CLINIC", "7")
    monkeypatch.setenv("ANCHOR_ASSISTANT_MONTHLY_RUN_LIMIT_PER_CLINIC", "42")
    assert daily_run_limit() == 7
    assert monthly_run_limit() == 42


# ---------------------------------------------------------------------
# 5. Count SQL does NOT filter by run_status
# ---------------------------------------------------------------------

def test_limit_counts_all_run_statuses() -> None:
    from app.assistant_usage_limits import _COUNT_SQL

    assert "run_status" not in _COUNT_SQL, (
        "count query must NOT filter by run_status — every assistant_runs "
        "row counts, regardless of created/succeeded/refused/failed"
    )


# ---------------------------------------------------------------------
# 6. Count SQL uses clinic_id + created_at, and params look right
# ---------------------------------------------------------------------

def test_limit_query_uses_clinic_id_and_created_at(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANCHOR_ASSISTANT_DAILY_RUN_LIMIT_PER_CLINIC", "10")
    monkeypatch.setenv("ANCHOR_ASSISTANT_MONTHLY_RUN_LIMIT_PER_CLINIC", "1000")

    app, db = build_app()
    db.count_queue = [0, 0]

    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={"mode": "client_communication", "input": _safe_input()},
        headers=auth_headers(),
    )
    assert resp.status_code == 201

    count_calls = db.count_calls
    assert len(count_calls) == 2

    for sql, p in count_calls:
        assert "clinic_id" in sql
        assert "created_at" in sql
        assert ":window_start" in sql
        assert p["clinic_id"] == TEST_CLINIC_ID
        assert isinstance(p["window_start"], datetime)
        assert p["window_start"].tzinfo is not None

    # The two window_starts must be distinct (day_start, month_start).
    starts = [p["window_start"] for _, p in count_calls]
    assert starts[0] >= starts[1], "day_start should be >= month_start"


# ---------------------------------------------------------------------
# 7. Refused runs are persisted (so they count toward future limits)
# ---------------------------------------------------------------------

def test_refused_requests_count_after_creation_when_under_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANCHOR_ASSISTANT_DAILY_RUN_LIMIT_PER_CLINIC", "10")
    monkeypatch.setenv("ANCHOR_ASSISTANT_MONTHLY_RUN_LIMIT_PER_CLINIC", "100")

    app, db = build_app(model_stub=_fail_if_called)  # must not be called
    db.count_queue = [0, 0]

    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={"mode": "client_communication", "input": _unsafe_dose_input()},
        headers=auth_headers(),
    )
    assert resp.status_code == 201

    body = resp.json()["run"]
    assert body["run_status"] == "generation_refused"
    assert body["refused"] is True

    # The INSERT happened — this row will count toward subsequent limit checks.
    sql, params = db.insert_call
    assert "INSERT INTO assistant_runs" in sql
    assert params["run_status"] == "created"

    # And the run was updated to generation_refused (still a persisted row).
    db.update_call_with_status("generation_refused")


# ---------------------------------------------------------------------
# 8. Failed runs are also persisted and count
# ---------------------------------------------------------------------

def test_generation_failure_counts_after_creation_when_under_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANCHOR_ASSISTANT_DAILY_RUN_LIMIT_PER_CLINIC", "10")
    monkeypatch.setenv("ANCHOR_ASSISTANT_MONTHLY_RUN_LIMIT_PER_CLINIC", "100")

    from app.assistant_anthropic_client import AssistantModelCallError

    def _stub_fail(*, system_prompt: str, user_message: str):
        raise AssistantModelCallError("simulated_provider_failure")

    app, db = build_app(model_stub=_stub_fail)
    db.count_queue = [0, 0]

    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={"mode": "client_communication", "input": _safe_input()},
        headers=auth_headers(),
    )
    assert resp.status_code == 503

    # INSERT happened (will count toward future limits).
    sql, params = db.insert_call
    assert "INSERT INTO assistant_runs" in sql
    assert params["run_status"] == "created"

    # And we wrote generation_failed on the same row.
    db.update_call_with_status("generation_failed")


# ---------------------------------------------------------------------
# 9. 429 response does not leak raw input
# ---------------------------------------------------------------------

def test_limit_response_does_not_include_raw_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANCHOR_ASSISTANT_DAILY_RUN_LIMIT_PER_CLINIC", "1")
    monkeypatch.setenv("ANCHOR_ASSISTANT_MONTHLY_RUN_LIMIT_PER_CLINIC", "1000")

    distinctive_goal = "uniquetoken-goal-DO-NOT-LEAK-12345"
    distinctive_facts = "uniquetoken-facts-DO-NOT-LEAK-67890"

    app, db = build_app(model_stub=_fail_if_called)
    db.count_queue = [1, 0]  # daily over → 429

    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={
            "mode": "client_communication",
            "input": {
                "communication_goal": distinctive_goal,
                "clinician_confirmed_facts": distinctive_facts,
            },
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 429

    body_text = resp.text
    assert distinctive_goal not in body_text
    assert distinctive_facts not in body_text

    # No INSERT params can contain the raw input either (because nothing
    # is inserted on the over-limit path).
    inserts = [
        (sql, p) for sql, p in db.calls if "INSERT INTO assistant_runs" in sql
    ]
    assert inserts == []

    # Defensive: also confirm no DB call captured the raw values.
    for sql, params in db.calls:
        blob = repr(params)
        assert distinctive_goal not in blob, (
            f"raw goal leaked into DB params for SQL: {sql[:80]!r}"
        )
        assert distinctive_facts not in blob, (
            f"raw facts leaked into DB params for SQL: {sql[:80]!r}"
        )


# ---------------------------------------------------------------------
# Window helper sanity (utc midnight, first-of-month)
# ---------------------------------------------------------------------

def test_utc_window_helpers() -> None:
    from app.assistant_usage_limits import utc_day_start, utc_month_start

    sample = datetime(2026, 5, 23, 14, 37, 42, 123456, tzinfo=timezone.utc)
    day = utc_day_start(sample)
    month = utc_month_start(sample)

    assert day == datetime(2026, 5, 23, 0, 0, 0, 0, tzinfo=timezone.utc)
    assert month == datetime(2026, 5, 1, 0, 0, 0, 0, tzinfo=timezone.utc)

    # Naive input is treated as UTC.
    naive = datetime(2026, 5, 23, 14, 37, 42, 123456)
    assert utc_day_start(naive).tzinfo is not None
    assert utc_month_start(naive).tzinfo is not None
