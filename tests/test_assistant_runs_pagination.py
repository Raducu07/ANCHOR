"""M6.11.2 — GET /v1/assistant/runs cursor pagination and has_receipt filter.

Backwards-compatible additions to the existing list endpoint:
  * `cursor` query param + `next_cursor`/`has_more` response keys
  * `has_receipt=true` filter for receipt-bearing runs
  * `applied_filters` echo
  * stable total ordering by `(created_at DESC, id DESC)`
  * LEFT JOIN to `assistant_run_receipts` hydrates `receipt_created_at`
    in the list path

Doctrine guards:
  * metadata-only — no raw prompt/output/draft/transcript fields appear
  * clinic-wide visibility — every authenticated clinic role can list
  * unauthenticated → 401 (covered by existing traceability tests; this
    file adds an additional explicit assertion for clarity)
"""
from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest

from tests._assistant_test_helpers import (
    TEST_CLINIC_ID,
    TEST_USER_ID,
    auth_headers,
    build_app,
    client_for,
)


# ---------------------------------------------------------------------
# Local row helper — mirrors the test_assistant_run_traceability helper
# but also supports receipt_id / receipt_created_at hydration so the
# new LEFT JOIN code path is exercised end-to-end through FakeDB.
# ---------------------------------------------------------------------


def _row(
    *,
    run_id: Optional[str] = None,
    created_at: Optional[datetime] = None,
    run_status: str = "generation_succeeded",
    mode: str = "client_communication",
    receipt_id: Optional[str] = None,
    receipt_created_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    now = created_at or datetime(2026, 5, 30, 10, 0, 0, tzinfo=timezone.utc)
    return {
        "run_id": _uuid.UUID(run_id) if run_id else _uuid.uuid4(),
        "clinic_id": _uuid.UUID(TEST_CLINIC_ID),
        "clinic_user_id": _uuid.UUID(TEST_USER_ID),
        "mode": mode,
        "contract_version": "assistant_contract_v1",
        "workflow_origin": "anchor_assistant",
        "input_sha256": "b" * 64,
        "output_sha256": "a" * 64,
        "input_field_keys": ["clinician_confirmed_facts", "communication_goal"],
        "pii_detected": False,
        "pii_types": [],
        "safety_flags": [],
        "refusal_reason_codes": [],
        "review_status": "not_reviewed",
        "run_status": run_status,
        "receipt_id": _uuid.UUID(receipt_id) if receipt_id else None,
        "governance_event_id": None,
        "model_provider": "anthropic",
        "model_name": "claude-sonnet-4-6",
        "review_decision": None,
        "reviewed_at": None,
        "reviewed_by_user_id": None,
        "assistant_policy_id": None,
        "assistant_policy_version": None,
        "assistant_validation_profile": "standard",
        "created_at": now,
        "updated_at": now,
        "receipt_created_at": receipt_created_at,
    }


def _list_select_calls(db) -> List[tuple]:
    return [
        (s, p) for s, p in db.calls
        if "FROM assistant_runs" in s and "ORDER BY" in s
    ]


# =====================================================================
# 1. Backwards compatibility
# =====================================================================


def test_list_runs_backwards_compatible_no_cursor_no_has_receipt() -> None:
    app, db = build_app()
    db.select_list_rows = [_row(run_status="generation_succeeded")]

    resp = client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Existing keys preserved.
    assert "runs" in body and isinstance(body["runs"], list)
    assert body["limit"] == 25
    # New keys present and safe-defaulted.
    assert body["has_more"] is False
    assert body["next_cursor"] is None
    assert body["applied_filters"] == {
        "run_status": None, "mode": None, "has_receipt": None,
    }


# =====================================================================
# 2. Cursor pagination
# =====================================================================


def test_list_runs_has_more_true_when_overflow_and_next_cursor_emitted() -> None:
    # FakeDB returns exactly limit + 1 rows -> overflow detected.
    base = datetime(2026, 5, 30, 12, 0, 0, tzinfo=timezone.utc)
    rows = [
        _row(created_at=base - timedelta(minutes=i))
        for i in range(26)  # 25 + 1
    ]
    app, db = build_app()
    db.select_list_rows = rows

    resp = client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Extra row dropped.
    assert len(body["runs"]) == 25
    assert body["has_more"] is True
    # next_cursor encodes (created_at_iso, run_id) of the LAST emitted row,
    # not the dropped overflow row. Compare via datetime parsing because
    # FastAPI may render the same instant as `Z` while
    # _encode_assistant_runs_cursor uses `+00:00`.
    last_run = body["runs"][-1]
    assert body["next_cursor"] is not None
    assert "|" in body["next_cursor"]
    cursor_ts, cursor_uuid = body["next_cursor"].split("|", 1)
    response_ts = last_run["created_at"].replace("Z", "+00:00")
    assert datetime.fromisoformat(cursor_ts) == datetime.fromisoformat(response_ts)
    assert cursor_uuid == last_run["run_id"]


def test_list_runs_has_more_false_when_under_limit() -> None:
    app, db = build_app()
    db.select_list_rows = [_row(), _row(), _row()]  # 3 < 25

    resp = client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["runs"]) == 3
    assert body["has_more"] is False
    assert body["next_cursor"] is None


def test_list_runs_has_more_false_when_exactly_limit() -> None:
    # Exactly `limit` rows returned (no overflow) → no next page.
    rows = [_row() for _ in range(5)]
    app, db = build_app()
    db.select_list_rows = rows

    resp = client_for(app).get("/v1/assistant/runs?limit=5", headers=auth_headers())
    assert resp.status_code == 200
    body = resp.json()
    # NB: FakeDB returns whatever we put in select_list_rows regardless of
    # the LIMIT clause; this test asserts handler behaviour when the row
    # count is at most `limit` (i.e. no overflow row present).
    assert len(body["runs"]) == 5
    assert body["has_more"] is False
    assert body["next_cursor"] is None


def test_list_runs_cursor_binds_created_at_and_run_id_params() -> None:
    app, db = build_app()
    db.select_list_rows = []

    cursor_id = "11111111-1111-4111-8111-111111111111"
    # URL-encode the `+` in the timezone offset so FastAPI doesn't
    # decode it as a space.
    cursor_ts = "2026-05-30T11:30:00%2B00:00"
    resp = client_for(app).get(
        f"/v1/assistant/runs?cursor={cursor_ts}|{cursor_id}",
        headers=auth_headers(),
    )
    assert resp.status_code == 200

    sql, params = _list_select_calls(db)[-1]
    # Keyset predicate present.
    assert "ar.created_at < :cursor_created_at" in sql
    assert "ar.id < :cursor_run_id" in sql
    # Parameters bound.
    assert params["cursor_run_id"] == cursor_id
    # cursor_created_at is a datetime object after parsing.
    assert isinstance(params["cursor_created_at"], datetime)


@pytest.mark.parametrize(
    "bad_cursor",
    [
        "not-a-cursor",
        "2026-05-30T11:30:00+00:00",            # missing | + run_id
        "2026-05-30T11:30:00+00:00|not-a-uuid", # bad uuid
        "not-a-timestamp|11111111-1111-4111-8111-111111111111",
        "|",
        "|11111111-1111-4111-8111-111111111111",
    ],
)
def test_list_runs_invalid_cursor_returns_400(bad_cursor: str) -> None:
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get(
        f"/v1/assistant/runs?cursor={bad_cursor}",
        headers=auth_headers(),
    )
    assert resp.status_code == 400, resp.text
    assert resp.json().get("detail") == "invalid_cursor"


# =====================================================================
# 3. Stable ordering
# =====================================================================


def test_list_runs_sql_orders_by_created_at_then_id_desc() -> None:
    app, db = build_app()
    db.select_list_rows = []
    client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    sql, _ = _list_select_calls(db)[-1]
    assert "ORDER BY ar.created_at DESC, ar.id DESC" in sql


# =====================================================================
# 4. has_receipt filter
# =====================================================================


def test_list_runs_has_receipt_true_adds_receipt_id_not_null_filter() -> None:
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get(
        "/v1/assistant/runs?has_receipt=true",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    sql, _ = _list_select_calls(db)[-1]
    assert "ar.receipt_id IS NOT NULL" in sql
    assert resp.json()["applied_filters"]["has_receipt"] is True


def test_list_runs_has_receipt_false_does_not_add_filter() -> None:
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get(
        "/v1/assistant/runs?has_receipt=false",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    sql, _ = _list_select_calls(db)[-1]
    assert "receipt_id IS NOT NULL" not in sql
    assert resp.json()["applied_filters"]["has_receipt"] is False


def test_list_runs_has_receipt_omitted_does_not_add_filter() -> None:
    app, db = build_app()
    db.select_list_rows = []
    client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    sql, _ = _list_select_calls(db)[-1]
    assert "receipt_id IS NOT NULL" not in sql


# =====================================================================
# 5. Existing filters preserved
# =====================================================================


def test_list_runs_run_status_filter_still_works() -> None:
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get(
        "/v1/assistant/runs?run_status=generation_refused",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    sql, params = _list_select_calls(db)[-1]
    assert "ar.run_status = :run_status" in sql
    assert params["run_status"] == "generation_refused"
    assert resp.json()["applied_filters"]["run_status"] == "generation_refused"


def test_list_runs_invalid_run_status_still_400() -> None:
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get(
        "/v1/assistant/runs?run_status=bogus",
        headers=auth_headers(),
    )
    assert resp.status_code == 400


def test_list_runs_mode_filter_still_works() -> None:
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get(
        "/v1/assistant/runs?mode=client_communication",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    sql, params = _list_select_calls(db)[-1]
    assert "ar.mode = :mode" in sql
    assert params["mode"] == "client_communication"


def test_list_runs_invalid_mode_still_400() -> None:
    app, db = build_app()
    db.select_list_rows = []
    resp = client_for(app).get(
        "/v1/assistant/runs?mode=discharge_instructions",
        headers=auth_headers(),
    )
    assert resp.status_code == 400


# =====================================================================
# 6. Visibility — clinic-wide, all authenticated roles
# =====================================================================


@pytest.mark.parametrize(
    "role",
    ["admin", "owner", "practice_manager", "staff", "clinic_user", "reader"],
)
def test_list_runs_visible_to_all_authenticated_clinic_roles(role: str) -> None:
    """Codifies the M6.11.2 visibility decision: GET /v1/assistant/runs
    (with or without has_receipt=true) remains clinic-wide for every
    authenticated clinic user — receipts are governance evidence for
    the clinic, not personal records."""
    app, db = build_app(auth_role=role)
    db.select_list_rows = [
        _row(receipt_id=str(_uuid.uuid4()),
             receipt_created_at=datetime(2026, 5, 30, tzinfo=timezone.utc)),
    ]
    resp = client_for(app).get(
        "/v1/assistant/runs?has_receipt=true",
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["runs"]) == 1


def test_list_runs_unauthenticated_returns_401() -> None:
    app, db = build_app(authenticated=False)
    db.select_list_rows = []
    from fastapi.testclient import TestClient
    resp = TestClient(app).get("/v1/assistant/runs")
    assert resp.status_code == 401


# =====================================================================
# 7. Metadata-only response (regression doctrine)
# =====================================================================


def test_list_runs_response_has_no_raw_content_fields() -> None:
    app, db = build_app()
    db.select_list_rows = [_row()]
    resp = client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    assert resp.status_code == 200

    forbidden = {
        "draft", "draft_output", "input", "input_text", "output", "output_text",
        "prompt", "user_message", "raw_input", "raw_output",
        "transcript", "client_narrative", "policy_notes",
        "reviewer_name", "reviewer_email", "reviewed_by_email",
    }
    body = resp.json()
    for item in body["runs"]:
        leaked = forbidden & set(item.keys())
        assert not leaked, f"forbidden raw-content fields leaked: {leaked}"


# =====================================================================
# 8. receipt_created_at hydration
# =====================================================================


def test_list_runs_receipt_created_at_populated_via_join() -> None:
    """The LEFT JOIN to assistant_run_receipts should hydrate
    receipt_created_at in the list path. We exercise this via FakeDB
    by populating the column on the returned row dict."""
    receipt_ts = datetime(2026, 5, 30, 9, 30, 0, tzinfo=timezone.utc)
    app, db = build_app()
    db.select_list_rows = [
        _row(
            receipt_id=str(_uuid.uuid4()),
            receipt_created_at=receipt_ts,
        ),
    ]
    resp = client_for(app).get(
        "/v1/assistant/runs?has_receipt=true",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    item = resp.json()["runs"][0]
    assert item["receipt_created_at"] is not None
    assert item["has_receipt"] is True


def test_list_runs_sql_includes_left_join_to_receipts() -> None:
    app, db = build_app()
    db.select_list_rows = []
    client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    sql, _ = _list_select_calls(db)[-1]
    assert "LEFT JOIN assistant_run_receipts" in sql
    # Tenant-isolated join: the right side must also bind clinic_id so
    # FORCE RLS independently protects the receipts table.
    assert "arr.clinic_id = ar.clinic_id" in sql


# =====================================================================
# 9. Regression — no broken admin_audit_events ON CONFLICT reintroduced
# =====================================================================


def test_no_invalid_partial_index_on_conflict_in_portal_assistant() -> None:
    """Belt-and-braces against the M6.10.1 prod 500. Scans the
    portal_assistant module source for the unsafe conflict target."""
    import inspect
    from app import portal_assistant

    src = inspect.getsource(portal_assistant)
    assert "ON CONFLICT (clinic_id, action, idempotency_key)" not in src
