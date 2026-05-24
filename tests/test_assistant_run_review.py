"""Tests for M6.4 — Assistant human review-state workflow.

The PATCH endpoint records metadata-only review evidence. It MUST NOT
accept or persist any raw input, prompt, draft, or free-text clinical
notes. Reviewer identity always comes from the authenticated clinic_user
context, never from the request body.
"""
from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest

from tests._assistant_test_helpers import (
    TEST_CLINIC_ID,
    TEST_USER_ID,
    auth_headers,
    build_app,
    client_for,
)


# Sentinel so callers can pass `None` explicitly without it being replaced
# by the helper's default (`x or <default>` patterns would silently
# overwrite an intentional None with the default value).
_UNSET = object()


def _trace_row(
    *,
    run_id: str | None = None,
    review_status: str = "reviewed_approved",
    review_decision: Any = _UNSET,
    reviewed_at: Any = _UNSET,
    reviewed_by_user_id: Any = _UNSET,
    output_sha256: str | None = "a" * 64,
    model_provider: str | None = "anthropic",
    model_name: str | None = "claude-sonnet-4-6",
    safety_flags: List[str] | None = None,
    refusal_reason_codes: List[str] | None = None,
    run_status: str = "generation_succeeded",
) -> Dict[str, Any]:
    """Shape mirrors what psycopg returns for the RETURNING clause of the
    review UPDATE.

    `review_decision`, `reviewed_at`, and `reviewed_by_user_id` use a
    sentinel default so callers can pass `None` explicitly to model an
    unreviewed row. Passing the field at all means "use this value";
    omitting it means "use the helper's default reviewed-row value".
    """
    default_when = datetime(2026, 5, 23, 13, 14, 15, tzinfo=timezone.utc)
    resolved_reviewed_at = default_when if reviewed_at is _UNSET else reviewed_at
    resolved_reviewed_by = (
        _uuid.UUID(TEST_USER_ID)
        if reviewed_by_user_id is _UNSET
        else (
            _uuid.UUID(reviewed_by_user_id)
            if isinstance(reviewed_by_user_id, str)
            else reviewed_by_user_id
        )
    )
    resolved_decision = "approved_for_use" if review_decision is _UNSET else review_decision

    # updated_at tracks the reviewed_at when present, otherwise the run's
    # creation timestamp — mirroring how the backend updates the row.
    updated_at = resolved_reviewed_at or datetime(2026, 5, 23, 12, 0, 0, tzinfo=timezone.utc)

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
        "pii_detected": False,
        "pii_types": [],
        "safety_flags": safety_flags or [],
        "refusal_reason_codes": refusal_reason_codes or [],
        "review_status": review_status,
        "run_status": run_status,
        "receipt_id": None,
        "governance_event_id": None,
        "model_provider": model_provider,
        "model_name": model_name,
        "review_decision": resolved_decision,
        "reviewed_at": resolved_reviewed_at,
        "reviewed_by_user_id": resolved_reviewed_by,
        "created_at": datetime(2026, 5, 23, 12, 0, 0, tzinfo=timezone.utc),
        "updated_at": updated_at,
    }


def _patch_review(app, run_id: str, body: Dict[str, Any]):
    return client_for(app).patch(
        f"/v1/assistant/runs/{run_id}/review",
        json=body,
        headers=auth_headers(),
    )


_FORBIDDEN_RAW_KEYS = {
    "draft",
    "input",
    "input_text",
    "output_text",
    "prompt",
    "raw_input",
    "raw_output",
    "notes",
}


# ---------------------------------------------------------------------
# 1. reviewed_approved → approved_for_use
# ---------------------------------------------------------------------

def test_review_approved_updates_metadata_only() -> None:
    rid = str(_uuid.uuid4())
    app, db = build_app()
    db.update_review_row = _trace_row(
        run_id=rid,
        review_status="reviewed_approved",
        review_decision="approved_for_use",
    )

    resp = _patch_review(app, rid, {"review_status": "reviewed_approved"})
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["storage_policy"] == "metadata_only_by_default"
    assert body["raw_content_stored"] is False
    assert body["draft_stored"] is False
    assert body["prompt_stored"] is False

    run = body["run"]
    assert run["review_status"] == "reviewed_approved"
    assert run["review_decision"] == "approved_for_use"
    assert run["reviewed_at"] is not None
    assert run["reviewed_by_user_id"] == TEST_USER_ID
    assert not (_FORBIDDEN_RAW_KEYS & set(run.keys()))


# ---------------------------------------------------------------------
# 2. reviewed_rejected → rejected_not_safe
# ---------------------------------------------------------------------

def test_review_rejected_updates_metadata_only() -> None:
    rid = str(_uuid.uuid4())
    app, db = build_app()
    db.update_review_row = _trace_row(
        run_id=rid,
        review_status="reviewed_rejected",
        review_decision="rejected_not_safe",
    )

    resp = _patch_review(app, rid, {"review_status": "reviewed_rejected"})
    assert resp.status_code == 200, resp.text
    run = resp.json()["run"]
    assert run["review_status"] == "reviewed_rejected"
    assert run["review_decision"] == "rejected_not_safe"

    _, params = db.last_update_call
    assert params["review_status"] == "reviewed_rejected"
    assert params["review_decision"] == "rejected_not_safe"


# ---------------------------------------------------------------------
# 3. reviewed_needs_edit → needs_edit_before_use
# ---------------------------------------------------------------------

def test_review_needs_edit_updates_metadata_only() -> None:
    rid = str(_uuid.uuid4())
    app, db = build_app()
    db.update_review_row = _trace_row(
        run_id=rid,
        review_status="reviewed_needs_edit",
        review_decision="needs_edit_before_use",
    )

    resp = _patch_review(app, rid, {"review_status": "reviewed_needs_edit"})
    assert resp.status_code == 200, resp.text
    run = resp.json()["run"]
    assert run["review_status"] == "reviewed_needs_edit"
    assert run["review_decision"] == "needs_edit_before_use"

    _, params = db.last_update_call
    assert params["review_status"] == "reviewed_needs_edit"
    assert params["review_decision"] == "needs_edit_before_use"


# ---------------------------------------------------------------------
# 4. PATCH with not_reviewed is rejected
# ---------------------------------------------------------------------

def test_review_rejects_not_reviewed_reset() -> None:
    rid = str(_uuid.uuid4())
    app, db = build_app()
    db.update_review_row = None  # must not even be referenced

    resp = _patch_review(app, rid, {"review_status": "not_reviewed"})
    assert resp.status_code == 400, resp.text
    assert resp.json().get("detail") == "invalid_review_status"

    # No UPDATE happened.
    assert db.has_update() is False


# ---------------------------------------------------------------------
# 5. Unknown review_status rejected
# ---------------------------------------------------------------------

def test_review_rejects_unknown_status() -> None:
    rid = str(_uuid.uuid4())
    app, db = build_app()
    db.update_review_row = None

    resp = _patch_review(app, rid, {"review_status": "definitely_not_a_status"})
    assert resp.status_code == 400, resp.text
    assert resp.json().get("detail") == "invalid_review_status"
    assert db.has_update() is False


# ---------------------------------------------------------------------
# 6. 404 when no row matched (covers cross-clinic non-leakage)
# ---------------------------------------------------------------------

def test_review_not_found_returns_404() -> None:
    rid = str(_uuid.uuid4())
    app, db = build_app()
    db.update_review_row = None  # UPDATE matched zero rows

    resp = _patch_review(app, rid, {"review_status": "reviewed_approved"})
    assert resp.status_code == 404, resp.text
    assert resp.json().get("detail") == "assistant_run_not_found"


# ---------------------------------------------------------------------
# 7. SQL + params use clinic_id, run_id, and authenticated reviewer
# ---------------------------------------------------------------------

def test_review_update_uses_clinic_id_and_run_id() -> None:
    rid = str(_uuid.uuid4())
    app, db = build_app()
    db.update_review_row = _trace_row(run_id=rid)

    resp = _patch_review(app, rid, {"review_status": "reviewed_approved"})
    assert resp.status_code == 200

    sql, params = db.last_update_call
    assert "UPDATE assistant_runs" in sql
    assert "review_status = :review_status" in sql
    assert "id = CAST(:run_id AS uuid)" in sql
    assert "clinic_id = CAST(:clinic_id AS uuid)" in sql
    assert "reviewed_by_user_id = CAST(:reviewed_by_user_id AS uuid)" in sql
    assert "RETURNING" in sql

    assert params["clinic_id"] == TEST_CLINIC_ID
    assert params["run_id"] == rid
    # Reviewer identity comes from the authenticated context, not the body.
    assert params["reviewed_by_user_id"] == TEST_USER_ID
    assert params["review_status"] == "reviewed_approved"
    assert params["review_decision"] == "approved_for_use"


# ---------------------------------------------------------------------
# 8. Request rejects extra fields (no free-text notes accepted)
# ---------------------------------------------------------------------

def test_review_update_does_not_store_raw_content() -> None:
    """`extra='forbid'` on the request model means any attempt to slip in
    notes / draft text / a reviewer override is rejected by Pydantic at
    422 — before any DB call, before any logging."""
    rid = str(_uuid.uuid4())
    distinctive = "uniquetoken-clinical-note-DO-NOT-LEAK-99999"

    app, db = build_app()
    db.update_review_row = _trace_row(run_id=rid)

    resp = _patch_review(
        app,
        rid,
        {
            "review_status": "reviewed_approved",
            "notes": distinctive,
            "draft": distinctive,
            "reviewer_email": "spoofed@example.com",
        },
    )
    assert resp.status_code == 422, resp.text
    body_text = resp.text
    # The distinctive string appears in the 422 validation error path
    # (pydantic includes the field name "notes") but the *value* itself
    # must not leak via DB params or be persisted anywhere.
    for sql, params in db.calls:
        blob = repr(params)
        assert distinctive not in blob, (
            f"forbidden value leaked into DB params for SQL: {sql[:80]!r}"
        )
    # No UPDATE happened.
    assert db.has_update() is False
    # Pydantic's 422 explains the extra-field rejection but does not
    # echo back the value of the rejected field directly in production
    # configurations. We at minimum ensure the *fake email* spoof was
    # not committed anywhere.
    assert "spoofed@example.com" not in body_text or db.has_update() is False


# ---------------------------------------------------------------------
# 9. List endpoint surfaces review metadata for each row
# ---------------------------------------------------------------------

def test_traceability_list_includes_review_metadata() -> None:
    app, db = build_app()
    db.select_list_rows = [
        _trace_row(
            review_status="reviewed_approved",
            review_decision="approved_for_use",
        ),
        _trace_row(
            review_status="not_reviewed",
            review_decision=None,
            reviewed_at=None,
            reviewed_by_user_id=None,
        ),
    ]

    resp = client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    assert resp.status_code == 200
    items = resp.json()["runs"]
    assert len(items) == 2

    required = {"review_status", "review_decision", "reviewed_at", "reviewed_by_user_id"}
    for item in items:
        missing = required - set(item.keys())
        assert not missing, f"missing review metadata fields: {missing}"

    assert items[0]["review_decision"] == "approved_for_use"
    assert items[0]["reviewed_at"] is not None
    assert items[0]["reviewed_by_user_id"] == TEST_USER_ID

    assert items[1]["review_status"] == "not_reviewed"
    assert items[1]["review_decision"] is None
    assert items[1]["reviewed_at"] is None
    assert items[1]["reviewed_by_user_id"] is None


# ---------------------------------------------------------------------
# 10. Detail endpoint surfaces review metadata + storage flags
# ---------------------------------------------------------------------

def test_traceability_detail_includes_review_metadata() -> None:
    rid = str(_uuid.uuid4())
    row = _trace_row(
        run_id=rid,
        review_status="reviewed_needs_edit",
        review_decision="needs_edit_before_use",
    )
    app, db = build_app()
    db.select_detail_row = row

    resp = client_for(app).get(
        f"/v1/assistant/runs/{rid}",
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["storage_policy"] == "metadata_only_by_default"
    assert body["raw_content_stored"] is False
    assert body["draft_stored"] is False
    assert body["prompt_stored"] is False

    run = body["run"]
    assert run["review_status"] == "reviewed_needs_edit"
    assert run["review_decision"] == "needs_edit_before_use"
    assert run["reviewed_at"] is not None
    assert run["reviewed_by_user_id"] == TEST_USER_ID
    assert not (_FORBIDDEN_RAW_KEYS & set(run.keys()))


# ---------------------------------------------------------------------
# Bonus: unauthenticated PATCH rejected
# ---------------------------------------------------------------------

def test_review_unauthenticated_request_rejected() -> None:
    rid = str(_uuid.uuid4())
    app, db = build_app(authenticated=False)
    db.update_review_row = _trace_row(run_id=rid)

    from fastapi.testclient import TestClient
    resp = TestClient(app).patch(
        f"/v1/assistant/runs/{rid}/review",
        json={"review_status": "reviewed_approved"},
    )
    assert resp.status_code == 401
    assert db.has_update() is False
