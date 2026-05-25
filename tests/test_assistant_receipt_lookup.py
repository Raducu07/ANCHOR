"""Tests for M6.9.3 — identifier-keyed Assistant receipt lookup.

GET /v1/assistant/receipts/{identifier} resolves an Assistant metadata
receipt from either a receipt UUID or a run UUID. The endpoint is
metadata-only by contract (mirrors the existing per-run endpoint), is
clinic-scoped, and never returns raw input, prompt, draft, or policy
notes. The existing per-run endpoint is untouched.
"""
from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from tests._assistant_test_helpers import (
    TEST_CLINIC_ID,
    TEST_USER_ID,
    auth_headers,
    build_app,
    client_for,
)


# ---------------------------------------------------------------------
# Fixture helpers (local copies — same shapes as test_assistant_run_receipts)
# ---------------------------------------------------------------------

def _trace_run_row(
    *,
    run_id: str | None = None,
    run_status: str = "generation_succeeded",
    review_status: str = "reviewed_approved",
    review_decision: str | None = "approved_for_use",
    output_sha256: str | None = "a" * 64,
    safety_flags: List[str] | None = None,
    refusal_reason_codes: List[str] | None = None,
    pii_types: List[str] | None = None,
    pii_detected: bool = False,
    receipt_id: str | None = None,
) -> Dict[str, Any]:
    when_run = datetime(2026, 5, 24, 10, 0, 0, tzinfo=timezone.utc)
    when_review = datetime(2026, 5, 24, 11, 0, 0, tzinfo=timezone.utc)
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
        "review_status": review_status,
        "run_status": run_status,
        "receipt_id": _uuid.UUID(receipt_id) if receipt_id else None,
        "governance_event_id": None,
        "model_provider": "anthropic",
        "model_name": "claude-sonnet-4-6",
        "review_decision": review_decision,
        "reviewed_at": when_review if review_status != "not_reviewed" else None,
        "reviewed_by_user_id": _uuid.UUID(TEST_USER_ID)
        if review_status != "not_reviewed"
        else None,
        "created_at": when_run,
        "updated_at": when_review,
    }


def _receipt_row(
    *,
    receipt_id: str,
    assistant_run_id: str,
    run_status: str = "generation_succeeded",
    review_status: str = "reviewed_approved",
    review_decision: str | None = "approved_for_use",
    output_sha256: str | None = "a" * 64,
    safety_flags: List[str] | None = None,
    refusal_reason_codes: List[str] | None = None,
    pii_detected: bool = False,
    # M6.7.1: legacy receipts may have NULL policy fields. Tests can
    # override these to verify legacy-safety.
    assistant_policy_version: Optional[int] = None,
    assistant_validation_profile: Optional[str] = None,
    assistant_policy_id: Optional[_uuid.UUID] = None,
) -> Dict[str, Any]:
    when_recv = datetime(2026, 5, 24, 12, 0, 0, tzinfo=timezone.utc)
    return {
        "receipt_id": _uuid.UUID(receipt_id),
        "assistant_run_id": _uuid.UUID(assistant_run_id),
        "clinic_id": _uuid.UUID(TEST_CLINIC_ID),
        "created_by_user_id": _uuid.UUID(TEST_USER_ID),
        "receipt_kind": "assistant_run_metadata",
        "receipt_version": "assistant_receipt_v1",
        "storage_policy": "metadata_only_by_default",
        "raw_content_stored": False,
        "prompt_stored": False,
        "draft_stored": False,
        "run_status": run_status,
        "review_status": review_status,
        "review_decision": review_decision,
        "input_sha256": "b" * 64,
        "output_sha256": output_sha256,
        "mode": "client_communication",
        "contract_version": "assistant_contract_v1",
        "workflow_origin": "anchor_assistant",
        "pii_detected": pii_detected,
        "pii_types": [],
        "safety_flags": safety_flags or [],
        "refusal_reason_codes": refusal_reason_codes or [],
        "model_provider": "anthropic",
        "model_name": "claude-sonnet-4-6",
        "assistant_policy_id": assistant_policy_id,
        "assistant_policy_version": assistant_policy_version,
        "assistant_validation_profile": assistant_validation_profile,
        "assistant_run_created_at": datetime(2026, 5, 24, 10, 0, 0, tzinfo=timezone.utc),
        "assistant_run_reviewed_at": datetime(2026, 5, 24, 11, 0, 0, tzinfo=timezone.utc),
        "assistant_run_reviewed_by_user_id": _uuid.UUID(TEST_USER_ID),
        "receipt_created_at": when_recv,
        "created_at": when_recv,
        "updated_at": when_recv,
    }


# Schema-level fields we expect to never appear on the receipt envelope —
# raw user content, raw model output, configurable policy free-text. Schema
# label words like "input_hash" or "output_sha256" are governance metadata
# and are intentionally allowed.
_FORBIDDEN_RAW_FIELDS = {
    "raw_input",
    "raw_output",
    "raw_prompt",
    "raw_draft",
    "input_text",
    "output_text",
    "prompt",
    "user_message",
    "system_prompt",
    "clinical_content",
    "draft",
    "policy_notes",
    "communication_goal",
    "clinician_confirmed_facts",
    "notes",
}


def _get_by_identifier(app, identifier: str):
    return client_for(app).get(
        f"/v1/assistant/receipts/{identifier}",
        headers=auth_headers(),
    )


# ---------------------------------------------------------------------
# 1. Lookup by receipt_id
# ---------------------------------------------------------------------

def test_get_assistant_receipt_lookup_by_receipt_id() -> None:
    rid = str(_uuid.uuid4())
    recv_id = str(_uuid.uuid4())

    app, db = build_app()
    db.select_receipt_row = _receipt_row(
        receipt_id=recv_id, assistant_run_id=rid
    )
    db.select_detail_row = _trace_run_row(run_id=rid, receipt_id=recv_id)

    resp = _get_by_identifier(app, recv_id)
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["receipt"]["receipt_id"] == recv_id
    assert body["receipt"]["assistant_run_id"] == rid
    assert body["matched_by"] == "receipt_id"
    assert body["run"]["run_id"] == rid
    assert "metadata-only" in body["governance_note"].lower()


# ---------------------------------------------------------------------
# 2. Lookup by run_id
# ---------------------------------------------------------------------

def test_get_assistant_receipt_lookup_by_run_id() -> None:
    rid = str(_uuid.uuid4())
    recv_id = str(_uuid.uuid4())

    app, db = build_app()
    db.select_receipt_row = _receipt_row(
        receipt_id=recv_id, assistant_run_id=rid
    )
    db.select_detail_row = _trace_run_row(run_id=rid, receipt_id=recv_id)

    resp = _get_by_identifier(app, rid)
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["receipt"]["receipt_id"] == recv_id
    assert body["receipt"]["assistant_run_id"] == rid
    assert body["matched_by"] == "run_id"


# ---------------------------------------------------------------------
# 3. Unknown identifier → 404
# ---------------------------------------------------------------------

def test_get_assistant_receipt_lookup_not_found() -> None:
    app, db = build_app()
    db.select_receipt_row = None  # no receipt matches identifier

    resp = _get_by_identifier(app, str(_uuid.uuid4()))
    assert resp.status_code == 404
    assert resp.json().get("detail") == "assistant_receipt_not_found"


# ---------------------------------------------------------------------
# 4. Auth required
# ---------------------------------------------------------------------

def test_get_assistant_receipt_lookup_requires_auth() -> None:
    # build_app(authenticated=False) leaves the real require_clinic_user
    # dependency in place; without a valid bearer token it should reject.
    app, _db = build_app(authenticated=False)
    resp = client_for(app).get(
        f"/v1/assistant/receipts/{_uuid.uuid4()}",
    )
    # 401 from require_clinic_user, or 422 if FastAPI rejects the missing
    # header earlier — either way the request must not return a receipt.
    assert resp.status_code in (401, 403, 422), resp.text
    if resp.status_code == 200:  # pragma: no cover - defensive
        raise AssertionError("unauthenticated request must not return a receipt")


# ---------------------------------------------------------------------
# 5. Clinic isolation — a receipt from another clinic is not returned
# ---------------------------------------------------------------------

def test_get_assistant_receipt_lookup_clinic_isolation() -> None:
    other_recv = str(_uuid.uuid4())

    app, db = build_app()
    # FakeDB returns select_receipt_row only when the SELECT matches its
    # routing heuristic. The endpoint's SQL is parameterized with the
    # caller's clinic_id, and the FakeDB exposes select_receipt_row=None
    # to model "no receipt for this clinic". This mirrors the real RLS
    # behaviour where the WHERE clinic_id = :clinic_id predicate filters
    # out cross-clinic rows.
    db.select_receipt_row = None

    resp = _get_by_identifier(app, other_recv)
    assert resp.status_code == 404
    assert resp.json().get("detail") == "assistant_receipt_not_found"

    # The SELECT must have been parameterized with the authenticated
    # clinic_id (not the other clinic's id), proving clinic scoping.
    receipt_selects = [
        (sql, params)
        for sql, params in db.calls
        if "SELECT" in sql
        and "FROM assistant_run_receipts" in sql
        and "INSERT" not in sql
    ]
    assert receipt_selects, "lookup did not issue a receipts SELECT"
    _sql, params = receipt_selects[0]
    assert params.get("clinic_id") == TEST_CLINIC_ID


# ---------------------------------------------------------------------
# 6. Metadata-only — no raw content / no policy_notes
# ---------------------------------------------------------------------

def test_get_assistant_receipt_lookup_metadata_only() -> None:
    rid = str(_uuid.uuid4())
    recv_id = str(_uuid.uuid4())

    app, db = build_app()
    db.select_receipt_row = _receipt_row(
        receipt_id=recv_id, assistant_run_id=rid
    )
    db.select_detail_row = _trace_run_row(run_id=rid, receipt_id=recv_id)

    resp = _get_by_identifier(app, recv_id)
    assert resp.status_code == 200

    body = resp.json()
    # No raw content fields on receipt, run, or top-level envelope.
    for scope in (body, body["receipt"], body["run"]):
        assert isinstance(scope, dict)
        overlap = _FORBIDDEN_RAW_FIELDS & set(scope.keys())
        assert not overlap, (
            f"receipt envelope leaked raw content fields: {overlap!r}"
        )
    # Explicit storage-posture assertions must remain "no raw content".
    assert body["receipt"]["raw_content_stored"] is False
    assert body["receipt"]["prompt_stored"] is False
    assert body["receipt"]["draft_stored"] is False


# ---------------------------------------------------------------------
# 7. Existing per-run endpoint is unchanged
# ---------------------------------------------------------------------

def test_existing_run_receipt_endpoint_still_works() -> None:
    """Regression guard: M6.9.3 must not alter GET /runs/{run_id}/receipt.
    The per-run endpoint returns the same envelope; matched_by stays None
    so older frontends see no behavioural change."""
    rid = str(_uuid.uuid4())
    recv_id = str(_uuid.uuid4())

    app, db = build_app()
    db.select_detail_row = _trace_run_row(
        run_id=rid,
        review_status="reviewed_approved",
        receipt_id=recv_id,
    )
    db.select_receipt_row = _receipt_row(
        receipt_id=recv_id, assistant_run_id=rid
    )

    resp = client_for(app).get(
        f"/v1/assistant/runs/{rid}/receipt",
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["receipt"]["receipt_id"] == recv_id
    assert body["receipt"]["assistant_run_id"] == rid
    # matched_by is absent on the legacy endpoint (Pydantic serialises
    # Optional[str] = None as null).
    assert body.get("matched_by") is None


# ---------------------------------------------------------------------
# 8. Legacy receipt with NULL policy fields is safe
# ---------------------------------------------------------------------

def test_get_assistant_receipt_lookup_legacy_policy_fields_safe() -> None:
    rid = str(_uuid.uuid4())
    recv_id = str(_uuid.uuid4())

    app, db = build_app()
    db.select_receipt_row = _receipt_row(
        receipt_id=recv_id,
        assistant_run_id=rid,
        assistant_policy_version=None,
        assistant_validation_profile=None,
        assistant_policy_id=None,
    )
    db.select_detail_row = _trace_run_row(run_id=rid, receipt_id=recv_id)

    resp = _get_by_identifier(app, recv_id)
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["receipt"]["assistant_policy_version"] is None
    assert body["receipt"]["assistant_validation_profile"] is None
    assert body["receipt"]["assistant_policy_id"] is None
