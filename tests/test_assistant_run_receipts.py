"""Tests for M6.5 — Assistant receipt linkage.

Receipts are metadata-only governance evidence. They MUST NOT contain or
imply any stored raw input, prompt, draft, or clinical content. One
receipt per (clinic_id, assistant_run_id); repeated POSTs return the
same receipt (idempotent).
"""
from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pytest

from tests._assistant_test_helpers import (
    TEST_CLINIC_ID,
    TEST_USER_ID,
    auth_headers,
    build_app,
    client_for,
)


def _trace_run_row(
    *,
    run_id: str | None = None,
    run_status: str = "generation_succeeded",
    review_status: str = "reviewed_approved",
    review_decision: str | None = "approved_for_use",
    output_sha256: str | None = "a" * 64,
    model_provider: str | None = "anthropic",
    model_name: str | None = "claude-sonnet-4-6",
    safety_flags: List[str] | None = None,
    refusal_reason_codes: List[str] | None = None,
    pii_types: List[str] | None = None,
    pii_detected: bool = False,
    receipt_id: str | None = None,
    reviewed_at: datetime | None = None,
    reviewed_by_user_id: str | None = TEST_USER_ID,
) -> Dict[str, Any]:
    """Shape returned by the SELECT in _fetch_run_for_clinic (psycopg
    returns jsonb already decoded, timestamps tz-aware)."""
    when_run = datetime(2026, 5, 24, 10, 0, 0, tzinfo=timezone.utc)
    when_review = reviewed_at or datetime(2026, 5, 24, 11, 0, 0, tzinfo=timezone.utc)
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
        "model_provider": model_provider,
        "model_name": model_name,
        "review_decision": review_decision,
        "reviewed_at": when_review if review_status != "not_reviewed" else None,
        "reviewed_by_user_id": _uuid.UUID(reviewed_by_user_id)
        if reviewed_by_user_id and review_status != "not_reviewed"
        else None,
        "created_at": when_run,
        "updated_at": when_review if review_status != "not_reviewed" else when_run,
    }


def _receipt_row(
    *,
    receipt_id: str | None = None,
    assistant_run_id: str | None = None,
    run_status: str = "generation_succeeded",
    review_status: str = "reviewed_approved",
    review_decision: str | None = "approved_for_use",
    output_sha256: str | None = "a" * 64,
    model_provider: str | None = "anthropic",
    model_name: str | None = "claude-sonnet-4-6",
    safety_flags: List[str] | None = None,
    refusal_reason_codes: List[str] | None = None,
    pii_types: List[str] | None = None,
    pii_detected: bool = False,
) -> Dict[str, Any]:
    """Shape returned by the RETURNING/SELECT against assistant_run_receipts."""
    when_recv = datetime(2026, 5, 24, 12, 0, 0, tzinfo=timezone.utc)
    return {
        "receipt_id": _uuid.UUID(receipt_id) if receipt_id else _uuid.uuid4(),
        "assistant_run_id": _uuid.UUID(assistant_run_id) if assistant_run_id else _uuid.uuid4(),
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
        "pii_types": pii_types or [],
        "safety_flags": safety_flags or [],
        "refusal_reason_codes": refusal_reason_codes or [],
        "model_provider": model_provider,
        "model_name": model_name,
        "assistant_run_created_at": datetime(2026, 5, 24, 10, 0, 0, tzinfo=timezone.utc),
        "assistant_run_reviewed_at": datetime(2026, 5, 24, 11, 0, 0, tzinfo=timezone.utc),
        "assistant_run_reviewed_by_user_id": _uuid.UUID(TEST_USER_ID),
        "receipt_created_at": when_recv,
        "created_at": when_recv,
        "updated_at": when_recv,
    }


_FORBIDDEN_RAW_KEYS = {
    "draft",
    "input",
    "input_text",
    "output_text",
    "prompt",
    "raw_input",
    "raw_output",
    "user_message",
    "system_prompt",
    "clinical_content",
    "notes",
}


def _post_receipt(app, run_id: str):
    return client_for(app).post(
        f"/v1/assistant/runs/{run_id}/receipt",
        json={},
        headers=auth_headers(),
    )


def _get_receipt(app, run_id: str):
    return client_for(app).get(
        f"/v1/assistant/runs/{run_id}/receipt",
        headers=auth_headers(),
    )


# ---------------------------------------------------------------------
# 1. Create receipt for reviewed, generated run
# ---------------------------------------------------------------------

def test_create_receipt_for_reviewed_generated_run() -> None:
    rid = str(_uuid.uuid4())
    recv_id = str(_uuid.uuid4())

    app, db = build_app()
    db.select_detail_row = _trace_run_row(
        run_id=rid,
        run_status="generation_succeeded",
        review_status="reviewed_approved",
    )
    db.insert_receipt_row = _receipt_row(
        receipt_id=recv_id,
        assistant_run_id=rid,
    )

    resp = _post_receipt(app, rid)
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert "receipt" in body and "run" in body
    assert "metadata-only" in body["governance_note"].lower()

    receipt = body["receipt"]
    assert receipt["receipt_id"] == recv_id
    assert receipt["assistant_run_id"] == rid
    assert receipt["receipt_kind"] == "assistant_run_metadata"
    assert receipt["receipt_version"] == "assistant_receipt_v1"
    assert receipt["storage_policy"] == "metadata_only_by_default"
    assert receipt["raw_content_stored"] is False
    assert receipt["prompt_stored"] is False
    assert receipt["draft_stored"] is False
    assert receipt["run_status"] == "generation_succeeded"
    assert receipt["review_status"] == "reviewed_approved"
    assert receipt["review_decision"] == "approved_for_use"
    assert receipt["output_sha256"] is not None

    # No raw-content fields on either side of the envelope.
    assert not (_FORBIDDEN_RAW_KEYS & set(receipt.keys()))
    assert not (_FORBIDDEN_RAW_KEYS & set(body["run"].keys()))


# ---------------------------------------------------------------------
# 2. Create receipt for reviewed refused run (refusal is evidence too)
# ---------------------------------------------------------------------

def test_create_receipt_for_reviewed_refused_run() -> None:
    rid = str(_uuid.uuid4())
    recv_id = str(_uuid.uuid4())

    app, db = build_app()
    db.select_detail_row = _trace_run_row(
        run_id=rid,
        run_status="generation_refused",
        review_status="reviewed_rejected",
        review_decision="rejected_not_safe",
        output_sha256=None,
        model_provider=None,
        model_name=None,
        safety_flags=["dose_calculation_request"],
        refusal_reason_codes=["dose_calculation_request"],
    )
    db.insert_receipt_row = _receipt_row(
        receipt_id=recv_id,
        assistant_run_id=rid,
        run_status="generation_refused",
        review_status="reviewed_rejected",
        review_decision="rejected_not_safe",
        output_sha256=None,
        model_provider=None,
        model_name=None,
        safety_flags=["dose_calculation_request"],
        refusal_reason_codes=["dose_calculation_request"],
    )

    resp = _post_receipt(app, rid)
    assert resp.status_code == 200, resp.text

    receipt = resp.json()["receipt"]
    assert receipt["run_status"] == "generation_refused"
    assert receipt["review_status"] == "reviewed_rejected"
    assert receipt["review_decision"] == "rejected_not_safe"
    assert "dose_calculation_request" in receipt["refusal_reason_codes"]
    assert "dose_calculation_request" in receipt["safety_flags"]
    assert receipt["output_sha256"] is None
    assert receipt["model_provider"] is None
    assert receipt["model_name"] is None
    assert receipt["raw_content_stored"] is False
    assert receipt["prompt_stored"] is False
    assert receipt["draft_stored"] is False


# ---------------------------------------------------------------------
# 3. Reject not-reviewed run with 400
# ---------------------------------------------------------------------

def test_create_receipt_rejects_not_reviewed_run() -> None:
    rid = str(_uuid.uuid4())
    app, db = build_app()
    db.select_detail_row = _trace_run_row(
        run_id=rid,
        run_status="generation_succeeded",
        review_status="not_reviewed",
        review_decision=None,
    )

    resp = _post_receipt(app, rid)
    assert resp.status_code == 400, resp.text
    assert resp.json().get("detail") == "assistant_run_not_reviewed"

    # No receipt INSERT happened.
    receipt_inserts = [
        sql for sql, _ in db.calls if "INSERT INTO assistant_run_receipts" in sql
    ]
    assert receipt_inserts == []


# ---------------------------------------------------------------------
# 4. Idempotent — second POST returns existing receipt, no duplicate row
# ---------------------------------------------------------------------

def test_create_receipt_idempotent() -> None:
    rid = str(_uuid.uuid4())
    existing_recv_id = str(_uuid.uuid4())

    app, db = build_app()
    db.select_detail_row = _trace_run_row(
        run_id=rid,
        run_status="generation_succeeded",
        review_status="reviewed_approved",
    )
    # Simulate the unique conflict path: INSERT ON CONFLICT DO NOTHING
    # returns no row; the SELECT fallback finds the existing receipt.
    db.insert_receipt_row = None
    db.select_receipt_row = _receipt_row(
        receipt_id=existing_recv_id,
        assistant_run_id=rid,
    )

    resp = _post_receipt(app, rid)
    assert resp.status_code == 200, resp.text
    assert resp.json()["receipt"]["receipt_id"] == existing_recv_id

    # One INSERT attempted, one SELECT fallback executed — no duplicates.
    inserts = [sql for sql, _ in db.calls if "INSERT INTO assistant_run_receipts" in sql]
    selects = [
        sql
        for sql, _ in db.calls
        if "FROM assistant_run_receipts" in sql and "INSERT" not in sql
    ]
    assert len(inserts) == 1
    assert len(selects) == 1


# ---------------------------------------------------------------------
# 5. GET returns existing receipt
# ---------------------------------------------------------------------

def test_get_existing_receipt() -> None:
    rid = str(_uuid.uuid4())
    recv_id = str(_uuid.uuid4())

    app, db = build_app()
    db.select_detail_row = _trace_run_row(
        run_id=rid,
        review_status="reviewed_approved",
        receipt_id=recv_id,
    )
    db.select_receipt_row = _receipt_row(
        receipt_id=recv_id,
        assistant_run_id=rid,
    )

    resp = _get_receipt(app, rid)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["receipt"]["receipt_id"] == recv_id
    assert body["receipt"]["raw_content_stored"] is False
    assert body["receipt"]["draft_stored"] is False
    assert body["receipt"]["prompt_stored"] is False
    assert not (_FORBIDDEN_RAW_KEYS & set(body["receipt"].keys()))


# ---------------------------------------------------------------------
# 6. GET 404 when no receipt has been created yet
# ---------------------------------------------------------------------

def test_get_receipt_not_found() -> None:
    rid = str(_uuid.uuid4())
    app, db = build_app()
    db.select_detail_row = _trace_run_row(run_id=rid, review_status="reviewed_approved")
    db.select_receipt_row = None  # no receipt yet

    resp = _get_receipt(app, rid)
    assert resp.status_code == 404
    assert resp.json().get("detail") == "assistant_run_receipt_not_found"


# ---------------------------------------------------------------------
# 7. Cross-clinic / missing run → 404 assistant_run_not_found
# ---------------------------------------------------------------------

def test_receipt_not_found_for_cross_clinic_or_missing_run() -> None:
    rid = str(_uuid.uuid4())

    # POST path
    app, db = build_app()
    db.select_detail_row = None  # run not visible for this clinic
    resp = _post_receipt(app, rid)
    assert resp.status_code == 404
    assert resp.json().get("detail") == "assistant_run_not_found"
    # No INSERT happened.
    assert [sql for sql, _ in db.calls if "INSERT INTO assistant_run_receipts" in sql] == []

    # GET path
    app, db = build_app()
    db.select_detail_row = None
    resp = _get_receipt(app, rid)
    assert resp.status_code == 404
    assert resp.json().get("detail") == "assistant_run_not_found"


# ---------------------------------------------------------------------
# 8. SQL/params use clinic_id + run_id + authenticated created_by_user_id
# ---------------------------------------------------------------------

def test_receipt_sql_uses_clinic_id_and_run_id() -> None:
    rid = str(_uuid.uuid4())
    recv_id = str(_uuid.uuid4())

    app, db = build_app()
    db.select_detail_row = _trace_run_row(run_id=rid, review_status="reviewed_approved")
    db.insert_receipt_row = _receipt_row(receipt_id=recv_id, assistant_run_id=rid)

    resp = _post_receipt(app, rid)
    assert resp.status_code == 200, resp.text

    # Run-fetch (SELECT FROM assistant_runs) uses clinic_id + id.
    run_fetches = [
        (sql, p)
        for sql, p in db.calls
        if "FROM assistant_runs" in sql and "ORDER BY" not in sql and "run_id" in p
    ]
    assert run_fetches
    rsql, rparams = run_fetches[0]
    assert "clinic_id = CAST(:clinic_id AS uuid)" in rsql
    assert "id = CAST(:run_id AS uuid)" in rsql
    assert rparams["clinic_id"] == TEST_CLINIC_ID
    assert rparams["run_id"] == rid

    # Receipt INSERT uses clinic_id + assistant_run_id and pulls the
    # reviewer/creator from the authenticated context.
    inserts = [
        (sql, p)
        for sql, p in db.calls
        if "INSERT INTO assistant_run_receipts" in sql
    ]
    assert inserts
    isql, iparams = inserts[0]
    assert "ON CONFLICT (clinic_id, assistant_run_id) DO NOTHING" in isql
    assert iparams["clinic_id"] == TEST_CLINIC_ID
    assert iparams["assistant_run_id"] == rid
    assert iparams["created_by_user_id"] == TEST_USER_ID

    # Link-back UPDATE writes receipt_id onto the run.
    links = [
        (sql, p)
        for sql, p in db.calls
        if "UPDATE assistant_runs" in sql
        and "receipt_id" in sql
        and "review_status" not in sql
    ]
    assert links
    lsql, lparams = links[0]
    assert "clinic_id = CAST(:clinic_id AS uuid)" in lsql
    assert "id = CAST(:run_id AS uuid)" in lsql
    assert lparams["receipt_id"] == recv_id


# ---------------------------------------------------------------------
# 9. Response/params carry no raw content
# ---------------------------------------------------------------------

def test_receipt_response_does_not_include_raw_content() -> None:
    rid = str(_uuid.uuid4())
    recv_id = str(_uuid.uuid4())
    distinctive = "uniquetoken-clinical-DO-NOT-LEAK-77777"

    app, db = build_app()
    # Whatever the run's actual fields contained, the receipt path must
    # never echo raw content. The hash and field-keys are derived from
    # input but are non-reversible / structure-only.
    db.select_detail_row = _trace_run_row(run_id=rid, review_status="reviewed_approved")
    db.insert_receipt_row = _receipt_row(receipt_id=recv_id, assistant_run_id=rid)

    resp = _post_receipt(app, rid)
    assert resp.status_code == 200
    body_text = resp.text
    assert distinctive not in body_text  # belt-and-braces

    receipt = resp.json()["receipt"]
    assert not (_FORBIDDEN_RAW_KEYS & set(receipt.keys()))

    # And no DB call params can contain the distinctive raw value.
    for sql, params in db.calls:
        blob = repr(params)
        assert distinctive not in blob, (
            f"raw value leaked into DB params for SQL: {sql[:80]!r}"
        )


# ---------------------------------------------------------------------
# 10. Trace detail surfaces receipt linkage once a receipt exists
# ---------------------------------------------------------------------

def test_traceability_detail_shows_receipt_linkage() -> None:
    rid = str(_uuid.uuid4())
    recv_id = str(_uuid.uuid4())

    app, db = build_app()
    db.select_detail_row = _trace_run_row(
        run_id=rid,
        review_status="reviewed_approved",
        receipt_id=recv_id,  # linkage already written by an earlier POST
    )

    resp = client_for(app).get(f"/v1/assistant/runs/{rid}", headers=auth_headers())
    assert resp.status_code == 200, resp.text
    run = resp.json()["run"]

    assert run["receipt_id"] == recv_id
    assert run["has_receipt"] is True


def test_traceability_detail_no_receipt_linkage_when_unlinked() -> None:
    rid = str(_uuid.uuid4())
    app, db = build_app()
    db.select_detail_row = _trace_run_row(
        run_id=rid,
        review_status="reviewed_approved",
        receipt_id=None,
    )

    resp = client_for(app).get(f"/v1/assistant/runs/{rid}", headers=auth_headers())
    assert resp.status_code == 200
    run = resp.json()["run"]
    assert run["receipt_id"] is None
    assert run["has_receipt"] is False


# ---------------------------------------------------------------------
# Bonus: unauthenticated requests rejected
# ---------------------------------------------------------------------

def test_receipt_unauthenticated_request_rejected() -> None:
    rid = str(_uuid.uuid4())
    app, db = build_app(authenticated=False)
    db.select_detail_row = _trace_run_row(run_id=rid)

    from fastapi.testclient import TestClient
    client = TestClient(app)
    assert client.post(f"/v1/assistant/runs/{rid}/receipt", json={}).status_code == 401
    assert client.get(f"/v1/assistant/runs/{rid}/receipt").status_code == 401
