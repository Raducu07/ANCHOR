"""Tests for M6.7.1 — surface Assistant policy metadata in run
traceability and metadata-only receipts.

Default-policy representation (documented):
  * assistant_policy_id            -> null
  * assistant_policy_version       -> null   (default policy is synthesised,
                                              not a persisted row)
  * assistant_validation_profile   -> "standard"
"""
from __future__ import annotations

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


# ---------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------

def _policy_row(
    *,
    policy_version: int = 2,
    validation_profile: str = "conservative",
) -> Dict[str, Any]:
    now = datetime(2026, 5, 24, 12, 0, 0, tzinfo=timezone.utc)
    return {
        "id": _uuid.uuid4(),
        "clinic_id": _uuid.UUID(TEST_CLINIC_ID),
        "policy_version": policy_version,
        "is_active": True,
        "client_communication_enabled": True,
        "generation_enabled": True,
        "validation_profile": validation_profile,
        "daily_run_limit_per_clinic": 50,
        "monthly_run_limit_per_clinic": 1000,
        "require_human_review": True,
        "allow_receipts_after_review": True,
        "policy_label": "Conservative — Q3",
        "policy_notes": "internal-only notes that must NEVER appear in receipts",
        "created_by_user_id": _uuid.UUID(TEST_USER_ID),
        "created_at": now,
        "activated_at": now,
        "superseded_at": None,
    }


def _trace_row_with_policy(
    *,
    run_id: str | None = None,
    assistant_policy_id: Any = "use-default",
    assistant_policy_version: Any = 3,
    assistant_validation_profile: Any = "conservative",
) -> Dict[str, Any]:
    """Fake row in the shape psycopg returns for SELECT against
    assistant_runs after M6.7.1."""
    now = datetime(2026, 5, 24, 12, 0, 0, tzinfo=timezone.utc)
    rid = _uuid.UUID(run_id) if run_id else _uuid.uuid4()
    # `"use-default"` sentinel → fresh random UUID; tests can pass None
    # to model a legacy / default-policy row.
    if assistant_policy_id == "use-default":
        assistant_policy_id = _uuid.uuid4()
    return {
        "run_id": rid,
        "clinic_id": _uuid.UUID(TEST_CLINIC_ID),
        "clinic_user_id": _uuid.UUID(TEST_USER_ID),
        "mode": "client_communication",
        "contract_version": "assistant_contract_v1",
        "workflow_origin": "anchor_assistant",
        "input_sha256": "b" * 64,
        "output_sha256": "a" * 64,
        "input_field_keys": ["clinician_confirmed_facts", "communication_goal"],
        "pii_detected": False,
        "pii_types": [],
        "safety_flags": [],
        "refusal_reason_codes": [],
        "review_status": "reviewed_approved",
        "run_status": "generation_succeeded",
        "receipt_id": None,
        "governance_event_id": None,
        "model_provider": "anthropic",
        "model_name": "claude-sonnet-4-6",
        "review_decision": "approved_for_use",
        "reviewed_at": now,
        "reviewed_by_user_id": _uuid.UUID(TEST_USER_ID),
        "assistant_policy_id": assistant_policy_id,
        "assistant_policy_version": assistant_policy_version,
        "assistant_validation_profile": assistant_validation_profile,
        "created_at": now,
        "updated_at": now,
    }


def _receipt_row(
    *,
    assistant_policy_id: Any = "use-default",
    assistant_policy_version: Any = 3,
    assistant_validation_profile: Any = "conservative",
) -> Dict[str, Any]:
    now = datetime(2026, 5, 24, 13, 0, 0, tzinfo=timezone.utc)
    rid = _uuid.uuid4()
    if assistant_policy_id == "use-default":
        assistant_policy_id = _uuid.uuid4()
    return {
        "receipt_id": _uuid.uuid4(),
        "assistant_run_id": rid,
        "clinic_id": _uuid.UUID(TEST_CLINIC_ID),
        "created_by_user_id": _uuid.UUID(TEST_USER_ID),
        "receipt_kind": "assistant_run_metadata",
        "receipt_version": "assistant_receipt_v1",
        "storage_policy": "metadata_only_by_default",
        "raw_content_stored": False,
        "prompt_stored": False,
        "draft_stored": False,
        "run_status": "generation_succeeded",
        "review_status": "reviewed_approved",
        "review_decision": "approved_for_use",
        "input_sha256": "b" * 64,
        "output_sha256": "a" * 64,
        "mode": "client_communication",
        "contract_version": "assistant_contract_v1",
        "workflow_origin": "anchor_assistant",
        "pii_detected": False,
        "pii_types": [],
        "safety_flags": [],
        "refusal_reason_codes": [],
        "model_provider": "anthropic",
        "model_name": "claude-sonnet-4-6",
        "assistant_policy_id": assistant_policy_id,
        "assistant_policy_version": assistant_policy_version,
        "assistant_validation_profile": assistant_validation_profile,
        "assistant_run_created_at": now,
        "assistant_run_reviewed_at": now,
        "assistant_run_reviewed_by_user_id": _uuid.UUID(TEST_USER_ID),
        "receipt_created_at": now,
        "created_at": now,
        "updated_at": now,
    }


def _safe_input() -> Dict[str, Any]:
    return {
        "communication_goal": "Reassure owner about post-op recovery",
        "clinician_confirmed_facts": "Patient is stable. Sutures intact.",
    }


# ---------------------------------------------------------------------
# 1. Create-run response includes policy metadata when policy is active
# ---------------------------------------------------------------------

def test_create_run_response_includes_policy_metadata_when_active_policy() -> None:
    app, db = build_app()
    db.select_policy_row = _policy_row(
        policy_version=4, validation_profile="conservative"
    )

    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={"mode": "client_communication", "input": _safe_input()},
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text
    run = resp.json()["run"]

    assert run["assistant_policy_id"] == str(db.select_policy_row["id"])
    assert run["assistant_policy_version"] == 4
    assert run["assistant_validation_profile"] == "conservative"


# ---------------------------------------------------------------------
# 2. Default-policy fallback in the create-run response
# ---------------------------------------------------------------------

def test_create_run_response_uses_standard_profile_for_default_policy() -> None:
    """No persisted policy → default policy is used. The response carries
    null id/version and the standard validation profile."""
    app, db = build_app()
    db.select_policy_row = None

    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={"mode": "client_communication", "input": _safe_input()},
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text
    run = resp.json()["run"]

    assert run["assistant_policy_id"] is None
    assert run["assistant_policy_version"] is None
    assert run["assistant_validation_profile"] == "standard"


# ---------------------------------------------------------------------
# 3. Traceability list — policy fields surface for each item
# ---------------------------------------------------------------------

def test_traceability_list_includes_policy_metadata() -> None:
    app, db = build_app()
    db.select_list_rows = [
        _trace_row_with_policy(
            assistant_policy_version=2,
            assistant_validation_profile="standard",
        ),
        # Legacy / default-policy row (NULLs).
        _trace_row_with_policy(
            assistant_policy_id=None,
            assistant_policy_version=None,
            assistant_validation_profile=None,
        ),
    ]

    resp = client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    assert resp.status_code == 200, resp.text
    items = resp.json()["runs"]
    assert len(items) == 2

    required = {
        "assistant_policy_id",
        "assistant_policy_version",
        "assistant_validation_profile",
    }
    for item in items:
        assert required.issubset(item.keys()), (
            f"missing policy metadata fields: {required - set(item.keys())}"
        )

    # First item carries a populated policy snapshot.
    assert items[0]["assistant_policy_version"] == 2
    assert items[0]["assistant_validation_profile"] == "standard"
    assert items[0]["assistant_policy_id"] is not None

    # Legacy / default-policy row serialises with nulls.
    assert items[1]["assistant_policy_id"] is None
    assert items[1]["assistant_policy_version"] is None
    assert items[1]["assistant_validation_profile"] is None


# ---------------------------------------------------------------------
# 4. Traceability detail — policy fields surface
# ---------------------------------------------------------------------

def test_traceability_detail_includes_policy_metadata() -> None:
    row = _trace_row_with_policy(
        assistant_policy_version=7, assistant_validation_profile="conservative"
    )
    app, db = build_app()
    db.select_detail_row = row

    resp = client_for(app).get(
        f"/v1/assistant/runs/{row['run_id']}", headers=auth_headers()
    )
    assert resp.status_code == 200, resp.text
    run = resp.json()["run"]
    assert run["assistant_policy_version"] == 7
    assert run["assistant_validation_profile"] == "conservative"
    assert run["assistant_policy_id"] is not None


# ---------------------------------------------------------------------
# 5. Receipt payload includes policy metadata (and never the policy notes)
# ---------------------------------------------------------------------

def test_receipt_payload_includes_policy_metadata() -> None:
    rid = _uuid.uuid4()

    # The route first fetches the assistant_runs row (trace detail SELECT).
    run_row = _trace_row_with_policy(
        run_id=str(rid),
        assistant_policy_version=3,
        assistant_validation_profile="conservative",
    )
    app, db = build_app()
    db.select_detail_row = run_row

    # INSERT ON CONFLICT RETURNING — we make the freshly-inserted receipt
    # carry the same policy metadata the run was stamped with.
    receipt_row = _receipt_row(
        assistant_policy_id=run_row["assistant_policy_id"],
        assistant_policy_version=3,
        assistant_validation_profile="conservative",
    )
    receipt_row["assistant_run_id"] = run_row["run_id"]
    db.insert_receipt_row = receipt_row

    resp = client_for(app).post(
        f"/v1/assistant/runs/{rid}/receipt",
        json={},
        headers=auth_headers(),
    )
    assert resp.status_code in (200, 201), resp.text

    body = resp.json()
    receipt = body["receipt"]
    assert receipt["assistant_policy_version"] == 3
    assert receipt["assistant_validation_profile"] == "conservative"
    assert receipt["assistant_policy_id"] is not None

    # Doctrine — receipt never carries raw content or policy notes.
    forbidden = {"draft", "input", "input_text", "output_text", "prompt", "policy_notes"}
    assert not (forbidden & set(receipt.keys()))
    body_text = resp.text
    assert "internal-only notes that must NEVER appear in receipts" not in body_text

    # INSERT bound the policy snapshot.
    insert_calls = [
        (s, p) for s, p in db.calls if "INSERT INTO assistant_run_receipts" in s
    ]
    assert insert_calls, "expected receipt INSERT"
    _, params = insert_calls[-1]
    assert params["assistant_policy_version"] == 3
    assert params["assistant_validation_profile"] == "conservative"
    # The empty-string sentinel rule: a present UUID is bound as its string.
    assert isinstance(params["assistant_policy_id"], str) and params["assistant_policy_id"] != ""


# ---------------------------------------------------------------------
# 6. Receipt payload handles the default-policy fallback
# ---------------------------------------------------------------------

def test_receipt_payload_handles_default_policy_metadata() -> None:
    rid = _uuid.uuid4()
    run_row = _trace_row_with_policy(
        run_id=str(rid),
        assistant_policy_id=None,
        assistant_policy_version=None,
        assistant_validation_profile="standard",
    )
    app, db = build_app()
    db.select_detail_row = run_row

    receipt_row = _receipt_row(
        assistant_policy_id=None,
        assistant_policy_version=None,
        assistant_validation_profile="standard",
    )
    receipt_row["assistant_run_id"] = run_row["run_id"]
    db.insert_receipt_row = receipt_row

    resp = client_for(app).post(
        f"/v1/assistant/runs/{rid}/receipt",
        json={},
        headers=auth_headers(),
    )
    assert resp.status_code in (200, 201), resp.text
    receipt = resp.json()["receipt"]

    assert receipt["assistant_policy_id"] is None
    assert receipt["assistant_policy_version"] is None
    assert receipt["assistant_validation_profile"] == "standard"

    # The INSERT must bind the empty-string sentinel for null policy id.
    insert_calls = [
        (s, p) for s, p in db.calls if "INSERT INTO assistant_run_receipts" in s
    ]
    assert insert_calls
    _, params = insert_calls[-1]
    assert params["assistant_policy_id"] == ""
    assert params["assistant_policy_version"] is None
    assert params["assistant_validation_profile"] == "standard"


# ---------------------------------------------------------------------
# 7. Legacy run rows without the new fields still deserialise
# ---------------------------------------------------------------------

def test_legacy_runs_without_policy_metadata_still_work() -> None:
    """Legacy rows simply omit the new keys. `_row_to_trace_item` uses
    `.get()` so this is safe."""
    now = datetime(2026, 5, 24, 12, 0, 0, tzinfo=timezone.utc)
    legacy_row = {
        "run_id": _uuid.uuid4(),
        "clinic_id": _uuid.UUID(TEST_CLINIC_ID),
        "clinic_user_id": _uuid.UUID(TEST_USER_ID),
        "mode": "client_communication",
        "contract_version": "assistant_contract_v1",
        "workflow_origin": "anchor_assistant",
        "input_sha256": "b" * 64,
        "output_sha256": "a" * 64,
        "input_field_keys": ["communication_goal", "clinician_confirmed_facts"],
        "pii_detected": False,
        "pii_types": [],
        "safety_flags": [],
        "refusal_reason_codes": [],
        "review_status": "not_reviewed",
        "run_status": "generation_succeeded",
        "receipt_id": None,
        "governance_event_id": None,
        "model_provider": "anthropic",
        "model_name": "claude-sonnet-4-6",
        "review_decision": None,
        "reviewed_at": None,
        "reviewed_by_user_id": None,
        "created_at": now,
        "updated_at": now,
        # NOTE: no assistant_policy_* keys at all.
    }
    app, db = build_app()
    db.select_list_rows = [legacy_row]

    resp = client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    assert resp.status_code == 200, resp.text
    item = resp.json()["runs"][0]
    assert item["assistant_policy_id"] is None
    assert item["assistant_policy_version"] is None
    assert item["assistant_validation_profile"] is None


# ---------------------------------------------------------------------
# 8. Policy metadata is evidence only — review/receipt rules unchanged
# ---------------------------------------------------------------------

def test_policy_metadata_does_not_change_review_or_receipt_rules() -> None:
    """Receipt creation still requires a completed review, regardless of
    policy metadata being present."""
    rid = _uuid.uuid4()
    run_row = _trace_row_with_policy(run_id=str(rid))
    # Force review_status to not_reviewed to prove the receipt gate still fires.
    run_row["review_status"] = "not_reviewed"

    app, db = build_app()
    db.select_detail_row = run_row
    db.insert_receipt_row = _receipt_row()

    resp = client_for(app).post(
        f"/v1/assistant/runs/{rid}/receipt",
        json={},
        headers=auth_headers(),
    )
    assert resp.status_code == 400, resp.text
    assert resp.json().get("detail") == "assistant_run_not_reviewed"
    # No INSERT happened.
    assert not any(
        "INSERT INTO assistant_run_receipts" in s for s, _ in db.calls
    )
