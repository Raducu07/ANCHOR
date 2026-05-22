"""Tests for POST /v1/assistant/runs â€” metadata-only creation, PR 2A."""
from __future__ import annotations

import json
import re
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


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _jsonb_list(value: Any) -> List[Any]:
    """JSONB-bound params are JSON-serialised strings. Decode for assertion."""
    if isinstance(value, str):
        return list(json.loads(value))
    return list(value or [])


def _valid_input() -> Dict[str, Any]:
    return {
        "communication_goal": "Reassure owner about post-op recovery",
        "clinician_confirmed_facts": "Patient is stable. Sutures intact.",
    }


def _post_run(payload: Dict[str, Any]):
    app, db = build_app()
    resp = client_for(app).post(
        "/v1/assistant/runs", json=payload, headers=auth_headers()
    )
    return resp, db


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------

def test_valid_request_creates_metadata_run() -> None:
    """With the default success stub installed by build_app(), a safe
    request reaches generation_succeeded. Metadata-only persistence is
    still required."""
    resp, db = _post_run({"mode": "client_communication", "input": _valid_input()})

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert "run" in body

    run = body["run"]
    assert run["mode"] == "client_communication"
    assert run["contract_version"] == "assistant_contract_v1"
    assert run["review_status"] == "not_reviewed"
    assert run["run_status"] == "generation_succeeded"
    assert run["refused"] is False
    assert run["draft"] == DEFAULT_DRAFT_TEXT
    # output_sha256 is now the hash of the transient draft.
    assert SHA256_RE.match(run["output_sha256"]) is not None
    assert run["model_provider"] == DEFAULT_PROVIDER
    assert run["model_name"] == DEFAULT_MODEL
    assert run["generation_enabled"] is True
    assert "governance_note" in run and run["governance_note"]

    # Insert was executed under the right tenant — run_status='created'.
    sql, params = db.insert_call
    assert "INSERT INTO assistant_runs" in sql
    assert params["clinic_id"] == TEST_CLINIC_ID
    assert params["clinic_user_id"] == TEST_USER_ID
    assert params["mode"] == "client_communication"
    assert params["contract_version"] == "assistant_contract_v1"
    assert params["workflow_origin"] == "anchor_assistant"
    assert params["review_status"] == "not_reviewed"
    assert params["run_status"] == "created"


def test_input_sha256_is_64_char_lowercase_hex() -> None:
    _, db = _post_run({"mode": "client_communication", "input": _valid_input()})
    _, params = db.insert_call
    assert SHA256_RE.match(params["input_sha256"]) is not None


def test_input_field_keys_are_keys_only_not_values() -> None:
    payload_input = _valid_input()
    _, db = _post_run({"mode": "client_communication", "input": payload_input})

    _, params = db.insert_call
    keys = _jsonb_list(params["input_field_keys"])

    assert set(keys) == {"communication_goal", "clinician_confirmed_facts"}
    # Critically: none of the actual values appear in the stored keys list.
    for v in payload_input.values():
        for k in keys:
            assert v not in k


def test_raw_input_values_never_appear_in_inserted_params() -> None:
    payload_input = _valid_input()
    _, db = _post_run({"mode": "client_communication", "input": payload_input})

    _, params = db.insert_call
    # Strip the columns that legitimately carry user-derived data (the hash
    # and the key-list, both of which exclude raw values).
    safe = dict(params)
    safe.pop("input_sha256", None)
    safe.pop("input_field_keys", None)

    blob = repr(safe)
    for v in payload_input.values():
        assert v not in blob, f"raw input value leaked into insert params: {v!r}"


def test_response_does_not_include_raw_input() -> None:
    """The transient draft is allowed in the response (PR 2B), but the
    raw input values must never appear in the response body or in any of
    the PR 2A metadata fields."""
    payload_input = _valid_input()
    resp, _ = _post_run({"mode": "client_communication", "input": payload_input})

    # Strip the transient draft before scanning for raw input — the canned
    # stub draft doesn't contain user inputs, so this is belt-and-braces.
    body = resp.json()
    run = body["run"]
    scrubbed_run = {k: v for k, v in run.items() if k != "draft"}

    blob = repr(scrubbed_run)
    for v in payload_input.values():
        assert v not in blob, f"raw input leaked into response metadata: {v!r}"

    # No raw prompt / system-prompt / user-message fields are exposed.
    forbidden_keys = {"prompt", "system_prompt", "user_message", "output_text"}
    assert not (forbidden_keys & set(run.keys()))


# ---------------------------------------------------------------------
# Mode validation
# ---------------------------------------------------------------------

def test_unsupported_mode_rejected() -> None:
    resp, _ = _post_run({"mode": "diagnosis_helper", "input": _valid_input()})
    assert resp.status_code == 400


def test_inactive_known_mode_rejected_with_400() -> None:
    # No additional modes are active in PR 2A, so a plausible-but-not-allowed
    # mode is rejected at the same boundary (unsupported_mode == 400).
    resp, _ = _post_run({"mode": "clinical_note", "input": _valid_input()})
    assert resp.status_code == 400


# ---------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------

def test_missing_communication_goal_rejected() -> None:
    bad = _valid_input()
    bad.pop("communication_goal")
    resp, _ = _post_run({"mode": "client_communication", "input": bad})
    assert resp.status_code == 422


def test_missing_clinician_confirmed_facts_rejected() -> None:
    bad = _valid_input()
    bad.pop("clinician_confirmed_facts")
    resp, _ = _post_run({"mode": "client_communication", "input": bad})
    assert resp.status_code == 422


def test_empty_communication_goal_rejected() -> None:
    bad = _valid_input()
    bad["communication_goal"] = ""
    resp, _ = _post_run({"mode": "client_communication", "input": bad})
    assert resp.status_code == 422


# ---------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------

def test_unauthenticated_request_rejected() -> None:
    # Use a build_app variant that does NOT override require_clinic_user, so
    # the real auth dependency runs and rejects the missing bearer.
    app, _ = build_app(authenticated=False)
    from fastapi.testclient import TestClient

    resp = TestClient(app).post(
        "/v1/assistant/runs",
        json={"mode": "client_communication", "input": _valid_input()},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------
# PII detection
# ---------------------------------------------------------------------

@pytest.mark.parametrize(
    "value,expected_tag",
    [
        ("Owner postcode is SW1A 1AA, please confirm.", "uk_postcode"),
        ("Contact: owner@example.com for follow-up.", "email_address"),
        ("Call owner on +44 20 7946 0958 tomorrow.", "phone_number"),
        ("Microchip 982000123456789 on file.", "numeric_id"),
    ],
)
def test_pii_detected_for_each_category(value: str, expected_tag: str) -> None:
    payload = {
        "mode": "client_communication",
        "input": {
            "communication_goal": "Reassure owner",
            "clinician_confirmed_facts": value,
        },
    }
    resp, db = _post_run(payload)
    assert resp.status_code == 201

    _, params = db.insert_call
    assert params["pii_detected"] is True
    assert expected_tag in _jsonb_list(params["pii_types"])

    run = resp.json()["run"]
    assert run["pii_detected"] is True
    assert expected_tag in run["pii_types"]


def test_clean_input_has_no_pii_flags() -> None:
    payload = {
        "mode": "client_communication",
        "input": {
            "communication_goal": "Provide gentle reassurance",
            "clinician_confirmed_facts": "Patient is stable and recovering well.",
        },
    }
    resp, db = _post_run(payload)
    assert resp.status_code == 201
    _, params = db.insert_call
    assert params["pii_detected"] is False
    assert _jsonb_list(params["pii_types"]) == []


# ---------------------------------------------------------------------
# RLS / session-context expectations
# ---------------------------------------------------------------------

def test_insert_uses_clinic_user_context_via_get_db() -> None:
    """The endpoint depends on get_db, which is the RLS-setting dependency.
    The fake replaces get_db, so we assert the dependency was used (commit
    fired) AND the clinic_id/user_id flowed through to the insert params â€”
    exactly mirroring how RLS context is bound for tenant tables."""
    resp, db = _post_run({"mode": "client_communication", "input": _valid_input()})
    assert resp.status_code == 201
    assert db.committed is True

    _, params = db.insert_call
    assert params["clinic_id"] == TEST_CLINIC_ID
    assert params["clinic_user_id"] == TEST_USER_ID

