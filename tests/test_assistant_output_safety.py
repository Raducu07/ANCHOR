"""Tests for M6.6 — Assistant post-output safety validation.

Two layers:
 1) Unit tests for `validate_client_communication_output` — the validator
    in `app/assistant_output_safety.py` must never echo any excerpt of
    the draft; it returns codes only.
 2) Endpoint tests for the POST /v1/assistant/runs success path: when
    the model returns an unsafe draft, the route blocks it (run_status =
    output_blocked), persists ONLY the hash, and returns no raw draft.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Tuple

import pytest

from app.assistant_output_safety import (
    OUTPUT_BLOCKED_MESSAGE,
    SAFETY_CODE_DIAGNOSIS_LANGUAGE,
    SAFETY_CODE_IDENTIFIER_RISK,
    SAFETY_CODE_MISSING_REVIEW_WARNING,
    SAFETY_CODE_PRESCRIBING_OR_DOSE,
    SAFETY_CODE_PROGNOSIS_OR_CLINICAL_JUDGEMENT,
    SAFETY_CODE_TREATMENT_RECOMMENDATION,
    SAFETY_CODE_TRIAGE_OR_DISCHARGE_DECISION,
    validate_client_communication_output,
)
from tests._assistant_test_helpers import (
    DEFAULT_MODEL,
    DEFAULT_PROVIDER,
    auth_headers,
    build_app,
    client_for,
)


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_REVIEW_TAIL = (
    "⚠ REVIEW REQUIRED — check against the clinical record before use. "
    "ANCHOR does not replace professional judgement."
)


def _safe_input() -> dict:
    return {
        "communication_goal": "Reassure owner about post-op recovery",
        "clinician_confirmed_facts": "Patient is stable. Sutures intact.",
    }


def _draft(body: str) -> str:
    """Helper: body + governance review tail (so we test the rule we want
    rather than tripping the missing-review check)."""
    return f"{body}\n{_REVIEW_TAIL}"


def _stub_returning(draft: str):
    def _stub(*, system_prompt: str, user_message: str) -> Tuple[str, str, str]:
        return draft, DEFAULT_PROVIDER, DEFAULT_MODEL
    return _stub


# =====================================================================
# 1) Validator unit tests
# =====================================================================

def test_output_safety_allows_simple_client_update_with_review_warning() -> None:
    draft = _draft(
        "Hello, your pet's stitches are healing well and ready for collection."
    )
    result = validate_client_communication_output(draft)
    assert result.allowed is True
    assert result.safety_flags == []
    assert result.refusal_reason_codes == []


def test_output_safety_blocks_missing_review_warning() -> None:
    draft = "Hello — your pet is doing fine. Please collect tomorrow."
    result = validate_client_communication_output(draft)
    assert result.allowed is False
    assert SAFETY_CODE_MISSING_REVIEW_WARNING in result.safety_flags
    assert SAFETY_CODE_MISSING_REVIEW_WARNING in result.refusal_reason_codes


def test_output_safety_blocks_dose_language() -> None:
    draft = _draft("Please give 5 mg twice daily for two weeks.")
    result = validate_client_communication_output(draft)
    assert result.allowed is False
    assert SAFETY_CODE_PRESCRIBING_OR_DOSE in result.safety_flags


def test_output_safety_blocks_diagnosis_language() -> None:
    draft = _draft("Your pet has been diagnosed with pancreatitis.")
    result = validate_client_communication_output(draft)
    assert result.allowed is False
    assert SAFETY_CODE_DIAGNOSIS_LANGUAGE in result.safety_flags


def test_output_safety_blocks_treatment_recommendation() -> None:
    draft = _draft("We recommend starting antibiotics this week.")
    result = validate_client_communication_output(draft)
    assert result.allowed is False
    assert SAFETY_CODE_TREATMENT_RECOMMENDATION in result.safety_flags


def test_output_safety_blocks_strong_triage_language() -> None:
    draft = _draft("Your pet does not need urgent care.")
    result = validate_client_communication_output(draft)
    assert result.allowed is False
    assert SAFETY_CODE_TRIAGE_OR_DISCHARGE_DECISION in result.safety_flags


def test_output_safety_allows_ready_for_collection() -> None:
    draft = _draft("Your pet is ready for collection any time after 2pm.")
    result = validate_client_communication_output(draft)
    assert result.allowed is True, (
        f"unexpected block on benign collection wording: {result.safety_flags}"
    )


def test_output_safety_allows_ready_to_go_home() -> None:
    """Spec explicitly says administrative 'ready to go home' wording
    must not trigger the triage rule."""
    draft = _draft("Your pet is ready to go home this afternoon.")
    result = validate_client_communication_output(draft)
    assert result.allowed is True, result.safety_flags


def test_output_safety_blocks_prognosis_language() -> None:
    draft = _draft("Your pet will make a full recovery.")
    result = validate_client_communication_output(draft)
    assert result.allowed is False
    assert SAFETY_CODE_PROGNOSIS_OR_CLINICAL_JUDGEMENT in result.safety_flags


@pytest.mark.parametrize(
    "identifier",
    [
        "Please contact owner@example.com to confirm.",
        "Call us on +44 20 7946 0958 if you have questions.",
        "Owner postcode SW1A 1AA on file.",
    ],
)
def test_output_safety_blocks_email_phone_postcode(identifier: str) -> None:
    draft = _draft(identifier)
    result = validate_client_communication_output(draft)
    assert result.allowed is False
    assert SAFETY_CODE_IDENTIFIER_RISK in result.safety_flags


def test_output_safety_does_not_block_confirm_placeholders() -> None:
    """The system prompt asks the model to use [CONFIRM: …] placeholders
    when details are missing. These must never be treated as identifiers
    or otherwise trip the validator."""
    draft = _draft(
        "Dear [CONFIRM: owner name — add before use], your pet "
        "[CONFIRM: patient name — add before use] is doing well at "
        "[CONFIRM: practice name — add before use]."
    )
    result = validate_client_communication_output(draft)
    assert result.allowed is True, result.safety_flags


def test_output_safety_returns_no_raw_excerpt() -> None:
    """Belt-and-braces: the validator's return shape contains only codes
    and a bool. No fields exist that could carry an excerpt of the draft."""
    draft = _draft("uniquetoken-DO-NOT-LEAK-12345 give 5 mg twice daily")
    result = validate_client_communication_output(draft)
    blob = repr(result)
    assert "uniquetoken-DO-NOT-LEAK-12345" not in blob
    assert "5 mg" not in blob


# =====================================================================
# 2) Endpoint tests
# =====================================================================

def _safe_draft() -> str:
    return _draft(
        "Hello, your pet is recovering well after the procedure and is "
        "ready for collection any time after 2pm."
    )


def _unsafe_dose_draft() -> str:
    # Contains both required review phrases + a dose pattern so the
    # block is provably triggered by the dose rule, not the missing
    # review-line rule.
    return _draft("Please give 5 mg twice daily for two weeks at home.")


def test_generation_success_still_returns_safe_draft() -> None:
    """The default model stub returns DEFAULT_DRAFT_TEXT which carries
    the governance review line and no unsafe phrases. The success path
    must continue to work end-to-end."""
    safe_draft = _safe_draft()
    app, db = build_app(model_stub=_stub_returning(safe_draft))
    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={"mode": "client_communication", "input": _safe_input()},
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text
    run = resp.json()["run"]

    assert run["run_status"] == "generation_succeeded"
    assert run["draft"] == safe_draft
    assert run["refused"] is False
    assert run["blocked"] is False
    assert SHA256_RE.match(run["output_sha256"]) is not None
    assert run["model_provider"] == DEFAULT_PROVIDER
    assert run["model_name"] == DEFAULT_MODEL


def test_generation_output_blocked_does_not_return_raw_draft() -> None:
    unsafe = _unsafe_dose_draft()
    expected_hash = hashlib.sha256(unsafe.encode("utf-8")).hexdigest()

    app, db = build_app(model_stub=_stub_returning(unsafe))
    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={"mode": "client_communication", "input": _safe_input()},
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text

    run = resp.json()["run"]
    assert run["run_status"] == "output_blocked"
    # Raw unsafe draft is NEVER returned.
    assert run["draft"] is None
    body_text = resp.text
    assert "give 5 mg" not in body_text.lower()
    # blocked_message present and clear.
    assert run["blocked"] is True
    assert "ANCHOR blocked" in (run.get("blocked_message") or "")
    assert OUTPUT_BLOCKED_MESSAGE in (run.get("blocked_message") or "")

    # Safety codes surfaced.
    assert SAFETY_CODE_PRESCRIBING_OR_DOSE in run["safety_flags"]
    assert SAFETY_CODE_PRESCRIBING_OR_DOSE in run["refusal_reason_codes"]

    # Hash recorded; model metadata kept because the model WAS invoked.
    assert run["output_sha256"] == expected_hash
    assert run["model_provider"] == DEFAULT_PROVIDER
    assert run["model_name"] == DEFAULT_MODEL
    assert run["generation_enabled"] is True
    assert run["refused"] is True


def test_output_blocked_updates_metadata_only() -> None:
    unsafe = _unsafe_dose_draft()
    expected_hash = hashlib.sha256(unsafe.encode("utf-8")).hexdigest()

    app, db = build_app(model_stub=_stub_returning(unsafe))
    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={"mode": "client_communication", "input": _safe_input()},
        headers=auth_headers(),
    )
    assert resp.status_code == 201

    sql, params = db.update_call_with_status("output_blocked")
    assert params["output_sha256"] == expected_hash
    assert SHA256_RE.match(params["output_sha256"]) is not None
    assert params["model_provider"] == DEFAULT_PROVIDER
    assert params["model_name"] == DEFAULT_MODEL

    # JSONB-bound safety codes round-trip through the json.dumps + jsonb cast.
    safety = json.loads(params["safety_flags"])
    refusal = json.loads(params["refusal_reason_codes"])
    assert SAFETY_CODE_PRESCRIBING_OR_DOSE in safety
    assert SAFETY_CODE_PRESCRIBING_OR_DOSE in refusal

    # Raw draft text must not appear in ANY DB call params.
    for s, p in db.calls:
        blob = repr(p)
        assert unsafe not in blob, (
            f"raw blocked draft leaked into DB params for SQL: {s[:80]!r}"
        )
        assert "give 5 mg twice daily for two weeks" not in blob.lower()


def test_output_blocked_is_not_provider_failure() -> None:
    unsafe = _unsafe_dose_draft()

    call_count = {"n": 0}

    def _stub(*, system_prompt: str, user_message: str):
        call_count["n"] += 1
        return unsafe, DEFAULT_PROVIDER, DEFAULT_MODEL

    app, db = build_app(model_stub=_stub)
    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={"mode": "client_communication", "input": _safe_input()},
        headers=auth_headers(),
    )
    assert resp.status_code == 201  # not 503
    run = resp.json()["run"]
    assert run["run_status"] == "output_blocked"
    assert run["run_status"] != "generation_failed"
    # Model was invoked (this is what distinguishes output_blocked from
    # generation_refused).
    assert call_count["n"] == 1


def test_input_refusal_still_happens_before_model_call() -> None:
    """Regression — M6.6 must not weaken input-side refusal."""

    def _fail_if_called(*, system_prompt: str, user_message: str):
        raise AssertionError("model must not be called for dose-request input")

    app, db = build_app(model_stub=_fail_if_called)
    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={
            "mode": "client_communication",
            "input": {
                "communication_goal": "What dose of metacam should I give a 12kg dog?",
                "clinician_confirmed_facts": "Patient is post-op.",
            },
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 201
    run = resp.json()["run"]
    assert run["run_status"] == "generation_refused"
    assert run["refused"] is True
    # blocked is False — input-refused is distinct from output-blocked.
    assert run["blocked"] is False
    assert run["output_sha256"] is None
    assert run["model_provider"] is None
    assert run["model_name"] is None


def test_provider_failure_still_returns_503() -> None:
    """Regression — M6.6 must not change the provider-failure path."""
    from app.assistant_anthropic_client import AssistantModelCallError

    def _stub(*, system_prompt: str, user_message: str):
        raise AssistantModelCallError("simulated_provider_failure")

    app, db = build_app(model_stub=_stub)
    resp = client_for(app).post(
        "/v1/assistant/runs",
        json={"mode": "client_communication", "input": _safe_input()},
        headers=auth_headers(),
    )
    assert resp.status_code == 503
    # Failed UPDATE happened, not output_blocked.
    db.update_call_with_status("generation_failed")
    with pytest.raises(AssertionError):
        db.update_call_with_status("output_blocked")


def test_traceability_handles_output_blocked_status() -> None:
    """The trace/list endpoint must surface output_blocked rows with
    their safety codes + output hash and no raw draft."""
    import uuid as _uuid
    from datetime import datetime, timezone

    app, db = build_app()
    db.select_list_rows = [
        {
            "run_id": _uuid.uuid4(),
            "clinic_id": _uuid.uuid4(),
            "clinic_user_id": _uuid.uuid4(),
            "mode": "client_communication",
            "contract_version": "assistant_contract_v1",
            "workflow_origin": "anchor_assistant",
            "input_sha256": "b" * 64,
            "output_sha256": "c" * 64,
            "input_field_keys": ["clinician_confirmed_facts", "communication_goal"],
            "pii_detected": False,
            "pii_types": [],
            "safety_flags": [SAFETY_CODE_PRESCRIBING_OR_DOSE],
            "refusal_reason_codes": [SAFETY_CODE_PRESCRIBING_OR_DOSE],
            "review_status": "not_reviewed",
            "run_status": "output_blocked",
            "receipt_id": None,
            "governance_event_id": None,
            "model_provider": "anthropic",
            "model_name": "claude-sonnet-4-6",
            "review_decision": None,
            "reviewed_at": None,
            "reviewed_by_user_id": None,
            "created_at": datetime(2026, 5, 24, 12, 0, 0, tzinfo=timezone.utc),
            "updated_at": datetime(2026, 5, 24, 12, 0, 0, tzinfo=timezone.utc),
        }
    ]

    resp = client_for(app).get("/v1/assistant/runs", headers=auth_headers())
    assert resp.status_code == 200
    items = resp.json()["runs"]
    assert len(items) == 1
    row = items[0]

    assert row["run_status"] == "output_blocked"
    assert row["output_sha256"] == "c" * 64
    assert SAFETY_CODE_PRESCRIBING_OR_DOSE in row["safety_flags"]
    assert SAFETY_CODE_PRESCRIBING_OR_DOSE in row["refusal_reason_codes"]
    assert row["model_provider"] == "anthropic"
    assert row["model_name"] == "claude-sonnet-4-6"
    # Trace items never carry draft text.
    assert "draft" not in row
