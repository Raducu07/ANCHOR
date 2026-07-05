"""Phase 2A-C.5E - Safety-gate harness tests (deterministic; no network).

Covers:
  * deterministic boundary checks: every prohibited category's canned
    unsafe draft is blocked with the expected safety code; the safe
    control draft passes (standard + conservative profiles)
  * a bare model refusal (no review line) is still blocked by the
    validator, so it can never leak out unmarked
  * live gate refuses outright when APP_ENV=prod
  * live gate is skipped (and never calls the provider) when the
    ANCHOR_SAFETY_GATE_LIVE_ENABLED flag is off
  * live gate PASS when the (fake) provider refuses adversarial probes
    and answers the benign control
  * live gate FAIL when the (fake) provider returns an allowed,
    non-refusal draft for an adversarial probe (boundary breach)
  * live gate INCONCLUSIVE on provider config error, and when the
    benign control does not come back allowed
  * reports are metadata-only: no draft text ever appears in the
    serialised report

No real Anthropic API call is performed. No DB session is required.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Dummy env so app.* imports succeed in any test environment.
os.environ.setdefault("DATABASE_URL", "postgresql://x:y@localhost:5432/z")
os.environ.setdefault("RATE_LIMIT_ENABLED", "0")
os.environ.setdefault("ANCHOR_JWT_SECRET", "test")

from app import workspace_safety_gate as sg  # noqa: E402
from app.assistant_anthropic_client import (  # noqa: E402
    AssistantModelConfigError,
)
from app.assistant_output_safety import (  # noqa: E402
    validate_client_communication_output,
)
from app.assistant_prompts import FIXED_REFUSAL_MESSAGE  # noqa: E402


_REFUSAL_DRAFT = (
    FIXED_REFUSAL_MESSAGE
    + " REVIEW REQUIRED - check against the clinical record before use. "
    "ANCHOR does not replace professional judgement."
)

_UNSAFE_DRAFT = (
    "Based on the signs, the diagnosis is gastroenteritis. "
    "REVIEW REQUIRED - check against the clinical record before use. "
    "ANCHOR does not replace professional judgement."
)


def _fake_provider_refusing(system_prompt: str, user_message: str):
    """Refuse adversarial probes; answer the benign control."""
    if "ready for collection" in user_message:
        return (sg.SAFE_CONTROL_DRAFT, "fake-provider", "fake-model")
    return (_REFUSAL_DRAFT, "fake-provider", "fake-model")


def _fake_provider_breaching(system_prompt: str, user_message: str):
    """Return an allowed, non-refusal draft for everything - the exact
    failure mode the gate exists to catch."""
    return (sg.SAFE_CONTROL_DRAFT, "fake-provider", "fake-model")


def _fake_provider_unsafe(system_prompt: str, user_message: str):
    """Return clinically unsafe content for everything."""
    return (_UNSAFE_DRAFT, "fake-provider", "fake-model")


def _enable_live_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(sg.LIVE_GATE_FLAG_ENV, "1")
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.delenv("ENV", raising=False)


# ---------------------------------------------------------------------
# Deterministic layer
# ---------------------------------------------------------------------

@pytest.mark.parametrize("profile", ["standard", "conservative"])
def test_deterministic_checks_block_every_category(profile: str) -> None:
    results = sg.run_deterministic_boundary_checks(profile=profile)
    assert sg.deterministic_checks_pass(results) is True

    by_id = {r.probe_id: r for r in results}
    for probe in sg.HARD_REFUSAL_PROBES:
        result = by_id[probe.probe_id]
        assert result.outcome == sg.OUTCOME_BLOCKED
        assert probe.expected_block_code in result.safety_codes

    control = by_id[sg.BENIGN_CONTROL_PROBE.probe_id]
    assert control.outcome == sg.OUTCOME_ALLOWED_CONTROL
    assert control.safety_codes == []


def test_probe_set_covers_all_hard_refusal_categories() -> None:
    categories = {p.category for p in sg.HARD_REFUSAL_PROBES}
    assert categories == {
        "diagnosis",
        "prescribing_or_dose",
        "treatment_planning",
        "autonomous_triage",
        "prognosis",
    }


def test_bare_refusal_without_review_line_is_blocked() -> None:
    safety = validate_client_communication_output(FIXED_REFUSAL_MESSAGE)
    assert safety.allowed is False


# ---------------------------------------------------------------------
# Live layer - environment guards
# ---------------------------------------------------------------------

def test_live_gate_refuses_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv(sg.LIVE_GATE_FLAG_ENV, "1")
    with pytest.raises(sg.SafetyGateProdRefusal):
        sg.run_live_safety_gate()


def test_live_gate_skipped_when_flag_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.delenv(sg.LIVE_GATE_FLAG_ENV, raising=False)

    def _explode(system_prompt: str, user_message: str):
        raise AssertionError("provider must not be called when skipped")

    monkeypatch.setattr(sg, "_call_provider", _explode)
    report = sg.run_live_safety_gate()
    assert report.overall == sg.GATE_SKIPPED
    assert report.reason == "live_gate_flag_off"
    assert report.probe_results == []


# ---------------------------------------------------------------------
# Live layer - outcomes (fake provider; no network)
# ---------------------------------------------------------------------

def test_live_gate_pass_with_refusing_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_live_gate(monkeypatch)
    monkeypatch.setattr(sg, "_call_provider", _fake_provider_refusing)

    report = sg.run_live_safety_gate()
    assert report.overall == sg.GATE_PASS
    assert report.reason is None
    assert report.model_provider == "fake-provider"

    by_id = {r.probe_id: r for r in report.probe_results}
    for probe in sg.HARD_REFUSAL_PROBES:
        # The refusal draft carries the review line, so the validator
        # allows it and the refusal sentinel classifies it as refused.
        assert by_id[probe.probe_id].outcome == sg.OUTCOME_REFUSED
    control = by_id[sg.BENIGN_CONTROL_PROBE.probe_id]
    assert control.outcome == sg.OUTCOME_ALLOWED_CONTROL


def test_live_gate_fail_on_boundary_breach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_live_gate(monkeypatch)
    monkeypatch.setattr(sg, "_call_provider", _fake_provider_breaching)

    report = sg.run_live_safety_gate()
    assert report.overall == sg.GATE_FAIL
    assert report.reason == "hard_refusal_boundary_breach"
    breach_outcomes = [
        r.outcome
        for r in report.probe_results
        if r.category != sg.BENIGN_CONTROL_PROBE.category
    ]
    assert all(o == sg.OUTCOME_BOUNDARY_BREACH for o in breach_outcomes)


def test_live_gate_blocked_probes_but_control_blocked_is_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_live_gate(monkeypatch)
    monkeypatch.setattr(sg, "_call_provider", _fake_provider_unsafe)

    report = sg.run_live_safety_gate()
    # Adversarial probes are blocked (good), but the benign control is
    # also blocked, so the run cannot prove the live path works.
    assert report.overall == sg.GATE_INCONCLUSIVE
    assert report.reason == "benign_control_not_allowed"
    for r in report.probe_results:
        if r.category != sg.BENIGN_CONTROL_PROBE.category:
            assert r.outcome == sg.OUTCOME_BLOCKED


def test_live_gate_provider_config_error_is_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_live_gate(monkeypatch)

    def _unconfigured(system_prompt: str, user_message: str):
        raise AssistantModelConfigError("anthropic_api_key_missing")

    monkeypatch.setattr(sg, "_call_provider", _unconfigured)
    report = sg.run_live_safety_gate()
    assert report.overall == sg.GATE_INCONCLUSIVE
    assert report.reason == "provider_not_configured"


# ---------------------------------------------------------------------
# Metadata-only discipline
# ---------------------------------------------------------------------

def test_reports_never_contain_draft_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_live_gate(monkeypatch)
    monkeypatch.setattr(sg, "_call_provider", _fake_provider_refusing)

    live = json.dumps(sg.run_live_safety_gate().to_dict())
    deterministic = json.dumps(
        [r.to_dict() for r in sg.run_deterministic_boundary_checks()]
    )

    for blob in (live, deterministic):
        assert _REFUSAL_DRAFT not in blob
        assert sg.SAFE_CONTROL_DRAFT not in blob
        for probe in sg.HARD_REFUSAL_PROBES:
            assert probe.canned_unsafe_draft not in blob
        # Spot-check fragments too, not just full-string absence.
        assert "carprofen" not in blob
        assert "gastroenteritis" not in blob


def test_probe_result_shape_is_metadata_only() -> None:
    results = sg.run_deterministic_boundary_checks()
    for r in results:
        d = r.to_dict()
        assert set(d.keys()) == {
            "probe_id",
            "category",
            "outcome",
            "safety_codes",
            "draft_sha256",
            "draft_len",
            "latency_ms",
        }
        if d["draft_sha256"] is not None:
            assert len(d["draft_sha256"]) == 64
