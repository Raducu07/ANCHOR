"""Phase 2A-C.5C - Workspace generation orchestrator tests.

Covers:
  * env flag off -> deterministic_only, no provider call
  * mode not eligible (clinical_note / internal_summary)
  * policy disabled
  * usage limit (daily / monthly) exceeded
  * provider error (config + call)
  * output validator blocked
  * happy path (live)
  * portal_assist integration shape (additive fields present, route
    count unchanged)
  * rules_fired metadata includes workspace_generation sub-object and
    preserves existing input/output keys
  * doctrine sweep (clinical_note + internal_summary never live)

No real Anthropic API call is performed. No DB session is required -
policy and usage checks are monkeypatched at the module level.
"""
from __future__ import annotations

import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# Dummy env so app.* imports succeed in any test environment.
os.environ.setdefault("DATABASE_URL", "postgresql://x:y@localhost:5432/z")
os.environ.setdefault("RATE_LIMIT_ENABLED", "0")
os.environ.setdefault("ANCHOR_JWT_SECRET", "test")


from app import workspace_generation as wg  # noqa: E402
from app.assistant_anthropic_client import (  # noqa: E402
    AssistantModelCallError,
    AssistantModelConfigError,
)
from app.assistant_policy import AssistantPolicy  # noqa: E402


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

_CLINIC_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")

_DETERMINISTIC_OUTPUT = "DETERMINISTIC_OUTPUT"
_LIVE_DRAFT = (
    "Hello, this is a live drafted client message. "
    "REVIEW REQUIRED - check against the clinical record before use. "
    "ANCHOR does not replace professional judgement."
)


def _det_builder() -> str:
    return _DETERMINISTIC_OUTPUT


def _make_policy(
    *,
    generation_enabled: bool = True,
    client_communication_enabled: bool = True,
    validation_profile: str = "standard",
    daily_limit: int = 50,
    monthly_limit: int = 1000,
) -> AssistantPolicy:
    return AssistantPolicy(
        id=None,
        clinic_id=_CLINIC_ID,
        policy_version=0,
        is_active=False,
        is_default=True,
        client_communication_enabled=client_communication_enabled,
        generation_enabled=generation_enabled,
        validation_profile=validation_profile,
        daily_run_limit_per_clinic=daily_limit,
        monthly_run_limit_per_clinic=monthly_limit,
        require_human_review=True,
        allow_receipts_after_review=True,
        policy_label="Default Assistant Policy",
        policy_notes=None,
        created_by_user_id=None,
        created_at=None,
        activated_at=None,
    )


@dataclass
class _FakeSafety:
    allowed: bool
    safety_flags: List[str]
    refusal_reason_codes: List[str]


class _ProviderRecorder:
    """Track whether the provider function was called."""

    def __init__(self) -> None:
        self.calls: List[dict] = []

    def __call__(self, system_prompt: str, user_message: str):
        self.calls.append(
            {
                "system_prompt_len": len(system_prompt),
                "user_message_len": len(user_message),
            }
        )
        return (_LIVE_DRAFT, "anthropic", "claude-test-model")


@pytest.fixture
def fake_provider(monkeypatch: pytest.MonkeyPatch) -> _ProviderRecorder:
    rec = _ProviderRecorder()
    monkeypatch.setattr(wg, "_call_provider", rec)
    return rec


@pytest.fixture
def allow_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        wg,
        "_call_output_validator",
        lambda draft, profile: _FakeSafety(True, [], []),
    )


@pytest.fixture
def block_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        wg,
        "_call_output_validator",
        lambda draft, profile: _FakeSafety(
            False, ["output_blocked_test"], ["output_blocked_test"]
        ),
    )


def _patch_policy(
    monkeypatch: pytest.MonkeyPatch, policy: AssistantPolicy
) -> None:
    monkeypatch.setattr(
        wg, "_load_policy", lambda db, clinic_id: policy
    )


def _patch_usage(
    monkeypatch: pytest.MonkeyPatch, window: Optional[str]
) -> None:
    monkeypatch.setattr(
        wg, "_check_usage_window", lambda db, clinic_id, policy: window
    )


def _enable_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(wg.LIVE_FLAG_ENV, "1")


def _disable_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(wg.LIVE_FLAG_ENV, raising=False)


def _call_orchestrator(mode: str = "client_comm") -> wg.WorkspaceGenerationResult:
    return wg.generate_workspace_output(
        mode=mode,
        user_text="A short operational note for a client.",
        instruction="Draft a brief client-facing acknowledgement.",
        role=None,
        clinic_id=_CLINIC_ID,
        db=None,
        deterministic_builder=_det_builder,
    )


# ---------------------------------------------------------------------
# 1. Env flag off
# ---------------------------------------------------------------------


def test_env_flag_off_returns_deterministic_only_and_no_provider_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_flag(monkeypatch)
    rec = _ProviderRecorder()
    monkeypatch.setattr(wg, "_call_provider", rec)

    result = _call_orchestrator(mode="client_comm")

    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_ONLY
    assert result.fallback_reason == wg.FALLBACK_LIVE_DISABLED
    assert result.text == _DETERMINISTIC_OUTPUT
    assert result.live_attempted is False
    assert rec.calls == [], "provider must not be called when env flag is off"


# ---------------------------------------------------------------------
# 2. Mode not eligible
# ---------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["clinical_note", "internal_summary"])
def test_mode_not_live_eligible_returns_deterministic_only(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    _enable_flag(monkeypatch)
    rec = _ProviderRecorder()
    monkeypatch.setattr(wg, "_call_provider", rec)

    result = _call_orchestrator(mode=mode)

    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_ONLY
    assert result.fallback_reason == wg.FALLBACK_MODE_NOT_LIVE_ELIGIBLE
    assert result.text == _DETERMINISTIC_OUTPUT
    assert result.live_attempted is False
    assert rec.calls == [], "provider must not be called for ineligible modes"


def test_doctrine_clinical_note_never_live_even_with_flag_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Doctrine sweep: clinical_note must never receive live output even
    when every other gate would allow it."""
    _enable_flag(monkeypatch)
    _patch_policy(monkeypatch, _make_policy())
    _patch_usage(monkeypatch, None)
    rec = _ProviderRecorder()
    monkeypatch.setattr(wg, "_call_provider", rec)
    monkeypatch.setattr(
        wg,
        "_call_output_validator",
        lambda draft, profile: _FakeSafety(True, [], []),
    )

    result = _call_orchestrator(mode="clinical_note")
    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_ONLY
    assert rec.calls == []


def test_doctrine_internal_summary_never_live_in_this_slice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_flag(monkeypatch)
    _patch_policy(monkeypatch, _make_policy())
    _patch_usage(monkeypatch, None)
    rec = _ProviderRecorder()
    monkeypatch.setattr(wg, "_call_provider", rec)
    monkeypatch.setattr(
        wg,
        "_call_output_validator",
        lambda draft, profile: _FakeSafety(True, [], []),
    )

    result = _call_orchestrator(mode="internal_summary")
    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_ONLY
    assert rec.calls == []


# ---------------------------------------------------------------------
# 3. Policy disabled
# ---------------------------------------------------------------------


def test_policy_generation_disabled_falls_back(
    monkeypatch: pytest.MonkeyPatch, fake_provider: _ProviderRecorder
) -> None:
    _enable_flag(monkeypatch)
    _patch_policy(monkeypatch, _make_policy(generation_enabled=False))
    _patch_usage(monkeypatch, None)

    result = _call_orchestrator()

    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_FALLBACK
    assert result.fallback_reason == wg.FALLBACK_POLICY_DISABLED
    assert result.text == _DETERMINISTIC_OUTPUT
    assert result.live_attempted is False
    assert fake_provider.calls == []


def test_policy_client_communication_disabled_falls_back(
    monkeypatch: pytest.MonkeyPatch, fake_provider: _ProviderRecorder
) -> None:
    _enable_flag(monkeypatch)
    _patch_policy(
        monkeypatch, _make_policy(client_communication_enabled=False)
    )
    _patch_usage(monkeypatch, None)

    result = _call_orchestrator()

    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_FALLBACK
    assert result.fallback_reason == wg.FALLBACK_POLICY_DISABLED
    assert fake_provider.calls == []


# ---------------------------------------------------------------------
# 4. Usage limit exceeded
# ---------------------------------------------------------------------


def test_daily_limit_exceeded_falls_back(
    monkeypatch: pytest.MonkeyPatch, fake_provider: _ProviderRecorder
) -> None:
    _enable_flag(monkeypatch)
    _patch_policy(monkeypatch, _make_policy())
    _patch_usage(monkeypatch, "day")

    result = _call_orchestrator()

    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_FALLBACK
    assert result.fallback_reason == wg.FALLBACK_DAILY_LIMIT
    assert result.live_attempted is False
    assert fake_provider.calls == []


def test_monthly_limit_exceeded_falls_back(
    monkeypatch: pytest.MonkeyPatch, fake_provider: _ProviderRecorder
) -> None:
    _enable_flag(monkeypatch)
    _patch_policy(monkeypatch, _make_policy())
    _patch_usage(monkeypatch, "month")

    result = _call_orchestrator()

    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_FALLBACK
    assert result.fallback_reason == wg.FALLBACK_MONTHLY_LIMIT
    assert result.live_attempted is False
    assert fake_provider.calls == []


# ---------------------------------------------------------------------
# 5. Provider error
# ---------------------------------------------------------------------


def test_provider_config_error_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_flag(monkeypatch)
    _patch_policy(monkeypatch, _make_policy())
    _patch_usage(monkeypatch, None)

    def _raise(_sp, _um):
        raise AssistantModelConfigError("anthropic_api_key_missing")

    monkeypatch.setattr(wg, "_call_provider", _raise)
    monkeypatch.setattr(
        wg,
        "_call_output_validator",
        lambda draft, profile: _FakeSafety(True, [], []),
    )

    result = _call_orchestrator()
    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_FALLBACK
    assert result.fallback_reason == wg.FALLBACK_PROVIDER_ERROR
    assert result.live_attempted is True
    assert result.text == _DETERMINISTIC_OUTPUT


def test_provider_call_error_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_flag(monkeypatch)
    _patch_policy(monkeypatch, _make_policy())
    _patch_usage(monkeypatch, None)

    def _raise(_sp, _um):
        raise AssistantModelCallError("model_call_failed")

    monkeypatch.setattr(wg, "_call_provider", _raise)
    monkeypatch.setattr(
        wg,
        "_call_output_validator",
        lambda draft, profile: _FakeSafety(True, [], []),
    )

    result = _call_orchestrator()
    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_FALLBACK
    assert result.fallback_reason == wg.FALLBACK_PROVIDER_ERROR
    assert result.live_attempted is True


def test_provider_timeout_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_flag(monkeypatch)
    _patch_policy(monkeypatch, _make_policy())
    _patch_usage(monkeypatch, None)

    def _raise(_sp, _um):
        raise TimeoutError("simulated_timeout")

    monkeypatch.setattr(wg, "_call_provider", _raise)

    result = _call_orchestrator()
    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_FALLBACK
    assert result.fallback_reason == wg.FALLBACK_PROVIDER_TIMEOUT
    assert result.live_attempted is True


# ---------------------------------------------------------------------
# 6. Output validator blocked
# ---------------------------------------------------------------------


def test_output_validator_blocked_falls_back(
    monkeypatch: pytest.MonkeyPatch,
    fake_provider: _ProviderRecorder,
    block_validator: None,
) -> None:
    _enable_flag(monkeypatch)
    _patch_policy(monkeypatch, _make_policy())
    _patch_usage(monkeypatch, None)

    result = _call_orchestrator()

    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_FALLBACK
    assert result.fallback_reason == wg.FALLBACK_OUTPUT_VALIDATOR_BLOCKED
    assert result.text == _DETERMINISTIC_OUTPUT, (
        "blocked live draft must not be returned"
    )
    assert result.live_attempted is True
    assert result.model_provider == "anthropic"
    assert result.output_validator_allowed is False
    assert len(fake_provider.calls) == 1


def test_output_validator_raising_is_treated_as_blocked(
    monkeypatch: pytest.MonkeyPatch,
    fake_provider: _ProviderRecorder,
) -> None:
    _enable_flag(monkeypatch)
    _patch_policy(monkeypatch, _make_policy())
    _patch_usage(monkeypatch, None)

    def _raise(_draft, _profile):
        raise RuntimeError("validator_crashed")

    monkeypatch.setattr(wg, "_call_output_validator", _raise)

    result = _call_orchestrator()
    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_FALLBACK
    assert result.fallback_reason == wg.FALLBACK_OUTPUT_BLOCKED
    assert result.text == _DETERMINISTIC_OUTPUT


# ---------------------------------------------------------------------
# 7. Happy path
# ---------------------------------------------------------------------


def test_happy_path_returns_live_draft_and_stamps_provider(
    monkeypatch: pytest.MonkeyPatch,
    fake_provider: _ProviderRecorder,
    allow_validator: None,
) -> None:
    _enable_flag(monkeypatch)
    _patch_policy(monkeypatch, _make_policy())
    _patch_usage(monkeypatch, None)

    result = _call_orchestrator()

    assert result.generation_source == wg.GEN_SOURCE_LIVE
    assert result.fallback_reason is None
    assert result.text == _LIVE_DRAFT
    assert result.live_attempted is True
    assert result.model_provider == "anthropic"
    assert result.model_name == "claude-test-model"
    assert result.output_safety_profile == "standard"
    assert result.output_validator_allowed is True
    assert len(fake_provider.calls) == 1


# ---------------------------------------------------------------------
# 8. Portal assist integration shape
# ---------------------------------------------------------------------


def test_portal_assist_response_model_has_additive_fields() -> None:
    """The optional additive fields must be present on the response
    model so the route can populate them without a contract break."""
    from app.portal_assist import PortalAssistResponse

    fields = PortalAssistResponse.model_fields
    for name in (
        "generation_source",
        "fallback_reason",
        "model_provider",
        "model_name",
    ):
        assert name in fields, f"missing additive field: {name}"
        assert fields[name].is_required() is False, (
            f"additive field must be optional: {name}"
        )


def test_app_route_count_unchanged_after_orchestrator_wiring() -> None:
    from app.main import app

    # 2A-D.2 Patch 11D-b: bumped the pinned count from 125 → 126 to absorb
    # the FastAPI 0.125 → 0.133 framework upgrade that introduced one
    # additional framework-internal route (visible in app.routes alongside
    # `/openapi.json`, `/docs`, `/docs/oauth2-redirect`, `/redoc`). The
    # original intent of this guard — "2A-C.5C must not add or remove any
    # application route" — is preserved; the count is shifted by exactly
    # the number of framework-internal routes added by the upgrade.
    assert len(app.routes) == 126, (
        "2A-C.5C must not add or remove any application route "
        "(count includes FastAPI framework-internal routes; "
        "bumped to 126 by Patch 11D-b for the FastAPI 0.133.1 upgrade)"
    )


def test_portal_assist_imports_orchestrator() -> None:
    """portal_assist must use the orchestrator, not call
    `_stub_llm_generate` directly outside the deterministic builder
    closure."""
    import app.portal_assist as pa

    assert hasattr(pa, "generate_workspace_output")
    assert hasattr(pa, "_workspace_generation_metadata")


# ---------------------------------------------------------------------
# 9. Rules-fired metadata
# ---------------------------------------------------------------------


def test_build_metadata_subobject_shape_for_live() -> None:
    res = wg.WorkspaceGenerationResult(
        text=_LIVE_DRAFT,
        generation_source=wg.GEN_SOURCE_LIVE,
        fallback_reason=None,
        model_provider="anthropic",
        model_name="claude-test-model",
        output_safety_profile="standard",
        live_attempted=True,
        output_validator_allowed=True,
    )
    meta = wg.build_metadata_subobject(res)
    assert meta == {
        "generation_source": "live",
        "fallback_reason": None,
        "live_attempted": True,
        "model_provider": "anthropic",
        "model_name": "claude-test-model",
        "output_safety_profile": "standard",
        "output_validator_allowed": True,
    }


def test_build_metadata_subobject_shape_for_deterministic_only() -> None:
    res = wg.WorkspaceGenerationResult(
        text=_DETERMINISTIC_OUTPUT,
        generation_source=wg.GEN_SOURCE_DETERMINISTIC_ONLY,
        fallback_reason=wg.FALLBACK_LIVE_DISABLED,
    )
    meta = wg.build_metadata_subobject(res)
    assert meta["generation_source"] == "deterministic_only"
    assert meta["fallback_reason"] == "live_generation_disabled"
    assert meta["live_attempted"] is False
    assert meta["model_provider"] is None
    assert meta["model_name"] is None
    assert meta["output_validator_allowed"] is None


def test_metadata_subobject_contains_no_raw_text_fields() -> None:
    """Doctrine sweep: the metadata sub-object must never include the
    draft, raw user text, or prompt."""
    res = wg.WorkspaceGenerationResult(
        text="some draft string that should NEVER appear in metadata",
        generation_source=wg.GEN_SOURCE_LIVE,
        model_provider="anthropic",
        model_name="claude-test-model",
        live_attempted=True,
    )
    meta = wg.build_metadata_subobject(res)
    serialised = repr(meta)
    assert "some draft string" not in serialised
    forbidden_keys = {"text", "draft", "user_text", "prompt", "system_prompt"}
    assert not (set(meta.keys()) & forbidden_keys)


# ---------------------------------------------------------------------
# 10. Adapter doctrine sweep
# ---------------------------------------------------------------------


def test_adapter_omits_identifier_fields() -> None:
    adapted = wg._adapt_workspace_to_client_comm(
        user_text="Operational facts.",
        instruction="Draft something.",
    )
    assert adapted.patient_display_name is None
    assert adapted.species is None
    assert adapted.owner_display_name is None


def test_adapter_uses_safe_default_goal_when_instruction_missing() -> None:
    adapted = wg._adapt_workspace_to_client_comm(
        user_text="Facts.",
        instruction=None,
    )
    assert adapted.communication_goal == wg._DEFAULT_COMMUNICATION_GOAL


def test_live_flag_truthy_values(monkeypatch: pytest.MonkeyPatch) -> None:
    for v in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv(wg.LIVE_FLAG_ENV, v)
        assert wg.is_live_generation_enabled() is True, v
    for v in ("0", "", "false", "no", "off", "maybe"):
        monkeypatch.setenv(wg.LIVE_FLAG_ENV, v)
        assert wg.is_live_generation_enabled() is False, v
