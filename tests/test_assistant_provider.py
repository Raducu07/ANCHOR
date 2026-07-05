"""M6.12 - vendor-neutral connector layer tests (gated).

Covers:
  * default resolution is the Anthropic adapter (no env var needed)
  * explicit "anthropic" resolves the Anthropic adapter
  * "openai" resolves the gated adapter in non-prod; without
    OPENAI_API_KEY it fails closed as a config error with no I/O
  * unknown provider names raise AssistantModelConfigError
  * prod refuses every non-Anthropic provider at resolution time
  * OpenAI adapter happy path / unparseable body / transport error via
    a fake transport (no network)
  * the Workspace orchestrator falls back deterministically end-to-end
    when the configured provider is unconfigured
  * output safety validation is provider-independent: an unsafe draft
    from the OpenAI adapter is blocked exactly like an Anthropic one
  * doctrine: OPENAI_* env vars are read only inside
    app/assistant_provider.py

No real provider call is performed. No DB session is required.
"""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Dummy env so app.* imports succeed in any test environment.
os.environ.setdefault("DATABASE_URL", "postgresql://x:y@localhost:5432/z")
os.environ.setdefault("RATE_LIMIT_ENABLED", "0")
os.environ.setdefault("ANCHOR_JWT_SECRET", "test")

from app import assistant_provider as ap  # noqa: E402
from app import workspace_generation as wg  # noqa: E402
from app.assistant_anthropic_client import (  # noqa: E402
    AssistantModelConfigError,
)
from app.assistant_policy import AssistantPolicy  # noqa: E402


_CLINIC_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
_DETERMINISTIC_OUTPUT = "DETERMINISTIC_OUTPUT"


def _det_builder() -> str:
    return _DETERMINISTIC_OUTPUT


def _make_policy() -> AssistantPolicy:
    return AssistantPolicy(
        id=None,
        clinic_id=_CLINIC_ID,
        policy_version=0,
        is_active=False,
        is_default=True,
        client_communication_enabled=True,
        generation_enabled=True,
        validation_profile="standard",
        daily_run_limit_per_clinic=50,
        monthly_run_limit_per_clinic=1000,
        require_human_review=True,
        allow_receipts_after_review=True,
        policy_label="Default Assistant Policy",
        policy_notes=None,
        created_by_user_id=None,
        created_at=None,
        activated_at=None,
    )


def _non_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.delenv("ENV", raising=False)


# ---------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------

def test_default_provider_is_anthropic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _non_prod(monkeypatch)
    monkeypatch.delenv(ap.PROVIDER_ENV, raising=False)
    provider = ap.resolve_provider()
    assert isinstance(provider, ap.AnthropicProviderAdapter)
    assert provider.name == ap.PROVIDER_ANTHROPIC


def test_explicit_anthropic_resolves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _non_prod(monkeypatch)
    monkeypatch.setenv(ap.PROVIDER_ENV, "anthropic")
    assert isinstance(ap.resolve_provider(), ap.AnthropicProviderAdapter)


def test_openai_adapter_without_key_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _non_prod(monkeypatch)
    monkeypatch.setenv(ap.PROVIDER_ENV, "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = ap.resolve_provider()
    assert isinstance(provider, ap.OpenAIProviderAdapter)

    def _no_transport(payload_json: str, api_key: str) -> str:
        raise AssertionError("transport must not be reached without a key")

    monkeypatch.setattr(ap, "_openai_post", _no_transport)
    with pytest.raises(AssistantModelConfigError):
        provider.generate_client_communication(
            system_prompt="s", user_message="u"
        )


def test_unknown_provider_raises_config_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _non_prod(monkeypatch)
    monkeypatch.setenv(ap.PROVIDER_ENV, "nonsense-provider")
    with pytest.raises(AssistantModelConfigError):
        ap.resolve_provider()


def test_prod_refuses_non_anthropic_providers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv(ap.PROVIDER_ENV, "openai")
    with pytest.raises(AssistantModelConfigError):
        ap.resolve_provider()


def test_prod_still_resolves_anthropic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv(ap.PROVIDER_ENV, "anthropic")
    assert isinstance(ap.resolve_provider(), ap.AnthropicProviderAdapter)


# ---------------------------------------------------------------------
# OpenAI adapter transport behaviour (fake transport, no network)
# ---------------------------------------------------------------------

_UNSAFE_OPENAI_DRAFT = (
    "Give 200 mg of carprofen twice daily with food. "
    "REVIEW REQUIRED - check against the clinical record before use. "
    "ANCHOR does not replace professional judgement."
)


def _openai_body(content: str) -> str:
    import json

    return json.dumps(
        {"choices": [{"message": {"role": "assistant", "content": content}}]}
    )


def _with_openai(monkeypatch: pytest.MonkeyPatch) -> None:
    _non_prod(monkeypatch)
    monkeypatch.setenv(ap.PROVIDER_ENV, "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-real")
    monkeypatch.setenv("ANCHOR_OPENAI_MODEL", "fake-openai-model")


def test_openai_adapter_happy_path_with_fake_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_openai(monkeypatch)
    monkeypatch.setattr(
        ap, "_openai_post", lambda payload, key: _openai_body("  a draft  ")
    )
    draft, provider, model = ap.resolve_provider().generate_client_communication(
        system_prompt="s", user_message="u"
    )
    assert (draft, provider, model) == ("a draft", "openai", "fake-openai-model")


def test_openai_adapter_unparseable_body_is_call_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.assistant_anthropic_client import AssistantModelCallError

    _with_openai(monkeypatch)
    monkeypatch.setattr(ap, "_openai_post", lambda payload, key: "not-json")
    with pytest.raises(AssistantModelCallError):
        ap.resolve_provider().generate_client_communication(
            system_prompt="s", user_message="u"
        )


def test_openai_adapter_transport_error_is_call_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from urllib.error import URLError

    from app.assistant_anthropic_client import AssistantModelCallError

    _with_openai(monkeypatch)

    def _boom(payload_json: str, api_key: str) -> str:
        raise URLError("connection refused")

    monkeypatch.setattr(ap, "_openai_post", _boom)
    with pytest.raises(AssistantModelCallError):
        ap.resolve_provider().generate_client_communication(
            system_prompt="s", user_message="u"
        )


# ---------------------------------------------------------------------
# Orchestrator integration - fail closed end-to-end
# ---------------------------------------------------------------------

def test_orchestrator_falls_back_when_openai_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With openai selected but no API key, a live-eligible request must
    end in a deterministic fallback - never an exception, never a live
    draft."""
    _non_prod(monkeypatch)
    monkeypatch.setenv(ap.PROVIDER_ENV, "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv(wg.LIVE_FLAG_ENV, "1")
    monkeypatch.setattr(wg, "_load_policy", lambda db, clinic_id: _make_policy())
    monkeypatch.setattr(
        wg, "_check_usage_window", lambda db, clinic_id, policy: None
    )

    result = wg.generate_workspace_output(
        mode=wg.WORKSPACE_MODE_CLIENT_COMM,
        user_text="Bella is ready for collection this afternoon.",
        instruction=None,
        role=None,
        clinic_id=_CLINIC_ID,
        db=None,
        deterministic_builder=_det_builder,
    )
    assert result.text == _DETERMINISTIC_OUTPUT
    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_FALLBACK
    assert result.fallback_reason == wg.FALLBACK_PROVIDER_ERROR
    assert result.live_attempted is True


def test_output_safety_is_provider_independent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unsafe draft from the OpenAI adapter must be blocked by the
    same post-output validator that governs the Anthropic path, ending
    in a deterministic fallback - the draft never reaches the caller."""
    _with_openai(monkeypatch)
    monkeypatch.setenv(wg.LIVE_FLAG_ENV, "1")
    monkeypatch.setattr(
        ap,
        "_openai_post",
        lambda payload, key: _openai_body(_UNSAFE_OPENAI_DRAFT),
    )
    monkeypatch.setattr(wg, "_load_policy", lambda db, clinic_id: _make_policy())
    monkeypatch.setattr(
        wg, "_check_usage_window", lambda db, clinic_id, policy: None
    )

    result = wg.generate_workspace_output(
        mode=wg.WORKSPACE_MODE_CLIENT_COMM,
        user_text="Owner asked about medication.",
        instruction=None,
        role=None,
        clinic_id=_CLINIC_ID,
        db=None,
        deterministic_builder=_det_builder,
    )
    assert result.text == _DETERMINISTIC_OUTPUT
    assert result.generation_source == wg.GEN_SOURCE_DETERMINISTIC_FALLBACK
    assert result.fallback_reason == wg.FALLBACK_OUTPUT_VALIDATOR_BLOCKED
    assert result.model_provider == "openai"
    assert result.output_validator_allowed is False
    assert isinstance(result.provider_latency_ms, int)


# ---------------------------------------------------------------------
# Doctrine
# ---------------------------------------------------------------------

def test_openai_env_vars_read_only_in_assistant_provider() -> None:
    """OPENAI_* env reads are confined to the gated adapter module in
    app/assistant_provider.py (documented in docs/operations/env.md).
    Nothing else in app/ may quietly grow an OpenAI dependency."""
    app_dir = REPO_ROOT / "app"
    read_markers = (
        'getenv("OPENAI',
        "getenv('OPENAI",
        'environ["OPENAI',
        "environ['OPENAI",
        'environ.get("OPENAI',
        "environ.get('OPENAI",
    )
    offenders = []
    for path in app_dir.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if any(marker in text for marker in read_markers):
            offenders.append(path.name)
    assert offenders == ["assistant_provider.py"]
