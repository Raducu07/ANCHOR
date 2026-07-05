"""M6.12 precursor - provider interface skeleton tests.

Covers:
  * default resolution is the Anthropic adapter (no env var needed)
  * explicit "anthropic" resolves the Anthropic adapter
  * "openai" resolves the fail-closed stub in non-prod; calling it
    raises AssistantModelConfigError and performs no network I/O
  * unknown provider names raise AssistantModelConfigError
  * prod refuses every non-Anthropic provider at resolution time
  * the Workspace orchestrator falls back deterministically end-to-end
    when the configured provider is the unconfigured stub
  * doctrine: no OPENAI_* env var is read anywhere in app/

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


def test_openai_stub_resolves_but_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _non_prod(monkeypatch)
    monkeypatch.setenv(ap.PROVIDER_ENV, "openai")
    provider = ap.resolve_provider()
    assert isinstance(provider, ap.OpenAIProviderStub)
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
# Orchestrator integration - fail closed end-to-end
# ---------------------------------------------------------------------

def test_orchestrator_falls_back_when_stub_provider_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the unconfigured stub selected, a live-eligible request must
    end in a deterministic fallback - never an exception, never a live
    draft."""
    _non_prod(monkeypatch)
    monkeypatch.setenv(ap.PROVIDER_ENV, "openai")
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


# ---------------------------------------------------------------------
# Doctrine
# ---------------------------------------------------------------------

def test_no_openai_env_vars_read_in_app() -> None:
    """docs/operations/env.md documents that no OPENAI_* env var is read
    in code. The stub must not quietly change that (comments referring
    to the doctrine are fine; env reads are not)."""
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
    assert offenders == []
