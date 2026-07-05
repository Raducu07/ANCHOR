# app/assistant_provider.py
#
# M6.12 precursor - provider-neutral generation interface (skeleton).
#
# ANCHOR is ARCHITECTED FOR vendor-neutrality; it is not vendor-neutral
# today and must not be described as such. Only the Anthropic adapter is
# wired. The OpenAI entry is a deliberately unconfigured stub that fails
# closed so the interface shape can be exercised without implying a
# second provider exists.
#
# Doctrine:
#   * Default behaviour is byte-identical to the previous direct call
#     into app/assistant_anthropic_client.py.
#   * Production only permits the "anthropic" provider. Any other value
#     of ANCHOR_GENERATION_PROVIDER in prod is a configuration error,
#     which the Workspace orchestrator already translates into a
#     deterministic fallback (fail closed, never fail open).
#   * No raw prompt / draft content is logged or persisted here.
#   * This module does NOT enable live generation anywhere. The
#     ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED gate in
#     app/workspace_generation.py remains the only live switch and
#     remains production-off.

from __future__ import annotations

import os
from typing import Protocol, Tuple

from app.anchor_logging import get_app_env
from app.assistant_anthropic_client import (
    AssistantModelConfigError,
    generate_client_communication_draft,
)


PROVIDER_ENV = "ANCHOR_GENERATION_PROVIDER"

PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_OPENAI = "openai"

# Production allow-list. Deliberately a single entry: widening it is an
# M6.12 decision that requires a founder addendum, a configured adapter,
# and legal/subprocessor coverage - not an env change.
_PROD_ALLOWED_PROVIDERS = frozenset({PROVIDER_ANTHROPIC})


class GenerationProvider(Protocol):
    """Interface every generation provider adapter satisfies.

    Returns (draft_text, provider_name, model_name). The system prompt
    and user message are transient and must never be logged or persisted
    by an implementation."""

    name: str

    def generate_client_communication(
        self,
        *,
        system_prompt: str,
        user_message: str,
    ) -> Tuple[str, str, str]: ...


class AnthropicProviderAdapter:
    """Adapter over the existing Anthropic client. Behaviour-identical
    to calling app/assistant_anthropic_client.py directly."""

    name = PROVIDER_ANTHROPIC

    def generate_client_communication(
        self,
        *,
        system_prompt: str,
        user_message: str,
    ) -> Tuple[str, str, str]:
        return generate_client_communication_draft(
            system_prompt=system_prompt,
            user_message=user_message,
        )


class OpenAIProviderStub:
    """Unconfigured placeholder. Always fails closed with a config error
    so callers fall back deterministically. It performs no network I/O,
    reads no OPENAI_* env vars, and must not be presented anywhere as a
    supported provider."""

    name = PROVIDER_OPENAI

    def generate_client_communication(
        self,
        *,
        system_prompt: str,
        user_message: str,
    ) -> Tuple[str, str, str]:
        raise AssistantModelConfigError("provider_not_configured")


def get_configured_provider_name() -> str:
    raw = (os.getenv(PROVIDER_ENV, "") or "").strip().lower()
    return raw or PROVIDER_ANTHROPIC


def resolve_provider() -> GenerationProvider:
    """Resolve the configured provider adapter.

    Raises AssistantModelConfigError (never a raw KeyError) for unknown
    names, and for any non-Anthropic provider when APP_ENV=prod. Callers
    already treat that exception as "provider unavailable" and fall back
    deterministically."""
    name = get_configured_provider_name()

    if get_app_env() == "prod" and name not in _PROD_ALLOWED_PROVIDERS:
        raise AssistantModelConfigError("provider_not_permitted_in_prod")

    if name == PROVIDER_ANTHROPIC:
        return AnthropicProviderAdapter()
    if name == PROVIDER_OPENAI:
        return OpenAIProviderStub()
    raise AssistantModelConfigError("unknown_generation_provider")
