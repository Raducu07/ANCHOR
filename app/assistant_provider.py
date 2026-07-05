# app/assistant_provider.py
#
# M6.12 - Vendor-neutral connector layer (code-wise completion, gated).
#
# ANCHOR is ARCHITECTED FOR vendor-neutrality; it is not vendor-neutral
# as a public current-state capability and must not be described as
# such. The Anthropic adapter is the only provider permitted in
# production. The OpenAI adapter exists code-wise (founder decision
# record, 5 July 2026: docs/operations/
# 2026-07-05_founder_code_completion_experiment_decision.md) but is
# disabled by default: it is reachable only when an operator explicitly
# sets ANCHOR_GENERATION_PROVIDER=openai in a NON-production
# environment and supplies OPENAI_API_KEY. Selecting it in production
# is refused at resolution time.
#
# Doctrine:
#   * Default behaviour is byte-identical to the original direct call
#     into app/assistant_anthropic_client.py.
#   * Production only permits the "anthropic" provider. Any other value
#     of ANCHOR_GENERATION_PROVIDER in prod is a configuration error,
#     which the Workspace orchestrator already translates into a
#     deterministic fallback (fail closed, never fail open).
#   * No raw prompt / draft content is logged or persisted here. Error
#     logs carry error types only - never response bodies.
#   * This module does NOT enable live generation anywhere. The
#     ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED gate in
#     app/workspace_generation.py remains the only live switch and
#     remains production-off.
#   * Output safety validation is provider-independent by construction:
#     the orchestrator runs the post-output validator on every live
#     draft regardless of which adapter produced it.

from __future__ import annotations

import json
import logging
import os
from typing import Protocol, Tuple
from urllib import request as _urllib_request
from urllib.error import URLError

from app.anchor_logging import get_app_env
from app.assistant_anthropic_client import (
    AssistantModelCallError,
    AssistantModelConfigError,
    generate_client_communication_draft,
)

logger = logging.getLogger(__name__)


PROVIDER_ENV = "ANCHOR_GENERATION_PROVIDER"

PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_OPENAI = "openai"

# Production allow-list. Deliberately a single entry: widening it is a
# founder decision that requires legal/subprocessor coverage - not an
# env change. The OpenAI adapter therefore cannot be selected in prod
# even where a key is present.
_PROD_ALLOWED_PROVIDERS = frozenset({PROVIDER_ANTHROPIC})

_OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
_OPENAI_DEFAULT_MODEL = "gpt-4o-mini"
_OPENAI_TIMEOUT_S = 30


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


def _openai_post(payload_json: str, api_key: str) -> str:
    """POST one chat-completion request over stdlib HTTPS and return the
    raw response body text. Module-level so tests can monkeypatch it; no
    part of the payload or response is ever logged here."""
    req = _urllib_request.Request(
        url=_OPENAI_API_URL,
        data=payload_json.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with _urllib_request.urlopen(req, timeout=_OPENAI_TIMEOUT_S) as resp:
        body: str = resp.read().decode("utf-8")
        return body


class OpenAIProviderAdapter:
    """Gated OpenAI adapter (stdlib HTTPS; no SDK dependency).

    Disabled by default three ways: never selectable in prod (resolution
    allow-list), requires ANCHOR_GENERATION_PROVIDER=openai to be set
    explicitly, and fails closed as a config error without
    OPENAI_API_KEY. Any transport or response-shape failure raises
    AssistantModelCallError with error-type-only logging."""

    name = PROVIDER_OPENAI

    def generate_client_communication(
        self,
        *,
        system_prompt: str,
        user_message: str,
    ) -> Tuple[str, str, str]:
        api_key = (os.getenv("OPENAI_API_KEY") or "").strip()
        if not api_key:
            raise AssistantModelConfigError("openai_api_key_missing")

        model = (
            os.getenv("ANCHOR_OPENAI_MODEL", _OPENAI_DEFAULT_MODEL).strip()
            or _OPENAI_DEFAULT_MODEL
        )
        max_tokens = int(
            os.getenv("ANCHOR_ASSISTANT_MAX_TOKENS", "1000") or 1000
        )
        payload = json.dumps(
            {
                "model": model,
                "max_completion_tokens": max_tokens,
                "temperature": 0.3,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
            },
            ensure_ascii=False,
        )

        try:
            body = _openai_post(payload, api_key)
        except (URLError, TimeoutError, OSError) as exc:
            logger.warning(
                "assistant_model_call_failed",
                extra={
                    "provider": self.name,
                    "error_type": type(exc).__name__,
                },
            )
            raise AssistantModelCallError("model_call_failed") from exc

        try:
            parsed = json.loads(body)
            draft = parsed["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            logger.warning(
                "assistant_model_response_unparseable",
                extra={
                    "provider": self.name,
                    "error_type": type(exc).__name__,
                },
            )
            raise AssistantModelCallError("empty_model_response") from exc

        if not isinstance(draft, str) or not draft.strip():
            raise AssistantModelCallError("empty_model_response")
        return draft.strip(), self.name, model


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
        return OpenAIProviderAdapter()
    raise AssistantModelConfigError("unknown_generation_provider")
