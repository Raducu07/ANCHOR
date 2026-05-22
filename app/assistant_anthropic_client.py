# app/assistant_anthropic_client.py
#
# Thin Anthropic client wrapper for the Governed Vet Assistant.
#
# Doctrine:
#   * Vendor-neutral over time — provider/model come from env, not hardcoded.
#   * The system prompt and user message are transient: they are never
#     persisted by callers, and they are never logged here either.
#   * Missing API key is treated as a configuration error and raised as a
#     typed exception. Callers translate this into 503 + a generic message.
#   * The raw provider exception is never propagated to clients; callers
#     wrap it in their own safe HTTP response.
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


PROVIDER_NAME = "anthropic"
DEFAULT_MODEL = "claude-sonnet-4-20250514"
DEFAULT_MAX_TOKENS = 1000
DEFAULT_TEMPERATURE = 0.3


class AssistantModelConfigError(RuntimeError):
    """Raised when required model configuration is missing (e.g. API key)."""


class AssistantModelCallError(RuntimeError):
    """Raised when the provider call fails for any reason. The original
    exception is chained via __cause__ but the message exposed to callers
    must be generic."""


@dataclass(frozen=True)
class ModelConfig:
    provider: str
    model: str
    max_tokens: int
    temperature: float


def get_model_config() -> ModelConfig:
    return ModelConfig(
        provider=PROVIDER_NAME,
        model=os.getenv("ANCHOR_ASSISTANT_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL,
        max_tokens=int(os.getenv("ANCHOR_ASSISTANT_MAX_TOKENS", str(DEFAULT_MAX_TOKENS)) or DEFAULT_MAX_TOKENS),
        temperature=DEFAULT_TEMPERATURE,
    )


def _get_api_key() -> Optional[str]:
    key = (os.getenv("ANTHROPIC_API_KEY") or "").strip()
    return key or None


def _extract_text_from_response(resp) -> str:
    """Pull the assistant text block from an Anthropic messages response.

    Defensive: anthropic SDK has shifted shapes across minor versions. We
    accept either a SDK object with `.content` blocks or a plain dict."""
    content = getattr(resp, "content", None)
    if content is None and isinstance(resp, dict):
        content = resp.get("content")

    if not content:
        raise AssistantModelCallError("empty_model_response")

    parts: list = []
    for block in content:
        block_type = getattr(block, "type", None) or (block.get("type") if isinstance(block, dict) else None)
        if block_type != "text":
            continue
        text_value = getattr(block, "text", None) or (block.get("text") if isinstance(block, dict) else None)
        if text_value:
            parts.append(text_value)

    out = "".join(parts).strip()
    if not out:
        raise AssistantModelCallError("empty_model_response")
    return out


def generate_client_communication_draft(
    *,
    system_prompt: str,
    user_message: str,
) -> Tuple[str, str, str]:
    """Call Anthropic and return (draft_text, provider, model_name).

    Raises:
        AssistantModelConfigError: ANTHROPIC_API_KEY missing.
        AssistantModelCallError: any provider-side failure.

    The system_prompt and user_message arguments are transient: they MUST
    NOT be logged by this function or by callers.
    """
    api_key = _get_api_key()
    if not api_key:
        # No raw config detail propagated upward.
        raise AssistantModelConfigError("anthropic_api_key_missing")

    cfg = get_model_config()

    try:
        # Imported lazily so that test environments without the SDK
        # installed can still import this module.
        import anthropic  # type: ignore
    except Exception as exc:  # pragma: no cover - import-time only
        raise AssistantModelCallError("anthropic_sdk_unavailable") from exc

    try:
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model=cfg.model,
            max_tokens=cfg.max_tokens,
            temperature=cfg.temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
    except Exception as exc:
        # Do not leak prompt, message, or provider stack details. The
        # caller is expected to translate this into a generic 503.
        logger.warning(
            "assistant_model_call_failed",
            extra={"error_type": type(exc).__name__},
        )
        raise AssistantModelCallError("model_call_failed") from exc

    draft = _extract_text_from_response(resp)
    return draft, cfg.provider, cfg.model
