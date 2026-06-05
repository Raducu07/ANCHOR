from __future__ import annotations

# app/workspace_generation.py
#
# Phase 2A-C.5C - Workspace generation orchestrator.
#
# Decides whether one Workspace request should be served by live model
# generation or by the existing deterministic builder, based on:
#   * env flag ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED
#   * Workspace mode eligibility (only client_comm is live-capable in
#     this slice; clinical_note and internal_summary are deterministic)
#   * the clinic's active Assistant policy
#   * shared Assistant daily / monthly usage limits
#   * provider availability and behaviour
#   * Assistant post-output safety validator
#
# Doctrine:
#   * Does NOT own DB writes.
#   * Does NOT mutate state.
#   * Does NOT persist raw prompt / output / draft content.
#   * Does NOT call POST /v1/assistant/runs.
#   * Deterministic fallback is always available - if any live gate
#     fails the deterministic builder is used.
#   * Returns metadata-only governance evidence alongside the text.

import logging
import os
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from app.assistant_anthropic_client import (
    AssistantModelCallError,
    AssistantModelConfigError,
    generate_client_communication_draft,
)
from app.assistant_output_safety import validate_client_communication_output
from app.assistant_policy import AssistantPolicy, get_effective_policy
from app.assistant_prompts import (
    CLIENT_COMMUNICATION_SYSTEM_PROMPT,
    build_client_communication_user_message,
)
from app.assistant_usage_limits import (
    daily_run_limit as _env_daily_run_limit,
    get_assistant_run_counts,
    monthly_run_limit as _env_monthly_run_limit,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

GEN_SOURCE_LIVE = "live"
GEN_SOURCE_DETERMINISTIC_FALLBACK = "deterministic_fallback"
GEN_SOURCE_DETERMINISTIC_ONLY = "deterministic_only"

FALLBACK_LIVE_DISABLED = "live_generation_disabled"
FALLBACK_MODE_NOT_LIVE_ELIGIBLE = "mode_not_live_eligible"
FALLBACK_POLICY_DISABLED = "assistant_mode_disabled_by_policy"
FALLBACK_DAILY_LIMIT = "assistant_daily_run_limit_exceeded"
FALLBACK_MONTHLY_LIMIT = "assistant_monthly_run_limit_exceeded"
FALLBACK_PROVIDER_TIMEOUT = "provider_timeout"
FALLBACK_PROVIDER_ERROR = "provider_error"
FALLBACK_OUTPUT_BLOCKED = "output_blocked_by_governance"
FALLBACK_OUTPUT_VALIDATOR_BLOCKED = "output_validator_blocked"
FALLBACK_USED = "fallback_used"

LIVE_FLAG_ENV = "ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED"

WORKSPACE_MODE_CLIENT_COMM = "client_comm"
WORKSPACE_MODE_CLINICAL_NOTE = "clinical_note"
WORKSPACE_MODE_INTERNAL_SUMMARY = "internal_summary"

# Only client_comm is live-capable in this slice. clinical_note remains
# deterministic-only by doctrine. internal_summary is deferred to a
# follow-up slice once its own Assistant prompt + safety profile are
# designed.
_LIVE_ELIGIBLE_MODES = frozenset({WORKSPACE_MODE_CLIENT_COMM})

_TRUTHY = {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class WorkspaceGenerationResult:
    """Outcome of one orchestrator call.

    Metadata-only: contains the chosen text plus governance evidence
    fields. Raw prompt / draft is never embedded here beyond the chosen
    final `text`, which is what the caller would also have produced via
    the deterministic path."""

    text: str
    generation_source: str
    fallback_reason: Optional[str] = None
    model_provider: Optional[str] = None
    model_name: Optional[str] = None
    output_safety_profile: Optional[str] = None
    live_attempted: bool = False
    output_validator_allowed: Optional[bool] = None


# ---------------------------------------------------------------------
# Env flag
# ---------------------------------------------------------------------

def is_live_generation_enabled() -> bool:
    raw = (os.getenv(LIVE_FLAG_ENV, "") or "").strip().lower()
    return raw in _TRUTHY


# ---------------------------------------------------------------------
# Indirection points (monkeypatched by tests)
# ---------------------------------------------------------------------
#
# Tests replace these module-level functions to inject fakes without
# touching the real Anthropic client, the DB, or the network.

def _call_provider(system_prompt: str, user_message: str):
    """Thin wrapper around the existing Anthropic client. The system
    prompt and user message are transient and never logged here."""
    return generate_client_communication_draft(
        system_prompt=system_prompt,
        user_message=user_message,
    )


def _call_output_validator(draft: str, profile: str):
    """Thin wrapper around the Assistant post-output safety validator."""
    return validate_client_communication_output(draft, profile=profile)


def _load_policy(db: Any, clinic_id: str) -> AssistantPolicy:
    """Read the effective Assistant policy. Indirection so tests can
    inject a fake policy without a DB session."""
    return get_effective_policy(db, clinic_id=clinic_id)


def _check_usage_window(
    db: Any,
    clinic_id: str,
    policy: AssistantPolicy,
) -> Optional[str]:
    """Return None if under limits, otherwise:
      - "day"   - daily limit exceeded
      - "month" - monthly limit exceeded
    """
    daily_count, monthly_count = get_assistant_run_counts(
        db, clinic_id=clinic_id
    )
    d_limit = int(
        policy.daily_run_limit_per_clinic or _env_daily_run_limit()
    )
    m_limit = int(
        policy.monthly_run_limit_per_clinic or _env_monthly_run_limit()
    )
    if daily_count >= d_limit:
        return "day"
    if monthly_count >= m_limit:
        return "month"
    return None


# ---------------------------------------------------------------------
# Workspace -> Assistant input adapter
# ---------------------------------------------------------------------

_DEFAULT_COMMUNICATION_GOAL = (
    "Draft a client-facing communication from clinician-confirmed "
    "operational facts."
)
_DEFAULT_TONE = "warm, professional, UK veterinary practice"


class _AdaptedClientCommInput:
    """Duck-typed object compatible with
    `build_client_communication_user_message`. We deliberately do NOT
    construct a real ClientCommunicationInput - that model enforces
    identifier-bearing optional fields, and in this first slice we
    intentionally omit patient / owner / species so no identifiers are
    forwarded to the live provider."""

    def __init__(
        self,
        *,
        communication_goal: str,
        clinician_confirmed_facts: str,
        tone: Optional[str] = None,
    ) -> None:
        self.communication_goal = communication_goal
        self.clinician_confirmed_facts = clinician_confirmed_facts
        # Identifier-bearing fields are deliberately None. The prompt
        # builder falls back to "[not provided]" for missing attrs.
        self.patient_display_name = None
        self.species = None
        self.owner_display_name = None
        self.tone = tone or _DEFAULT_TONE
        self.destination = None
        self.things_to_include = None
        self.things_to_avoid = None


def _adapt_workspace_to_client_comm(
    *,
    user_text: str,
    instruction: Optional[str],
) -> _AdaptedClientCommInput:
    goal = (instruction or "").strip() or _DEFAULT_COMMUNICATION_GOAL
    facts = (user_text or "").strip()
    return _AdaptedClientCommInput(
        communication_goal=goal,
        clinician_confirmed_facts=facts,
    )


# ---------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------

def generate_workspace_output(
    *,
    mode: str,
    user_text: str,
    instruction: Optional[str],
    role: Optional[str],
    clinic_id: uuid.UUID,
    db: Any,
    deterministic_builder: Callable[[], str],
) -> WorkspaceGenerationResult:
    """Decide live vs deterministic for one Workspace request.

    `deterministic_builder` is a zero-arg callable that yields the
    deterministic draft. The orchestrator invokes it whenever any live
    gate fails or whenever live generation fails or is blocked.

    Doctrine:
      * Never calls a provider when the env flag is off.
      * Never calls a provider for non-eligible modes.
      * Never persists state.
      * Never returns raw provider draft when the post-output safety
        validator blocks it; deterministic fallback is used instead.
    """
    # `role` is currently unused as live-path context but kept on the
    # signature so the caller surface stays stable and a future slice
    # can route role-aware Assistant modes without a signature change.
    _ = role

    # Gate 1: env flag.
    if not is_live_generation_enabled():
        return WorkspaceGenerationResult(
            text=deterministic_builder(),
            generation_source=GEN_SOURCE_DETERMINISTIC_ONLY,
            fallback_reason=FALLBACK_LIVE_DISABLED,
            live_attempted=False,
        )

    # Gate 2: mode eligibility.
    if mode not in _LIVE_ELIGIBLE_MODES:
        return WorkspaceGenerationResult(
            text=deterministic_builder(),
            generation_source=GEN_SOURCE_DETERMINISTIC_ONLY,
            fallback_reason=FALLBACK_MODE_NOT_LIVE_ELIGIBLE,
            live_attempted=False,
        )

    # Gate 3: clinic policy.
    try:
        policy = _load_policy(db, str(clinic_id))
    except Exception:
        logger.warning(
            "workspace_generation_policy_lookup_failed",
            extra={"clinic_id": str(clinic_id)},
        )
        return WorkspaceGenerationResult(
            text=deterministic_builder(),
            generation_source=GEN_SOURCE_DETERMINISTIC_FALLBACK,
            fallback_reason=FALLBACK_USED,
            live_attempted=False,
        )

    if (
        not policy.generation_enabled
        or not policy.client_communication_enabled
    ):
        return WorkspaceGenerationResult(
            text=deterministic_builder(),
            generation_source=GEN_SOURCE_DETERMINISTIC_FALLBACK,
            fallback_reason=FALLBACK_POLICY_DISABLED,
            live_attempted=False,
        )

    # Gate 4: usage limits (shared bucket with Assistant runs).
    try:
        window = _check_usage_window(db, str(clinic_id), policy)
    except Exception:
        logger.warning(
            "workspace_generation_usage_check_failed",
            extra={"clinic_id": str(clinic_id)},
        )
        # Fail open on usage check so a transient DB blip does not block
        # Workspace; the provider call may still itself be governed by
        # provider-side rate limits.
        window = None

    if window == "day":
        return WorkspaceGenerationResult(
            text=deterministic_builder(),
            generation_source=GEN_SOURCE_DETERMINISTIC_FALLBACK,
            fallback_reason=FALLBACK_DAILY_LIMIT,
            live_attempted=False,
        )
    if window == "month":
        return WorkspaceGenerationResult(
            text=deterministic_builder(),
            generation_source=GEN_SOURCE_DETERMINISTIC_FALLBACK,
            fallback_reason=FALLBACK_MONTHLY_LIMIT,
            live_attempted=False,
        )

    # Adapt Workspace input to the existing client_communication
    # prompt builder. No identifiers are forwarded.
    adapted = _adapt_workspace_to_client_comm(
        user_text=user_text,
        instruction=instruction,
    )
    system_prompt = CLIENT_COMMUNICATION_SYSTEM_PROMPT
    user_message = build_client_communication_user_message(adapted)

    # Live provider call.
    try:
        draft, provider, model_name = _call_provider(
            system_prompt, user_message
        )
    except AssistantModelConfigError:
        logger.info(
            "workspace_generation_provider_unavailable",
            extra={"clinic_id": str(clinic_id), "reason": "config"},
        )
        return WorkspaceGenerationResult(
            text=deterministic_builder(),
            generation_source=GEN_SOURCE_DETERMINISTIC_FALLBACK,
            fallback_reason=FALLBACK_PROVIDER_ERROR,
            live_attempted=True,
        )
    except AssistantModelCallError:
        logger.info(
            "workspace_generation_provider_failed",
            extra={"clinic_id": str(clinic_id)},
        )
        return WorkspaceGenerationResult(
            text=deterministic_builder(),
            generation_source=GEN_SOURCE_DETERMINISTIC_FALLBACK,
            fallback_reason=FALLBACK_PROVIDER_ERROR,
            live_attempted=True,
        )
    except TimeoutError:
        logger.info(
            "workspace_generation_provider_timeout",
            extra={"clinic_id": str(clinic_id)},
        )
        return WorkspaceGenerationResult(
            text=deterministic_builder(),
            generation_source=GEN_SOURCE_DETERMINISTIC_FALLBACK,
            fallback_reason=FALLBACK_PROVIDER_TIMEOUT,
            live_attempted=True,
        )
    except Exception:
        logger.warning(
            "workspace_generation_provider_unexpected_error",
            extra={"clinic_id": str(clinic_id)},
        )
        return WorkspaceGenerationResult(
            text=deterministic_builder(),
            generation_source=GEN_SOURCE_DETERMINISTIC_FALLBACK,
            fallback_reason=FALLBACK_PROVIDER_ERROR,
            live_attempted=True,
        )

    # Post-output safety validator.
    profile = policy.validation_profile or "standard"
    try:
        safety = _call_output_validator(draft, profile)
    except Exception:
        logger.warning(
            "workspace_generation_output_validator_failed",
            extra={"clinic_id": str(clinic_id)},
        )
        return WorkspaceGenerationResult(
            text=deterministic_builder(),
            generation_source=GEN_SOURCE_DETERMINISTIC_FALLBACK,
            fallback_reason=FALLBACK_OUTPUT_BLOCKED,
            live_attempted=True,
            model_provider=provider,
            model_name=model_name,
            output_safety_profile=profile,
            output_validator_allowed=False,
        )

    if not getattr(safety, "allowed", False):
        return WorkspaceGenerationResult(
            text=deterministic_builder(),
            generation_source=GEN_SOURCE_DETERMINISTIC_FALLBACK,
            fallback_reason=FALLBACK_OUTPUT_VALIDATOR_BLOCKED,
            live_attempted=True,
            model_provider=provider,
            model_name=model_name,
            output_safety_profile=profile,
            output_validator_allowed=False,
        )

    return WorkspaceGenerationResult(
        text=draft,
        generation_source=GEN_SOURCE_LIVE,
        fallback_reason=None,
        live_attempted=True,
        model_provider=provider,
        model_name=model_name,
        output_safety_profile=profile,
        output_validator_allowed=True,
    )


def build_metadata_subobject(
    result: WorkspaceGenerationResult,
) -> Dict[str, Any]:
    """Build the `workspace_generation` sub-object recorded inside
    `rules_fired` on `clinic_governance_events`. Metadata-only - no raw
    prompt / output / draft content is included."""
    return {
        "generation_source": result.generation_source,
        "fallback_reason": result.fallback_reason,
        "live_attempted": bool(result.live_attempted),
        "model_provider": result.model_provider,
        "model_name": result.model_name,
        "output_safety_profile": result.output_safety_profile,
        "output_validator_allowed": result.output_validator_allowed,
    }
