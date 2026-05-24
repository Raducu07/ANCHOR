# app/portal_assistant.py
#
# Backend PR 2B — Client communication draft generation.
#
# Pipeline:
#   clinic auth
#     -> RLS context (via get_db)
#     -> mode validation
#     -> structured input validation
#     -> deterministic input hashing
#     -> field-key extraction (keys only, never values)
#     -> PII metadata detection
#     -> INSERT assistant_runs (run_status='created'); no model call yet
#     -> input-side safety gate
#         * if unsafe: UPDATE run_status='generation_refused';
#                      return fixed refusal text transiently (never stored)
#         * if safe:   call Anthropic; UPDATE run_status='generation_succeeded'
#                      with output_sha256 + model_provider + model_name;
#                      return draft transiently
#         * if model failure: UPDATE run_status='generation_failed'; 503
#
# Persistence doctrine:
#   * Raw input is never stored. Only input_sha256 + key list.
#   * Raw prompt/user-message is never stored and never logged.
#   * Raw draft is never stored. Only output_sha256.
#   * Refusal message is a governance constant, returned transiently only.

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.assistant_anthropic_client import (
    AssistantModelCallError,
    AssistantModelConfigError,
    generate_client_communication_draft,
    get_model_config,
)
from app.assistant_output_safety import (
    OUTPUT_BLOCKED_MESSAGE,
    validate_client_communication_output,
)
from app.assistant_policy import (
    ALLOWED_PATCH_FIELDS,
    ALLOWED_VALIDATION_PROFILES,
    AssistantPolicy,
    DEFAULT_POLICY_LABEL,
    FORBIDDEN_PATCH_FIELDS,
    VALIDATION_PROFILE_STANDARD,
    deactivate_active_policies,
    get_active_policy_row,
    get_effective_policy,
    get_policy_history_rows,
    insert_new_policy_version,
    insert_policy_audit_event,
)
from app.assistant_prompts import (
    CLIENT_COMMUNICATION_SYSTEM_PROMPT,
    FIXED_REFUSAL_MESSAGE,
    GOVERNANCE_NOTE,
    build_client_communication_user_message,
)
from app.assistant_usage_limits import (
    AssistantUsageLimitExceeded,
    enforce_assistant_run_limits,
)
from app.auth_and_rls import require_clinic_user
from app.db import get_db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Contract constants
# ---------------------------------------------------------------------

ASSISTANT_CONTRACT_VERSION = "assistant_contract_v1"
WORKFLOW_ORIGIN = "anchor_assistant"

MODE_CLIENT_COMMUNICATION = "client_communication"

# Modes the backend recognises in PR 2B (others are contract_defined_only).
_KNOWN_MODES = {MODE_CLIENT_COMMUNICATION}
_ACTIVE_MODES = {MODE_CLIENT_COMMUNICATION}

RUN_STATUS_CREATED = "created"
RUN_STATUS_SUCCEEDED = "generation_succeeded"
RUN_STATUS_FAILED = "generation_failed"
RUN_STATUS_REFUSED = "generation_refused"
# M6.6 — model returned a draft but ANCHOR's post-output safety
# validator blocked it before the route returned the draft.
RUN_STATUS_OUTPUT_BLOCKED = "output_blocked"


# ---------------------------------------------------------------------
# PII detection (regex only, metadata-only)
# ---------------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"\b\+?\d[\d\s().-]{7,}\d\b")
_UK_POSTCODE_RE = re.compile(r"\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b", re.IGNORECASE)
_NUMERIC_ID_RE = re.compile(r"\b\d{6,}\b")


def detect_pii_types(serialised_input: str) -> List[str]:
    """Return ordered, de-duplicated PII type tags. Detection-only — never
    blocks; never stores values."""
    text_value = serialised_input or ""
    found: List[str] = []
    if _UK_POSTCODE_RE.search(text_value):
        found.append("uk_postcode")
    if _EMAIL_RE.search(text_value):
        found.append("email_address")
    if _PHONE_RE.search(text_value):
        found.append("phone_number")
    if _NUMERIC_ID_RE.search(text_value):
        found.append("numeric_id")

    seen: set = set()
    out: List[str] = []
    for item in found:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# ---------------------------------------------------------------------
# Input-side safety gate
# ---------------------------------------------------------------------
#
# These patterns intentionally over-trigger: we'd rather refuse a borderline
# request and have a human re-phrase it than send unsafe clinical asks to
# the model. The codes match AssistantSafetyCode in assistant_models.py.

_SAFETY_PATTERNS: List[Tuple[str, List[re.Pattern]]] = [
    (
        "diagnosis_request",
        [
            re.compile(r"\bdiagnos(e|is|ed|ing|es)\b", re.IGNORECASE),
            re.compile(r"\bdifferential\s+diagnos\w*\b", re.IGNORECASE),
            re.compile(r"\bwhat\s+(is\s+)?wrong\s+with\b", re.IGNORECASE),
        ],
    ),
    (
        "treatment_recommendation_request",
        [
            re.compile(r"\btreatment\s+(plan|recommend\w*|protocol)\b", re.IGNORECASE),
            re.compile(r"\brecommend\s+(a\s+)?treatment\b", re.IGNORECASE),
            re.compile(r"\bhow\s+should\s+(i|we)\s+treat\b", re.IGNORECASE),
            re.compile(r"\bwhat\s+treatment\b", re.IGNORECASE),
        ],
    ),
    (
        "prescribing_request",
        [
            re.compile(r"\bprescrib(e|ing|ed|es)\b", re.IGNORECASE),
            re.compile(r"\bwhat\s+(drug|medication|antibiotic|nsaid)\b", re.IGNORECASE),
            re.compile(r"\bwhich\s+(drug|medication|antibiotic)\b", re.IGNORECASE),
        ],
    ),
    (
        "dose_calculation_request",
        [
            re.compile(r"\bdos(e|age|ing)\b", re.IGNORECASE),
            re.compile(r"\bmg\s*/\s*kg\b", re.IGNORECASE),
            re.compile(r"\bml\s*/\s*kg\b", re.IGNORECASE),
            re.compile(r"\bhow\s+(much|many)\s+(mg|ml|mls|tablets?|drops?)\b", re.IGNORECASE),
            re.compile(r"\banaesthetic\s+protocol\b", re.IGNORECASE),
        ],
    ),
    (
        "imaging_interpretation_request",
        [
            re.compile(r"\b(interpret|read|explain)\s+(the\s+)?(x[-\s]?ray|ct|mri|ultrasound|radiograph)", re.IGNORECASE),
            re.compile(r"\bwhat\s+does\s+(the\s+)?(x[-\s]?ray|ct|mri|ultrasound)\b", re.IGNORECASE),
        ],
    ),
    (
        "lab_interpretation_request",
        [
            re.compile(r"\b(interpret|explain)\s+(the\s+)?(blood\s+(work|test|results)|lab(\s+results)?|biochem\w*|haemato\w*|cbc)\b", re.IGNORECASE),
            re.compile(r"\bwhat\s+do\s+(the\s+)?(blood|lab)\s+results\b", re.IGNORECASE),
        ],
    ),
    (
        "triage_or_discharge_decision_request",
        [
            re.compile(r"\b(should|can)\s+(i|we)\s+(discharge|send\s+(them\s+)?home)\b", re.IGNORECASE),
            re.compile(r"\btriage\b", re.IGNORECASE),
            re.compile(r"\bgo[-\s]?home\s+decision\b", re.IGNORECASE),
        ],
    ),
    (
        "unsupported_prognosis",
        [
            re.compile(r"\bwhat\s+is\s+the\s+prognos\w*\b", re.IGNORECASE),
            re.compile(r"\b(life\s+expectancy|chance\s+of\s+survival|will\s+(my|the)\s+(dog|cat|pet)\s+(die|survive|recover))\b", re.IGNORECASE),
        ],
    ),
    (
        "jailbreak_attempt",
        [
            re.compile(r"\bignore\s+(all\s+|your\s+|the\s+|previous\s+)?(rules|instructions|policy|policies|guidelines)\b", re.IGNORECASE),
            re.compile(r"\b(override|disregard|bypass)\s+(your\s+|the\s+)?(rules|policy|safety|guidelines|guardrails)\b", re.IGNORECASE),
            re.compile(r"\bpretend\s+you\s+are\s+not\b", re.IGNORECASE),
            re.compile(r"\bact\s+as\s+if\s+you\s+had\s+no\s+(rules|restrictions)\b", re.IGNORECASE),
        ],
    ),
]


def evaluate_input_safety(input_obj: Dict[str, Any]) -> List[str]:
    """Return ordered list of refusal_reason_codes if the input asks for
    or strongly implies an out-of-scope clinical action. Empty list means
    the input is safe to forward to the model.

    The combined text searched is all string values from `input_obj`, not
    a fingerprint — pattern matching needs the original characters."""
    chunks: List[str] = []
    for v in input_obj.values():
        if isinstance(v, str) and v.strip():
            chunks.append(v)
    haystack = " \n ".join(chunks)
    if not haystack:
        return []

    codes: List[str] = []
    for code, patterns in _SAFETY_PATTERNS:
        for pat in patterns:
            if pat.search(haystack):
                if code not in codes:
                    codes.append(code)
                break
    return codes


# ---------------------------------------------------------------------
# Hashing / key-only helpers
# ---------------------------------------------------------------------

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()


def _is_meaningful(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


def extract_input_field_keys(input_obj: Dict[str, Any]) -> List[str]:
    if not isinstance(input_obj, dict):
        return []
    return sorted([k for k, v in input_obj.items() if _is_meaningful(v)])


# ---------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------

class ClientCommunicationInput(BaseModel):
    """PR 2B client_communication input. Required fields must be non-empty.

    Optional fields are declared so the prompt builder can read them via
    getattr without falling back to opaque dict lookups; unknown extras
    are tolerated for forward compatibility but never persisted as values."""

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    communication_goal: str = Field(..., min_length=1, max_length=2000)
    clinician_confirmed_facts: str = Field(..., min_length=1, max_length=8000)

    patient_display_name: Optional[str] = Field(default=None, max_length=200)
    species: Optional[str] = Field(default=None, max_length=100)
    owner_display_name: Optional[str] = Field(default=None, max_length=200)
    tone: Optional[str] = Field(default=None, max_length=64)
    destination: Optional[str] = Field(default=None, max_length=64)
    things_to_include: Optional[str] = Field(default=None, max_length=2000)
    things_to_avoid: Optional[str] = Field(default=None, max_length=2000)


class AssistantRunCreate(BaseModel):
    mode: str = Field(..., min_length=1, max_length=64)
    input: Dict[str, Any] = Field(..., description="Mode-specific structured input")


class AssistantRunMetadata(BaseModel):
    # `model_provider` and `model_name` collide with Pydantic v2's
    # protected `model_` namespace and would otherwise warn at import.
    # Disable protected_namespaces locally; field names are part of the
    # public wire contract and must not be renamed.
    model_config = ConfigDict(protected_namespaces=())

    run_id: uuid.UUID
    mode: str
    contract_version: str
    run_status: str
    draft: Optional[str] = None
    refused: bool = False
    # M6.6 — true when the model produced a draft but ANCHOR's
    # post-output safety validator blocked it. Distinct from `refused`,
    # which still means "refused before model call".
    blocked: bool = False
    blocked_message: Optional[str] = None
    refusal_reason_codes: List[str] = Field(default_factory=list)
    safety_flags: List[str] = Field(default_factory=list)
    pii_detected: bool
    pii_types: List[str] = Field(default_factory=list)
    input_field_keys: List[str] = Field(default_factory=list)
    review_status: str
    output_sha256: Optional[str] = None
    model_provider: Optional[str] = None
    model_name: Optional[str] = None
    generation_enabled: bool
    governance_note: str
    # M6.7.1 — policy context surfaced on every Assistant run response.
    # Null when the run was governed by the synthesised default policy
    # (no persisted assistant_policy_settings row for the clinic).
    # `assistant_validation_profile` reports the effective profile and
    # therefore stays a non-null string ("standard" by default).
    assistant_policy_id: Optional[uuid.UUID] = None
    assistant_policy_version: Optional[int] = None
    assistant_validation_profile: Optional[str] = None


class AssistantRunCreateResponse(BaseModel):
    run: AssistantRunMetadata


# ---------------------------------------------------------------------
# M6.3 — Traceability / evidence response models
# ---------------------------------------------------------------------
#
# These response models intentionally OMIT `draft`. The traceability surface
# is metadata-only governance evidence — it must not include or imply any
# stored raw content. `draft_stored=False` is asserted explicitly on the
# detail response.

_TRACEABILITY_GOVERNANCE_NOTE = (
    "Assistant run records contain metadata only. Raw input, prompts, and "
    "draft output are not stored."
)


class AssistantRunTraceItem(BaseModel):
    """Metadata-only view of an assistant_runs row. Contains no draft, no
    input text, no prompt text — only hashes, key lists, flags, and the
    governance pointers."""

    # See AssistantRunMetadata for the rationale on protected_namespaces.
    model_config = ConfigDict(protected_namespaces=())

    run_id: uuid.UUID
    clinic_id: uuid.UUID
    clinic_user_id: uuid.UUID
    mode: str
    contract_version: str
    workflow_origin: str

    input_sha256: str
    output_sha256: Optional[str] = None

    input_field_keys: List[str] = Field(default_factory=list)

    pii_detected: bool
    pii_types: List[str] = Field(default_factory=list)
    safety_flags: List[str] = Field(default_factory=list)
    refusal_reason_codes: List[str] = Field(default_factory=list)

    review_status: str
    run_status: str

    receipt_id: Optional[uuid.UUID] = None
    governance_event_id: Optional[uuid.UUID] = None

    model_provider: Optional[str] = None
    model_name: Optional[str] = None

    # M6.4 — metadata-only human review evidence.
    review_decision: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    reviewed_by_user_id: Optional[uuid.UUID] = None

    # M6.5 — metadata-only receipt linkage (derived). `has_receipt` is
    # true when receipt_id is populated; `receipt_created_at` is only
    # populated by the GET-receipt endpoint that joins the receipts row.
    has_receipt: bool = False
    receipt_created_at: Optional[datetime] = None

    # M6.7.1 — policy context for this run. Null when the run was
    # governed by the synthesised default policy.
    assistant_policy_id: Optional[uuid.UUID] = None
    assistant_policy_version: Optional[int] = None
    assistant_validation_profile: Optional[str] = None

    created_at: datetime
    updated_at: Optional[datetime] = None


class AssistantRunListResponse(BaseModel):
    runs: List[AssistantRunTraceItem]
    limit: int


class AssistantRunDetailResponse(BaseModel):
    run: AssistantRunTraceItem
    storage_policy: str = "metadata_only_by_default"
    raw_content_stored: bool = False
    draft_stored: bool = False
    prompt_stored: bool = False
    governance_note: str = _TRACEABILITY_GOVERNANCE_NOTE


class AssistantContractItem(BaseModel):
    mode: str
    contract_version: str
    storage_policy: str
    metadata_only: bool
    no_raw_content: bool
    status: str


class AssistantContractsResponse(BaseModel):
    contracts: List[AssistantContractItem]


# ---------------------------------------------------------------------
# M6.7 — Assistant policy / settings response models
# ---------------------------------------------------------------------

_ASSISTANT_POLICY_GOVERNANCE_NOTE = (
    "Assistant policy settings are clinic-scoped. Core clinical safety "
    "prohibitions cannot be disabled."
)


class AssistantPolicySettings(BaseModel):
    """Effective Assistant policy for a clinic. Metadata-only — contains
    operational toggles and limits but never any raw content."""

    id: Optional[uuid.UUID] = None
    clinic_id: Optional[uuid.UUID] = None
    policy_version: int
    is_active: bool
    is_default: bool

    client_communication_enabled: bool
    generation_enabled: bool
    validation_profile: str

    daily_run_limit_per_clinic: int
    monthly_run_limit_per_clinic: int

    require_human_review: bool
    allow_receipts_after_review: bool

    policy_label: str
    policy_notes: Optional[str] = None

    created_by_user_id: Optional[uuid.UUID] = None
    created_at: Optional[datetime] = None
    activated_at: Optional[datetime] = None


class AssistantPolicyResponse(BaseModel):
    policy: AssistantPolicySettings
    governance_note: str = _ASSISTANT_POLICY_GOVERNANCE_NOTE


class AssistantPolicyUpdateRequest(BaseModel):
    """Bounded PATCH body. `extra='forbid'` rejects unknown / hard-doctrine
    fields at the parser layer; the route also explicitly rejects the
    forbidden field names with a clearer error code."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    client_communication_enabled: Optional[bool] = None
    generation_enabled: Optional[bool] = None
    validation_profile: Optional[str] = Field(default=None, max_length=64)
    daily_run_limit_per_clinic: Optional[int] = Field(default=None, ge=1, le=500)
    monthly_run_limit_per_clinic: Optional[int] = Field(default=None, ge=1, le=10000)
    policy_label: Optional[str] = Field(default=None, min_length=1, max_length=200)
    policy_notes: Optional[str] = Field(default=None, max_length=2000)


class AssistantPolicyHistoryItem(BaseModel):
    policy_version: int
    is_active: bool
    validation_profile: str
    client_communication_enabled: bool
    generation_enabled: bool
    daily_run_limit_per_clinic: int
    monthly_run_limit_per_clinic: int
    policy_label: str
    created_at: datetime
    activated_at: Optional[datetime] = None
    superseded_at: Optional[datetime] = None
    created_by_user_id: Optional[uuid.UUID] = None


class AssistantPolicyHistoryResponse(BaseModel):
    items: List[AssistantPolicyHistoryItem]


# ---------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------

router = APIRouter(
    prefix="/v1/assistant",
    tags=["Assistant"],
    dependencies=[Depends(require_clinic_user)],
)


@router.get("/contracts", response_model=AssistantContractsResponse)
def get_assistant_contracts() -> AssistantContractsResponse:
    return AssistantContractsResponse(
        contracts=[
            AssistantContractItem(
                mode=MODE_CLIENT_COMMUNICATION,
                contract_version=ASSISTANT_CONTRACT_VERSION,
                storage_policy="metadata_only_by_default",
                metadata_only=True,
                no_raw_content=True,
                status="active",
            ),
        ],
    )


# ---------------------------------------------------------------------
# M6.7 — Assistant policy endpoints
# ---------------------------------------------------------------------

# Roles permitted to update Assistant policy. Matches the clinic admin
# pattern used by portal_submit.override_submission (`role != "admin"`).
_POLICY_ADMIN_ROLES = {"admin", "owner", "practice_manager"}


def _policy_to_settings_model(policy: AssistantPolicy) -> AssistantPolicySettings:
    return AssistantPolicySettings(
        id=policy.id,
        clinic_id=policy.clinic_id,
        policy_version=policy.policy_version,
        is_active=policy.is_active,
        is_default=policy.is_default,
        client_communication_enabled=policy.client_communication_enabled,
        generation_enabled=policy.generation_enabled,
        validation_profile=policy.validation_profile,
        daily_run_limit_per_clinic=policy.daily_run_limit_per_clinic,
        monthly_run_limit_per_clinic=policy.monthly_run_limit_per_clinic,
        require_human_review=policy.require_human_review,
        allow_receipts_after_review=policy.allow_receipts_after_review,
        policy_label=policy.policy_label,
        policy_notes=policy.policy_notes,
        created_by_user_id=policy.created_by_user_id,
        created_at=policy.created_at,
        activated_at=policy.activated_at,
    )


def _row_to_history_item(row: Dict[str, Any]) -> AssistantPolicyHistoryItem:
    return AssistantPolicyHistoryItem(
        policy_version=int(row["policy_version"]),
        is_active=bool(row["is_active"]),
        validation_profile=str(row["validation_profile"]),
        client_communication_enabled=bool(row["client_communication_enabled"]),
        generation_enabled=bool(row["generation_enabled"]),
        daily_run_limit_per_clinic=int(row["daily_run_limit_per_clinic"]),
        monthly_run_limit_per_clinic=int(row["monthly_run_limit_per_clinic"]),
        policy_label=str(row["policy_label"]),
        created_at=row["created_at"],
        activated_at=row.get("activated_at"),
        superseded_at=row.get("superseded_at"),
        created_by_user_id=row.get("created_by_user_id"),
    )


@router.get("/policy", response_model=AssistantPolicyResponse)
def get_assistant_policy(
    request: Request,
    db: Session = Depends(get_db),
) -> AssistantPolicyResponse:
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    policy = get_effective_policy(db, clinic_id=str(clinic_id))
    return AssistantPolicyResponse(policy=_policy_to_settings_model(policy))


@router.patch("/policy", response_model=AssistantPolicyResponse)
def update_assistant_policy(
    payload: AssistantPolicyUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> AssistantPolicyResponse:
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    role = getattr(request.state, "role", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")
    if role not in _POLICY_ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="forbidden_not_admin")

    # Validate validation_profile early.
    if (
        payload.validation_profile is not None
        and payload.validation_profile not in ALLOWED_VALIDATION_PROFILES
    ):
        raise HTTPException(
            status_code=400, detail="invalid_validation_profile"
        )

    # Belt-and-braces: even though `extra='forbid'` blocks unknown keys,
    # we explicitly reject the hard-doctrine field names if they ever
    # become aliases. (No-op today; future-proof.)
    patch_dict = payload.model_dump(exclude_unset=True)
    forbidden = set(patch_dict.keys()) & FORBIDDEN_PATCH_FIELDS
    if forbidden:
        raise HTTPException(
            status_code=400, detail="assistant_policy_field_not_allowed"
        )

    # Cross-field validation: monthly limit must be >= daily limit.
    current = get_effective_policy(db, clinic_id=str(clinic_id))
    effective_daily = patch_dict.get(
        "daily_run_limit_per_clinic", current.daily_run_limit_per_clinic
    )
    effective_monthly = patch_dict.get(
        "monthly_run_limit_per_clinic", current.monthly_run_limit_per_clinic
    )
    if int(effective_monthly) < int(effective_daily):
        raise HTTPException(
            status_code=400, detail="monthly_limit_below_daily_limit"
        )

    # Build the full settings dict for the new version row by merging
    # the patch on top of the current effective policy.
    new_settings = {
        "client_communication_enabled": patch_dict.get(
            "client_communication_enabled", current.client_communication_enabled
        ),
        "generation_enabled": patch_dict.get(
            "generation_enabled", current.generation_enabled
        ),
        "validation_profile": patch_dict.get(
            "validation_profile", current.validation_profile
        ),
        "daily_run_limit_per_clinic": int(effective_daily),
        "monthly_run_limit_per_clinic": int(effective_monthly),
        "policy_label": patch_dict.get("policy_label", current.policy_label),
        "policy_notes": patch_dict.get("policy_notes", current.policy_notes),
    }

    # Compute the new version number — based on the highest version in
    # history, not just the active row, so deactivated rows aren't
    # silently overwritten.
    from app.assistant_policy import _max_policy_version  # local import to avoid cycle nag

    next_version = _max_policy_version(db, clinic_id=str(clinic_id)) + 1
    previous_version = current.policy_version

    # Deactivate any currently-active row before inserting the new one
    # (partial unique index would otherwise reject the new is_active=true).
    deactivate_active_policies(db, clinic_id=str(clinic_id))

    new_row = insert_new_policy_version(
        db,
        clinic_id=str(clinic_id),
        created_by_user_id=str(clinic_user_id),
        policy_version=next_version,
        settings=new_settings,
    )

    # Audit (metadata only).
    changed_fields = sorted(set(patch_dict.keys()))
    ip_hash = getattr(request.state, "ip_hash", None)
    insert_policy_audit_event(
        db,
        clinic_id=str(clinic_id),
        admin_user_id=str(clinic_user_id),
        previous_policy_version=int(previous_version),
        new_policy_version=int(next_version),
        changed_fields=changed_fields,
        ip_hash=ip_hash,
    )
    logger.info(
        "assistant_policy_updated",
        extra={
            "route": getattr(request.url, "path", None),
            "clinic_id": str(clinic_id),
            "clinic_user_id": str(clinic_user_id),
            "previous_policy_version": int(previous_version),
            "new_policy_version": int(next_version),
            "changed_fields": changed_fields,
        },
    )

    # Map the new row into the response model.
    from app.assistant_policy import _row_to_policy  # type: ignore

    new_policy = _row_to_policy(new_row)
    return AssistantPolicyResponse(policy=_policy_to_settings_model(new_policy))


@router.get("/policy/history", response_model=AssistantPolicyHistoryResponse)
def get_assistant_policy_history(
    request: Request,
    db: Session = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=200),
) -> AssistantPolicyHistoryResponse:
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    role = getattr(request.state, "role", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")
    if role not in _POLICY_ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="forbidden_not_admin")

    rows = get_policy_history_rows(db, clinic_id=str(clinic_id), limit=limit)
    items = [_row_to_history_item(r) for r in rows]
    return AssistantPolicyHistoryResponse(items=items)


# ---------------------------------------------------------------------
# M6.3 — Traceability endpoints
# ---------------------------------------------------------------------

_ALL_RUN_STATUSES = {
    RUN_STATUS_CREATED,
    RUN_STATUS_SUCCEEDED,
    RUN_STATUS_REFUSED,
    RUN_STATUS_FAILED,
}


def _row_to_trace_item(row: Dict[str, Any]) -> AssistantRunTraceItem:
    """Map a SELECT row (dict-like Mapping) into the metadata-only
    response model. psycopg returns jsonb as already-decoded Python
    objects, so the list fields can pass through unchanged."""
    return AssistantRunTraceItem(
        run_id=row["run_id"],
        clinic_id=row["clinic_id"],
        clinic_user_id=row["clinic_user_id"],
        mode=row["mode"],
        contract_version=row["contract_version"],
        workflow_origin=row["workflow_origin"],
        input_sha256=row["input_sha256"],
        output_sha256=row.get("output_sha256"),
        input_field_keys=list(row.get("input_field_keys") or []),
        pii_detected=bool(row.get("pii_detected") or False),
        pii_types=list(row.get("pii_types") or []),
        safety_flags=list(row.get("safety_flags") or []),
        refusal_reason_codes=list(row.get("refusal_reason_codes") or []),
        review_status=row["review_status"],
        run_status=row.get("run_status") or RUN_STATUS_CREATED,
        receipt_id=row.get("receipt_id"),
        governance_event_id=row.get("governance_event_id"),
        model_provider=row.get("model_provider"),
        model_name=row.get("model_name"),
        review_decision=row.get("review_decision"),
        reviewed_at=row.get("reviewed_at"),
        reviewed_by_user_id=row.get("reviewed_by_user_id"),
        has_receipt=row.get("receipt_id") is not None,
        receipt_created_at=row.get("receipt_created_at"),
        assistant_policy_id=row.get("assistant_policy_id"),
        assistant_policy_version=row.get("assistant_policy_version"),
        assistant_validation_profile=row.get("assistant_validation_profile"),
        created_at=row["created_at"],
        updated_at=row.get("updated_at"),
    )


_TRACE_SELECT_COLUMNS = """
    id AS run_id,
    clinic_id,
    clinic_user_id,
    mode,
    contract_version,
    workflow_origin,
    input_sha256,
    output_sha256,
    input_field_keys,
    pii_detected,
    pii_types,
    safety_flags,
    refusal_reason_codes,
    review_status,
    run_status,
    receipt_id,
    governance_event_id,
    model_provider,
    model_name,
    review_decision,
    reviewed_at,
    reviewed_by_user_id,
    assistant_policy_id,
    assistant_policy_version,
    assistant_validation_profile,
    created_at,
    updated_at
"""


@router.get("/runs", response_model=AssistantRunListResponse)
def list_assistant_runs(
    request: Request,
    db: Session = Depends(get_db),
    limit: int = Query(default=25, ge=1, le=100),
    run_status: Optional[str] = Query(default=None),
    mode: Optional[str] = Query(default=None),
) -> AssistantRunListResponse:
    """List recent Assistant run metadata for the authenticated clinic.

    Metadata-only — never includes raw input, prompts, or draft output."""
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    if run_status is not None and run_status not in _ALL_RUN_STATUSES:
        raise HTTPException(status_code=400, detail="invalid_run_status")

    if mode is not None and mode not in _KNOWN_MODES:
        raise HTTPException(status_code=400, detail="invalid_mode")

    filters: List[str] = []
    params: Dict[str, Any] = {"clinic_id": str(clinic_id), "limit": int(limit)}
    if run_status is not None:
        filters.append("run_status = :run_status")
        params["run_status"] = run_status
    if mode is not None:
        filters.append("mode = :mode")
        params["mode"] = mode

    where_extra = ""
    if filters:
        where_extra = " AND " + " AND ".join(filters)

    rows = (
        db.execute(
            text(
                f"""
                SELECT {_TRACE_SELECT_COLUMNS}
                FROM assistant_runs
                WHERE clinic_id = CAST(:clinic_id AS uuid)
                {where_extra}
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )

    items = [_row_to_trace_item(dict(r)) for r in rows]
    return AssistantRunListResponse(runs=items, limit=int(limit))


@router.get("/runs/{run_id}", response_model=AssistantRunDetailResponse)
def get_assistant_run_detail(
    run_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> AssistantRunDetailResponse:
    """Fetch one Assistant run metadata record by ID. RLS + explicit
    clinic_id predicate ensure cross-clinic isolation; a non-matching ID
    returns 404 with no information about whether the row exists for
    another clinic."""
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    row = (
        db.execute(
            text(
                f"""
                SELECT {_TRACE_SELECT_COLUMNS}
                FROM assistant_runs
                WHERE clinic_id = CAST(:clinic_id AS uuid)
                  AND id = CAST(:run_id AS uuid)
                LIMIT 1
                """
            ),
            {"clinic_id": str(clinic_id), "run_id": str(run_id)},
        )
        .mappings()
        .first()
    )

    if not row:
        raise HTTPException(status_code=404, detail="assistant_run_not_found")

    return AssistantRunDetailResponse(run=_row_to_trace_item(dict(row)))


# ---------------------------------------------------------------------
# M6.4 — Human review-state workflow
# ---------------------------------------------------------------------

REVIEW_STATUS_NOT_REVIEWED = "not_reviewed"
REVIEW_STATUS_APPROVED = "reviewed_approved"
REVIEW_STATUS_REJECTED = "reviewed_rejected"
REVIEW_STATUS_NEEDS_EDIT = "reviewed_needs_edit"

REVIEW_DECISION_APPROVED = "approved_for_use"
REVIEW_DECISION_REJECTED = "rejected_not_safe"
REVIEW_DECISION_NEEDS_EDIT = "needs_edit_before_use"

# Allowed PATCH values for review_status. 'not_reviewed' is intentionally
# excluded: this endpoint records review completion and is not a reset path.
_PATCH_REVIEW_STATUSES = {
    REVIEW_STATUS_APPROVED,
    REVIEW_STATUS_REJECTED,
    REVIEW_STATUS_NEEDS_EDIT,
}

_REVIEW_STATUS_TO_DECISION: Dict[str, str] = {
    REVIEW_STATUS_APPROVED: REVIEW_DECISION_APPROVED,
    REVIEW_STATUS_REJECTED: REVIEW_DECISION_REJECTED,
    REVIEW_STATUS_NEEDS_EDIT: REVIEW_DECISION_NEEDS_EDIT,
}


class AssistantRunReviewUpdate(BaseModel):
    """Request body for PATCH /v1/assistant/runs/{run_id}/review.

    `extra="forbid"` ensures the endpoint rejects any extra fields (notes,
    reviewer overrides, free text) at the parsing layer — review evidence
    is metadata-only by contract."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    review_status: str = Field(..., min_length=1, max_length=64)


@router.patch(
    "/runs/{run_id}/review",
    response_model=AssistantRunDetailResponse,
)
def update_assistant_run_review(
    run_id: uuid.UUID,
    payload: AssistantRunReviewUpdate,
    request: Request,
    db: Session = Depends(get_db),
) -> AssistantRunDetailResponse:
    """Record a metadata-only human review outcome for one Assistant run.

    Reviewer identity comes from the authenticated clinic_user context;
    it cannot be set by the client. The request carries only the review
    completion status; the decision token is derived server-side."""
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    review_status_in = payload.review_status

    # 'not_reviewed' is explicitly rejected: PATCH cannot be used to
    # reset review state. Unknown values also rejected at 400.
    if review_status_in == REVIEW_STATUS_NOT_REVIEWED:
        raise HTTPException(status_code=400, detail="invalid_review_status")
    if review_status_in not in _PATCH_REVIEW_STATUSES:
        raise HTTPException(status_code=400, detail="invalid_review_status")

    review_decision = _REVIEW_STATUS_TO_DECISION[review_status_in]

    row = (
        db.execute(
            text(
                f"""
                UPDATE assistant_runs
                SET review_status = :review_status,
                    review_decision = :review_decision,
                    reviewed_at = now(),
                    reviewed_by_user_id = CAST(:reviewed_by_user_id AS uuid),
                    updated_at = now()
                WHERE id = CAST(:run_id AS uuid)
                  AND clinic_id = CAST(:clinic_id AS uuid)
                RETURNING {_TRACE_SELECT_COLUMNS}
                """
            ),
            {
                "review_status": review_status_in,
                "review_decision": review_decision,
                "reviewed_by_user_id": str(clinic_user_id),
                "run_id": str(run_id),
                "clinic_id": str(clinic_id),
            },
        )
        .mappings()
        .first()
    )

    if not row:
        # Same generic detail as GET /runs/{run_id} — no cross-clinic leakage.
        raise HTTPException(status_code=404, detail="assistant_run_not_found")

    # Safe metadata-only log. No raw input, draft, or prompt is involved.
    logger.info(
        "assistant_run_review_updated",
        extra={
            "route": getattr(request.url, "path", None),
            "clinic_id": str(clinic_id),
            "clinic_user_id": str(clinic_user_id),
            "run_id": str(run_id),
            "review_status": review_status_in,
            "review_decision": review_decision,
        },
    )

    return AssistantRunDetailResponse(run=_row_to_trace_item(dict(row)))


# ---------------------------------------------------------------------
# M6.5 — Assistant receipt linkage (metadata only)
# ---------------------------------------------------------------------
#
# A receipt is a frozen snapshot of an Assistant run's governance metadata
# at the moment a human-reviewed run is sealed as evidence. It carries no
# raw input, no prompt, no draft. One receipt per (clinic_id, run) is
# enforced by the unique index in 20260524_01_assistant_run_receipts.sql.

_RECEIPT_KIND = "assistant_run_metadata"
_RECEIPT_VERSION = "assistant_receipt_v1"
_RECEIPT_GOVERNANCE_NOTE = (
    "This receipt is metadata-only evidence. "
    "Raw input, prompts, and draft output are not stored."
)

_RECEIPT_RETURNING_COLUMNS = """
    id AS receipt_id,
    assistant_run_id,
    clinic_id,
    created_by_user_id,
    receipt_kind,
    receipt_version,
    storage_policy,
    raw_content_stored,
    prompt_stored,
    draft_stored,
    run_status,
    review_status,
    review_decision,
    input_sha256,
    output_sha256,
    mode,
    contract_version,
    workflow_origin,
    pii_detected,
    pii_types,
    safety_flags,
    refusal_reason_codes,
    model_provider,
    model_name,
    assistant_policy_id,
    assistant_policy_version,
    assistant_validation_profile,
    assistant_run_created_at,
    assistant_run_reviewed_at,
    assistant_run_reviewed_by_user_id,
    receipt_created_at,
    created_at,
    updated_at
"""


class AssistantRunReceipt(BaseModel):
    """Metadata-only Assistant receipt. No raw content fields."""

    # See AssistantRunMetadata for the rationale on protected_namespaces.
    model_config = ConfigDict(protected_namespaces=())

    receipt_id: uuid.UUID
    assistant_run_id: uuid.UUID
    clinic_id: uuid.UUID
    created_by_user_id: uuid.UUID

    receipt_kind: str
    receipt_version: str

    storage_policy: str = "metadata_only_by_default"
    raw_content_stored: bool = False
    prompt_stored: bool = False
    draft_stored: bool = False

    run_status: str
    review_status: str
    review_decision: Optional[str] = None

    input_sha256: str
    output_sha256: Optional[str] = None

    mode: str
    contract_version: str
    workflow_origin: str

    pii_detected: bool
    pii_types: List[str] = Field(default_factory=list)
    safety_flags: List[str] = Field(default_factory=list)
    refusal_reason_codes: List[str] = Field(default_factory=list)

    model_provider: Optional[str] = None
    model_name: Optional[str] = None

    # M6.7.1 — policy context snapshot. Null on legacy receipts written
    # before policy stamping, and on runs governed by the default policy.
    assistant_policy_id: Optional[uuid.UUID] = None
    assistant_policy_version: Optional[int] = None
    assistant_validation_profile: Optional[str] = None

    assistant_run_created_at: datetime
    assistant_run_reviewed_at: Optional[datetime] = None
    assistant_run_reviewed_by_user_id: Optional[uuid.UUID] = None

    receipt_created_at: datetime
    created_at: datetime
    updated_at: Optional[datetime] = None


class AssistantRunReceiptResponse(BaseModel):
    receipt: AssistantRunReceipt
    run: AssistantRunTraceItem
    governance_note: str = _RECEIPT_GOVERNANCE_NOTE


def _row_to_receipt(row: Dict[str, Any]) -> AssistantRunReceipt:
    return AssistantRunReceipt(
        receipt_id=row["receipt_id"],
        assistant_run_id=row["assistant_run_id"],
        clinic_id=row["clinic_id"],
        created_by_user_id=row["created_by_user_id"],
        receipt_kind=row["receipt_kind"],
        receipt_version=row["receipt_version"],
        storage_policy=row.get("storage_policy") or "metadata_only_by_default",
        raw_content_stored=bool(row.get("raw_content_stored") or False),
        prompt_stored=bool(row.get("prompt_stored") or False),
        draft_stored=bool(row.get("draft_stored") or False),
        run_status=row["run_status"],
        review_status=row["review_status"],
        review_decision=row.get("review_decision"),
        input_sha256=row["input_sha256"],
        output_sha256=row.get("output_sha256"),
        mode=row["mode"],
        contract_version=row["contract_version"],
        workflow_origin=row["workflow_origin"],
        pii_detected=bool(row.get("pii_detected") or False),
        pii_types=list(row.get("pii_types") or []),
        safety_flags=list(row.get("safety_flags") or []),
        refusal_reason_codes=list(row.get("refusal_reason_codes") or []),
        model_provider=row.get("model_provider"),
        model_name=row.get("model_name"),
        assistant_policy_id=row.get("assistant_policy_id"),
        assistant_policy_version=row.get("assistant_policy_version"),
        assistant_validation_profile=row.get("assistant_validation_profile"),
        assistant_run_created_at=row["assistant_run_created_at"],
        assistant_run_reviewed_at=row.get("assistant_run_reviewed_at"),
        assistant_run_reviewed_by_user_id=row.get("assistant_run_reviewed_by_user_id"),
        receipt_created_at=row["receipt_created_at"],
        created_at=row["created_at"],
        updated_at=row.get("updated_at"),
    )


def _fetch_run_for_clinic(
    db: Session, *, clinic_id: str, run_id: uuid.UUID
) -> Optional[Dict[str, Any]]:
    row = (
        db.execute(
            text(
                f"""
                SELECT {_TRACE_SELECT_COLUMNS}
                FROM assistant_runs
                WHERE clinic_id = CAST(:clinic_id AS uuid)
                  AND id = CAST(:run_id AS uuid)
                LIMIT 1
                """
            ),
            {"clinic_id": clinic_id, "run_id": str(run_id)},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def _select_receipt_for_run(
    db: Session, *, clinic_id: str, run_id: uuid.UUID
) -> Optional[Dict[str, Any]]:
    row = (
        db.execute(
            text(
                f"""
                SELECT {_RECEIPT_RETURNING_COLUMNS}
                FROM assistant_run_receipts
                WHERE clinic_id = CAST(:clinic_id AS uuid)
                  AND assistant_run_id = CAST(:run_id AS uuid)
                LIMIT 1
                """
            ),
            {"clinic_id": clinic_id, "run_id": str(run_id)},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def _insert_receipt(
    db: Session,
    *,
    clinic_id: str,
    created_by_user_id: str,
    run: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Insert a metadata-only receipt for `run`. On unique-constraint
    conflict (a receipt already exists for this run), returns None and
    the caller falls back to `_select_receipt_for_run`."""
    row = (
        db.execute(
            text(
                f"""
                INSERT INTO assistant_run_receipts (
                    clinic_id,
                    assistant_run_id,
                    created_by_user_id,
                    receipt_kind,
                    receipt_version,
                    storage_policy,
                    raw_content_stored,
                    prompt_stored,
                    draft_stored,
                    run_status,
                    review_status,
                    review_decision,
                    input_sha256,
                    output_sha256,
                    mode,
                    contract_version,
                    workflow_origin,
                    pii_detected,
                    pii_types,
                    safety_flags,
                    refusal_reason_codes,
                    model_provider,
                    model_name,
                    assistant_policy_id,
                    assistant_policy_version,
                    assistant_validation_profile,
                    assistant_run_created_at,
                    assistant_run_reviewed_at,
                    assistant_run_reviewed_by_user_id
                )
                VALUES (
                    CAST(:clinic_id AS uuid),
                    CAST(:assistant_run_id AS uuid),
                    CAST(:created_by_user_id AS uuid),
                    :receipt_kind,
                    :receipt_version,
                    :storage_policy,
                    false, false, false,
                    :run_status,
                    :review_status,
                    :review_decision,
                    :input_sha256,
                    :output_sha256,
                    :mode,
                    :contract_version,
                    :workflow_origin,
                    :pii_detected,
                    CAST(:pii_types AS jsonb),
                    CAST(:safety_flags AS jsonb),
                    CAST(:refusal_reason_codes AS jsonb),
                    :model_provider,
                    :model_name,
                    CAST(NULLIF(:assistant_policy_id, '') AS uuid),
                    :assistant_policy_version,
                    :assistant_validation_profile,
                    :assistant_run_created_at,
                    :assistant_run_reviewed_at,
                    :assistant_run_reviewed_by_user_id
                )
                ON CONFLICT (clinic_id, assistant_run_id) DO NOTHING
                RETURNING {_RECEIPT_RETURNING_COLUMNS}
                """
            ),
            {
                "clinic_id": clinic_id,
                "assistant_run_id": str(run["run_id"]),
                "created_by_user_id": created_by_user_id,
                "receipt_kind": _RECEIPT_KIND,
                "receipt_version": _RECEIPT_VERSION,
                "storage_policy": "metadata_only_by_default",
                "run_status": run["run_status"],
                "review_status": run["review_status"],
                "review_decision": run.get("review_decision"),
                "input_sha256": run["input_sha256"],
                "output_sha256": run.get("output_sha256"),
                "mode": run["mode"],
                "contract_version": run["contract_version"],
                "workflow_origin": run["workflow_origin"],
                "pii_detected": bool(run.get("pii_detected") or False),
                # JSONB columns: serialise + cast (same pattern as the PR 2A
                # production fix in _insert_assistant_run_created).
                "pii_types": json.dumps(list(run.get("pii_types") or [])),
                "safety_flags": json.dumps(list(run.get("safety_flags") or [])),
                "refusal_reason_codes": json.dumps(
                    list(run.get("refusal_reason_codes") or [])
                ),
                "model_provider": run.get("model_provider"),
                "model_name": run.get("model_name"),
                # M6.7.1 — snapshot policy context onto the receipt. The
                # NULLIF/CAST pattern lets the empty-string sentinel for
                # "no policy id" round-trip to a SQL NULL.
                "assistant_policy_id": (
                    str(run["assistant_policy_id"])
                    if run.get("assistant_policy_id")
                    else ""
                ),
                "assistant_policy_version": run.get("assistant_policy_version"),
                "assistant_validation_profile": run.get(
                    "assistant_validation_profile"
                ),
                "assistant_run_created_at": run["created_at"],
                "assistant_run_reviewed_at": run.get("reviewed_at"),
                "assistant_run_reviewed_by_user_id": run.get("reviewed_by_user_id"),
            },
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def _link_receipt_on_run(
    db: Session,
    *,
    clinic_id: str,
    run_id: uuid.UUID,
    receipt_id: uuid.UUID,
) -> None:
    """Write the receipt id back onto assistant_runs.receipt_id. Safe to
    re-run because the unique index on receipts means the value must
    already match if it was previously set."""
    db.execute(
        text(
            """
            UPDATE assistant_runs
            SET receipt_id = CAST(:receipt_id AS uuid),
                updated_at = now()
            WHERE id = CAST(:run_id AS uuid)
              AND clinic_id = CAST(:clinic_id AS uuid)
            """
        ),
        {
            "receipt_id": str(receipt_id),
            "run_id": str(run_id),
            "clinic_id": clinic_id,
        },
    )


@router.post(
    "/runs/{run_id}/receipt",
    response_model=AssistantRunReceiptResponse,
)
def create_or_return_assistant_run_receipt(
    run_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> AssistantRunReceiptResponse:
    """Create (or return existing) metadata-only receipt for an Assistant
    run. Requires the run to be human-reviewed; refused and failed runs
    can still get receipts because refusal/failure is governance evidence
    in its own right."""
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    clinic_id_s = str(clinic_id)
    clinic_user_id_s = str(clinic_user_id)

    run = _fetch_run_for_clinic(db, clinic_id=clinic_id_s, run_id=run_id)
    if not run:
        raise HTTPException(status_code=404, detail="assistant_run_not_found")

    if run.get("review_status") in (None, "", REVIEW_STATUS_NOT_REVIEWED):
        raise HTTPException(status_code=400, detail="assistant_run_not_reviewed")

    receipt_row = _insert_receipt(
        db,
        clinic_id=clinic_id_s,
        created_by_user_id=clinic_user_id_s,
        run=run,
    )
    log_event = "assistant_run_receipt_created"
    if receipt_row is None:
        # Unique conflict — receipt already exists for this run.
        receipt_row = _select_receipt_for_run(
            db, clinic_id=clinic_id_s, run_id=run_id
        )
        log_event = "assistant_run_receipt_returned"

    if receipt_row is None:
        # Should not happen (conflict implies a row exists), but treat as
        # a safe 500 rather than crashing.
        raise HTTPException(status_code=500, detail="assistant_run_receipt_unavailable")

    receipt = _row_to_receipt(receipt_row)

    # Link the receipt id back onto the run (idempotent — the unique
    # constraint on receipts means this can only ever resolve to one id).
    _link_receipt_on_run(
        db,
        clinic_id=clinic_id_s,
        run_id=run_id,
        receipt_id=receipt.receipt_id,
    )

    # Reflect the link in the run dict before mapping to the response.
    run["receipt_id"] = receipt.receipt_id
    run["receipt_created_at"] = receipt.receipt_created_at

    logger.info(
        log_event,
        extra={
            "route": getattr(request.url, "path", None),
            "clinic_id": clinic_id_s,
            "clinic_user_id": clinic_user_id_s,
            "run_id": str(run_id),
            "receipt_id": str(receipt.receipt_id),
            "review_status": run.get("review_status"),
            "run_status": run.get("run_status"),
        },
    )

    return AssistantRunReceiptResponse(
        receipt=receipt,
        run=_row_to_trace_item(run),
    )


@router.get(
    "/runs/{run_id}/receipt",
    response_model=AssistantRunReceiptResponse,
)
def get_assistant_run_receipt(
    run_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> AssistantRunReceiptResponse:
    """Return the metadata-only receipt for an Assistant run, or 404 if
    none has been created yet. A non-matching `clinic_id + run_id` returns
    404 for both the run and the receipt — no cross-clinic leakage."""
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    clinic_id_s = str(clinic_id)

    run = _fetch_run_for_clinic(db, clinic_id=clinic_id_s, run_id=run_id)
    if not run:
        raise HTTPException(status_code=404, detail="assistant_run_not_found")

    receipt_row = _select_receipt_for_run(
        db, clinic_id=clinic_id_s, run_id=run_id
    )
    if not receipt_row:
        raise HTTPException(status_code=404, detail="assistant_run_receipt_not_found")

    receipt = _row_to_receipt(receipt_row)
    run["receipt_id"] = receipt.receipt_id
    run["receipt_created_at"] = receipt.receipt_created_at

    return AssistantRunReceiptResponse(
        receipt=receipt,
        run=_row_to_trace_item(run),
    )


def _validate_client_communication(input_obj: Dict[str, Any]) -> ClientCommunicationInput:
    if not isinstance(input_obj, dict):
        raise HTTPException(status_code=422, detail="input_must_be_object")
    try:
        return ClientCommunicationInput(**input_obj)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=422, detail="invalid_input_for_client_communication"
        )


# ---------------------------------------------------------------------
# Indirection points for tests (monkeypatch these, never the real client)
# ---------------------------------------------------------------------

def _perform_generation(*, system_prompt: str, user_message: str) -> Tuple[str, str, str]:
    """Default model dispatch. Returns (draft_text, provider, model_name).

    Tests replace this with a deterministic stub so that no real network
    call is ever made under pytest."""
    return generate_client_communication_draft(
        system_prompt=system_prompt, user_message=user_message
    )


# ---------------------------------------------------------------------
# DB helpers — INSERT (created) + UPDATE (finalise)
# ---------------------------------------------------------------------

def _insert_assistant_run_created(
    db: Session,
    *,
    run_id: uuid.UUID,
    clinic_id: str,
    clinic_user_id: str,
    input_sha256: str,
    input_field_keys: List[str],
    pii_detected: bool,
    pii_types: List[str],
    # M6.7 — forward-link to the active policy that governed this run.
    # All three may be None when no policy row exists yet (default policy).
    assistant_policy_id: Optional[str] = None,
    assistant_policy_version: Optional[int] = None,
    assistant_validation_profile: Optional[str] = None,
) -> Dict[str, Any]:
    row = (
        db.execute(
            text(
                """
                INSERT INTO assistant_runs (
                  id,
                  clinic_id, clinic_user_id,
                  mode, contract_version, workflow_origin,
                  input_sha256, output_sha256,
                  input_field_keys,
                  pii_detected, pii_types,
                  safety_flags, refusal_reason_codes,
                  review_status,
                  receipt_id, governance_event_id,
                  model_provider, model_name,
                  run_status,
                  assistant_policy_id,
                  assistant_policy_version,
                  assistant_validation_profile
                )
                VALUES (
                  CAST(:run_id AS uuid),
                  CAST(:clinic_id AS uuid),
                  CAST(:clinic_user_id AS uuid),
                  :mode, :contract_version, :workflow_origin,
                  :input_sha256, NULL,
                  CAST(:input_field_keys AS jsonb),
                  :pii_detected,
                  CAST(:pii_types AS jsonb),
                  CAST(:safety_flags AS jsonb),
                  CAST(:refusal_reason_codes AS jsonb),
                  :review_status,
                  NULL, NULL,
                  NULL, NULL,
                  :run_status,
                  CAST(NULLIF(:assistant_policy_id, '') AS uuid),
                  :assistant_policy_version,
                  :assistant_validation_profile
                )
                RETURNING
                  id AS run_id, mode, contract_version,
                  pii_detected, pii_types, input_field_keys,
                  review_status, output_sha256,
                  model_provider, model_name,
                  run_status
                """
            ),
            {
                "run_id": str(run_id),
                "clinic_id": clinic_id,
                "clinic_user_id": clinic_user_id,
                "mode": MODE_CLIENT_COMMUNICATION,
                "contract_version": ASSISTANT_CONTRACT_VERSION,
                "workflow_origin": WORKFLOW_ORIGIN,
                "input_sha256": input_sha256,
                # JSONB columns require JSON-serialised strings + jsonb cast.
                "input_field_keys": json.dumps(input_field_keys),
                "pii_detected": pii_detected,
                "pii_types": json.dumps(pii_types),
                "safety_flags": json.dumps([]),
                "refusal_reason_codes": json.dumps([]),
                "review_status": "not_reviewed",
                "run_status": RUN_STATUS_CREATED,
                "assistant_policy_id": (
                    str(assistant_policy_id) if assistant_policy_id else ""
                ),
                "assistant_policy_version": assistant_policy_version,
                "assistant_validation_profile": assistant_validation_profile,
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=500, detail="assistant_run_insert_failed")
    return dict(row)


def _update_assistant_run_refused(
    db: Session,
    *,
    run_id: uuid.UUID,
    clinic_id: str,
    refusal_codes: List[str],
) -> None:
    db.execute(
        text(
            """
            UPDATE assistant_runs
            SET run_status = :run_status,
                output_sha256 = NULL,
                safety_flags = CAST(:safety_flags AS jsonb),
                refusal_reason_codes = CAST(:refusal_reason_codes AS jsonb),
                model_provider = NULL,
                model_name = NULL,
                updated_at = now()
            WHERE id = CAST(:run_id AS uuid)
              AND clinic_id = CAST(:clinic_id AS uuid)
            """
        ),
        {
            "run_id": str(run_id),
            "clinic_id": clinic_id,
            "run_status": RUN_STATUS_REFUSED,
            "safety_flags": json.dumps(refusal_codes),
            "refusal_reason_codes": json.dumps(refusal_codes),
        },
    )


def _update_assistant_run_succeeded(
    db: Session,
    *,
    run_id: uuid.UUID,
    clinic_id: str,
    output_sha256: str,
    model_provider: str,
    model_name: str,
) -> None:
    db.execute(
        text(
            """
            UPDATE assistant_runs
            SET run_status = :run_status,
                output_sha256 = :output_sha256,
                model_provider = :model_provider,
                model_name = :model_name,
                safety_flags = CAST(:safety_flags AS jsonb),
                refusal_reason_codes = CAST(:refusal_reason_codes AS jsonb),
                updated_at = now()
            WHERE id = CAST(:run_id AS uuid)
              AND clinic_id = CAST(:clinic_id AS uuid)
            """
        ),
        {
            "run_id": str(run_id),
            "clinic_id": clinic_id,
            "run_status": RUN_STATUS_SUCCEEDED,
            "output_sha256": output_sha256,
            "model_provider": model_provider,
            "model_name": model_name,
            "safety_flags": json.dumps([]),
            "refusal_reason_codes": json.dumps([]),
        },
    )


def _update_assistant_run_failed(
    db: Session,
    *,
    run_id: uuid.UUID,
    clinic_id: str,
) -> None:
    db.execute(
        text(
            """
            UPDATE assistant_runs
            SET run_status = :run_status,
                updated_at = now()
            WHERE id = CAST(:run_id AS uuid)
              AND clinic_id = CAST(:clinic_id AS uuid)
            """
        ),
        {
            "run_id": str(run_id),
            "clinic_id": clinic_id,
            "run_status": RUN_STATUS_FAILED,
        },
    )


def _update_assistant_run_output_blocked(
    db: Session,
    *,
    run_id: uuid.UUID,
    clinic_id: str,
    output_sha256: str,
    model_provider: str,
    model_name: str,
    safety_flags: List[str],
    refusal_reason_codes: List[str],
) -> None:
    """M6.6 — model produced a draft but ANCHOR blocked it. The hash IS
    persisted because a generated output existed (governance evidence)
    but the raw draft is never stored. Model provider/name are kept
    populated because the model was invoked."""
    db.execute(
        text(
            """
            UPDATE assistant_runs
            SET run_status = :run_status,
                output_sha256 = :output_sha256,
                model_provider = :model_provider,
                model_name = :model_name,
                safety_flags = CAST(:safety_flags AS jsonb),
                refusal_reason_codes = CAST(:refusal_reason_codes AS jsonb),
                updated_at = now()
            WHERE id = CAST(:run_id AS uuid)
              AND clinic_id = CAST(:clinic_id AS uuid)
            """
        ),
        {
            "run_id": str(run_id),
            "clinic_id": clinic_id,
            "run_status": RUN_STATUS_OUTPUT_BLOCKED,
            "output_sha256": output_sha256,
            "model_provider": model_provider,
            "model_name": model_name,
            "safety_flags": json.dumps(safety_flags),
            "refusal_reason_codes": json.dumps(refusal_reason_codes),
        },
    )


# ---------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------


def _policy_response_kwargs(policy: AssistantPolicy) -> Dict[str, Any]:
    """M6.7.1 — common kwargs that stamp policy context onto every
    AssistantRunMetadata response. Default policy → null id/version,
    `standard` profile."""
    return {
        "assistant_policy_id": policy.id if not policy.is_default else None,
        "assistant_policy_version": (
            int(policy.policy_version) if not policy.is_default else None
        ),
        "assistant_validation_profile": policy.validation_profile,
    }


@router.post(
    "/runs",
    response_model=AssistantRunCreateResponse,
    status_code=201,
)
def create_assistant_run(
    payload: AssistantRunCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> AssistantRunCreateResponse:
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    mode = (payload.mode or "").strip()
    if mode not in _KNOWN_MODES:
        raise HTTPException(status_code=400, detail="unsupported_mode")
    if mode not in _ACTIVE_MODES:
        raise HTTPException(status_code=400, detail="mode_inactive")
    if mode != MODE_CLIENT_COMMUNICATION:
        raise HTTPException(status_code=400, detail="unsupported_mode")

    clinic_id_s = str(clinic_id)
    clinic_user_id_s = str(clinic_user_id)

    # M6.7: load active Assistant policy (or safe default). The policy
    # governs mode availability, generation toggle, usage limits, and
    # validation profile for THIS run.
    policy = get_effective_policy(db, clinic_id=clinic_id_s)

    # Policy may disable a mode for this clinic. Reject BEFORE any
    # insert / model call.
    if mode == MODE_CLIENT_COMMUNICATION and not policy.client_communication_enabled:
        logger.info(
            "assistant_mode_disabled_by_policy",
            extra={
                "route": getattr(request.url, "path", None),
                "clinic_id": clinic_id_s,
                "mode": mode,
                "policy_version": policy.policy_version,
            },
        )
        raise HTTPException(
            status_code=403, detail="assistant_mode_disabled_by_policy"
        )

    # PR 2D: cost-control guardrail.
    # Check usage limits BEFORE any input hashing, assistant_runs insert,
    # safety gate, or model call. An over-limit clinic must not be able to
    # silently create uncontrolled records or Anthropic spend.
    # M6.7 — pass the policy's per-clinic caps (env defaults flow through
    # when no policy row exists).
    try:
        enforce_assistant_run_limits(
            db,
            clinic_id=clinic_id_s,
            daily_limit_override=policy.daily_run_limit_per_clinic,
            monthly_limit_override=policy.monthly_run_limit_per_clinic,
        )
    except AssistantUsageLimitExceeded as exc:
        code = (
            "assistant_daily_run_limit_exceeded"
            if exc.window == "day"
            else "assistant_monthly_run_limit_exceeded"
        )
        # Safe metadata-only log. No input, prompt, or draft is involved
        # because none of those have been computed yet.
        logger.warning(
            "assistant_run_limit_exceeded",
            extra={
                "route": getattr(request.url, "path", None),
                "clinic_id": clinic_id_s,
                "window": exc.window,
                "limit": exc.limit,
                "current_count": exc.current_count,
            },
        )
        return JSONResponse(
            status_code=429,
            content={
                "detail": code,
                "limit": exc.limit,
                "window": exc.window,
            },
        )

    validated = _validate_client_communication(payload.input)
    validated_dict: Dict[str, Any] = validated.model_dump()

    # Step 2: PR 2A metadata.
    serialised_input = canonical_json(validated_dict)
    input_sha256 = sha256_hex(serialised_input)
    input_field_keys = extract_input_field_keys(validated_dict)
    pii_types = detect_pii_types(serialised_input)
    pii_detected = len(pii_types) > 0

    run_id = uuid.uuid4()

    # Step 3: INSERT before any model call. Stamp the active policy
    # version + validation profile on the run for traceability.
    row = _insert_assistant_run_created(
        db,
        run_id=run_id,
        clinic_id=clinic_id_s,
        clinic_user_id=clinic_user_id_s,
        input_sha256=input_sha256,
        input_field_keys=input_field_keys,
        pii_detected=pii_detected,
        pii_types=pii_types,
        assistant_policy_id=(str(policy.id) if policy.id else None),
        assistant_policy_version=(
            int(policy.policy_version) if not policy.is_default else None
        ),
        assistant_validation_profile=policy.validation_profile,
    )

    # M6.7 — policy may disable generation. If so, we DO NOT call the
    # model; we record a refused-by-policy outcome. The metadata-only
    # record + refusal code make this auditable governance evidence.
    if not policy.generation_enabled:
        policy_refusal_codes = ["generation_disabled_by_policy"]
        _update_assistant_run_refused(
            db,
            run_id=run_id,
            clinic_id=clinic_id_s,
            refusal_codes=policy_refusal_codes,
        )
        return AssistantRunCreateResponse(
            run=AssistantRunMetadata(
                run_id=run_id,
                mode=MODE_CLIENT_COMMUNICATION,
                contract_version=ASSISTANT_CONTRACT_VERSION,
                run_status=RUN_STATUS_REFUSED,
                draft=FIXED_REFUSAL_MESSAGE,
                refused=True,
                refusal_reason_codes=policy_refusal_codes,
                safety_flags=policy_refusal_codes,
                pii_detected=pii_detected,
                pii_types=list(pii_types),
                input_field_keys=list(input_field_keys),
                review_status="not_reviewed",
                output_sha256=None,
                model_provider=None,
                model_name=None,
                generation_enabled=False,
                governance_note=GOVERNANCE_NOTE,
                **_policy_response_kwargs(policy),
            )
        )

    # Step 4: input-side safety gate.
    refusal_codes = evaluate_input_safety(validated_dict)

    if refusal_codes:
        # Step 5a: refuse without calling model. Refusal text is a
        # governance constant — returned transiently, never persisted.
        _update_assistant_run_refused(
            db,
            run_id=run_id,
            clinic_id=clinic_id_s,
            refusal_codes=refusal_codes,
        )
        return AssistantRunCreateResponse(
            run=AssistantRunMetadata(
                run_id=run_id,
                mode=MODE_CLIENT_COMMUNICATION,
                contract_version=ASSISTANT_CONTRACT_VERSION,
                run_status=RUN_STATUS_REFUSED,
                draft=FIXED_REFUSAL_MESSAGE,
                refused=True,
                refusal_reason_codes=list(refusal_codes),
                safety_flags=list(refusal_codes),
                pii_detected=pii_detected,
                pii_types=list(pii_types),
                input_field_keys=list(input_field_keys),
                review_status="not_reviewed",
                output_sha256=None,
                model_provider=None,
                model_name=None,
                generation_enabled=False,
                governance_note=GOVERNANCE_NOTE,
                **_policy_response_kwargs(policy),
            )
        )

    # Step 5b: safe path — build transient prompt + user message, call model.
    system_prompt = CLIENT_COMMUNICATION_SYSTEM_PROMPT
    user_message = build_client_communication_user_message(validated)

    try:
        draft, provider, model_name = _perform_generation(
            system_prompt=system_prompt,
            user_message=user_message,
        )
    except AssistantModelConfigError:
        _update_assistant_run_failed(db, run_id=run_id, clinic_id=clinic_id_s)
        logger.warning(
            "assistant_generation_unavailable",
            extra={
                "route": getattr(request.url, "path", None),
                "clinic_id": clinic_id_s,
                "run_id": str(run_id),
                "reason": "model_unavailable",
            },
        )
        raise HTTPException(
            status_code=503,
            detail="assistant_generation_unavailable",
        )
    except AssistantModelCallError:
        _update_assistant_run_failed(db, run_id=run_id, clinic_id=clinic_id_s)
        logger.warning(
            "assistant_generation_failed",
            extra={
                "route": getattr(request.url, "path", None),
                "clinic_id": clinic_id_s,
                "run_id": str(run_id),
            },
        )
        raise HTTPException(
            status_code=503,
            detail="assistant_generation_unavailable",
        )
    except HTTPException:
        raise
    except Exception:
        _update_assistant_run_failed(db, run_id=run_id, clinic_id=clinic_id_s)
        logger.warning(
            "assistant_generation_unexpected_error",
            extra={
                "route": getattr(request.url, "path", None),
                "clinic_id": clinic_id_s,
                "run_id": str(run_id),
            },
        )
        raise HTTPException(
            status_code=503,
            detail="assistant_generation_unavailable",
        )

    # Step 5b — model returned a draft. Hash it now so the same hash is
    # recorded whether validation allows or blocks the draft (governance
    # evidence that a generated output existed).
    output_sha256 = sha256_hex(draft)

    # Step 5c (M6.6) — post-output safety validation. The validator
    # operates on the transient draft string and returns only codes; the
    # raw draft is never returned, logged, or persisted from this point.
    # M6.7 — validation profile comes from the active policy.
    safety_result = validate_client_communication_output(
        draft, profile=policy.validation_profile
    )

    if not safety_result.allowed:
        _update_assistant_run_output_blocked(
            db,
            run_id=run_id,
            clinic_id=clinic_id_s,
            output_sha256=output_sha256,
            model_provider=provider,
            model_name=model_name,
            safety_flags=list(safety_result.safety_flags),
            refusal_reason_codes=list(safety_result.refusal_reason_codes),
        )
        logger.warning(
            "assistant_output_blocked",
            extra={
                "route": getattr(request.url, "path", None),
                "clinic_id": clinic_id_s,
                "clinic_user_id": clinic_user_id_s,
                "run_id": str(run_id),
                "safety_flags": list(safety_result.safety_flags),
                "refusal_reason_codes": list(safety_result.refusal_reason_codes),
                "model_provider": provider,
                "model_name": model_name,
            },
        )
        return AssistantRunCreateResponse(
            run=AssistantRunMetadata(
                run_id=run_id,
                mode=MODE_CLIENT_COMMUNICATION,
                contract_version=ASSISTANT_CONTRACT_VERSION,
                run_status=RUN_STATUS_OUTPUT_BLOCKED,
                # NEVER return the raw blocked draft.
                draft=None,
                refused=True,
                blocked=True,
                blocked_message=OUTPUT_BLOCKED_MESSAGE,
                refusal_reason_codes=list(safety_result.refusal_reason_codes),
                safety_flags=list(safety_result.safety_flags),
                pii_detected=pii_detected,
                pii_types=list(pii_types),
                input_field_keys=list(input_field_keys),
                review_status="not_reviewed",
                output_sha256=output_sha256,
                model_provider=provider,
                model_name=model_name,
                generation_enabled=True,
                governance_note=GOVERNANCE_NOTE,
                **_policy_response_kwargs(policy),
            )
        )

    # Step 5b success: hash recorded above; persist + return the draft.
    _update_assistant_run_succeeded(
        db,
        run_id=run_id,
        clinic_id=clinic_id_s,
        output_sha256=output_sha256,
        model_provider=provider,
        model_name=model_name,
    )

    return AssistantRunCreateResponse(
        run=AssistantRunMetadata(
            run_id=run_id,
            mode=MODE_CLIENT_COMMUNICATION,
            contract_version=ASSISTANT_CONTRACT_VERSION,
            run_status=RUN_STATUS_SUCCEEDED,
            draft=draft,
            refused=False,
            blocked=False,
            refusal_reason_codes=[],
            safety_flags=[],
            pii_detected=pii_detected,
            pii_types=list(pii_types),
            input_field_keys=list(input_field_keys),
            review_status="not_reviewed",
            output_sha256=output_sha256,
            model_provider=provider,
            model_name=model_name,
            generation_enabled=True,
            governance_note=GOVERNANCE_NOTE,
            **_policy_response_kwargs(policy),
        )
    )
