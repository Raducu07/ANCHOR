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
    run_id: uuid.UUID
    mode: str
    contract_version: str
    run_status: str
    draft: Optional[str] = None
    refused: bool = False
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
                  run_status
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
                  :run_status
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


# ---------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------

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

    # PR 2D: cost-control guardrail.
    # Check usage limits BEFORE any input hashing, assistant_runs insert,
    # safety gate, or model call. An over-limit clinic must not be able to
    # silently create uncontrolled records or Anthropic spend.
    try:
        enforce_assistant_run_limits(db, clinic_id=clinic_id_s)
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

    # Step 3: INSERT before any model call.
    row = _insert_assistant_run_created(
        db,
        run_id=run_id,
        clinic_id=clinic_id_s,
        clinic_user_id=clinic_user_id_s,
        input_sha256=input_sha256,
        input_field_keys=input_field_keys,
        pii_detected=pii_detected,
        pii_types=pii_types,
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

    # Step 5b success: hash and record.
    output_sha256 = sha256_hex(draft)
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
        )
    )
