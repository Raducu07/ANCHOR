# app/portal_assistant.py
#
# Backend PR 2A â€” Assistant metadata-only run creation.
#
# Hard doctrine (this PR):
#   * No model/LLM call of any kind.
#   * No raw input, raw output, prompt, draft, transcript, field values,
#     or clinical content is persisted or returned.
#   * Only metadata: hashes, field-key set, PII type flags, safety scaffolding.
#
# Safe path:
#   clinic auth -> RLS context (via get_db) -> mode validation ->
#   structured input validation -> deterministic input hashing ->
#   field-key extraction only -> PII metadata detection ->
#   assistant_runs metadata insert -> metadata-only response.

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Contract constants
# ---------------------------------------------------------------------

ASSISTANT_CONTRACT_VERSION = "assistant_contract_v1"
WORKFLOW_ORIGIN = "anchor_assistant"

MODE_CLIENT_COMMUNICATION = "client_communication"

# Modes the backend recognises in PR 2A.
_KNOWN_MODES = {MODE_CLIENT_COMMUNICATION}
# Modes that are active (callable) in PR 2A.
_ACTIVE_MODES = {MODE_CLIENT_COMMUNICATION}

_GOVERNANCE_NOTE = (
    "Generation is not enabled in this PR. "
    "This record only confirms metadata-safe assistant run creation."
)


# ---------------------------------------------------------------------
# PII detection (regex only, metadata-only)
# ---------------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"\b\+?\d[\d\s().-]{7,}\d\b")
_UK_POSTCODE_RE = re.compile(
    r"\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b", re.IGNORECASE
)
_NUMERIC_ID_RE = re.compile(r"\b\d{6,}\b")


def detect_pii_types(serialised_input: str) -> List[str]:
    """Return ordered, de-duplicated list of PII type tags found in the
    deterministically-serialised input. PR 2A is detection-only; we do
    NOT block on PII here."""
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
# Hashing / key-only helpers
# ---------------------------------------------------------------------

def canonical_json(obj: Any) -> str:
    """Deterministic JSON serialisation for hashing. Sorted keys, stable
    separators. The output is hashed and discarded â€” never stored."""
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
    """Return sorted list of top-level keys with non-null / non-empty
    values. Keys only â€” values are never returned or stored."""
    if not isinstance(input_obj, dict):
        return []
    return sorted([k for k, v in input_obj.items() if _is_meaningful(v)])


# ---------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------

class ClientCommunicationInput(BaseModel):
    """PR 2A only supports client_communication mode. Required fields
    must be present and non-empty. Additional keys are tolerated but
    only their key names ever leave this process."""

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    communication_goal: str = Field(..., min_length=1, max_length=2000)
    clinician_confirmed_facts: str = Field(..., min_length=1, max_length=8000)


class AssistantRunCreate(BaseModel):
    mode: str = Field(..., min_length=1, max_length=64)
    input: Dict[str, Any] = Field(..., description="Mode-specific structured input")


class AssistantRunMetadata(BaseModel):
    run_id: uuid.UUID
    mode: str
    contract_version: str
    pii_detected: bool
    pii_types: List[str]
    input_field_keys: List[str]
    review_status: str
    output_sha256: Optional[str] = None
    model_provider: Optional[str] = None
    model_name: Optional[str] = None
    generation_enabled: bool = False
    governance_note: str


class AssistantRunCreateResponse(BaseModel):
    run: AssistantRunMetadata


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
    """Public-to-clinic Assistant contract surface.

    PR 2A advertises only client_communication as active. Storage policy
    is metadata-only and is the same for every Assistant mode by design."""
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
        # Reserved for future modes that exist but are not callable yet.
        raise HTTPException(status_code=400, detail="mode_inactive")

    # PR 2A allows client_communication only.
    if mode != MODE_CLIENT_COMMUNICATION:
        raise HTTPException(status_code=400, detail="unsupported_mode")

    validated = _validate_client_communication(payload.input)
    validated_dict: Dict[str, Any] = validated.model_dump()

    # Hash + field-key extraction. The serialised string is used only
    # to compute the hash + run regex PII detection, then discarded.
    serialised_input = canonical_json(validated_dict)
    input_sha256 = sha256_hex(serialised_input)
    input_field_keys = extract_input_field_keys(validated_dict)
    pii_types = detect_pii_types(serialised_input)
    pii_detected = len(pii_types) > 0

    run_id = uuid.uuid4()

    try:
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
                      model_provider, model_name
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
                      NULL, NULL
                    )
                    RETURNING
                      id AS run_id, mode, contract_version,
                      pii_detected, pii_types, input_field_keys,
                      review_status, output_sha256,
                      model_provider, model_name
                    """
                ),
                {
                    "run_id": str(run_id),
                    "clinic_id": str(clinic_id),
                    "clinic_user_id": str(clinic_user_id),
                    "mode": MODE_CLIENT_COMMUNICATION,
                    "contract_version": ASSISTANT_CONTRACT_VERSION,
                    "workflow_origin": WORKFLOW_ORIGIN,
                    "input_sha256": input_sha256,
                    # JSONB columns require JSON-serialised strings + an
                    # explicit CAST(... AS jsonb) in the VALUES clause.
                    # Passing a Python list directly fails under
                    # psycopg/SQLAlchemy (sqlalche.me/e/20/f405).
                    "input_field_keys": json.dumps(input_field_keys),
                    "pii_detected": pii_detected,
                    "pii_types": json.dumps(pii_types),
                    "safety_flags": json.dumps([]),
                    "refusal_reason_codes": json.dumps([]),
                    "review_status": "not_reviewed",
                },
            )
            .mappings()
            .first()
        )

        if not row:
            raise HTTPException(status_code=500, detail="assistant_run_insert_failed")

        return AssistantRunCreateResponse(
            run=AssistantRunMetadata(
                run_id=uuid.UUID(str(row["run_id"])),
                mode=row["mode"],
                contract_version=row["contract_version"],
                pii_detected=bool(row["pii_detected"]),
                pii_types=list(row.get("pii_types") or []),
                input_field_keys=list(row.get("input_field_keys") or []),
                review_status=row["review_status"],
                output_sha256=row.get("output_sha256"),
                model_provider=row.get("model_provider"),
                model_name=row.get("model_name"),
                generation_enabled=False,
                governance_note=_GOVERNANCE_NOTE,
            )
        )

    except HTTPException:
        raise
    except Exception:
        logger.exception(
            "assistant_run_create_failed",
            extra={
                "route": getattr(request.url, "path", None),
                "clinic_id": str(clinic_id),
                "clinic_user_id": str(clinic_user_id),
                "mode": mode,
            },
        )
        raise HTTPException(status_code=500, detail="internal_server_error")

