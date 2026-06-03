# app/incident_near_miss.py
#
# Phase 2A-5.2 - Basic Incident / Near-Miss Logging endpoints.
#
# Scope of THIS slice:
#   * GET /vocabulary
#   * POST /records
#   * GET /records             (admin tier)
#   * GET /records/mine        (self)
#   * GET /records/{incident_id}  (admin OR creator)
#
# Out of scope (deferred to 2A-5.3+):
#   * PATCH, review, close, void, summary endpoints.
#   * Trust posture / Trust Pack integration.
#
# Doctrine:
#   * Structured AI-use review-signal records. NOT clinical records,
#     NOT legal claims, NOT insurance submissions, NOT regulator
#     reports. Human professional review remains required.
#   * No free-text columns and no free-text request fields. All
#     "what happened" granularity flows through CHECK-enforced enum
#     values (matched here as Python frozensets).
#   * Linked governance metadata is ID-only. Each non-null link is
#     validated clinic-scoped before insert; the link target's body
#     is never duplicated here.
#   * Append-only audit via the existing `admin_audit_events`
#     pattern. No `ON CONFLICT` against the partial idempotency
#     index (M6.10.1B / TD-BE postmortem).
#   * No staff names / emails returned. Only `*_by_user_id` UUIDs.

from __future__ import annotations

import json
import logging
import uuid as _uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db


logger = logging.getLogger(__name__)


_INCIDENT_ADMIN_ROLES: Set[str] = {"admin", "owner", "practice_manager"}


# ---------------------------------------------------------------------
# Controlled vocabulary - MUST match the CHECK constraints in
# migrations/20260603_03_incident_near_miss_schema.sql exactly. The
# `test_vocabulary_matches_migration_check_constraints` test in
# tests/test_incident_near_miss_endpoints.py asserts this drift-free.
# ---------------------------------------------------------------------

STATUS_VALUES: List[str] = [
    "open", "in_review", "actioned", "closed", "voided",
]
SEVERITY_VALUES: List[str] = ["low", "moderate", "high", "critical"]
CATEGORY_VALUES: List[str] = [
    "misleading_output",
    "inaccurate_output",
    "unsafe_suggestion",
    "privacy_or_identifier_risk",
    "overconfident_output",
    "missing_human_review",
    "policy_boundary_issue",
    "inappropriate_client_communication",
    "workflow_confusion",
    "other",
]
SOURCE_VALUES: List[str] = [
    "assistant_workspace",
    "external_ai_tool",
    "ambient_or_scribe",
    "client_communication",
    "internal_summary",
    "clinical_note_support",
    "other",
]
OUTCOME_VALUES: List[str] = [
    "caught_before_use",
    "corrected_before_use",
    "used_with_correction",
    "escalated_for_review",
    "client_communication_delayed",
    "clinical_team_reviewed",
    "other",
]
ACTION_TAKEN_VALUES: List[str] = [
    "no_action_required",
    "additional_review",
    "staff_briefing",
    "policy_review",
    "process_change",
    "vendor_followup",
    "other",
]
VOID_REASON_VALUES: List[str] = [
    "duplicate",
    "wrong_clinic_record",
    "test_data",
    "incorrect_metadata",
    "other",
]


_STATUS_SET = frozenset(STATUS_VALUES)
_SEVERITY_SET = frozenset(SEVERITY_VALUES)
_CATEGORY_SET = frozenset(CATEGORY_VALUES)
_SOURCE_SET = frozenset(SOURCE_VALUES)
_OUTCOME_SET = frozenset(OUTCOME_VALUES)
_ACTION_TAKEN_SET = frozenset(ACTION_TAKEN_VALUES)


# Frozen client-safe SELECT column list.
_RECORD_COLS = (
    "incident_id, clinic_id, "
    "created_by_user_id, reviewed_by_user_id, closed_by_user_id, "
    "voided_by_user_id, "
    "status, severity, category, source, outcome, "
    "action_taken_category, "
    "learning_recommended, policy_review_recommended, "
    "client_communication_review_recommended, "
    "occurred_at, detected_at, reported_at, "
    "reviewed_at, closed_at, voided_at, "
    "linked_receipt_id, linked_governance_event_id, "
    "linked_assistant_run_id, linked_clinic_policy_version_id, "
    "void_reason_category, "
    "created_at, updated_at"
)


_GOVERNANCE_NOTE = (
    "Incident and near-miss records are structured, metadata-only "
    "governance records for AI-use review and learning. They do not "
    "store raw prompts, outputs, clinical case material, client "
    "identifiers, or patient identifiers. They are not clinical "
    "records, not legal claims, not insurance submissions, and not "
    "regulator reports. Human professional review remains required."
)


# ---------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------


class IncidentNearMissRecord(BaseModel):
    """Metadata-only view of an `ai_incident_near_miss_records` row.

    Surfaces UUIDs for actor identity. Never surfaces names or
    emails. The five `*_included` flags are doctrine self-assertions
    enforced by the schema's absence of any corresponding columns.
    """

    incident_id: _uuid.UUID
    clinic_id: _uuid.UUID

    created_by_user_id: _uuid.UUID
    reviewed_by_user_id: Optional[_uuid.UUID] = None
    closed_by_user_id: Optional[_uuid.UUID] = None
    voided_by_user_id: Optional[_uuid.UUID] = None

    status: str
    severity: str
    category: str
    source: str
    outcome: str
    action_taken_category: Optional[str] = None

    learning_recommended: bool
    policy_review_recommended: bool
    client_communication_review_recommended: bool

    occurred_at: Optional[datetime] = None
    detected_at: Optional[datetime] = None
    reported_at: datetime
    reviewed_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    voided_at: Optional[datetime] = None

    linked_receipt_id: Optional[_uuid.UUID] = None
    linked_governance_event_id: Optional[_uuid.UUID] = None
    linked_assistant_run_id: Optional[_uuid.UUID] = None
    linked_clinic_policy_version_id: Optional[_uuid.UUID] = None

    void_reason_category: Optional[str] = None

    created_at: datetime
    updated_at: Optional[datetime] = None

    # Doctrine self-assertions. Always false on this surface.
    raw_content_included: bool = False
    clinical_content_included: bool = False
    staff_identifiers_included: bool = False
    client_identifiers_included: bool = False
    patient_identifiers_included: bool = False


class IncidentNearMissRecordResponse(BaseModel):
    record: IncidentNearMissRecord
    governance_note: str = _GOVERNANCE_NOTE


class IncidentNearMissAppliedFilters(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    source: Optional[str] = None
    linked_receipt_id: Optional[_uuid.UUID] = None


class IncidentNearMissRecordListResponse(BaseModel):
    records: List[IncidentNearMissRecord]
    limit: int
    applied_filters: IncidentNearMissAppliedFilters
    governance_note: str = _GOVERNANCE_NOTE


class IncidentNearMissVocabularyResponse(BaseModel):
    statuses: List[str]
    severities: List[str]
    categories: List[str]
    sources: List[str]
    outcomes: List[str]
    action_taken_categories: List[str]
    void_reason_categories: List[str]
    governance_note: str = _GOVERNANCE_NOTE


class IncidentNearMissCreateRequest(BaseModel):
    """Bounded create body. `extra='forbid'` rejects any attempt to
    send `summary`, `note`, `description`, `narrative`, `comments`,
    `free_text`, `clinical_content`, `client_identifier`,
    `patient_identifier`, `transcript`, `consent_text`, `legal_claim`,
    `insurance`, `negligence`, `malpractice`, etc. The schema and the
    request body BOTH refuse to carry those concepts."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    # Required enums.
    category: str = Field(..., min_length=1, max_length=64)
    severity: str = Field(..., min_length=1, max_length=64)
    source: str = Field(..., min_length=1, max_length=64)
    outcome: str = Field(..., min_length=1, max_length=64)

    # Optional metadata.
    occurred_at: Optional[datetime] = None
    detected_at: Optional[datetime] = None
    action_taken_category: Optional[str] = Field(default=None, max_length=64)

    # Reflective signals.
    learning_recommended: bool = False
    policy_review_recommended: bool = False
    client_communication_review_recommended: bool = False

    # Optional metadata-only links.
    linked_receipt_id: Optional[_uuid.UUID] = None
    linked_governance_event_id: Optional[_uuid.UUID] = None
    linked_assistant_run_id: Optional[_uuid.UUID] = None
    linked_clinic_policy_version_id: Optional[_uuid.UUID] = None


# ---------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------

router = APIRouter(
    prefix="/v1/governance/incidents",
    tags=["Governance Incident Near-Miss"],
    dependencies=[Depends(require_clinic_user)],
)


# ---------------------------------------------------------------------
# Context / role helpers
# ---------------------------------------------------------------------


def _ctx(request: Request) -> Dict[str, str]:
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    role = getattr(request.state, "role", "") or ""
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")
    return {
        "clinic_id": str(clinic_id),
        "clinic_user_id": str(clinic_user_id),
        "role": str(role),
        "ip_hash": getattr(request.state, "ip_hash", None) or "",
    }


def _is_incident_admin(role: str) -> bool:
    return role in _INCIDENT_ADMIN_ROLES


def _require_incident_admin(role: str) -> None:
    if not _is_incident_admin(role):
        raise HTTPException(status_code=403, detail="forbidden_not_admin")


# ---------------------------------------------------------------------
# Enum validation helpers
# ---------------------------------------------------------------------


def _validate_enum(
    value: Optional[str], allowed: frozenset, detail_code: str,
) -> None:
    if value is None:
        return
    if value not in allowed:
        raise HTTPException(status_code=400, detail=detail_code)


def _validate_create_enums(payload: IncidentNearMissCreateRequest) -> None:
    _validate_enum(payload.category, _CATEGORY_SET, "invalid_category")
    _validate_enum(payload.severity, _SEVERITY_SET, "invalid_severity")
    _validate_enum(payload.source, _SOURCE_SET, "invalid_source")
    _validate_enum(payload.outcome, _OUTCOME_SET, "invalid_outcome")
    _validate_enum(
        payload.action_taken_category,
        _ACTION_TAKEN_SET,
        "invalid_action_taken_category",
    )


# ---------------------------------------------------------------------
# Linked-ID clinic-scoped validation
# ---------------------------------------------------------------------
#
# Each non-null `linked_*_id` is verified to exist for the caller's
# clinic via a clinic-scoped SELECT before storing. This is defence in
# depth on top of FORCE RLS on the target tables. The cross-clinic
# case yields 404 with a stable error code that does not leak any
# information about the target row.


def _exists_for_clinic(
    db: Session, *, sql: str, params: Dict[str, Any],
) -> bool:
    row = db.execute(text(sql), params).mappings().first()
    return row is not None


def _check_linked_ids_for_clinic(
    db: Session,
    *,
    clinic_id: str,
    payload: IncidentNearMissCreateRequest,
) -> None:
    if payload.linked_receipt_id is not None:
        ok = _exists_for_clinic(
            db,
            sql=(
                "SELECT 1 FROM assistant_run_receipts "
                "WHERE clinic_id = CAST(:clinic_id AS uuid) "
                "  AND id = CAST(:link_id AS uuid) "
                "LIMIT 1"
            ),
            params={
                "clinic_id": clinic_id,
                "link_id": str(payload.linked_receipt_id),
            },
        )
        if not ok:
            raise HTTPException(
                status_code=404,
                detail="linked_receipt_not_found",
            )

    if payload.linked_governance_event_id is not None:
        ok = _exists_for_clinic(
            db,
            sql=(
                "SELECT 1 FROM clinic_governance_events "
                "WHERE clinic_id = CAST(:clinic_id AS uuid) "
                "  AND event_id = CAST(:link_id AS uuid) "
                "LIMIT 1"
            ),
            params={
                "clinic_id": clinic_id,
                "link_id": str(payload.linked_governance_event_id),
            },
        )
        if not ok:
            raise HTTPException(
                status_code=404,
                detail="linked_governance_event_not_found",
            )

    if payload.linked_assistant_run_id is not None:
        ok = _exists_for_clinic(
            db,
            sql=(
                "SELECT 1 FROM assistant_runs "
                "WHERE clinic_id = CAST(:clinic_id AS uuid) "
                "  AND id = CAST(:link_id AS uuid) "
                "LIMIT 1"
            ),
            params={
                "clinic_id": clinic_id,
                "link_id": str(payload.linked_assistant_run_id),
            },
        )
        if not ok:
            raise HTTPException(
                status_code=404,
                detail="linked_assistant_run_not_found",
            )

    if payload.linked_clinic_policy_version_id is not None:
        ok = _exists_for_clinic(
            db,
            sql=(
                "SELECT 1 FROM clinic_policy_versions "
                "WHERE clinic_id = CAST(:clinic_id AS uuid) "
                "  AND clinic_policy_version_id = CAST(:link_id AS uuid) "
                "LIMIT 1"
            ),
            params={
                "clinic_id": clinic_id,
                "link_id": str(payload.linked_clinic_policy_version_id),
            },
        )
        if not ok:
            raise HTTPException(
                status_code=404,
                detail="linked_clinic_policy_version_not_found",
            )


# ---------------------------------------------------------------------
# Row -> model + SQL helpers
# ---------------------------------------------------------------------


def _record_from_row(row: Dict[str, Any]) -> IncidentNearMissRecord:
    return IncidentNearMissRecord(
        incident_id=row["incident_id"],
        clinic_id=row["clinic_id"],
        created_by_user_id=row["created_by_user_id"],
        reviewed_by_user_id=row.get("reviewed_by_user_id"),
        closed_by_user_id=row.get("closed_by_user_id"),
        voided_by_user_id=row.get("voided_by_user_id"),
        status=row["status"],
        severity=row["severity"],
        category=row["category"],
        source=row["source"],
        outcome=row["outcome"],
        action_taken_category=row.get("action_taken_category"),
        learning_recommended=bool(row["learning_recommended"]),
        policy_review_recommended=bool(row["policy_review_recommended"]),
        client_communication_review_recommended=bool(
            row["client_communication_review_recommended"]
        ),
        occurred_at=row.get("occurred_at"),
        detected_at=row.get("detected_at"),
        reported_at=row["reported_at"],
        reviewed_at=row.get("reviewed_at"),
        closed_at=row.get("closed_at"),
        voided_at=row.get("voided_at"),
        linked_receipt_id=row.get("linked_receipt_id"),
        linked_governance_event_id=row.get("linked_governance_event_id"),
        linked_assistant_run_id=row.get("linked_assistant_run_id"),
        linked_clinic_policy_version_id=row.get(
            "linked_clinic_policy_version_id"
        ),
        void_reason_category=row.get("void_reason_category"),
        created_at=row["created_at"],
        updated_at=row.get("updated_at"),
    )


def _select_record_for_clinic(
    db: Session, *, clinic_id: str, incident_id: str,
) -> Optional[Dict[str, Any]]:
    row = db.execute(
        text(
            f"""
            SELECT {_RECORD_COLS}
            FROM ai_incident_near_miss_records
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND incident_id = CAST(:incident_id AS uuid)
            LIMIT 1
            """
        ),
        {"clinic_id": clinic_id, "incident_id": incident_id},
    ).mappings().first()
    return dict(row) if row else None


# ---------------------------------------------------------------------
# Audit event (append-only, NO ON CONFLICT)
# ---------------------------------------------------------------------


def _insert_audit_event(
    db: Session,
    *,
    clinic_id: str,
    admin_user_id: str,
    action: str,
    target_id: str,
    ip_hash: Optional[str],
    meta: Dict[str, Any],
) -> None:
    """Append-only metadata-only audit. Same posture as
    governance_policy._insert_audit_event / client_transparency
    audit. We deliberately do NOT use the partial-index conflict
    target that caused the M6.10.1B / TD-BE production 500."""
    db.execute(
        text(
            """
            INSERT INTO admin_audit_events (
                clinic_id, admin_user_id, action, target_id, ip_hash, meta
            ) VALUES (
                CAST(:clinic_id AS uuid),
                CAST(:admin_user_id AS uuid),
                :action,
                CAST(:target_id AS uuid),
                :ip_hash,
                CAST(:meta AS jsonb)
            )
            """
        ),
        {
            "clinic_id": clinic_id,
            "admin_user_id": admin_user_id,
            "action": action,
            "target_id": target_id,
            "ip_hash": ip_hash or None,
            "meta": json.dumps(meta),
        },
    )


# ---------------------------------------------------------------------
# 1. GET /vocabulary
# ---------------------------------------------------------------------


@router.get(
    "/vocabulary", response_model=IncidentNearMissVocabularyResponse,
)
def get_vocabulary(
    request: Request,
) -> IncidentNearMissVocabularyResponse:
    """Static controlled-vocabulary endpoint. Visible to any
    authenticated clinic user. Drives frontend dropdowns and keeps
    the canonical enums in one place."""
    _ctx(request)
    return IncidentNearMissVocabularyResponse(
        statuses=list(STATUS_VALUES),
        severities=list(SEVERITY_VALUES),
        categories=list(CATEGORY_VALUES),
        sources=list(SOURCE_VALUES),
        outcomes=list(OUTCOME_VALUES),
        action_taken_categories=list(ACTION_TAKEN_VALUES),
        void_reason_categories=list(VOID_REASON_VALUES),
    )


# ---------------------------------------------------------------------
# 2. POST /records
# ---------------------------------------------------------------------


@router.post(
    "/records",
    response_model=IncidentNearMissRecordResponse,
    status_code=201,
)
def create_record(
    payload: IncidentNearMissCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> IncidentNearMissRecordResponse:
    """Create a new incident / near-miss record. Any authenticated
    clinic user can create. Status defaults to `open`. Linked IDs
    are validated clinic-scoped before insert."""
    ctx = _ctx(request)

    # 1. Validate all enum fields server-side. Belt-and-braces over
    #    the Pydantic parser - the actual allow-list lives here.
    _validate_create_enums(payload)

    # 2. Validate linked IDs are clinic-scoped (defence in depth).
    _check_linked_ids_for_clinic(
        db, clinic_id=ctx["clinic_id"], payload=payload,
    )

    # 3. INSERT. `reported_at`, `created_at`, `updated_at` use DB
    #    defaults. `status` defaults to `open`. Reflective booleans
    #    default to false at the schema level too but we pass them
    #    explicitly so a request that opts a recommendation flag
    #    `true` is honoured.
    new_row = db.execute(
        text(
            f"""
            INSERT INTO ai_incident_near_miss_records (
                clinic_id,
                created_by_user_id,
                status,
                severity,
                category,
                source,
                outcome,
                action_taken_category,
                learning_recommended,
                policy_review_recommended,
                client_communication_review_recommended,
                occurred_at,
                detected_at,
                linked_receipt_id,
                linked_governance_event_id,
                linked_assistant_run_id,
                linked_clinic_policy_version_id
            )
            VALUES (
                CAST(:clinic_id AS uuid),
                CAST(:created_by_user_id AS uuid),
                'open',
                :severity,
                :category,
                :source,
                :outcome,
                :action_taken_category,
                :learning_recommended,
                :policy_review_recommended,
                :client_communication_review_recommended,
                :occurred_at,
                :detected_at,
                :linked_receipt_id,
                :linked_governance_event_id,
                :linked_assistant_run_id,
                :linked_clinic_policy_version_id
            )
            RETURNING {_RECORD_COLS}
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "created_by_user_id": ctx["clinic_user_id"],
            "severity": payload.severity,
            "category": payload.category,
            "source": payload.source,
            "outcome": payload.outcome,
            "action_taken_category": payload.action_taken_category,
            "learning_recommended": bool(payload.learning_recommended),
            "policy_review_recommended": bool(
                payload.policy_review_recommended
            ),
            "client_communication_review_recommended": bool(
                payload.client_communication_review_recommended
            ),
            "occurred_at": payload.occurred_at,
            "detected_at": payload.detected_at,
            "linked_receipt_id": (
                str(payload.linked_receipt_id)
                if payload.linked_receipt_id is not None else None
            ),
            "linked_governance_event_id": (
                str(payload.linked_governance_event_id)
                if payload.linked_governance_event_id is not None else None
            ),
            "linked_assistant_run_id": (
                str(payload.linked_assistant_run_id)
                if payload.linked_assistant_run_id is not None else None
            ),
            "linked_clinic_policy_version_id": (
                str(payload.linked_clinic_policy_version_id)
                if payload.linked_clinic_policy_version_id is not None else None
            ),
        },
    ).mappings().first()
    if not new_row:
        raise HTTPException(status_code=500, detail="internal_server_error")
    new_row_d = dict(new_row)

    # 4. Audit. IDs + enums + boolean flags only. No raw text.
    _insert_audit_event(
        db,
        clinic_id=ctx["clinic_id"],
        admin_user_id=ctx["clinic_user_id"],
        action="ai_incident_near_miss_record_created",
        target_id=str(new_row_d["incident_id"]),
        ip_hash=ctx["ip_hash"],
        meta={
            "category": payload.category,
            "severity": payload.severity,
            "source": payload.source,
            "outcome": payload.outcome,
            "action_taken_category": payload.action_taken_category,
            "learning_recommended": bool(payload.learning_recommended),
            "policy_review_recommended": bool(
                payload.policy_review_recommended
            ),
            "client_communication_review_recommended": bool(
                payload.client_communication_review_recommended
            ),
            "linked_receipt_id_present": payload.linked_receipt_id is not None,
            "linked_governance_event_id_present": (
                payload.linked_governance_event_id is not None
            ),
            "linked_assistant_run_id_present": (
                payload.linked_assistant_run_id is not None
            ),
            "linked_clinic_policy_version_id_present": (
                payload.linked_clinic_policy_version_id is not None
            ),
            "status": "open",
        },
    )
    logger.info(
        "ai_incident_near_miss_record_created",
        extra={
            "clinic_id": ctx["clinic_id"],
            "incident_id": str(new_row_d["incident_id"]),
            "category": payload.category,
            "severity": payload.severity,
        },
    )
    return IncidentNearMissRecordResponse(record=_record_from_row(new_row_d))


# ---------------------------------------------------------------------
# 3. GET /records         (admin tier - clinic-wide)
# 4. GET /records/mine    (self)
# ---------------------------------------------------------------------
#
# /records/mine is declared BEFORE /records/{incident_id} so the
# literal "mine" path segment doesn't get captured as a UUID
# parameter.


def _build_list_filters(
    *,
    status_v: Optional[str],
    severity_v: Optional[str],
    category_v: Optional[str],
    source_v: Optional[str],
    linked_receipt_id: Optional[_uuid.UUID],
) -> tuple[List[str], Dict[str, Any], IncidentNearMissAppliedFilters]:
    _validate_enum(status_v, _STATUS_SET, "invalid_status")
    _validate_enum(severity_v, _SEVERITY_SET, "invalid_severity")
    _validate_enum(category_v, _CATEGORY_SET, "invalid_category")
    _validate_enum(source_v, _SOURCE_SET, "invalid_source")

    clauses: List[str] = []
    params: Dict[str, Any] = {}
    if status_v is not None:
        clauses.append("status = :status")
        params["status"] = status_v
    if severity_v is not None:
        clauses.append("severity = :severity")
        params["severity"] = severity_v
    if category_v is not None:
        clauses.append("category = :category")
        params["category"] = category_v
    if source_v is not None:
        clauses.append("source = :source")
        params["source"] = source_v
    if linked_receipt_id is not None:
        clauses.append("linked_receipt_id = CAST(:linked_receipt_id AS uuid)")
        params["linked_receipt_id"] = str(linked_receipt_id)

    applied = IncidentNearMissAppliedFilters(
        status=status_v,
        severity=severity_v,
        category=category_v,
        source=source_v,
        linked_receipt_id=linked_receipt_id,
    )
    return clauses, params, applied


@router.get(
    "/records/mine",
    response_model=IncidentNearMissRecordListResponse,
)
def list_my_records(
    request: Request,
    db: Session = Depends(get_db),
    status: Optional[str] = Query(default=None, alias="status"),
    severity: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    source: Optional[str] = Query(default=None),
    linked_receipt_id: Optional[_uuid.UUID] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
) -> IncidentNearMissRecordListResponse:
    """Caller's own incident records. Self-only - the `created_by_user_id`
    bind comes from request.state, never a query parameter."""
    ctx = _ctx(request)
    clauses, params, applied = _build_list_filters(
        status_v=status,
        severity_v=severity,
        category_v=category,
        source_v=source,
        linked_receipt_id=linked_receipt_id,
    )
    clauses.insert(0, "clinic_id = CAST(:clinic_id AS uuid)")
    clauses.insert(1, "created_by_user_id = CAST(:user_id AS uuid)")
    params["clinic_id"] = ctx["clinic_id"]
    params["user_id"] = ctx["clinic_user_id"]
    params["limit"] = int(limit)

    rows = db.execute(
        text(
            f"""
            SELECT {_RECORD_COLS}
            FROM ai_incident_near_miss_records
            WHERE {' AND '.join(clauses)}
            ORDER BY reported_at DESC, created_at DESC
            LIMIT :limit
            """
        ),
        params,
    ).mappings().all()
    return IncidentNearMissRecordListResponse(
        records=[_record_from_row(dict(r)) for r in rows],
        limit=int(limit),
        applied_filters=applied,
    )


@router.get(
    "/records",
    response_model=IncidentNearMissRecordListResponse,
)
def list_records(
    request: Request,
    db: Session = Depends(get_db),
    status: Optional[str] = Query(default=None, alias="status"),
    severity: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    source: Optional[str] = Query(default=None),
    linked_receipt_id: Optional[_uuid.UUID] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
) -> IncidentNearMissRecordListResponse:
    """Clinic-wide incident records. Admin tier only."""
    ctx = _ctx(request)
    _require_incident_admin(ctx["role"])

    clauses, params, applied = _build_list_filters(
        status_v=status,
        severity_v=severity,
        category_v=category,
        source_v=source,
        linked_receipt_id=linked_receipt_id,
    )
    clauses.insert(0, "clinic_id = CAST(:clinic_id AS uuid)")
    params["clinic_id"] = ctx["clinic_id"]
    params["limit"] = int(limit)

    rows = db.execute(
        text(
            f"""
            SELECT {_RECORD_COLS}
            FROM ai_incident_near_miss_records
            WHERE {' AND '.join(clauses)}
            ORDER BY reported_at DESC, created_at DESC
            LIMIT :limit
            """
        ),
        params,
    ).mappings().all()
    return IncidentNearMissRecordListResponse(
        records=[_record_from_row(dict(r)) for r in rows],
        limit=int(limit),
        applied_filters=applied,
    )


# ---------------------------------------------------------------------
# 5. GET /records/{incident_id}
# ---------------------------------------------------------------------


@router.get(
    "/records/{incident_id}",
    response_model=IncidentNearMissRecordResponse,
)
def get_record(
    incident_id: _uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> IncidentNearMissRecordResponse:
    """Detail. Admin tier may read any clinic record. Non-admin may
    read only records they created. Cross-clinic or non-creator
    non-admin lookups return 404 (enumeration-safe)."""
    ctx = _ctx(request)
    row = _select_record_for_clinic(
        db,
        clinic_id=ctx["clinic_id"],
        incident_id=str(incident_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="incident_not_found")
    if not _is_incident_admin(ctx["role"]):
        if str(row["created_by_user_id"]) != ctx["clinic_user_id"]:
            # Non-admin caller is not the creator - same 404 as
            # missing/cross-clinic so the surface is not probeable.
            raise HTTPException(
                status_code=404, detail="incident_not_found",
            )
    return IncidentNearMissRecordResponse(record=_record_from_row(row))
