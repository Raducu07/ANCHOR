# app/ambient_governance.py
#
# M6.13 - Ambient Governance Integration (governance shell only).
# Authorised by the 2026-07-05 founder code-completion decision record.
#
# ANCHOR remains the GOVERNANCE LAYER around ambient/scribe workflows -
# it is not the scribe, stores no transcripts, generates no clinical
# notes, and integrates with no vendor.
#
# Hard boundaries:
#   * DISABLED BY DEFAULT: every endpoint returns 503 unless
#     ANCHOR_AMBIENT_GOVERNANCE_ENABLED is truthy.
#   * Metadata-only events: tool label, event type, timestamp,
#     duration, optional SHA-256 reference hash. The API validates the
#     hash shape (64 lowercase hex chars) so raw content cannot ride in
#     through that field, and rejects multi-line "labels" so pasted
#     transcript text cannot ride in through label fields either.
#   * The review gate records reviewer, time, and decision category -
#     never note content.
#   * The ingestion interface below is a validation-only placeholder;
#     no vendor adapter exists and none may be added without a founder
#     decision plus security/legal review (Roadmap v2.6 section 9
#     preconditions).

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

logger = logging.getLogger(__name__)

AMBIENT_FLAG_ENV = "ANCHOR_AMBIENT_GOVERNANCE_ENABLED"
_TRUTHY = {"1", "true", "yes", "on"}

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

AMBIENT_NOTE = (
    "Metadata-only governance record of an ambient AI workflow event. "
    "ANCHOR stores no transcript, no audio, and no note content; the "
    "clinical record remains in the clinic's own systems and "
    "professional review remains the clinic's responsibility."
)

EVENT_TYPES = {
    "consult_recorded",
    "note_generated",
    "note_reviewed_externally",
    "other",
}
REVIEW_DECISIONS = {
    "approved_for_record",
    "amended_before_use",
    "rejected",
}


def is_ambient_governance_enabled() -> bool:
    raw = (os.getenv(AMBIENT_FLAG_ENV, "") or "").strip().lower()
    return raw in _TRUTHY


def _require_enabled() -> None:
    if not is_ambient_governance_enabled():
        raise HTTPException(
            status_code=503, detail="ambient_governance_disabled"
        )


router = APIRouter(
    prefix="/v1/portal/ambient",
    tags=["Ambient Governance"],
    dependencies=[Depends(require_clinic_user)],
)


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


def _as_uuid(value: Any, *, field: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except Exception:
        raise HTTPException(status_code=400, detail=f"invalid_{field}")


def _insert_admin_audit_event(
    db: Session,
    *,
    clinic_id: str,
    admin_user_id: str,
    action: str,
    target_id: Optional[str],
    ip_hash: Optional[str],
    meta: Dict[str, Any],
) -> None:
    """Append-only metadata-only audit row (governance_policy /
    assistant_policy M6.10 precedent). NO ON CONFLICT against the
    partial admin_audit_events_idem_uq index. meta records the bounded
    decision category and resulting status only - there is no
    transcript, audio, or note content anywhere in this module to
    log."""
    db.execute(
        text(
            """
            INSERT INTO admin_audit_events (
                clinic_id,
                admin_user_id,
                action,
                target_id,
                ip_hash,
                meta
            )
            VALUES (
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
# Normalised ambient event schema + placeholder ingestion interface
# ---------------------------------------------------------------------

class NormalisedAmbientEvent(BaseModel):
    """The normalised, metadata-only ambient event shape. This is the
    contract any FUTURE (gated) vendor adapter would have to normalise
    into. It is intentionally incapable of carrying content."""

    source_label: str = Field(..., min_length=1, max_length=120)
    event_type: str
    occurred_at: datetime
    duration_seconds: Optional[int] = Field(default=None, ge=0, le=86400)
    workflow_reference_hash: Optional[str] = None

    @field_validator("source_label")
    @classmethod
    def _label_single_line(cls, v: str) -> str:
        # Anti-paste guard: a tool label is one short line. Anything
        # with line breaks is treated as attempted content and refused.
        if "\n" in v or "\r" in v:
            raise ValueError("source_label_must_be_single_line")
        return v.strip()

    @field_validator("event_type")
    @classmethod
    def _known_event_type(cls, v: str) -> str:
        if v not in EVENT_TYPES:
            raise ValueError("unknown_event_type")
        return v

    @field_validator("workflow_reference_hash")
    @classmethod
    def _hash_shape(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        candidate = v.strip().lower()
        if not _SHA256_RE.fullmatch(candidate):
            # Anything that is not exactly a sha256 hex digest is
            # refused - this field can never smuggle content.
            raise ValueError("workflow_reference_hash_must_be_sha256_hex")
        return candidate


class AmbientEventIngestor(Protocol):
    """Placeholder interface for a FUTURE, founder-gated vendor
    adapter. Implementations must emit NormalisedAmbientEvent only -
    the type system gives them nowhere to put a transcript. No
    implementation ships in this codebase."""

    source_name: str

    def normalise(self, raw: Dict[str, Any]) -> NormalisedAmbientEvent: ...


def validate_normalised_ambient_event(
    raw: Dict[str, Any],
) -> NormalisedAmbientEvent:
    """Pure validation entry point for the normalised schema. Unknown
    fields (e.g. 'transcript', 'note_text', 'audio') are dropped by the
    model; disallowed values raise ValueError via pydantic."""
    return NormalisedAmbientEvent(
        source_label=str(raw.get("source_label") or ""),
        event_type=str(raw.get("event_type") or ""),
        occurred_at=raw.get("occurred_at"),
        duration_seconds=raw.get("duration_seconds"),
        workflow_reference_hash=raw.get("workflow_reference_hash"),
    )


# ---------------------------------------------------------------------
# API models
# ---------------------------------------------------------------------

class AmbientEventResponse(BaseModel):
    ambient_event_id: str
    source_label: str
    event_type: str
    occurred_at: datetime
    duration_seconds: Optional[int] = None
    workflow_reference_hash: Optional[str] = None
    review_status: str
    review_decision: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    created_at: datetime
    ambient_note: str


class AmbientEventListResponse(BaseModel):
    events: List[AmbientEventResponse]
    ambient_note: str


class AmbientReviewRequest(BaseModel):
    review_decision: str

    @field_validator("review_decision")
    @classmethod
    def _known_decision(cls, v: str) -> str:
        if v not in REVIEW_DECISIONS:
            raise ValueError("unknown_review_decision")
        return v


class AmbientSummaryResponse(BaseModel):
    pending_review_count: int
    reviewed_count: int
    discarded_count: int
    latest_event_at: Optional[datetime] = None
    ambient_note: str


_EVENT_COLS = (
    "ambient_event_id, source_label, event_type, occurred_at, "
    "duration_seconds, workflow_reference_hash, review_status, "
    "review_decision, reviewed_at, created_at"
)


def _event_from_row(r: Dict[str, Any]) -> AmbientEventResponse:
    return AmbientEventResponse(
        ambient_event_id=str(r["ambient_event_id"]),
        source_label=str(r["source_label"]),
        event_type=str(r["event_type"]),
        occurred_at=r["occurred_at"],
        duration_seconds=r.get("duration_seconds"),
        workflow_reference_hash=r.get("workflow_reference_hash"),
        review_status=str(r["review_status"]),
        review_decision=r.get("review_decision"),
        reviewed_at=r.get("reviewed_at"),
        created_at=r["created_at"],
        ambient_note=AMBIENT_NOTE,
    )


# ---------------------------------------------------------------------
# Endpoints (all 503 unless the flag is on)
# ---------------------------------------------------------------------

@router.post("/events", response_model=AmbientEventResponse)
def create_ambient_event(
    payload: NormalisedAmbientEvent,
    request: Request,
    db: Session = Depends(get_db),
) -> AmbientEventResponse:
    _require_enabled()
    ctx = _ctx(request)
    row = db.execute(
        text(
            f"""
            INSERT INTO ambient_governance_events (
                clinic_id, recorded_by_user_id, source_label, event_type,
                occurred_at, duration_seconds, workflow_reference_hash
            )
            VALUES (
                CAST(:clinic_id AS uuid), CAST(:actor AS uuid),
                :source_label, :event_type, :occurred_at,
                :duration_seconds, :workflow_reference_hash
            )
            RETURNING {_EVENT_COLS}
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "actor": ctx["clinic_user_id"],
            "source_label": payload.source_label,
            "event_type": payload.event_type,
            "occurred_at": payload.occurred_at,
            "duration_seconds": payload.duration_seconds,
            "workflow_reference_hash": payload.workflow_reference_hash,
        },
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=500, detail="event_insert_failed")
    return _event_from_row(dict(row))


@router.get("/events", response_model=AmbientEventListResponse)
def list_ambient_events(
    request: Request,
    db: Session = Depends(get_db),
    review_status: Optional[str] = None,
) -> AmbientEventListResponse:
    _require_enabled()
    ctx = _ctx(request)

    clauses = ["clinic_id = CAST(:clinic_id AS uuid)"]
    params: Dict[str, Any] = {"clinic_id": ctx["clinic_id"]}
    if review_status is not None:
        if review_status not in {"pending_review", "reviewed", "discarded"}:
            raise HTTPException(
                status_code=400, detail="invalid_review_status"
            )
        clauses.append("review_status = :review_status")
        params["review_status"] = review_status

    rows = db.execute(
        text(
            f"""
            SELECT {_EVENT_COLS}
            FROM ambient_governance_events
            WHERE {' AND '.join(clauses)}
            ORDER BY occurred_at DESC
            LIMIT 500
            """
        ),
        params,
    ).mappings().all()
    return AmbientEventListResponse(
        events=[_event_from_row(dict(r)) for r in rows],
        ambient_note=AMBIENT_NOTE,
    )


@router.post(
    "/events/{ambient_event_id}/review",
    response_model=AmbientEventResponse,
)
def review_ambient_event(
    ambient_event_id: str,
    payload: AmbientReviewRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> AmbientEventResponse:
    _require_enabled()
    ctx = _ctx(request)
    eid = _as_uuid(ambient_event_id, field="ambient_event_id")

    new_status = (
        "discarded" if payload.review_decision == "rejected" else "reviewed"
    )
    row = db.execute(
        text(
            f"""
            UPDATE ambient_governance_events
            SET review_status = :new_status,
                review_decision = :review_decision,
                reviewed_by_user_id = CAST(:reviewer AS uuid),
                reviewed_at = now()
            WHERE ambient_event_id = CAST(:event_id AS uuid)
              AND review_status = 'pending_review'
            RETURNING {_EVENT_COLS}
            """
        ),
        {
            "new_status": new_status,
            "review_decision": payload.review_decision,
            "reviewer": ctx["clinic_user_id"],
            "event_id": eid,
        },
    ).mappings().first()
    if not row:
        raise HTTPException(
            status_code=404, detail="event_not_found_or_already_reviewed"
        )

    _insert_admin_audit_event(
        db,
        clinic_id=ctx["clinic_id"],
        admin_user_id=ctx["clinic_user_id"],
        action="ambient_event_reviewed",
        target_id=eid,
        ip_hash=ctx["ip_hash"],
        meta={
            "review_decision": str(payload.review_decision),
            "new_status": new_status,
        },
    )

    return _event_from_row(dict(row))


@router.get("/summary", response_model=AmbientSummaryResponse)
def ambient_summary(
    request: Request, db: Session = Depends(get_db)
) -> AmbientSummaryResponse:
    _require_enabled()
    ctx = _ctx(request)
    rows = db.execute(
        text(
            """
            SELECT review_status, COUNT(*)::int AS c,
                   MAX(occurred_at) AS latest
            FROM ambient_governance_events
            WHERE clinic_id = CAST(:clinic_id AS uuid)
            GROUP BY review_status
            """
        ),
        {"clinic_id": ctx["clinic_id"]},
    ).mappings().all()

    counts = {"pending_review": 0, "reviewed": 0, "discarded": 0}
    latest: Optional[datetime] = None
    for r in rows:
        status = str(r["review_status"])
        if status in counts:
            counts[status] = int(r["c"])
        row_latest = r.get("latest")
        if row_latest is not None and (latest is None or row_latest > latest):
            latest = row_latest

    return AmbientSummaryResponse(
        pending_review_count=counts["pending_review"],
        reviewed_count=counts["reviewed"],
        discarded_count=counts["discarded"],
        latest_event_at=latest,
        ambient_note=AMBIENT_NOTE,
    )
