import re
import time
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal"],
    dependencies=[Depends(require_clinic_user)],
)

_ALLOWED_MODES = {"clinical_note", "client_comm", "internal_summary"}

_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"\b(\+?\d[\d\s().-]{7,}\d)\b")
_UK_POSTCODE_RE = re.compile(r"\b([A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2})\b", re.IGNORECASE)


# ---------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------

def detect_pii_types(text_value: str) -> List[str]:
    t = text_value or ""
    types: List[str] = []

    if _EMAIL_RE.search(t):
        types.append("email")
    if _PHONE_RE.search(t):
        types.append("phone")
    if _UK_POSTCODE_RE.search(t):
        types.append("postcode")

    seen = set()
    out: List[str] = []
    for x in types:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _get_active_policy_version(db: Session) -> int:
    row = db.execute(
        text(
            """
            SELECT active_policy_version
            FROM clinic_policy_state
            WHERE clinic_id = app_current_clinic_id()
            LIMIT 1
            """
        )
    ).fetchone()

    if not row:
        return 1

    try:
        return int(row[0])
    except Exception:
        return 1


def _simple_risk_grade(pii_types: List[str]) -> str:
    return "med" if pii_types else "low"


def _simple_reason_code(pii_types: List[str]) -> str:
    return "pii_detected" if pii_types else "ok"


# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------

class PortalSubmitRequest(BaseModel):
    mode: str = Field(..., description="clinical_note | client_comm | internal_summary")
    text: str = Field(..., min_length=1, max_length=20000)
    request_id: Optional[uuid.UUID] = Field(default=None)


class GovernanceReceipt(BaseModel):
    request_id: uuid.UUID
    clinic_id: uuid.UUID
    clinic_user_id: uuid.UUID
    mode: str
    decision: str
    risk_grade: str
    reason_code: str
    pii_detected: bool
    pii_action: str
    pii_types: List[str]
    policy_version: int
    neutrality_version: str
    governance_score: Optional[float] = None
    created_at_utc: str


class PortalSubmitResponse(BaseModel):
    receipt: GovernanceReceipt


class SubmissionItem(BaseModel):
    request_id: uuid.UUID
    clinic_user_id: uuid.UUID
    mode: str
    decision: str
    risk_grade: str
    reason_code: str
    pii_detected: bool
    policy_version: int
    neutrality_version: str
    created_at_utc: str


class SubmissionsListResponse(BaseModel):
    items: List[SubmissionItem]
    next_cursor: Optional[str] = None


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _row_to_receipt(row) -> GovernanceReceipt:
    created_at = row["created_at"]
    created_iso = created_at.isoformat()

    return GovernanceReceipt(
        request_id=uuid.UUID(str(row["request_id"])),
        clinic_id=uuid.UUID(str(row["clinic_id"])),
        clinic_user_id=uuid.UUID(str(row["user_id"])),
        mode=row["mode"],
        decision=row["decision"],
        risk_grade=row["risk_grade"],
        reason_code=row["reason_code"],
        pii_detected=bool(row["pii_detected"]),
        pii_action=row["pii_action"],
        pii_types=list(row["pii_types"] or []),
        policy_version=int(row["policy_version"]),
        neutrality_version=row["neutrality_version"],
        governance_score=(
            float(row["governance_score"]) if row["governance_score"] else None
        ),
        created_at_utc=created_iso,
    )


# ---------------------------------------------------------------------
# POST /submit
# ---------------------------------------------------------------------

@router.post("/submit", response_model=PortalSubmitResponse)
def portal_submit(payload: PortalSubmitRequest, request: Request, db: Session = Depends(get_db)):

    mode = payload.mode.strip()
    if mode not in _ALLOWED_MODES:
        raise HTTPException(status_code=400, detail="invalid mode")

    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)

    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    req_id = payload.request_id or uuid.uuid4()

    pii_types = detect_pii_types(payload.text)
    pii_detected = bool(pii_types)

    policy_version = _get_active_policy_version(db)

    clinic_id_s = str(clinic_id)
    clinic_user_id_s = str(clinic_user_id)
    req_id_s = str(req_id)

    gov_row = (
        db.execute(
            text(
                """
                INSERT INTO clinic_governance_events (
                  clinic_id, request_id, user_id, mode,
                  pii_detected, pii_action, pii_types,
                  decision, risk_grade, reason_code,
                  governance_score, policy_version, neutrality_version
                )
                VALUES (
                  :clinic_id, :request_id, :user_id, :mode,
                  :pii_detected, :pii_action, :pii_types,
                  'allowed',
                  CASE WHEN :pii_detected THEN 'med' ELSE 'low' END,
                  CASE WHEN :pii_detected THEN 'pii_detected' ELSE 'ok' END,
                  NULL,
                  :policy_version,
                  'v1.1'
                )
                ON CONFLICT (clinic_id, request_id) DO NOTHING
                RETURNING *
                """
            ),
            {
                "clinic_id": clinic_id_s,
                "request_id": req_id_s,
                "user_id": clinic_user_id_s,
                "mode": mode,
                "pii_detected": pii_detected,
                "pii_action": "warn" if pii_detected else "allow",
                "pii_types": pii_types,
                "policy_version": policy_version,
            },
        )
        .mappings()
        .first()
    )

    db.execute(
        text(
            """
            INSERT INTO ops_metrics_events (
              clinic_id, request_id, route, status_code, latency_ms,
              mode, governance_replaced, pii_warned
            )
            VALUES (
              :clinic_id, :request_id, :route, 200, 0,
              :mode, false, :pii_warned
            )
            ON CONFLICT (clinic_id, request_id) DO NOTHING
            """
        ),
        {
            "clinic_id": clinic_id_s,
            "request_id": req_id_s,
            "route": request.url.path,
            "mode": mode,
            "pii_warned": pii_detected,
        },
    )

    db.commit()

    if gov_row:
        return PortalSubmitResponse(receipt=_row_to_receipt(gov_row))

    existing = db.execute(
        text(
            """
            SELECT *
            FROM clinic_governance_events
            WHERE clinic_id = :clinic_id
              AND request_id = :request_id
            LIMIT 1
            """
        ),
        {"clinic_id": clinic_id_s, "request_id": req_id_s},
    ).mappings().first()

    if not existing:
        raise HTTPException(status_code=500, detail="idempotency failure")

    return PortalSubmitResponse(receipt=_row_to_receipt(existing))


# ---------------------------------------------------------------------
# GET /receipts/{request_id}
# ---------------------------------------------------------------------

@router.get("/receipts/{request_id}", response_model=PortalSubmitResponse)
def get_receipt(request_id: uuid.UUID, request: Request, db: Session = Depends(get_db)):

    clinic_id = getattr(request.state, "clinic_id", None)
    if not clinic_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    row = db.execute(
        text(
            """
            SELECT *
            FROM clinic_governance_events
            WHERE clinic_id = :clinic_id
              AND request_id = :request_id
            LIMIT 1
            """
        ),
        {"clinic_id": str(clinic_id), "request_id": str(request_id)},
    ).mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="receipt not found")

    return PortalSubmitResponse(receipt=_row_to_receipt(row))


# ---------------------------------------------------------------------
# GET /submissions  (with filtering)
# ---------------------------------------------------------------------

@router.get("/submissions", response_model=SubmissionsListResponse)
def list_submissions(
    request: Request,
    db: Session = Depends(get_db),
    limit: int = 20,
    cursor: Optional[str] = None,
    mode: Optional[str] = None,
    decision: Optional[str] = None,
):

    clinic_id = getattr(request.state, "clinic_id", None)
    if not clinic_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    limit = max(1, min(100, limit))

    filters = []
    params = {"clinic_id": str(clinic_id), "limit": limit}

    if mode:
        if mode not in _ALLOWED_MODES:
            raise HTTPException(status_code=400, detail="invalid mode filter")
        filters.append("mode = :mode")
        params["mode"] = mode

    if decision:
        filters.append("decision = :decision")
        params["decision"] = decision

    cursor_clause = ""
    if cursor:
        created_at_str, request_id_str = cursor.split("|", 1)
        cursor_clause = """
            AND (
                created_at < :cursor_created_at
                OR (created_at = :cursor_created_at AND request_id < :cursor_request_id)
            )
        """
        params["cursor_created_at"] = created_at_str
        params["cursor_request_id"] = request_id_str

    where_extra = ""
    if filters:
        where_extra = " AND " + " AND ".join(filters)

    rows = db.execute(
        text(
            f"""
            SELECT *
            FROM clinic_governance_events
            WHERE clinic_id = :clinic_id
            {where_extra}
            {cursor_clause}
            ORDER BY created_at DESC, request_id DESC
            LIMIT :limit
            """
        ),
        params,
    ).mappings().all()

    items: List[SubmissionItem] = []

    for row in rows:
        items.append(
            SubmissionItem(
                request_id=uuid.UUID(str(row["request_id"])),
                clinic_user_id=uuid.UUID(str(row["user_id"])),
                mode=row["mode"],
                decision=row["decision"],
                risk_grade=row["risk_grade"],
                reason_code=row["reason_code"],
                pii_detected=bool(row["pii_detected"]),
                policy_version=int(row["policy_version"]),
                neutrality_version=row["neutrality_version"],
                created_at_utc=row["created_at"].isoformat(),
            )
        )

    next_cursor = None
    if rows:
        last = rows[-1]
        next_cursor = f"{last['created_at'].isoformat()}|{last['request_id']}"

    return SubmissionsListResponse(items=items, next_cursor=next_cursor)
