# app/portal_read.py
import uuid
from datetime import datetime
from typing import List, Optional, Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.auth_and_rls import require_clinic_user

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal Read"],
    # ✅ every /v1/portal/* endpoint is clinic-auth protected
    dependencies=[Depends(require_clinic_user)],
)

# -----------------------------
# Helpers
# -----------------------------

def _parse_iso8601(ts: str) -> datetime:
    """
    Accept ISO8601 timestamps from querystrings robustly.
    Some clients turn '+' into space, so normalize.
    """
    s = (ts or "").strip()
    if not s:
        raise ValueError("empty timestamp")

    # PowerShell / querystring edge: '+' may arrive as space
    s = s.replace(" ", "+")

    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    return datetime.fromisoformat(s)


# -----------------------------
# Models
# -----------------------------
class GovernanceEventItem(BaseModel):
    request_id: uuid.UUID
    clinic_id: uuid.UUID
    user_id: uuid.UUID
    mode: str

    decision: str
    risk_grade: str
    reason_code: str

    pii_detected: bool
    pii_action: str
    pii_types: List[str] = Field(default_factory=list)

    policy_version: int
    neutrality_version: str
    governance_score: Optional[float] = None

    created_at_utc: str


class GovernanceEventsResponse(BaseModel):
    items: List[GovernanceEventItem]
    next_cursor_created_at_utc: Optional[str] = None
    next_cursor_request_id: Optional[uuid.UUID] = None


class GovernanceReceiptResponse(BaseModel):
    receipt: GovernanceEventItem


# -----------------------------
# SQL
# -----------------------------
_SQL_LIST_EVENTS = """
SELECT
  request_id,
  clinic_id,
  user_id,
  mode,
  decision,
  risk_grade,
  reason_code,
  pii_detected,
  pii_action,
  COALESCE(pii_types, ARRAY[]::text[]) AS pii_types,
  policy_version,
  neutrality_version,
  governance_score,
  created_at
FROM clinic_governance_events
WHERE clinic_id = app_current_clinic_id()
{cursor_clause}
ORDER BY created_at DESC, request_id DESC
LIMIT :limit
"""

_SQL_GET_RECEIPT = """
SELECT
  request_id,
  clinic_id,
  user_id,
  mode,
  decision,
  risk_grade,
  reason_code,
  pii_detected,
  pii_action,
  COALESCE(pii_types, ARRAY[]::text[]) AS pii_types,
  policy_version,
  neutrality_version,
  governance_score,
  created_at
FROM clinic_governance_events
WHERE clinic_id = app_current_clinic_id()
  AND request_id = :rid
LIMIT 1
"""


# -----------------------------
# Routes
# -----------------------------
@router.get("/governance-events", response_model=GovernanceEventsResponse)
def list_governance_events(
    request: Request,
    db: Session = Depends(get_db),
    limit: int = 50,
    cursor_created_at_utc: Optional[str] = None,
    cursor_request_id: Optional[uuid.UUID] = None,
) -> GovernanceEventsResponse:
    """
    Returns recent governance events for the current clinic only (RLS enforced).
    Cursor pagination returns events strictly "older than" the cursor.
    """
    # safety bounds
    limit = int(limit)
    if limit < 1:
        limit = 1
    if limit > 200:
        limit = 200

    cursor_clause = ""
    params: Dict[str, Any] = {"limit": limit}

    if cursor_created_at_utc:
        try:
            cursor_dt = _parse_iso8601(cursor_created_at_utc)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid cursor_created_at_utc")

        # If caller supplies created_at cursor but not request_id, use a max UUID
        # so we paginate correctly on ties.
        cursor_rid = cursor_request_id or uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")

        cursor_clause = "AND (created_at, request_id) < (:cursor_dt, :cursor_rid)"
        params["cursor_dt"] = cursor_dt
        params["cursor_rid"] = str(cursor_rid)

    sql = _SQL_LIST_EVENTS.format(cursor_clause=cursor_clause)
    rows = db.execute(text(sql), params).mappings().all()

    items: List[GovernanceEventItem] = []
    for r in rows:
        created = r.get("created_at")
        created_at_utc = created.isoformat() if hasattr(created, "isoformat") and created else ""

        items.append(
            GovernanceEventItem(
                request_id=uuid.UUID(str(r["request_id"])),
                clinic_id=uuid.UUID(str(r["clinic_id"])),
                user_id=uuid.UUID(str(r["user_id"])),
                mode=str(r["mode"]),

                decision=str(r["decision"]),
                risk_grade=str(r["risk_grade"]),
                reason_code=str(r["reason_code"]),

                pii_detected=bool(r["pii_detected"]),
                pii_action=str(r["pii_action"]),
                pii_types=list(r.get("pii_types") or []),

                policy_version=int(r["policy_version"]),
                neutrality_version=str(r["neutrality_version"]),
                governance_score=r.get("governance_score", None),

                created_at_utc=created_at_utc,
            )
        )

    # next cursor = last item in this page (for fetching older items)
    next_created = items[-1].created_at_utc if items else None
    next_rid = items[-1].request_id if items else None

    return GovernanceEventsResponse(
        items=items,
        next_cursor_created_at_utc=next_created,
        next_cursor_request_id=next_rid,
    )


@router.get("/receipt/{request_id}", response_model=GovernanceReceiptResponse)
def get_receipt(
    request_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> GovernanceReceiptResponse:
    """
    Fetch a single governance receipt by request_id for the current clinic only (RLS enforced).
    """
    row = db.execute(text(_SQL_GET_RECEIPT), {"rid": str(request_id)}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="receipt not found")

    created = row.get("created_at")
    created_at_utc = created.isoformat() if hasattr(created, "isoformat") and created else ""

    item = GovernanceEventItem(
        request_id=uuid.UUID(str(row["request_id"])),
        clinic_id=uuid.UUID(str(row["clinic_id"])),
        user_id=uuid.UUID(str(row["user_id"])),
        mode=str(row["mode"]),

        decision=str(row["decision"]),
        risk_grade=str(row["risk_grade"]),
        reason_code=str(row["reason_code"]),

        pii_detected=bool(row["pii_detected"]),
        pii_action=str(row["pii_action"]),
        pii_types=list(row.get("pii_types") or []),

        policy_version=int(row["policy_version"]),
        neutrality_version=str(row["neutrality_version"]),
        governance_score=row.get("governance_score", None),

        created_at_utc=created_at_utc,
    )

    return GovernanceReceiptResponse(receipt=item)
