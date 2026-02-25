# app/portal_receipt.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.clinic_auth import require_clinic_user  # type: ignore


router = APIRouter(prefix="/v1/portal", tags=["portal"])


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class GovernanceReceipt(BaseModel):
    request_id: str
    created_at: str

    clinic_user_id: str
    mode: str
    route: str

    decision: str
    reason_code: Optional[str] = None

    policy_version: Optional[str] = None
    strictness: Optional[float] = None

    # PII fields (if present in your table)
    pii_action: Optional[str] = None

    # --- R1 fields ---
    ai_assisted: Optional[bool] = None
    user_confirmed_review: Optional[bool] = None

    # --- R3 fields ---
    override_flag: Optional[bool] = None
    override_reason: Optional[str] = None
    override_at: Optional[str] = None


class OverrideRequest(BaseModel):
    override_reason: str = Field(..., min_length=2, max_length=2000)


class OverrideResponse(BaseModel):
    status: str
    request_id: str
    override_flag: bool
    override_reason: str
    override_at: str


@router.get("/receipt/{request_id}", response_model=GovernanceReceipt)
def get_receipt(
    request_id: str,
    db: Session = Depends(get_db),
    auth: Dict[str, Any] = Depends(require_clinic_user),
):
    """
    R2: Governance Receipt (metadata-only, clinic-scoped via RLS + clinic_id filter).
    """
    clinic_id = str(auth.get("clinic_id"))
    if not clinic_id:
        raise HTTPException(status_code=401, detail="unauthorized")

    q = text(
        """
        SELECT
            request_id,
            created_at,
            clinic_user_id,
            mode,
            route,
            decision,
            reason_code,
            policy_version,
            strictness,
            pii_action,
            ai_assisted,
            user_confirmed_review,
            override_flag,
            override_reason,
            override_at
        FROM governance_events
        WHERE clinic_id = :clinic_id
          AND request_id = :request_id
        LIMIT 1
        """
    )

    row = db.execute(q, {"clinic_id": clinic_id, "request_id": request_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="not_found")

    # Ensure ISO strings
    def iso(v):
        if v is None:
            return None
        if hasattr(v, "isoformat"):
            return v.isoformat()
        return str(v)

    return GovernanceReceipt(
        request_id=str(row["request_id"]),
        created_at=iso(row["created_at"]) or "",
        clinic_user_id=str(row["clinic_user_id"]),
        mode=str(row["mode"]),
        route=str(row["route"]),
        decision=str(row["decision"]),
        reason_code=row.get("reason_code"),
        policy_version=row.get("policy_version"),
        strictness=row.get("strictness"),
        pii_action=row.get("pii_action"),
        ai_assisted=row.get("ai_assisted"),
        user_confirmed_review=row.get("user_confirmed_review"),
        override_flag=row.get("override_flag"),
        override_reason=row.get("override_reason"),
        override_at=iso(row.get("override_at")),
    )


@router.post("/override/{request_id}", response_model=OverrideResponse)
def override_event(
    request_id: str,
    payload: OverrideRequest,
    db: Session = Depends(get_db),
    auth: Dict[str, Any] = Depends(require_clinic_user),
):
    """
    R3: Override logging.

    Security:
      - same clinic_id
      - only the author (clinic_user_id) can override their own event
    """
    clinic_id = str(auth.get("clinic_id"))
    clinic_user_id = str(auth.get("clinic_user_id"))
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="unauthorized")

    now = datetime.now(timezone.utc).isoformat()

    q = text(
        """
        UPDATE governance_events
        SET
            override_flag = true,
            override_reason = :override_reason,
            override_at = :override_at
        WHERE clinic_id = :clinic_id
          AND request_id = :request_id
          AND clinic_user_id = :clinic_user_id
        RETURNING request_id, override_flag, override_reason, override_at
        """
    )

    row = (
        db.execute(
            q,
            {
                "clinic_id": clinic_id,
                "request_id": request_id,
                "clinic_user_id": clinic_user_id,
                "override_reason": payload.override_reason.strip(),
                "override_at": now,
            },
        )
        .mappings()
        .first()
    )

    if not row:
        # Either not found OR not owned by this clinic_user_id
        raise HTTPException(status_code=404, detail="not_found_or_not_owner")

    db.commit()

    return OverrideResponse(
        status="ok",
        request_id=str(row["request_id"]),
        override_flag=bool(row["override_flag"]),
        override_reason=str(row["override_reason"]),
        override_at=str(row["override_at"]),
    )
