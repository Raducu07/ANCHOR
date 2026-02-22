import re
import time
import uuid
from typing import List, Optional, Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal Submit"],
    dependencies=[Depends(require_clinic_user)],
)

_ALLOWED_MODES = {"clinical_note", "client_comm", "internal_summary"}

_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"\b(\+?\d[\d\s().-]{7,}\d)\b")
_UK_POSTCODE_RE = re.compile(r"\b([A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2})\b", re.IGNORECASE)


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


class PortalSubmitRequest(BaseModel):
    mode: str = Field(..., description="clinical_note | client_comm | internal_summary")
    text: str = Field(..., min_length=1, max_length=20000)
    request_id: Optional[uuid.UUID] = Field(
        default=None,
        description="Optional client-generated request_id for idempotency/traceability",
    )


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


def _fetch_existing_receipt(db: Session, clinic_id: str, request_id: str) -> GovernanceReceipt:
    row = (
        db.execute(
            text(
                """
                SELECT
                  request_id,
                  clinic_id,
                  user_id AS clinic_user_id,
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
                WHERE clinic_id = :clinic_id
                  AND request_id = :request_id
                ORDER BY created_at ASC
                LIMIT 1
                """
            ),
            {"clinic_id": clinic_id, "request_id": request_id},
        )
        .mappings()
        .first()
    )

    if not row:
        raise HTTPException(status_code=500, detail="idempotency fetch failed")

    created_at = row["created_at"]
    created_iso = created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at)

    return GovernanceReceipt(
        request_id=uuid.UUID(str(row["request_id"])),
        clinic_id=uuid.UUID(str(row["clinic_id"])),
        clinic_user_id=uuid.UUID(str(row["clinic_user_id"])),
        mode=str(row["mode"]),
        decision=str(row["decision"]),
        risk_grade=str(row["risk_grade"]),
        reason_code=str(row["reason_code"]),
        pii_detected=bool(row["pii_detected"]),
        pii_action=str(row["pii_action"]),
        pii_types=list(row["pii_types"] or []),
        policy_version=int(row["policy_version"]),
        neutrality_version=str(row["neutrality_version"]),
        governance_score=(float(row["governance_score"]) if row["governance_score"] is not None else None),
        created_at_utc=created_iso,
    )


@router.post("/submit", response_model=PortalSubmitResponse)
def portal_submit(
    payload: PortalSubmitRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> PortalSubmitResponse:
    t0 = time.time()

    mode = (payload.mode or "").strip()
    if mode not in _ALLOWED_MODES:
        raise HTTPException(status_code=400, detail="invalid mode")

    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    req_id = payload.request_id or uuid.uuid4()

    pii_types = detect_pii_types(payload.text)
    pii_detected = bool(pii_types)

    pii_action = "warn" if pii_detected else "allow"
    decision = "allowed"

    risk_grade = _simple_risk_grade(pii_types)
    reason_code = _simple_reason_code(pii_types)

    governance_score = None
    neutrality_version = "v1.1"
    policy_version = _get_active_policy_version(db)

    latency_ms = int((time.time() - t0) * 1000)
    status_code = 200

    clinic_id_s = str(clinic_id)
    clinic_user_id_s = str(clinic_user_id)
    req_id_s = str(req_id)

    # 1) Insert governance metadata (idempotent)
    gov_result = db.execute(
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
              :decision, :risk_grade, :reason_code,
              :governance_score, :policy_version, :neutrality_version
            )
            ON CONFLICT (clinic_id, request_id) DO NOTHING
            RETURNING created_at
            """
        ),
        {
            "clinic_id": clinic_id_s,
            "request_id": req_id_s,
            "user_id": clinic_user_id_s,
            "mode": mode,
            "pii_detected": bool(pii_detected),
            "pii_action": pii_action,
            "pii_types": pii_types if pii_types else None,
            "decision": decision,
            "risk_grade": risk_grade,
            "reason_code": reason_code,
            "governance_score": governance_score,
            "policy_version": int(policy_version),
            "neutrality_version": neutrality_version,
        },
    ).mappings().first()

    inserted_new = gov_result is not None

    # 2) Insert ops telemetry (idempotent)
    #    IMPORTANT: pii_warned is hygiene-only, NOT an intervention.
    pii_warned = bool(pii_detected)
    governance_replaced = False

    db.execute(
        text(
            """
            INSERT INTO ops_metrics_events (
              clinic_id, request_id, route, status_code, latency_ms,
              mode, governance_replaced, pii_warned
            )
            VALUES (
              :clinic_id, :request_id, :route, :status_code, :latency_ms,
              :mode, :gov_replaced, :pii_warned
            )
            ON CONFLICT (clinic_id, request_id) DO NOTHING
            """
        ),
        {
            "clinic_id": clinic_id_s,
            "request_id": req_id_s,
            "route": request.url.path,
            "status_code": int(status_code),
            "latency_ms": int(latency_ms),
            "mode": mode,
            "gov_replaced": bool(governance_replaced),
            "pii_warned": bool(pii_warned),
        },
    )

    db.commit()

    # 3) Return receipt
    if inserted_new:
        created_at = gov_result["created_at"]
        created_iso = created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at)

        receipt = GovernanceReceipt(
            request_id=req_id,
            clinic_id=uuid.UUID(clinic_id_s),
            clinic_user_id=uuid.UUID(clinic_user_id_s),
            mode=mode,
            decision=decision,
            risk_grade=risk_grade,
            reason_code=reason_code,
            pii_detected=pii_detected,
            pii_action=pii_action,
            pii_types=list(pii_types) if pii_types else [],
            policy_version=int(policy_version),
            neutrality_version=neutrality_version,
            governance_score=governance_score,
            created_at_utc=created_iso,
        )
        return PortalSubmitResponse(receipt=receipt)

    # Existing request_id: fetch canonical receipt and enforce strict mismatch checks
    existing = _fetch_existing_receipt(db, clinic_id=clinic_id_s, request_id=req_id_s)

    if existing.mode != mode:
        raise HTTPException(
            status_code=409,
            detail="idempotency conflict: request_id replayed with different mode",
        )

    if str(existing.clinic_user_id) != clinic_user_id_s:
        raise HTTPException(
            status_code=409,
            detail="idempotency conflict: request_id replayed by different clinic_user_id",
        )

    return PortalSubmitResponse(receipt=existing)
