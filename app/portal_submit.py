# app/portal_submit.py
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.db import SessionLocal
from app.auth_and_rls import require_clinic_user, set_rls_context

router = APIRouter(prefix="/v1/portal", tags=["Portal Submit"])

# -----------------------------
# Simple PII detection (no values stored)
# -----------------------------
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"\b(\+?\d[\d\s().-]{7,}\d)\b")
_UK_POSTCODE_RE = re.compile(
    r"\b([A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2})\b", re.IGNORECASE
)

def detect_pii_types(text_value: str) -> List[str]:
    t = text_value or ""
    types: List[str] = []

    if _EMAIL_RE.search(t):
        types.append("email")
    if _PHONE_RE.search(t):
        types.append("phone")
    if _UK_POSTCODE_RE.search(t):
        types.append("postcode")

    # De-dupe, stable order
    seen = set()
    out = []
    for x in types:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# -----------------------------
# Portal policy helpers
# -----------------------------
def _get_active_policy_version(db) -> int:
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
        # If a clinic is bootstrapped properly this should exist,
        # but keep a safe fallback.
        return 1
    try:
        return int(row[0])
    except Exception:
        return 1


def _simple_risk_grade(pii_types: List[str]) -> str:
    # Conservative default: any PII -> medium, none -> low.
    return "med" if pii_types else "low"


def _simple_reason_code(pii_types: List[str]) -> str:
    return "pii_detected" if pii_types else "ok"


# -----------------------------
# Schemas
# -----------------------------
class PortalSubmitRequest(BaseModel):
    mode: str = Field(..., description="clinical_note | client_comm | internal_summary")
    text: str = Field(..., min_length=1, max_length=20000)
    request_id: Optional[uuid.UUID] = Field(
        default=None,
        description="Optional client-generated request_id for idempotency/traceability",
    )

    # NOTE: We intentionally do NOT accept or store any structured patient identifiers here.
    # If later needed, they should be provided as hashed/pseudonymous tokens only.


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


# -----------------------------
# Route
# -----------------------------
@router.post("/submit", response_model=PortalSubmitResponse)
def portal_submit(
    payload: PortalSubmitRequest,
    request: Request,
    actor: Dict[str, str] = Depends(require_clinic_user),
) -> PortalSubmitResponse:
    """
    Metadata-only portal submission.
    - Requires clinic JWT (Bearer)
    - Sets RLS context on the DB connection
    - Writes:
        * clinic_governance_events (metadata only)
        * ops_metrics_events (telemetry only)
    - Returns a "Governance Receipt"
    """

    t0 = time.time()
    mode = (payload.mode or "").strip()

    allowed_modes = {"clinical_note", "client_comm", "internal_summary"}
    if mode not in allowed_modes:
        raise HTTPException(status_code=400, detail="invalid mode")

    clinic_id = actor["clinic_id"]
    clinic_user_id = actor["clinic_user_id"]

    # stable request_id for receipt
    req_id = payload.request_id or uuid.uuid4()

    # PII detection (types only; never store matches)
    pii_types = detect_pii_types(payload.text)
    pii_detected = bool(pii_types)

    # Simple action semantics:
    # - For now: allow if no PII, warn if PII (do not redact here; you are metadata-only).
    # - Later: wire to clinic privacy profile / policy for allow|warn|block|redact.
    pii_action = "warn" if pii_detected else "allow"

    # Governance decision semantics (portal table expects allowed|blocked|replaced|modified)
    # - For now: if pii_detected -> "modified" (means "requires review"), else "allowed".
    decision = "modified" if pii_detected else "allowed"
    risk_grade = _simple_risk_grade(pii_types)
    reason_code = _simple_reason_code(pii_types)

    # No content storage, so "governance_score" is optional; keep null for now.
    governance_score = None
    neutrality_version = "v1.1"

    # latency
    latency_ms = int((time.time() - t0) * 1000)
    status_code = 200

    with SessionLocal() as db:
        # Set tenant context for RLS on this connection.
        set_rls_context(db, clinic_id=str(clinic_id), user_id=str(clinic_user_id))

        policy_version = _get_active_policy_version(db)

        # Write portal governance metadata
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
                    :decision, :risk_grade, :reason_code,
                    :governance_score, :policy_version, :neutrality_version
                )
                """
            ),
            {
                "clinic_id": str(clinic_id),
                "request_id": str(req_id),
                "user_id": str(clinic_user_id),
                "mode": mode,
                "pii_detected": bool(pii_detected),
                "pii_action": pii_action,
                "pii_types": pii_types if pii_types else None,  # column is text[]; None => NULL
                "decision": decision,
                "risk_grade": risk_grade,
                "reason_code": reason_code,
                "governance_score": governance_score,
                "policy_version": int(policy_version),
                "neutrality_version": neutrality_version,
            },
        )

        # Write ops telemetry (still no content)
        db.execute(
            text(
                """
                INSERT INTO ops_metrics_events (
                    clinic_id, request_id, route, status_code, latency_ms,
                    mode, governance_replaced
                )
                VALUES (
                    :clinic_id, :request_id, :route, :status_code, :latency_ms,
                    :mode, :gov_replaced
                )
                """
            ),
            {
                "clinic_id": str(clinic_id),
                "request_id": str(req_id),
                "route": request.url.path,
                "status_code": int(status_code),
                "latency_ms": int(latency_ms),
                "mode": mode,
                "gov_replaced": bool(decision in {"replaced", "modified"}),
            },
        )

        db.commit()

        # created_at is NOW() in DB; to keep things simple, return server time.
        created_at_utc = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())

    receipt = GovernanceReceipt(
        request_id=req_id,
        clinic_id=uuid.UUID(str(clinic_id)),
        clinic_user_id=uuid.UUID(str(clinic_user_id)),
        mode=mode,
        decision=decision,
        risk_grade=risk_grade,
        reason_code=reason_code,
        pii_detected=pii_detected,
        pii_action=pii_action,
        pii_types=pii_types,
        policy_version=int(policy_version),
        neutrality_version=neutrality_version,
        governance_score=governance_score,
        created_at_utc=created_at_utc,
    )

    return PortalSubmitResponse(receipt=receipt)
