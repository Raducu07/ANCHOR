# app/portal_submit.py
import uuid
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.auth_and_rls import require_clinic_user
from app.governance import govern_output

router = APIRouter(tags=["Portal Submit"])


# -----------------------------
# Schemas
# -----------------------------
class PortalSubmitRequest(BaseModel):
    mode: str = Field(..., description="clinical_note | client_comm | internal_summary")
    user_text: str = Field(..., min_length=1, max_length=20000)
    assistant_text: str = Field(..., min_length=1, max_length=20000)
    debug: bool = False


class GovernanceReceipt(BaseModel):
    request_id: str
    clinic_id: str
    clinic_user_id: str
    mode: str

    decision: str              # allowed | blocked | replaced | modified
    risk_grade: str            # low | med | high
    reason_code: str

    governance_score: float
    grade: str
    replaced: bool
    allowed: bool

    policy_version: int
    neutrality_version: str

    pii_detected: bool
    pii_action: str
    pii_types: Optional[List[str]] = None

    created_at: str


class PortalSubmitResponse(BaseModel):
    reply_text: str
    receipt: GovernanceReceipt


# -----------------------------
# Helpers
# -----------------------------
def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _map_risk_grade(score: int, grade: str, replaced: bool, min_allow: int) -> str:
    # Simple, deterministic. You can refine later.
    if not replaced and grade != "fail" and score >= min_allow:
        return "low"
    if grade == "fail" or score < max(0, min_allow - 10):
        return "high"
    return "med"


def _load_active_policy(db: Session, clinic_id: str) -> Dict[str, Any]:
    """
    Loads the active policy JSON for the clinic.
    Uses clinic_policy_state.active_policy_version -> clinic_policies.policy_json
    """
    row = db.execute(
        text("""
            SELECT s.active_policy_version AS v
            FROM clinic_policy_state s
            WHERE s.clinic_id = :cid
            LIMIT 1
        """),
        {"cid": clinic_id},
    ).mappings().first()

    if not row:
        raise HTTPException(status_code=400, detail="clinic has no active policy_state")

    v = int(row["v"])

    prow = db.execute(
        text("""
            SELECT p.policy_json
            FROM clinic_policies p
            WHERE p.clinic_id = :cid AND p.policy_version = :v
            LIMIT 1
        """),
        {"cid": clinic_id, "v": v},
    ).mappings().first()

    if not prow:
        raise HTTPException(status_code=400, detail="active policy version not found")

    # SQLAlchemy returns jsonb as dict already
    policy_json = prow["policy_json"] or {}
    if not isinstance(policy_json, dict):
        raise HTTPException(status_code=500, detail="policy_json is not an object")

    policy_json["_policy_version_int"] = v
    return policy_json


def _mode_pii_action(policy_json: Dict[str, Any], mode: str) -> str:
    # Default to warn if unknown
    defaults = (policy_json.get("mode_defaults") or {})
    if isinstance(defaults, dict):
        m = defaults.get(mode) or {}
        if isinstance(m, dict):
            pa = (m.get("pii_action") or "").strip()
            if pa in ("allow", "warn", "block", "redact"):
                return pa
    return "warn"


# -----------------------------
# Route
# -----------------------------
@router.post("/v1/portal/submit", response_model=PortalSubmitResponse)
def portal_submit(
    req: PortalSubmitRequest,
    request: Request,
    db: Session = Depends(get_db),
    ctx: Dict[str, str] = Depends(require_clinic_user),
) -> PortalSubmitResponse:
    """
    Portal submit (clinic-scoped, RLS-safe).

    - DOES NOT store raw content in DB
    - Stores metadata-only governance + ops telemetry
    - Returns a Governance Receipt
    """
    start = time.time()
    request_id = str(uuid.uuid4())

    clinic_id = str(ctx["clinic_id"])
    clinic_user_id = str(ctx["clinic_user_id"])
    mode = (req.mode or "").strip()

    if mode not in ("clinical_note", "client_comm", "internal_summary"):
        raise HTTPException(status_code=422, detail="mode must be clinical_note | client_comm | internal_summary")

    # Load active clinic policy JSON
    policy_json = _load_active_policy(db, clinic_id=clinic_id)
    policy_version_int = int(policy_json.get("_policy_version_int", 1))

    # Map portal policy into governance engine policy shape
    # Your govern_output expects: policy_version(str), neutrality_version(str), min_score_allow, hard_block_rules, soft_rules, max_findings
    # We'll default safely if fields absent.
    engine_policy: Dict[str, Any] = {
        "policy_version": f"clinic-{policy_version_int}",
        "neutrality_version": str(policy_json.get("neutrality_version") or "n-v1.1"),
        "min_score_allow": int(policy_json.get("min_score_allow") or 75),
        "hard_block_rules": list(policy_json.get("hard_block_rules") or ["jailbreak", "therapy", "promise"]),
        "soft_rules": list(policy_json.get("soft_rules") or ["direct_advice", "coercion"]),
        "max_findings": int(policy_json.get("max_findings") or 10),
    }

    # PII policy (metadata only)
    pii_action = _mode_pii_action(policy_json, mode=mode)
    pii_detected = False
    pii_types: Optional[List[str]] = None

    # Run governance decision on provided assistant_text
    status_code = 200
    final_text = ""
    try:
        final_text, decision, audit = govern_output(
            user_text=req.user_text,
            assistant_text=req.assistant_text,
            user_id=None,         # portal uses clinic_users; we keep v0 user_id NULL
            session_id=None,
            mode=mode,
            debug=bool(req.debug),
            policy=engine_policy,
        )

        # Map to portal decision enums
        if decision.replaced:
            portal_decision = "replaced"
        elif decision.allowed:
            portal_decision = "allowed"
        else:
            portal_decision = "blocked"

        min_allow = int(engine_policy["min_score_allow"])
        risk_grade = _map_risk_grade(decision.score, decision.grade, decision.replaced, min_allow=min_allow)
        reason_code = str(decision.reason or "allowed")

        created_at = _now_utc_iso()

        # Write clinic_governance_events (metadata-only)
        db.execute(
            text("""
                INSERT INTO clinic_governance_events
                  (clinic_id, request_id, user_id, mode,
                   pii_detected, pii_action, pii_types,
                   decision, risk_grade, reason_code,
                   governance_score, policy_version, neutrality_version, created_at)
                VALUES
                  (:clinic_id, :request_id, :user_id, :mode,
                   :pii_detected, :pii_action, :pii_types,
                   :decision, :risk_grade, :reason_code,
                   :governance_score, :policy_version, :neutrality_version, now())
            """),
            {
                "clinic_id": clinic_id,
                "request_id": request_id,
                "user_id": clinic_user_id,
                "mode": mode,
                "pii_detected": bool(pii_detected),
                "pii_action": pii_action,
                "pii_types": pii_types,
                "decision": portal_decision,
                "risk_grade": risk_grade,
                "reason_code": reason_code,
                "governance_score": float(decision.score),
                "policy_version": int(policy_version_int),
                "neutrality_version": str(engine_policy["neutrality_version"]),
            },
        )

        # Write ops_metrics_events (telemetry-only)
        latency_ms = int(max(0.0, (time.time() - start) * 1000.0))
        db.execute(
            text("""
                INSERT INTO ops_metrics_events
                  (clinic_id, request_id, route, status_code, latency_ms, mode, governance_replaced, created_at)
                VALUES
                  (:clinic_id, :request_id, :route, :status_code, :latency_ms, :mode, :gov_replaced, now())
            """),
            {
                "clinic_id": clinic_id,
                "request_id": request_id,
                "route": "/v1/portal/submit",
                "status_code": int(status_code),
                "latency_ms": int(latency_ms),
                "mode": mode,
                "gov_replaced": bool(decision.replaced),
            },
        )

        db.commit()

        receipt = GovernanceReceipt(
            request_id=request_id,
            clinic_id=clinic_id,
            clinic_user_id=clinic_user_id,
            mode=mode,
            decision=portal_decision,
            risk_grade=risk_grade,
            reason_code=reason_code,
            governance_score=float(decision.score),
            grade=str(decision.grade),
            replaced=bool(decision.replaced),
            allowed=bool(decision.allowed),
            policy_version=int(policy_version_int),
            neutrality_version=str(engine_policy["neutrality_version"]),
            pii_detected=bool(pii_detected),
            pii_action=pii_action,
            pii_types=pii_types,
            created_at=created_at,
        )

        return PortalSubmitResponse(reply_text=final_text, receipt=receipt)

    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        status_code = 500
        # best-effort ops log
        try:
            latency_ms = int(max(0.0, (time.time() - start) * 1000.0))
            db.execute(
                text("""
                    INSERT INTO ops_metrics_events
                      (clinic_id, request_id, route, status_code, latency_ms, mode, governance_replaced, created_at)
                    VALUES
                      (:clinic_id, :request_id, :route, :status_code, :latency_ms, :mode, false, now())
                """),
                {
                    "clinic_id": clinic_id,
                    "request_id": request_id,
                    "route": "/v1/portal/submit",
                    "status_code": int(status_code),
                    "latency_ms": int(latency_ms),
                    "mode": mode,
                },
            )
            db.commit()
        except Exception:
            db.rollback()

        raise HTTPException(status_code=500, detail=f"portal_submit failed: {type(e).__name__}: {e}")
