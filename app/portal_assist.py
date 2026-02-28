# app/portal_assist.py
#
# Portal Assist (OUTPUT gate) — minimal endpoint that generates assistant output
# and applies governance replacement (neutrality scoring + hard-block rules).
#
# Privacy posture:
# - Does NOT store prompt or output content
# - Stores metadata-only in clinic_governance_events + ops_metrics_events
#
# This is the missing "Output Gate" that makes neutrality_v11 + governance.py real.

import json
import logging
import time
import uuid
import hashlib
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db
from app.portal_submit import (
    _set_rls_context,
    _get_active_policy_version,
    _get_policy_json,
    _canonical_json,
    _sha256_hex,
    detect_pii_types,
)
from app.portal_governance_engine import evaluate_input_governance, extract_neutrality_version
from app.governance import govern_output  # your output governance engine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal"],
    dependencies=[Depends(require_clinic_user)],
)

_ALLOWED_MODES = {"clinical_note", "client_comm", "internal_summary"}


# ----------------------------
# Models
# ----------------------------

class PortalAssistRequest(BaseModel):
    mode: str = Field(..., description="clinical_note | client_comm | internal_summary")
    text: str = Field(..., min_length=1, max_length=20000)
    request_id: Optional[uuid.UUID] = Field(default=None)

    # Optional: lightweight instruction for drafting style (NOT stored)
    instruction: Optional[str] = Field(default=None, max_length=1000)

    # R1
    ai_assisted: bool = Field(default=True)
    user_confirmed_review: bool = Field(default=False)


class PortalAssistResponse(BaseModel):
    request_id: uuid.UUID
    mode: str
    final_text: str

    # Governance metadata (safe to return)
    decision: str               # allowed | replaced | blocked
    reason_code: str
    risk_grade: str
    pii_detected: bool
    pii_action: str
    pii_types: List[str]

    policy_version: int
    neutrality_version: str
    governance_score: Optional[float] = None
    governance_grade: Optional[str] = None
    governance_replaced: bool = False

    # M2.7
    policy_sha256: Optional[str] = None
    rules_fired: Optional[dict] = None

    created_at_utc: str


# ----------------------------
# Helpers
# ----------------------------

def _compute_event_sha256(*, clinic_id: uuid.UUID, request_id: uuid.UUID, policy_sha256: Optional[str], meta: Dict[str, Any]) -> str:
    base = {
        "clinic_id": str(clinic_id),
        "request_id": str(request_id),
        "policy_sha256": policy_sha256,
        "meta": meta,
    }
    return _sha256_hex(_canonical_json(base))


def _now_iso_utc() -> str:
    # avoid importing datetime; keep simple + consistent with other modules
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _stub_llm_generate(*, mode: str, user_text: str, instruction: Optional[str]) -> str:
    """
    Replace this with a real model call later.
    For now: deterministic draft scaffolding so the route works end-to-end.
    """
    t = (user_text or "").strip()
    instr = (instruction or "").strip()

    if mode == "clinical_note":
        style = instr or "Write a concise SOAP-style clinical note."
        return (
            f"{style}\n\n"
            "S:\n"
            f"- {t}\n\n"
            "O:\n"
            "- \n\n"
            "A:\n"
            "- \n\n"
            "P:\n"
            "- \n"
        )

    if mode == "client_comm":
        style = instr or "Write a friendly, professional client update."
        return (
            f"{style}\n\n"
            "Hello,\n\n"
            f"{t}\n\n"
            "Kind regards,\n"
        )

    # internal_summary
    style = instr or "Summarise clearly for internal handover."
    return f"{style}\n\n- {t}\n"


# ----------------------------
# POST /assist
# ----------------------------

@router.post("/assist", response_model=PortalAssistResponse)
def portal_assist(payload: PortalAssistRequest, request: Request, db: Session = Depends(get_db)):
    t0 = time.monotonic()

    mode = (payload.mode or "").strip()
    if mode not in _ALLOWED_MODES:
        raise HTTPException(status_code=400, detail="invalid mode")

    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    _set_rls_context(db, clinic_id=clinic_id, clinic_user_id=clinic_user_id)

    req_id = payload.request_id or uuid.uuid4()

    # Load active policy JSON
    policy_version = _get_active_policy_version(db)
    policy_obj = _get_policy_json(db, policy_version=policy_version)
    policy_sha256 = _sha256_hex(_canonical_json(policy_obj)) if policy_obj is not None else None
    neutrality_version = extract_neutrality_version(policy_obj)

    # -------- INPUT GATE (metadata only)
    pii_types = detect_pii_types(payload.text)
    ig = evaluate_input_governance(
        text_value=payload.text,
        pii_types=pii_types,
        mode=mode,
        policy=policy_obj,
    )

    if ig.decision == "blocked":
        # We do not generate model output if input is blocked
        final_text = "Submission blocked by clinic policy."
        governance_replaced = False
        out_decision = "blocked"
        out_reason_code = ig.reason_code
        risk_grade = ig.risk_grade
        governance_score = None
        governance_grade = None
        rules_fired = ig.rules_fired
    else:
        # -------- GENERATE candidate assistant output (stub for now)
        candidate = _stub_llm_generate(
            mode=mode,
            user_text=payload.text,
            instruction=payload.instruction,
        )

        # -------- OUTPUT GATE (neutrality + hard rules)
        # Inject policy keys expected by app.governance.govern_output
        gov_policy = dict(policy_obj or {})
        gov_policy.setdefault("policy_version", f"clinic-policy-v{policy_version}")
        gov_policy.setdefault("neutrality_version", neutrality_version)

        final_text, decision_obj, audit = govern_output(
            user_text=payload.text,
            assistant_text=candidate,
            user_id=None,
            session_id=None,
            mode=mode,
            debug=False,
            policy=gov_policy,
        )

        governance_replaced = bool(getattr(decision_obj, "replaced", False))
        out_decision = "replaced" if governance_replaced else "allowed"

        governance_score = float(getattr(decision_obj, "score", 0) or 0)
        governance_grade = str(getattr(decision_obj, "grade", "") or "")
        # reason_code here reflects output gate; keep input gate reason_code separate
        out_reason_code = f"output_{getattr(decision_obj, 'reason', 'allowed')}"
        risk_grade = "med" if governance_replaced else ig.risk_grade

        # Combine explainability (M2.7): input + output
        rules_fired = {
            "input": ig.rules_fired,
            "output": (audit.get("decision_trace") if isinstance(audit, dict) else None),
        }

    # Metadata-only fingerprint for this request
    event_sha256 = _compute_event_sha256(
        clinic_id=clinic_id,
        request_id=req_id,
        policy_sha256=policy_sha256,
        meta={
            "mode": mode,
            "decision": out_decision,
            "risk_grade": risk_grade,
            "reason_code": out_reason_code,
            "pii_detected": bool(ig.pii_detected),
            "pii_action": ig.pii_action,
            "pii_types": pii_types,
            "policy_version": policy_version,
            "neutrality_version": neutrality_version,
            "governance_score": governance_score,
            "governance_grade": governance_grade,
            "governance_replaced": governance_replaced,
            "ai_assisted": bool(payload.ai_assisted),
            "user_confirmed_review": bool(payload.user_confirmed_review),
        },
    )

    clinic_id_s = str(clinic_id)
    clinic_user_id_s = str(clinic_user_id)
    req_id_s = str(req_id)

    try:
        # Persist governance metadata ONLY
        gov_row = (
            db.execute(
                text(
                    """
                    INSERT INTO clinic_governance_events (
                      clinic_id, request_id, user_id, mode,
                      pii_detected, pii_action, pii_types,
                      decision, risk_grade, reason_code,
                      governance_score, policy_version, neutrality_version,
                      ai_assisted, user_confirmed_review,
                      policy_sha256, rules_fired, event_sha256
                    )
                    VALUES (
                      :clinic_id, :request_id, :user_id, :mode,
                      :pii_detected, :pii_action, :pii_types,
                      :decision, :risk_grade, :reason_code,
                      :governance_score, :policy_version, :neutrality_version,
                      :ai_assisted, :user_confirmed_review,
                      :policy_sha256, CAST(:rules_fired AS jsonb), :event_sha256
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
                    "pii_detected": bool(ig.pii_detected),
                    "pii_action": ig.pii_action,
                    "pii_types": pii_types,
                    "decision": out_decision,
                    "risk_grade": risk_grade,
                    "reason_code": out_reason_code,
                    "governance_score": governance_score,
                    "policy_version": int(policy_version),
                    "neutrality_version": neutrality_version,
                    "ai_assisted": bool(payload.ai_assisted),
                    "user_confirmed_review": bool(payload.user_confirmed_review),
                    "policy_sha256": policy_sha256,
                    "rules_fired": _canonical_json(rules_fired) if rules_fired is not None else None,
                    "event_sha256": event_sha256,
                },
            )
            .fetchone()
        )

        latency_ms = int(max(0.0, (time.monotonic() - t0) * 1000.0))
        status_code = 200

        db.execute(
            text(
                """
                INSERT INTO ops_metrics_events (
                  clinic_id, request_id, route, status_code, latency_ms,
                  mode, governance_replaced, pii_warned
                )
                VALUES (
                  :clinic_id, :request_id, :route, :status_code, :latency_ms,
                  :mode, :governance_replaced, :pii_warned
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
                "governance_replaced": bool(governance_replaced),
                "pii_warned": bool(ig.pii_detected and ig.pii_action == "warn"),
            },
        )

        db.commit()

        created_at = None
        if gov_row:
            created_at = gov_row[0] if len(gov_row) > 0 else None
        created_at_utc = created_at.isoformat() if created_at is not None else _now_iso_utc()

        return PortalAssistResponse(
            request_id=req_id,
            mode=mode,
            final_text=final_text,
            decision=out_decision,
            reason_code=out_reason_code,
            risk_grade=risk_grade,
            pii_detected=bool(ig.pii_detected),
            pii_action=ig.pii_action,
            pii_types=pii_types,
            policy_version=int(policy_version),
            neutrality_version=neutrality_version,
            governance_score=governance_score,
            governance_grade=governance_grade,
            governance_replaced=bool(governance_replaced),
            policy_sha256=policy_sha256,
            rules_fired=rules_fired,
            created_at_utc=created_at_utc,
        )

    except HTTPException:
        try:
            db.rollback()
        except Exception:
            pass
        raise

    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        logger.exception(
            "portal_assist_failed",
            extra={
                "route": getattr(request.url, "path", None),
                "request_id": str(req_id),
                "clinic_id": str(clinic_id),
                "clinic_user_id": str(clinic_user_id),
                "mode": mode,
            },
        )
        raise HTTPException(status_code=500, detail="internal_server_error")
