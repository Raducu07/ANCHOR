from __future__ import annotations

# app/portal_assist.py
#
# Portal Assist (OUTPUT gate) — minimal endpoint that generates assistant output
# and applies governance replacement (neutrality scoring + hard-block rules).
#
# Privacy posture:
# - Does NOT store prompt or output content
# - Stores metadata-only in clinic_governance_events + ops_metrics_events
#
# Important note:
# - This endpoint still uses a deterministic drafting layer (_stub_llm_generate)
#   rather than a real model provider.
# - The changes below make that drafting layer substantially better while keeping
#   ANCHOR within purpose: governed drafting support, not clinical decision-making AI.

import logging
import re
import time
import uuid
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
from app.governance import govern_output

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

    # Optional: lightweight instruction for drafting style (NOT stored, NOT echoed)
    instruction: Optional[str] = Field(default=None, max_length=1000)

    # Optional control-plane context from Workspace
    role: Optional[str] = Field(default=None, max_length=100)

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

_SOAP_S_RE = re.compile(r"(?im)^\s*S:\s*")
_SOAP_O_RE = re.compile(r"(?im)^\s*O:\s*")
_SOAP_A_RE = re.compile(r"(?im)^\s*A:\s*")
_SOAP_P_RE = re.compile(r"(?im)^\s*P:\s*")

def _looks_like_soap(text_value: str) -> bool:
    """
    Heuristic: if the note already contains S:, O:, A:, P: headings on separate lines.
    """
    t = (text_value or "")
    return bool(_SOAP_S_RE.search(t) and _SOAP_O_RE.search(t) and _SOAP_A_RE.search(t) and _SOAP_P_RE.search(t))


def _compute_event_sha256(
    *,
    clinic_id: uuid.UUID,
    request_id: uuid.UUID,
    policy_sha256: Optional[str],
    meta: Dict[str, Any],
) -> str:
    base = {
        "clinic_id": str(clinic_id),
        "request_id": str(request_id),
        "policy_sha256": policy_sha256,
        "meta": meta,
    }
    return _sha256_hex(_canonical_json(base))


def _now_iso_utc() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _sanitize_instruction(instr: Optional[str]) -> str:
    """
    Control-plane only: used to guide generation, never included verbatim in output.
    Keep it low-risk, short, and non-directive.
    """
    s = (instr or "").strip()
    if not s:
        return ""
    s = re.sub(r"\s+", " ", s).strip()
    return s[:1000]


def _normalize_whitespace(text_value: str) -> str:
    return re.sub(r"\s+", " ", (text_value or "").strip()).strip()


def _non_empty_lines(text_value: str) -> List[str]:
    lines = []
    for raw in (text_value or "").splitlines():
        cleaned = raw.strip()
        if not cleaned:
            continue
        cleaned = re.sub(r"^[\-\*\u2022]+\s*", "", cleaned)
        lines.append(cleaned)
    return lines


def _word_count(text_value: str) -> int:
    trimmed = (text_value or "").strip()
    if not trimmed:
        return 0
    return len(re.findall(r"\S+", trimmed))


def _looks_like_email_already(text_value: str) -> bool:
    t = (text_value or "").strip()
    if not t:
        return False
    return bool(re.match(r"(?is)^\s*(hello|hi|dear)\b", t))


def _extract_case_reference(text_value: str) -> str:
    """
    Try to recover a light case reference without inventing detail.
    """
    t = _normalize_whitespace(text_value)
    m = re.search(r"\bregarding\s+(.+?)(?:[.!?]|$)", t, flags=re.I)
    if m:
        return m.group(1).strip()

    m = re.search(r"\bfor\s+(.+?)(?:[.!?]|$)", t, flags=re.I)
    if m:
        return m.group(1).strip()

    return "your message"


def _clean_request_like_prefix(text_value: str) -> str:
    """
    Remove common request wrappers so the output does not echo meta-instructions.
    """
    t = (text_value or "").strip()

    patterns = [
        r"(?is)^\s*please\s+write\s+",
        r"(?is)^\s*please\s+draft\s+",
        r"(?is)^\s*please\s+provide\s+",
        r"(?is)^\s*write\s+",
        r"(?is)^\s*draft\s+",
        r"(?is)^\s*provide\s+",
    ]
    for pattern in patterns:
        t = re.sub(pattern, "", t, count=1)

    return t.strip()


def _normalize_sentence(text_value: str) -> str:
    t = _normalize_whitespace(text_value)
    if not t:
        return ""
    if t[-1] not in ".!?":
        t += "."
    return t


def _build_sparse_client_comm(text_value: str) -> str:
    """
    Safe holding response for thin client-communication inputs.
    This avoids inventing case facts while still producing a usable output.
    """
    ref = _extract_case_reference(text_value)

    return (
        "Hello,\n\n"
        f"Thank you for your message regarding {ref}.\n\n"
        "We have noted your concern and a member of the team will review the matter and follow up with you as appropriate.\n\n"
        "Kind regards,\n"
    )


def _build_client_comm(text_value: str, instruction: str) -> str:
    t = (text_value or "").strip()
    instr = _sanitize_instruction(instruction)
    sparse = _word_count(t) < 14

    # If the source is already a plausible email/message, lightly normalize and return it.
    if _looks_like_email_already(t):
        cleaned = t.strip()
        if not cleaned.endswith("\n"):
            cleaned += "\n"
        return cleaned

    # Thin request-like prompts need a safe, usable holding response rather than an echo.
    if sparse:
        return _build_sparse_client_comm(t)

    core = _clean_request_like_prefix(t)
    core = _normalize_sentence(core)

    warm = bool(re.search(r"\b(warm|empathetic|kind)\b", instr, flags=re.I))
    formal = bool(re.search(r"\b(formal|very formal)\b", instr, flags=re.I))

    greeting = "Hello,"
    signoff = "Kind regards,"

    if formal:
        greeting = "Dear client,"
        signoff = "Kind regards,"
    elif warm:
        greeting = "Hello,"
        signoff = "Kind regards,"

    return (
        f"{greeting}\n\n"
        f"{core}\n\n"
        f"{signoff}\n"
    )


def _build_internal_summary(text_value: str, instruction: str) -> str:
    t = (text_value or "").strip()
    instr = _sanitize_instruction(instruction)
    lines = _non_empty_lines(t)

    if not lines:
        return ""

    # If the instruction explicitly asks for a one-liner, keep it to one line.
    if re.search(r"\b(one line|one-liner|single line)\b", instr, flags=re.I):
        return _normalize_sentence(lines[0]) + "\n"

    # One-line source becomes one clear bullet.
    if len(lines) == 1:
        return f"- {_normalize_sentence(lines[0])}\n"

    # Multi-line source becomes a clean bullet summary.
    bullets = [f"- {_normalize_sentence(line)}" for line in lines]
    return "\n".join(bullets) + "\n"


def _build_clinical_note(text_value: str, instruction: str) -> str:
    t = (text_value or "").strip()

    # If already SOAP, preserve structure and normalize lightly.
    if _looks_like_soap(t):
        lines = [ln.rstrip() for ln in t.splitlines()]
        out_lines: List[str] = []
        for ln in lines:
            m = re.match(r"^\s*([SOAPsoap])\s*:\s*(.*)$", ln)
            if m:
                head = m.group(1).upper()
                rest = m.group(2).strip()
                out_lines.append(f"{head}: {rest}".rstrip())
            else:
                out_lines.append(ln)
        cleaned = "\n".join(out_lines)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
        return cleaned + ("\n" if not cleaned.endswith("\n") else "")

    # For sparse inputs, use a safe scaffold that preserves the source in S and leaves the rest blank.
    # This improves usability without inventing findings or clinical judgment.
    cleaned = _normalize_sentence(t)

    return (
        "S:\n"
        f"- {cleaned}\n\n"
        "O:\n"
        "- \n\n"
        "A:\n"
        "- \n\n"
        "P:\n"
        "- \n"
    )


def _stub_llm_generate(*, mode: str, user_text: str, instruction: Optional[str], role: Optional[str] = None) -> str:
    """
    Deterministic governed drafting layer.

    This is NOT a real model call yet.
    It is a constrained drafting layer that:
    - preserves meaning
    - avoids invention of facts
    - avoids new clinical decision-making
    - produces more usable mode-specific output
    """
    t = (user_text or "").strip()
    instr = _sanitize_instruction(instruction)

    if mode == "clinical_note":
        return _build_clinical_note(t, instr)

    if mode == "client_comm":
        return _build_client_comm(t, instr)

    return _build_internal_summary(t, instr)


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
        # -------- GENERATE candidate assistant output
        candidate = _stub_llm_generate(
            mode=mode,
            user_text=payload.text,
            instruction=payload.instruction,
            role=payload.role,
        )

        # -------- OUTPUT GATE (neutrality + hard rules)
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
        out_reason_code = f"output_{getattr(decision_obj, 'reason', 'allowed')}"
        risk_grade = "med" if governance_replaced else ig.risk_grade

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
