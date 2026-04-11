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
# - This version is designed to be broader and more stable so ANCHOR does not
#   need a one-off code tweak for every slightly different request phrasing.

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

    # Optional UI context from Workspace
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

_EMAIL_RE = re.compile(r"\b(email|message|memo|letter|update|reply|response)\b", flags=re.I)
_BULLETS_RE = re.compile(r"\b(bullet point|bullet points|bullets|key points|main points|discussion points)\b", flags=re.I)
_ACTIONS_RE = re.compile(r"\b(action items|actions|next steps|follow-up|follow up)\b", flags=re.I)
_SUMMARY_RE = re.compile(r"\b(summary|summarise|summarize|overview|handover)\b", flags=re.I)
_REVIEW_RE = re.compile(r"\b(review|governance review|internal review|oversight|policy review|governance)\b", flags=re.I)
_GOVERNANCE_KEYWORDS_RE = re.compile(
    r"\b(governance|anchor|policy|privacy|compliance|audit|oversight|review|breach|incident|risk|disciplinary)\b",
    flags=re.I,
)
_STAFF_AUDIENCE_RE = re.compile(r"\b(staff|team|practice staff|all practice staff|colleagues)\b", flags=re.I)
_LEADERSHIP_AUDIENCE_RE = re.compile(r"\b(general director|director|leadership|manager|owners?)\b", flags=re.I)


def _looks_like_soap(text_value: str) -> bool:
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
    s = (instr or "").strip()
    if not s:
        return ""
    s = re.sub(r"\s+", " ", s).strip()
    return s[:1000]


def _normalize_whitespace(text_value: str) -> str:
    return re.sub(r"\s+", " ", (text_value or "").strip()).strip()


def _normalize_sentence(text_value: str) -> str:
    t = _normalize_whitespace(text_value)
    if not t:
        return ""
    if t[-1] not in ".!?":
        t += "."
    return t


def _word_count(text_value: str) -> int:
    trimmed = (text_value or "").strip()
    if not trimmed:
        return 0
    return len(re.findall(r"\S+", trimmed))


def _non_empty_lines(text_value: str) -> List[str]:
    lines = []
    for raw in (text_value or "").splitlines():
        cleaned = raw.strip()
        if not cleaned:
            continue
        cleaned = re.sub(r"^[\-\*\u2022]+\s*", "", cleaned)
        lines.append(cleaned)
    return lines


def _strip_request_wrapper(text_value: str) -> str:
    t = (text_value or "").strip()

    patterns = [
        r"(?is)^\s*please\s+write\s+",
        r"(?is)^\s*please\s+draft\s+",
        r"(?is)^\s*please\s+prepare\s+",
        r"(?is)^\s*please\s+provide\s+",
        r"(?is)^\s*please\s+summari[sz]e\s+",
        r"(?is)^\s*write\s+",
        r"(?is)^\s*draft\s+",
        r"(?is)^\s*prepare\s+",
        r"(?is)^\s*provide\s+",
        r"(?is)^\s*summari[sz]e\s+",
    ]
    for pattern in patterns:
        t = re.sub(pattern, "", t, count=1)

    return t.strip()


def _strip_meta_object(text_value: str) -> str:
    t = _strip_request_wrapper(text_value)

    patterns = [
        r"(?is)^\s*(an?|the)\s+(summary|review|email|message|note|update|overview)\s+(regarding|about|on|for)\s+",
        r"(?is)^\s*(summary|review|email|message|note|update|overview)\s+(regarding|about|on|for)\s+",
        r"(?is)^\s*(an?|the)\s+(summary|review|email|message|note|update|overview)\s+",
        r"(?is)^\s*(summary|review|email|message|note|update|overview)\s+",
    ]
    for pattern in patterns:
        t = re.sub(pattern, "", t, count=1)

    return t.strip(" ,.;:")


def _extract_topic_phrase(text_value: str) -> str:
    t = _normalize_whitespace(text_value)

    patterns = [
        r"\bregarding\s+(.+?)(?:[.!?]|$)",
        r"\babout\s+(.+?)(?:[.!?]|$)",
        r"\bon\s+(.+?)(?:[.!?]|$)",
        r"\bwith\s+(.+?)(?:[.!?]|$)",
        r"\bfor\s+(.+?)(?:[.!?]|$)",
    ]

    for pattern in patterns:
        m = re.search(pattern, t, flags=re.I)
        if m:
            value = m.group(1).strip(" ,.;:")
            if value:
                return value

    cleaned = _strip_meta_object(t)
    return cleaned.strip(" ,.;:")


def _title_case_subject(value: str) -> str:
    t = _normalize_whitespace(value)
    if not t:
        return "Internal update"
    if len(t) > 90:
        t = t[:90].rstrip()
    return t[0].upper() + t[1:]


def _infer_internal_profile(*, role: Optional[str], instruction: str, text_value: str) -> str:
    role_text = (role or "").strip().lower()
    combined = f"{role or ''} {instruction or ''} {text_value or ''}"

    if "practice manager" in role_text:
        return "internal_governance_review"

    if _GOVERNANCE_KEYWORDS_RE.search(combined):
        return "internal_governance_review"

    return "internal_summary"


def _infer_request_shape(*, mode: str, role: Optional[str], instruction: str, text_value: str) -> Dict[str, Any]:
    combined = f"{instruction or ''} {text_value or ''}"
    profile = _infer_internal_profile(role=role, instruction=instruction, text_value=text_value)

    wants_email = bool(_EMAIL_RE.search(combined))
    wants_bullets = bool(_BULLETS_RE.search(combined))
    wants_actions = bool(_ACTIONS_RE.search(combined))
    wants_summary = bool(_SUMMARY_RE.search(combined))
    wants_review = bool(_REVIEW_RE.search(combined)) or profile == "internal_governance_review"

    audience = "internal"
    if mode == "client_comm":
        audience = "client"
    elif _LEADERSHIP_AUDIENCE_RE.search(combined):
        audience = "leadership"
    elif _STAFF_AUDIENCE_RE.search(combined):
        audience = "staff"

    sparse = _word_count(text_value) < 24 or len(_non_empty_lines(text_value)) <= 1

    return {
        "profile": profile,
        "wants_email": wants_email,
        "wants_bullets": wants_bullets,
        "wants_actions": wants_actions,
        "wants_summary": wants_summary,
        "wants_review": wants_review,
        "audience": audience,
        "sparse": sparse,
    }


def _build_sparse_client_comm(text_value: str) -> str:
    ref = _extract_topic_phrase(text_value) or "your message"

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

    if re.match(r"(?is)^\s*(hello|hi|dear)\b", t):
        cleaned = t.strip()
        if not cleaned.endswith("\n"):
            cleaned += "\n"
        return cleaned

    if sparse:
        return _build_sparse_client_comm(t)

    core = _strip_request_wrapper(t)
    core = _normalize_sentence(core)

    warm = bool(re.search(r"\b(warm|empathetic|kind)\b", instr, flags=re.I))
    formal = bool(re.search(r"\b(formal|very formal)\b", instr, flags=re.I))

    greeting = "Hello,"
    signoff = "Kind regards,"

    if formal:
        greeting = "Dear client,"
    elif warm:
        greeting = "Hello,"

    return (
        f"{greeting}\n\n"
        f"{core}\n\n"
        f"{signoff}\n"
    )


def _build_clinical_note(text_value: str, instruction: str) -> str:
    t = (text_value or "").strip()

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


def _derive_internal_bullets(text_value: str, *, sparse: bool) -> List[str]:
    lines = _non_empty_lines(text_value)

    if len(lines) > 1:
        cleaned = []
        for line in lines:
            item = _normalize_sentence(_strip_meta_object(line))
            if item:
                cleaned.append(item)
        if cleaned:
            return cleaned

    topic = _normalize_sentence(_extract_topic_phrase(text_value))
    if sparse:
        return [
            topic,
            "Specific discussion details should be confirmed during human review.",
        ]

    if topic:
        return [topic]

    return ["Details should be confirmed during human review."]


def _derive_internal_action_items(text_value: str, *, sparse: bool) -> List[str]:
    if _ACTIONS_RE.search(text_value or ""):
        if sparse:
            return ["Action items should be confirmed during human review."]
        return ["Review and confirm follow-up actions before operational use."]

    return []


def _build_internal_email(*, text_value: str, profile: str, wants_bullets: bool, wants_actions: bool, audience: str, sparse: bool) -> str:
    topic = _extract_topic_phrase(text_value)
    greeting = "Hello,"
    if audience == "staff":
        greeting = "Hello team,"

    if profile == "internal_governance_review":
        if "anchor" in (text_value or "").lower() and "governance" in (text_value or "").lower():
            subject = "Internal AI governance update"
            opening = "I am writing to provide an internal update on the AI governance arrangements supported by ANCHOR."
        elif topic:
            subject = f"Internal governance update regarding {topic}"
            opening = f"I am writing to provide an internal governance update regarding {topic}."
        else:
            subject = "Internal governance update"
            opening = "I am writing to provide an internal governance update."
        if audience == "leadership":
            extra = "This note is intended for internal leadership review."
        else:
            extra = "This note is intended for internal review."
    else:
        if topic:
            subject = f"Internal update regarding {topic}"
            opening = f"I am writing regarding {topic}."
        else:
            subject = "Internal update"
            opening = "I am writing to share an internal update."
        if audience == "staff":
            extra = "This communication is intended for internal staff circulation."
        else:
            extra = "This communication is intended for internal review."

    parts: List[str] = [
        f"Subject: {_title_case_subject(subject)}",
        "",
        greeting,
        "",
        opening,
        extra,
    ]

    if wants_bullets:
        bullets = _derive_internal_bullets(text_value, sparse=sparse)
        parts.extend(["", "Key points:"])
        parts.extend([f"- {item}" for item in bullets])

    if wants_actions:
        actions = _derive_internal_action_items(text_value, sparse=sparse)
        if actions:
            parts.extend(["", "Action items:"])
            parts.extend([f"- {item}" for item in actions])

    parts.extend(
        [
            "",
            "Details should be reviewed and confirmed before operational use.",
            "",
            "Kind regards,",
        ]
    )

    return "\n".join(parts) + "\n"


def _build_internal_governance_review(text_value: str, instruction: str, role: Optional[str]) -> str:
    shape = _infer_request_shape(mode="internal_summary", role=role, instruction=instruction, text_value=text_value)

    if shape["wants_email"]:
        return _build_internal_email(
            text_value=text_value,
            profile="internal_governance_review",
            wants_bullets=shape["wants_bullets"],
            wants_actions=shape["wants_actions"],
            audience=shape["audience"],
            sparse=shape["sparse"],
        )

    topic = _normalize_sentence(_extract_topic_phrase(text_value))
    bullets = [
        f"Topic: {topic}",
        "Purpose: internal governance review requested.",
        "Status: requires human review before operational use.",
    ]

    if shape["wants_bullets"]:
        bullets.append("Discussion details should be confirmed during human review.")

    lines = ["Internal governance review note:"]
    lines.extend([f"- {item}" for item in bullets])
    return "\n".join(lines) + "\n"


def _build_internal_summary(text_value: str, instruction: str, role: Optional[str]) -> str:
    shape = _infer_request_shape(mode="internal_summary", role=role, instruction=instruction, text_value=text_value)
    profile = shape["profile"]

    if profile == "internal_governance_review":
        return _build_internal_governance_review(text_value, instruction, role)

    if shape["wants_email"]:
        return _build_internal_email(
            text_value=text_value,
            profile="internal_summary",
            wants_bullets=shape["wants_bullets"],
            wants_actions=shape["wants_actions"],
            audience=shape["audience"],
            sparse=shape["sparse"],
        )

    if re.search(r"\b(one line|one-liner|single line)\b", instruction or "", flags=re.I):
        first = _normalize_sentence(_strip_meta_object(text_value))
        return first + "\n" if first else ""

    topic = _normalize_sentence(_extract_topic_phrase(text_value))
    lines = [
        "Internal summary:",
        f"- Topic: {topic}",
        "- Context: summary prepared for internal review.",
        "- Status: requires human review before operational use.",
    ]

    if shape["wants_bullets"]:
        lines.append("- Discussion details should be confirmed during human review.")

    return "\n".join(lines) + "\n"


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

    return _build_internal_summary(t, instr, role)


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

    policy_version = _get_active_policy_version(db)
    policy_obj = _get_policy_json(db, policy_version=policy_version)
    policy_sha256 = _sha256_hex(_canonical_json(policy_obj)) if policy_obj is not None else None
    neutrality_version = extract_neutrality_version(policy_obj)

    pii_types = detect_pii_types(payload.text)
    ig = evaluate_input_governance(
        text_value=payload.text,
        pii_types=pii_types,
        mode=mode,
        policy=policy_obj,
    )

    if ig.decision == "blocked":
        final_text = "Submission blocked by clinic policy."
        governance_replaced = False
        out_decision = "blocked"
        out_reason_code = ig.reason_code
        risk_grade = ig.risk_grade
        governance_score = None
        governance_grade = None
        rules_fired = ig.rules_fired
    else:
        candidate = _stub_llm_generate(
            mode=mode,
            user_text=payload.text,
            instruction=payload.instruction,
            role=payload.role,
        )

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
