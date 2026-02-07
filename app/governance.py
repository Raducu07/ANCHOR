# app/governance.py
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from app.neutrality_v11 import score_neutrality


@dataclass
class GovernanceDecision:
    allowed: bool
    replaced: bool
    score: int
    grade: str
    findings: List[Dict[str, Any]]
    reason: str


MIN_SCORE_ALLOW = 75

HARD_BLOCK_RULES = {
    "jailbreak",
    "therapy",
    "promise",
}

SOFT_RULES = {
    "direct_advice",
    "coercion",
}

AUDIT_MAX_FINDINGS = 10


def witness_fallback(user_text: str) -> str:
    t = (user_text or "").strip()
    if not t:
        t = "what you shared"

    return (
        "I’m here with you.\n\n"
        "I want to stay with what you’re experiencing, without telling you what to do or making claims.\n\n"
        f"**What I heard:** {t}\n\n"
        "One question: what feels most present in this right now?"
    )


def _has_hard_block(findings: List[Dict[str, Any]]) -> bool:
    for f in findings or []:
        rid = (f.get("rule_id") or "").strip()
        if rid in HARD_BLOCK_RULES:
            return True
    return False


def govern_output(
    *,
    user_text: str,
    assistant_text: str,
    user_id: Optional[uuid.UUID] = None,
    session_id: Optional[uuid.UUID] = None,
    mode: str = "witness",
    debug: bool = False,
) -> Tuple[str, GovernanceDecision, Dict[str, Any]]:
    scored = score_neutrality(assistant_text, debug=debug)
    score = int(scored.get("score", 0) or 0)
    grade = str(scored.get("grade", "fail") or "fail")
    findings_all = scored.get("findings", []) or []
    findings = findings_all[:AUDIT_MAX_FINDINGS]

    hard = _has_hard_block(findings_all)
    should_block = hard or (grade == "fail") or (score < MIN_SCORE_ALLOW)

    if should_block:
        final_text = witness_fallback(user_text)
        decision = GovernanceDecision(
            allowed=False,
            replaced=True,
            score=score,
            grade=grade,
            findings=findings,
            reason="hard_block" if hard else ("grade_fail" if grade == "fail" else "low_score"),
        )
    else:
        final_text = assistant_text
        decision = GovernanceDecision(
            allowed=True,
            replaced=False,
            score=score,
            grade=grade,
            findings=findings,
            reason="allowed",
        )

    # ✅ Flattened keys added (DB-friendly)
    audit: Dict[str, Any] = {
        "ts_unix": int(time.time()),
        "user_id": str(user_id) if user_id else None,
        "session_id": str(session_id) if session_id else None,
        "mode": mode,

        # Flattened (easy DB write)
        "allowed": decision.allowed,
        "replaced": decision.replaced,
        "score": decision.score,
        "grade": decision.grade,
        "reason": decision.reason,
        "findings": decision.findings,

        # Keep the nested decision too (nice for logs)
        "decision": {
            "allowed": decision.allowed,
            "replaced": decision.replaced,
            "score": decision.score,
            "grade": decision.grade,
            "reason": decision.reason,
        },

        "notes": {
            "min_score_allow": MIN_SCORE_ALLOW,
            "hard_block_rules": sorted(list(HARD_BLOCK_RULES)),
            "soft_rules": sorted(list(SOFT_RULES)),
        },
    }

    if debug and scored.get("debug") is not None:
        audit["notes"]["scorer_debug"] = scored.get("debug")

    return final_text, decision, audit


def emit_audit_log(audit: Dict[str, Any]) -> None:
    try:
        print("[ANCHOR_GOVERNANCE_AUDIT] " + json.dumps(audit, ensure_ascii=False))
    except Exception:
        pass
