# app/governance.py
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

# We reuse your neutrality scorer as the policy engine
from app.neutrality_v11 import score_neutrality


@dataclass
class GovernanceDecision:
    allowed: bool
    replaced: bool
    score: int
    grade: str
    findings: List[Dict[str, Any]]
    reason: str


# ---------------------------
# Config (tune later)
# ---------------------------

# If grade == "fail" OR score < MIN_SCORE_ALLOW => block/replace
MIN_SCORE_ALLOW = 75

# Hard-block rules: if any of these appear, always replace output
HARD_BLOCK_RULES = {
    "jailbreak",
    "therapy",
    "promise",
}

# Soft-block rules: allowed but should be visible in audit
SOFT_RULES = {
    "direct_advice",
    "coercion",
}

# Optional: keep audit logs small + structured
AUDIT_MAX_FINDINGS = 10


# ---------------------------
# Witness fallback (deterministic)
# ---------------------------

def witness_fallback(user_text: str) -> str:
    """
    Deterministic, institution-safe fallback.
    No advice, no diagnosis, no promises.
    """
    t = (user_text or "").strip()
    if not t:
        t = "what you shared"

    return (
        "I’m here with you.\n\n"
        "I want to stay with what you’re experiencing, without telling you what to do or making claims.\n\n"
        f"**What I heard:** {t}\n\n"
        "One question: what feels most present in this right now?"
    )


# ---------------------------
# Governance engine
# ---------------------------

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
    """
    Returns:
      - final_text (possibly replaced)
      - governance decision (structured)
      - audit payload (structured)
    """
    scored = score_neutrality(assistant_text, debug=debug)  # your scorer supports debug now
    score = int(scored.get("score", 0) or 0)
    grade = str(scored.get("grade", "fail") or "fail")
    findings = scored.get("findings", []) or []

    hard = _has_hard_block(findings)
    should_block = hard or (grade == "fail") or (score < MIN_SCORE_ALLOW)

    if should_block:
        final_text = witness_fallback(user_text)
        decision = GovernanceDecision(
            allowed=False,
            replaced=True,
            score=score,
            grade=grade,
            findings=findings[:AUDIT_MAX_FINDINGS],
            reason="hard_block" if hard else "low_score_or_fail",
        )
    else:
        final_text = assistant_text
        decision = GovernanceDecision(
            allowed=True,
            replaced=False,
            score=score,
            grade=grade,
            findings=findings[:AUDIT_MAX_FINDINGS],
            reason="allowed",
        )

    audit = {
        "ts_unix": int(time.time()),
        "user_id": str(user_id) if user_id else None,
        "session_id": str(session_id) if session_id else None,
        "mode": mode,
        "decision": {
            "allowed": decision.allowed,
            "replaced": decision.replaced,
            "score": decision.score,
            "grade": decision.grade,
            "reason": decision.reason,
        },
        "findings": decision.findings,
        "notes": {
            "min_score_allow": MIN_SCORE_ALLOW,
            "hard_block_rules": sorted(list(HARD_BLOCK_RULES)),
            "soft_rules": sorted(list(SOFT_RULES)),
        },
    }

    return final_text, decision, audit


def emit_audit_log(audit: Dict[str, Any]) -> None:
    """
    v1: print structured JSON. Render logs will capture this.
    Later: write to DB table for full audit trail.
    """
    try:
        print("[ANCHOR_GOVERNANCE_AUDIT] " + json.dumps(audit, ensure_ascii=False))
    except Exception:
        # Never break runtime due to logging failure
        pass
