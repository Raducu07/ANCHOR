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


# ---------------------------
# Default policy (safe fallback)
# ---------------------------

DEFAULT_MIN_SCORE_ALLOW = 75
DEFAULT_HARD_BLOCK_RULES = {"jailbreak", "therapy", "promise"}
DEFAULT_SOFT_RULES = {"direct_advice", "coercion"}
DEFAULT_AUDIT_MAX_FINDINGS = 10


def witness_fallback(user_text: str) -> str:
    t = (user_text or "").strip() or "what you shared"
    return (
        "I’m here with you.\n\n"
        "I want to stay with what you’re experiencing, without telling you what to do or making claims.\n\n"
        f"**What I heard:** {t}\n\n"
        "One question: what feels most present in this right now?"
    )


def _has_hard_block(findings: List[Dict[str, Any]], hard_block_rules: set[str]) -> bool:
    for f in findings or []:
        rid = (f.get("rule_id") or "").strip()
        if rid in hard_block_rules:
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
    policy: Optional[Dict[str, Any]] = None,   # <-- A4: injected policy
) -> Tuple[str, GovernanceDecision, Dict[str, Any]]:
    """
    policy (optional) can contain:
      - policy_version: str
      - neutrality_version: str
      - min_score_allow: int
      - hard_block_rules: list[str]
      - soft_rules: list[str]
      - max_findings: int
    """
    policy_version = str((policy or {}).get("policy_version") or "gov-v1.0")
    neutrality_version = str((policy or {}).get("neutrality_version") or "n-v1.1")

    min_score_allow = int((policy or {}).get("min_score_allow") or DEFAULT_MIN_SCORE_ALLOW)
    hard_block_rules = set((policy or {}).get("hard_block_rules") or list(DEFAULT_HARD_BLOCK_RULES))
    soft_rules = set((policy or {}).get("soft_rules") or list(DEFAULT_SOFT_RULES))
    audit_max_findings = int((policy or {}).get("max_findings") or DEFAULT_AUDIT_MAX_FINDINGS)

    scored = score_neutrality(assistant_text, debug=debug)
    score = int(scored.get("score", 0) or 0)
    grade = str(scored.get("grade", "fail") or "fail")
    findings = scored.get("findings", []) or []

    hard = _has_hard_block(findings, hard_block_rules)
    should_block = hard or (grade == "fail") or (score < min_score_allow)

    if should_block:
        final_text = witness_fallback(user_text)
        decision = GovernanceDecision(
            allowed=False,
            replaced=True,
            score=score,
            grade=grade,
            findings=findings[:audit_max_findings],
            reason="hard_block" if hard else "low_score_or_fail",
        )
    else:
        final_text = assistant_text
        decision = GovernanceDecision(
            allowed=True,
            replaced=False,
            score=score,
            grade=grade,
            findings=findings[:audit_max_findings],
            reason="allowed",
        )

    triggered_rule_ids: List[str] = []
    for f in decision.findings:
        rid = (f.get("rule_id") or "").strip()
        if rid:
            triggered_rule_ids.append(rid)

    decision_trace = {
        "min_score_allow": min_score_allow,
        "hard_block_rules": sorted(list(hard_block_rules)),
        "soft_rules": sorted(list(soft_rules)),
        "triggered_rule_ids": triggered_rule_ids[:25],
        "score": score,
        "grade": grade,
        "replaced": decision.replaced,
        "reason": decision.reason,
    }

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
            "min_score_allow": min_score_allow,
            "hard_block_rules": sorted(list(hard_block_rules)),
            "soft_rules": sorted(list(soft_rules)),
        },
        # A4 stamps
        "policy_version": policy_version,
        "neutrality_version": neutrality_version,
        "decision_trace": decision_trace,
    }

    return final_text, decision, audit


def emit_audit_log(audit: Dict[str, Any]) -> None:
    try:
        print("[ANCHOR_GOVERNANCE_AUDIT] " + json.dumps(audit, ensure_ascii=False))
    except Exception:
        pass
