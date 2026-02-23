# app/governance.py
#
# Ready for deploy (copy/paste).
#
# Updates applied (practical hardening):
# - Python 3.9+ compatible typing (no set[str] runtime issues)
# - Input policy normalization + de-dupe rule lists
# - Safer, deterministic decision_trace (stable ordering, capped sizes)
# - Adds "soft rule" awareness to trace (without changing current allow/block logic)
# - Keeps witness fallback behavior as your “safe replacement” output
#
# IMPORTANT: This module stays content-light. It does NOT write to DB.
# DB persistence should happen in your FastAPI layer (main.py / routers).

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from app.neutrality_v11 import score_neutrality


@dataclass
class GovernanceDecision:
    allowed: bool
    replaced: bool
    score: int
    grade: str
    findings: List[Dict[str, Any]]
    reason: str  # e.g. "allowed" | "hard_block" | "low_score_or_fail"


# ---------------------------
# Default policy (safe fallback)
# ---------------------------

DEFAULT_MIN_SCORE_ALLOW = 75
DEFAULT_HARD_BLOCK_RULES: Set[str] = {"jailbreak", "therapy", "promise"}
DEFAULT_SOFT_RULES: Set[str] = {"direct_advice", "coercion"}
DEFAULT_AUDIT_MAX_FINDINGS = 10


def witness_fallback(user_text: str) -> str:
    """
    Neutral, non-directive, non-claim replacement response.
    """
    t = (user_text or "").strip() or "what you shared"
    return (
        "I’m here with you.\n\n"
        "I want to stay with what you’re experiencing, without telling you what to do or making claims.\n\n"
        f"**What I heard:** {t}\n\n"
        "One question: what feels most present in this right now?"
    )


def _norm_str_list(value: Any, default: List[str]) -> List[str]:
    """
    Normalize list-like policy fields to list[str].
    Accepts list or JSON string. Falls back to default.
    """
    try:
        if value is None:
            return list(default)
        if isinstance(value, list):
            return [str(x).strip() for x in value if str(x).strip()]
        if isinstance(value, str):
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(x).strip() for x in parsed if str(x).strip()]
        if isinstance(value, tuple):
            return [str(x).strip() for x in value if str(x).strip()]
        return list(default)
    except Exception:
        return list(default)


def _has_any_rule(findings: List[Dict[str, Any]], rule_ids: Set[str]) -> bool:
    """
    True if any finding.rule_id is in rule_ids.
    """
    if not findings or not rule_ids:
        return False
    for f in findings:
        rid = (f.get("rule_id") or "").strip()
        if rid and rid in rule_ids:
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
    policy: Optional[Dict[str, Any]] = None,  # injected policy row (already parsed or raw)
) -> Tuple[str, GovernanceDecision, Dict[str, Any]]:
    """
    Returns (final_text, decision, audit_dict).

    policy (optional) can contain:
      - policy_version: str
      - neutrality_version: str
      - min_score_allow: int
      - hard_block_rules: list[str] or JSON string
      - soft_rules: list[str] or JSON string
      - max_findings: int
    """
    p = policy or {}

    policy_version = str(p.get("policy_version") or "gov-v1.0")
    neutrality_version = str(p.get("neutrality_version") or "n-v1.1")

    try:
        min_score_allow = int(p.get("min_score_allow") or DEFAULT_MIN_SCORE_ALLOW)
    except Exception:
        min_score_allow = DEFAULT_MIN_SCORE_ALLOW

    try:
        audit_max_findings = int(p.get("max_findings") or DEFAULT_AUDIT_MAX_FINDINGS)
    except Exception:
        audit_max_findings = DEFAULT_AUDIT_MAX_FINDINGS
    audit_max_findings = max(1, min(50, audit_max_findings))

    hard_block_rules = set(
        _norm_str_list(p.get("hard_block_rules"), list(DEFAULT_HARD_BLOCK_RULES))
    )
    soft_rules = set(_norm_str_list(p.get("soft_rules"), list(DEFAULT_SOFT_RULES)))

    # Score neutrality on the assistant output (pre-governance)
    scored = score_neutrality(assistant_text, debug=debug) or {}
    score = int(scored.get("score", 0) or 0)
    grade = str(scored.get("grade", "fail") or "fail")
    findings = (scored.get("findings") or []) if isinstance(scored.get("findings"), list) else []

    # Current intervention logic (unchanged):
    # - hard-block rule triggers OR fail grade OR score below threshold => replace
    hard_triggered = _has_any_rule(findings, hard_block_rules)
    should_block = bool(hard_triggered or (grade == "fail") or (score < min_score_allow))

    if should_block:
        final_text = witness_fallback(user_text)
        decision = GovernanceDecision(
            allowed=False,
            replaced=True,
            score=score,
            grade=grade,
            findings=findings[:audit_max_findings],
            reason="hard_block" if hard_triggered else "low_score_or_fail",
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

    # Trace fields (deterministic and capped)
    triggered_rule_ids: List[str] = []
    for f in decision.findings:
        rid = (f.get("rule_id") or "").strip()
        if rid:
            triggered_rule_ids.append(rid)

    # Soft triggers are informative only (no effect on allow/block yet)
    soft_triggered = _has_any_rule(findings, soft_rules)

    decision_trace = {
        "min_score_allow": int(min_score_allow),
        "hard_block_rules": sorted(hard_block_rules)[:50],
        "soft_rules": sorted(soft_rules)[:50],
        "triggered_rule_ids": triggered_rule_ids[:25],
        "soft_triggered": bool(soft_triggered),
        "score": int(score),
        "grade": grade,
        "replaced": bool(decision.replaced),
        "reason": decision.reason,
    }

    audit: Dict[str, Any] = {
        "ts_unix": int(time.time()),
        "user_id": str(user_id) if user_id else None,
        "session_id": str(session_id) if session_id else None,
        "mode": mode,
        "decision": {
            "allowed": bool(decision.allowed),
            "replaced": bool(decision.replaced),
            "score": int(decision.score),
            "grade": decision.grade,
            "reason": decision.reason,
        },
        "findings": decision.findings,
        "notes": {
            "min_score_allow": int(min_score_allow),
            "hard_block_rules": sorted(hard_block_rules)[:50],
            "soft_rules": sorted(soft_rules)[:50],
        },
        # A4 stamps
        "policy_version": policy_version,
        "neutrality_version": neutrality_version,
        "decision_trace": decision_trace,
    }

    return final_text, decision, audit


def emit_audit_log(audit: Dict[str, Any]) -> None:
    """
    Structured-ish stdout log (your main.py already does structured logging too).
    Safe: never throws.
    """
    try:
        print("[ANCHOR_GOVERNANCE_AUDIT] " + json.dumps(audit, ensure_ascii=False))
    except Exception:
        pass
