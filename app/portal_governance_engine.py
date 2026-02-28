# app/portal_governance_engine.py
#
# Portal governance engine (INPUT gate).
# - Runs on submitted text BEFORE any model call.
# - Content-light: returns metadata-only decision.
# - No DB writes.
#
# Policy model (best-effort / backwards compatible):
#
# You can place any of these fields in clinic_policies.policy_json:
#
# {
#   "policy_version": "portal-policy-v1",
#   "neutrality_version": "v1.1",
#   "input_governance": {
#     "pii_default_action": "warn",     # allow|warn|block (default: warn)
#     "pii_block_types": ["email"],     # any of: email, phone, postcode
#     "pii_warn_types": ["phone"],      # optional
#     "pii_allow_types": ["postcode"],  # optional
#     "risk_map": {                     # optional
#       "allow": "low",
#       "warn": "med",
#       "block": "high"
#     }
#   }
# }
#
# If absent: defaults are sane + privacy-forward (warn on any PII).

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


_ALLOWED_PII_ACTIONS = {"allow", "warn", "block"}
_ALLOWED_PII_TYPES = {"email", "phone", "postcode"}
_ALLOWED_RISK = {"low", "med", "high"}


@dataclass
class InputGovernanceDecision:
    decision: str            # "allowed" | "blocked"
    pii_detected: bool
    pii_action: str          # "allow" | "warn" | "block"
    risk_grade: str          # "low" | "med" | "high"
    reason_code: str         # stable-ish code (metadata)
    rules_fired: Dict[str, Any]


def _norm_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, tuple):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, str):
        # allow comma separated as a convenience
        parts = [p.strip() for p in value.split(",")]
        return [p for p in parts if p]
    return []


def _pick_risk(action: str, policy: Dict[str, Any]) -> str:
    default_map = {"allow": "low", "warn": "med", "block": "high"}
    ig = (policy or {}).get("input_governance") or {}
    risk_map = ig.get("risk_map") if isinstance(ig, dict) else None
    if isinstance(risk_map, dict):
        v = str(risk_map.get(action) or "").strip().lower()
        if v in _ALLOWED_RISK:
            return v
    return default_map.get(action, "low")


def evaluate_input_governance(
    *,
    text_value: str,
    pii_types: List[str],
    mode: str,
    policy: Optional[Dict[str, Any]] = None,
) -> InputGovernanceDecision:
    """
    Evaluate input governance for Portal submissions.
    Does not look at raw content beyond the provided pii_types list.
    """
    p = policy or {}
    ig = p.get("input_governance") if isinstance(p, dict) else None
    ig = ig if isinstance(ig, dict) else {}

    # Normalize pii types
    seen = set()
    pii_norm: List[str] = []
    for t in (pii_types or []):
        tt = str(t).strip().lower()
        if tt in _ALLOWED_PII_TYPES and tt not in seen:
            seen.add(tt)
            pii_norm.append(tt)

    pii_detected = bool(pii_norm)

    # Defaults: warn on any PII (privacy-forward; doesn't block workflow)
    default_action = str(ig.get("pii_default_action") or "warn").strip().lower()
    if default_action not in _ALLOWED_PII_ACTIONS:
        default_action = "warn"

    block_types = {x.lower() for x in _norm_list(ig.get("pii_block_types")) if x.lower() in _ALLOWED_PII_TYPES}
    warn_types = {x.lower() for x in _norm_list(ig.get("pii_warn_types")) if x.lower() in _ALLOWED_PII_TYPES}
    allow_types = {x.lower() for x in _norm_list(ig.get("pii_allow_types")) if x.lower() in _ALLOWED_PII_TYPES}

    # Determine action precedence:
    # - If any type is in block_types => block
    # - Else if any type in warn_types => warn
    # - Else if ALL types in allow_types => allow (only if explicitly allowed)
    # - Else default_action (warn by default)
    pii_action = "allow"
    if not pii_detected:
        pii_action = "allow"
    else:
        if any(t in block_types for t in pii_norm):
            pii_action = "block"
        elif any(t in warn_types for t in pii_norm):
            pii_action = "warn"
        elif allow_types and all(t in allow_types for t in pii_norm):
            pii_action = "allow"
        else:
            pii_action = default_action

    risk_grade = _pick_risk(pii_action, p)

    # Decision: only block if pii_action=block
    decision = "blocked" if pii_action == "block" else "allowed"

    # Reason codes: stable + predictable
    if not pii_detected:
        reason_code = "ok"
    else:
        # e.g. pii_email_phone_warn
        types_part = "_".join(sorted(pii_norm))[:80]
        reason_code = f"pii_{types_part}_{pii_action}"

    rules_fired: Dict[str, Any] = {
        "input_gate": True,
        "mode": mode,
        "pii": {
            "types": pii_norm,
            "action": pii_action,
            "policy": {
                "default_action": default_action,
                "block_types": sorted(block_types),
                "warn_types": sorted(warn_types),
                "allow_types": sorted(allow_types),
            },
        },
        "decision": decision,
        "risk_grade": risk_grade,
        "reason_code": reason_code,
    }

    return InputGovernanceDecision(
        decision=decision,
        pii_detected=pii_detected,
        pii_action=pii_action,
        risk_grade=risk_grade,
        reason_code=reason_code,
        rules_fired=rules_fired,
    )


def extract_neutrality_version(policy: Optional[Dict[str, Any]]) -> str:
    """
    Portal submit is input-only; neutrality is typically an OUTPUT gate concept.
    We still surface neutrality_version on receipts for consistency.
    """
    try:
        p = policy or {}
        v = str(p.get("neutrality_version") or "v1.1").strip()
        return v or "v1.1"
    except Exception:
        return "v1.1"
