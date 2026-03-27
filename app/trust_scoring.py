from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _row(db: Session, sql: str, params: Dict[str, Any]) -> Dict[str, Any]:
    result = db.execute(text(sql), params).mappings().first()
    return dict(result) if result else {}


def _f(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    try:
        return float(value)
    except Exception:
        return default


def _i(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _round_rate(value: Any) -> float:
    return round(_f(value), 4)


def _status_from_score(score: int) -> str:
    if score >= 85:
        return "strong"
    if score >= 70:
        return "stable"
    if score >= 55:
        return "watch"
    return "needs_attention"


def _derive_trust_state(request_count: int, rate_5xx: float, p95_latency_ms: float, governance_replaced_rate: float) -> str:
    if request_count <= 0:
        return "yellow"

    if rate_5xx >= 0.05 or p95_latency_ms >= 3000 or governance_replaced_rate >= 0.30:
        return "red"

    if rate_5xx >= 0.01 or p95_latency_ms >= 1000 or governance_replaced_rate >= 0.10:
        return "yellow"

    return "green"


def _headline(posture_status: str, trust_state: str, request_count_24h: int) -> str:
    if request_count_24h <= 0:
        return "Controls are in place, but recent activity is insufficient to show an active operational trust signal."

    if posture_status == "strong" and trust_state == "green":
        return "AI use is actively governed with strong privacy and oversight controls."

    if posture_status in {"strong", "stable"}:
        return "AI use is governed with clear controls and a stable trust posture."

    if posture_status == "watch":
        return "AI use is governed, but recent signals suggest closer operational attention is warranted."

    return "AI use remains governed, but current signals indicate a weaker trust posture requiring action."


def _dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _recommended_topics(
    top_mode: Optional[str],
    top_route: Optional[str],
    intervention_rate: float,
    pii_rate: float,
    replacement_rate: float,
) -> List[str]:
    topics: List[str] = []

    route_value = (top_route or "").lower()
    mode_value = (top_mode or "").lower()

    if mode_value == "client_comm" or "client" in route_value or "comm" in route_value:
        topics.append("Client communication safety")

    if pii_rate >= 0.02:
        topics.append("PII-safe prompting")

    if intervention_rate >= 0.08:
        topics.append("Policy interpretation basics")

    if replacement_rate >= 0.05:
        topics.append("Prompt minimisation")

    if not topics:
        topics = [
            "Governance receipt basics",
            "Policy interpretation basics",
        ]

    return _dedupe_keep_order(topics)[:3]


def _compute_posture_score(
    *,
    trust_state: str,
    request_count_24h: int,
    receipt_coverage_rate: float,
    intervention_rate_30d: float,
    replacement_rate_30d: float,
    pii_warning_rate_30d: float,
    active_policy_version: Optional[int],
    learning_enabled: bool,
    export_capability: bool,
) -> int:
    score = 100.0

    if trust_state == "yellow":
        score -= 10
    elif trust_state == "red":
        score -= 25

    if request_count_24h <= 0:
        score -= 5

    if receipt_coverage_rate < 0.99:
        score -= 12

    if receipt_coverage_rate < 0.95:
        score -= 10

    if intervention_rate_30d >= 0.15:
        score -= 10
    elif intervention_rate_30d >= 0.08:
        score -= 5

    if replacement_rate_30d >= 0.08:
        score -= 8
    elif replacement_rate_30d >= 0.04:
        score -= 4

    if pii_warning_rate_30d >= 0.05:
        score -= 8
    elif pii_warning_rate_30d >= 0.02:
        score -= 4

    if active_policy_version is None:
        score -= 10

    if learning_enabled:
        score += 3

    if export_capability:
        score += 2

    return int(round(_clamp(score, 0, 100)))


def _attention_areas(
    *,
    trust_state: str,
    top_mode: Optional[str],
    intervention_rate_30d: float,
    replacement_rate_30d: float,
    pii_warning_rate_30d: float,
    receipt_coverage_rate: float,
) -> List[Dict[str, str]]:
    items: List[Dict[str, str]] = []

    mode_value = (top_mode or "").lower()

    if mode_value == "client_comm" and intervention_rate_30d >= 0.08:
        items.append(
            {
                "type": "mode_risk_concentration",
                "label": "Client communication activity shows a higher concentration of governed interventions.",
            }
        )

    if pii_warning_rate_30d >= 0.03:
        items.append(
            {
                "type": "privacy_hygiene",
                "label": "Privacy-related warning rates suggest value in reinforcing PII-safe prompting practices.",
            }
        )

    if replacement_rate_30d >= 0.05:
        items.append(
            {
                "type": "prompt_quality_friction",
                "label": "Replacement rates indicate prompt quality or policy-alignment friction in part of workflow usage.",
            }
        )

    if receipt_coverage_rate < 0.99:
        items.append(
            {
                "type": "receipt_coverage",
                "label": "Receipt coverage is below ideal completeness and should be reviewed.",
            }
        )

    if not items and trust_state != "green":
        items.append(
            {
                "type": "operational_watch",
                "label": "Recent operational trust signals justify continued monitoring even though core controls remain active.",
            }
        )

    if not items:
        items.append(
            {
                "type": "stable_posture",
                "label": "No material posture concentration stands out at present; continue routine monitoring.",
            }
        )

    return items[:3]


def _recommended_actions(
    attention_areas: List[Dict[str, str]],
    learning_topics: List[str],
    posture_status: str,
) -> List[str]:
    action_map = {
        "mode_risk_concentration": "Review guidance and policy wording for client communication workflows.",
        "privacy_hygiene": "Promote PII-safe prompting explainers and reinforce privacy-aware usage habits.",
        "prompt_quality_friction": "Use Learn explainers to reduce prompt-quality friction and improve policy alignment.",
        "receipt_coverage": "Verify receipt-generation and read-path coverage across recent governed activity.",
        "operational_watch": "Monitor trust-state trendlines and validate whether recent degradation is persistent.",
        "stable_posture": "Maintain current controls and continue periodic governance posture review.",
    }

    actions: List[str] = []
    for item in attention_areas:
        mapped = action_map.get(item.get("type", ""))
        if mapped:
            actions.append(mapped)

    if "PII-safe prompting" in learning_topics:
        actions.append("Promote explainer content for PII-safe prompting.")
    if "Client communication safety" in learning_topics:
        actions.append("Refresh client-facing AI-use guidance for staff.")
    if "Policy interpretation basics" in learning_topics:
        actions.append("Surface policy interpretation explainers more prominently in governed workflows.")

    if posture_status in {"strong", "stable"} and not actions:
        actions.append("Maintain current trust controls and continue routine leadership review.")

    return _dedupe_keep_order(actions)[:4]


def _collect_inputs(db: Session, clinic_id: str) -> Dict[str, Any]:
    params = {"clinic_id": clinic_id}

    health_24h = _row(
        db,
        """
        SELECT
            COUNT(*) AS request_count_24h,
            COALESCE(AVG(CASE WHEN status_code >= 500 THEN 1.0 ELSE 0.0 END), 0.0) AS rate_5xx_24h,
            COALESCE(percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms), 0) AS p95_latency_ms_24h,
            COALESCE(AVG(CASE WHEN governance_replaced THEN 1.0 ELSE 0.0 END), 0.0) AS governance_replaced_rate_24h
        FROM ops_metrics_events
        WHERE clinic_id = :clinic_id
          AND created_at >= now() - interval '24 hours'
        """,
        params,
    )

    ops_24h = _row(
        db,
        """
        SELECT
            COUNT(*) AS events_24h,
            COALESCE(AVG(CASE WHEN pii_warned THEN 1.0 ELSE 0.0 END), 0.0) AS pii_warned_rate_24h,
            (
                SELECT mode
                FROM ops_metrics_events
                WHERE clinic_id = :clinic_id
                  AND created_at >= now() - interval '24 hours'
                GROUP BY mode
                ORDER BY COUNT(*) DESC, mode ASC
                LIMIT 1
            ) AS top_mode_24h,
            (
                SELECT route
                FROM ops_metrics_events
                WHERE clinic_id = :clinic_id
                  AND created_at >= now() - interval '24 hours'
                GROUP BY route
                ORDER BY COUNT(*) DESC, route ASC
                LIMIT 1
            ) AS top_route_24h
        FROM ops_metrics_events
        WHERE clinic_id = :clinic_id
          AND created_at >= now() - interval '24 hours'
        """,
        params,
    )

    gov_24h = _row(
        db,
        """
        SELECT
            COUNT(*) AS governed_events_24h,
            COALESCE(
                AVG(
                    CASE
                        WHEN decision IN ('blocked', 'replaced', 'modified') THEN 1.0
                        ELSE 0.0
                    END
                ),
                0.0
            ) AS intervention_rate_24h,
            COALESCE(
                AVG(
                    CASE
                        WHEN pii_detected THEN 1.0
                        ELSE 0.0
                    END
                ),
                0.0
            ) AS pii_detected_rate_24h,
            COALESCE(
                AVG(
                    CASE
                        WHEN decision IN ('blocked', 'replaced', 'modified') OR pii_detected THEN 1.0
                        ELSE 0.0
                    END
                ),
                0.0
            ) AS learning_tie_in_rate_24h
        FROM clinic_governance_events
        WHERE clinic_id = :clinic_id
          AND created_at >= now() - interval '24 hours'
        """,
        params,
    )

    gov_30d = _row(
        db,
        """
        SELECT
            COUNT(*) AS governed_events_30d,
            COALESCE(
                AVG(
                    CASE
                        WHEN decision IN ('blocked', 'replaced', 'modified') THEN 1.0
                        ELSE 0.0
                    END
                ),
                0.0
            ) AS intervention_rate_30d,
            COALESCE(
                AVG(
                    CASE
                        WHEN decision = 'replaced' THEN 1.0
                        ELSE 0.0
                    END
                ),
                0.0
            ) AS replacement_rate_30d,
            COALESCE(
                AVG(
                    CASE
                        WHEN pii_detected THEN 1.0
                        ELSE 0.0
                    END
                ),
                0.0
            ) AS pii_warning_rate_30d,
            (
                SELECT array_remove(array_agg(DISTINCT mode), NULL)
                FROM clinic_governance_events
                WHERE clinic_id = :clinic_id
                  AND created_at >= now() - interval '30 days'
            ) AS active_modes_30d,
            (
                SELECT mode
                FROM clinic_governance_events
                WHERE clinic_id = :clinic_id
                  AND created_at >= now() - interval '30 days'
                GROUP BY mode
                ORDER BY COUNT(*) DESC, mode ASC
                LIMIT 1
            ) AS top_mode_30d
        FROM clinic_governance_events
        WHERE clinic_id = :clinic_id
          AND created_at >= now() - interval '30 days'
        """,
        params,
    )

    receipt_coverage = _row(
        db,
        """
        WITH ops AS (
            SELECT COUNT(DISTINCT request_id) AS n
            FROM ops_metrics_events
            WHERE clinic_id = :clinic_id
              AND created_at >= now() - interval '30 days'
        ),
        gov AS (
            SELECT COUNT(DISTINCT request_id) AS n
            FROM clinic_governance_events
            WHERE clinic_id = :clinic_id
              AND created_at >= now() - interval '30 days'
        )
        SELECT
            CASE
                WHEN ops.n <= 0 THEN 1.0
                ELSE LEAST(gov.n::numeric / NULLIF(ops.n, 0)::numeric, 1.0)
            END AS receipt_coverage_rate
        FROM ops, gov
        """,
        params,
    )

    policy = _row(
        db,
        """
        SELECT active_policy_version
        FROM clinic_policy_state
        WHERE clinic_id = :clinic_id
        LIMIT 1
        """,
        params,
    )

    return {
        "health_24h": health_24h,
        "ops_24h": ops_24h,
        "gov_24h": gov_24h,
        "gov_30d": gov_30d,
        "receipt_coverage": receipt_coverage,
        "policy": policy,
    }


def build_trust_profile(db: Session, clinic_id: str) -> Dict[str, Any]:
    inputs = _collect_inputs(db, clinic_id)

    request_count_24h = _i(inputs["health_24h"].get("request_count_24h"))
    rate_5xx_24h = _f(inputs["health_24h"].get("rate_5xx_24h"))
    p95_latency_ms_24h = _f(inputs["health_24h"].get("p95_latency_ms_24h"))
    governance_replaced_rate_24h = _f(inputs["health_24h"].get("governance_replaced_rate_24h"))

    trust_state = _derive_trust_state(
        request_count_24h=request_count_24h,
        rate_5xx=rate_5xx_24h,
        p95_latency_ms=p95_latency_ms_24h,
        governance_replaced_rate=governance_replaced_rate_24h,
    )

    intervention_rate_24h = _f(inputs["gov_24h"].get("intervention_rate_24h"))
    pii_warned_rate_24h = _f(inputs["ops_24h"].get("pii_warned_rate_24h"))
    learning_tie_in_rate_24h = _f(inputs["gov_24h"].get("learning_tie_in_rate_24h"))

    intervention_rate_30d = _f(inputs["gov_30d"].get("intervention_rate_30d"))
    replacement_rate_30d = _f(inputs["gov_30d"].get("replacement_rate_30d"))
    pii_warning_rate_30d = _f(inputs["gov_30d"].get("pii_warning_rate_30d"))
    receipt_coverage_rate = _f(inputs["receipt_coverage"].get("receipt_coverage_rate"), 1.0)
    active_policy_version = inputs["policy"].get("active_policy_version")

    top_mode_24h = inputs["ops_24h"].get("top_mode_24h")
    top_route_24h = inputs["ops_24h"].get("top_route_24h")

    learning_topics = _recommended_topics(
        top_mode=top_mode_24h,
        top_route=top_route_24h,
        intervention_rate=intervention_rate_24h,
        pii_rate=pii_warned_rate_24h,
        replacement_rate=replacement_rate_30d,
    )

    posture_score = _compute_posture_score(
        trust_state=trust_state,
        request_count_24h=request_count_24h,
        receipt_coverage_rate=receipt_coverage_rate,
        intervention_rate_30d=intervention_rate_30d,
        replacement_rate_30d=replacement_rate_30d,
        pii_warning_rate_30d=pii_warning_rate_30d,
        active_policy_version=active_policy_version,
        learning_enabled=True,
        export_capability=True,
    )

    posture_status = _status_from_score(posture_score)

    return {
        "clinic_id": clinic_id,
        "generated_at": _utcnow_iso(),
        "trust_state": trust_state,
        "posture_status": posture_status,
        "posture_score": posture_score,
        "controls": {
            "metadata_only_accountability": True,
            "governance_receipts": True,
            "policy_versioning": active_policy_version is not None,
            "tenant_isolation_rls_forced": True,
            "privacy_controls_active": True,
            "export_capability": True,
            "learning_layer_available": True,
        },
        "operations": {
            "events_24h": _i(inputs["ops_24h"].get("events_24h")),
            "intervention_rate_24h": _round_rate(intervention_rate_24h),
            "pii_warned_rate_24h": _round_rate(pii_warned_rate_24h),
            "top_mode_24h": top_mode_24h,
            "top_route_24h": top_route_24h,
        },
        "learning_readiness": {
            "recommended_topics": learning_topics,
            "learning_tie_in_rate_24h": _round_rate(learning_tie_in_rate_24h),
        },
        "export_readiness": {
            "trust_pack_available": False,
            "last_pack_generated_at": None,
        },
    }


def build_trust_posture(db: Session, clinic_id: str) -> Dict[str, Any]:
    inputs = _collect_inputs(db, clinic_id)

    request_count_24h = _i(inputs["health_24h"].get("request_count_24h"))
    rate_5xx_24h = _f(inputs["health_24h"].get("rate_5xx_24h"))
    p95_latency_ms_24h = _f(inputs["health_24h"].get("p95_latency_ms_24h"))
    governance_replaced_rate_24h = _f(inputs["health_24h"].get("governance_replaced_rate_24h"))

    trust_state = _derive_trust_state(
        request_count_24h=request_count_24h,
        rate_5xx=rate_5xx_24h,
        p95_latency_ms=p95_latency_ms_24h,
        governance_replaced_rate=governance_replaced_rate_24h,
    )

    intervention_rate_30d = _f(inputs["gov_30d"].get("intervention_rate_30d"))
    replacement_rate_30d = _f(inputs["gov_30d"].get("replacement_rate_30d"))
    pii_warning_rate_30d = _f(inputs["gov_30d"].get("pii_warning_rate_30d"))
    receipt_coverage_rate = _f(inputs["receipt_coverage"].get("receipt_coverage_rate"), 1.0)
    active_policy_version = inputs["policy"].get("active_policy_version")

    top_mode_30d = inputs["gov_30d"].get("top_mode_30d")
    active_modes_30d = inputs["gov_30d"].get("active_modes_30d") or []

    posture_score = _compute_posture_score(
        trust_state=trust_state,
        request_count_24h=request_count_24h,
        receipt_coverage_rate=receipt_coverage_rate,
        intervention_rate_30d=intervention_rate_30d,
        replacement_rate_30d=replacement_rate_30d,
        pii_warning_rate_30d=pii_warning_rate_30d,
        active_policy_version=active_policy_version,
        learning_enabled=True,
        export_capability=True,
    )

    posture_status = _status_from_score(posture_score)

    learning_topics = _recommended_topics(
        top_mode=top_mode_30d,
        top_route=None,
        intervention_rate=intervention_rate_30d,
        pii_rate=pii_warning_rate_30d,
        replacement_rate=replacement_rate_30d,
    )

    attention_areas = _attention_areas(
        trust_state=trust_state,
        top_mode=top_mode_30d,
        intervention_rate_30d=intervention_rate_30d,
        replacement_rate_30d=replacement_rate_30d,
        pii_warning_rate_30d=pii_warning_rate_30d,
        receipt_coverage_rate=receipt_coverage_rate,
    )

    recommended_actions = _recommended_actions(
        attention_areas=attention_areas,
        learning_topics=learning_topics,
        posture_status=posture_status,
    )

    events_30d = _i(inputs["gov_30d"].get("governed_events_30d"))

    return {
        "clinic_id": clinic_id,
        "generated_at": _utcnow_iso(),
        "summary": {
            "posture_status": posture_status,
            "posture_score": posture_score,
            "headline": _headline(posture_status, trust_state, request_count_24h),
        },
        "adoption": {
            "events_30d": events_30d,
            "active_modes": active_modes_30d,
            "top_mode": top_mode_30d,
        },
        "governance": {
            "intervention_rate_30d": _round_rate(intervention_rate_30d),
            "replacement_rate_30d": _round_rate(replacement_rate_30d),
            "receipt_coverage_rate": _round_rate(receipt_coverage_rate),
            "active_policy_version": active_policy_version,
        },
        "privacy": {
            "metadata_only_model": True,
            "pii_warning_rate_30d": _round_rate(pii_warning_rate_30d),
            "raw_content_storage": False,
        },
        "learning": {
            "learn_enabled": True,
            "top_recommended_topics": learning_topics,
        },
        "attention_areas": attention_areas,
        "recommended_actions": recommended_actions,
    }


def build_trust_pack_metadata() -> Dict[str, Any]:
    return {
        "available_packs": [
            {
                "pack_type": "trust_overview_pdf",
                "label": "Clinic Trust Overview",
                "available": False,
            },
            {
                "pack_type": "governance_posture_pdf",
                "label": "Governance Posture Summary",
                "available": False,
            },
        ],
        "recent_generations": [],
    }
