# app/trust_snapshot.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session


# ---------------------------
# Shared thresholds
# ---------------------------

SLO_MAX_5XX_RATE = 0.01
SLO_MAX_P95_LATENCY_MS = 1000
SLO_MAX_GOV_REPLACED_RATE = 0.10

RED_MAX_5XX_RATE = 0.05
RED_MAX_P95_LATENCY_MS = 3000
RED_MAX_GOV_REPLACED_RATE = 0.30


# ---------------------------
# Small utilities
# ---------------------------

def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def _clean_label(value: Optional[str]) -> str:
    value = (value or "").strip()
    return value if value else "—"


def _derive_trust_state(
    rate_5xx: float,
    p95_latency_ms: float,
    gov_replaced_rate: float,
) -> str:
    if (
        rate_5xx >= RED_MAX_5XX_RATE
        or p95_latency_ms >= RED_MAX_P95_LATENCY_MS
        or gov_replaced_rate >= RED_MAX_GOV_REPLACED_RATE
    ):
        return "red"

    if (
        rate_5xx >= SLO_MAX_5XX_RATE
        or p95_latency_ms >= SLO_MAX_P95_LATENCY_MS
        or gov_replaced_rate >= SLO_MAX_GOV_REPLACED_RATE
    ):
        return "yellow"

    return "green"


def _derive_signal_quality(request_count_24h: int, events_24h: int) -> str:
    total = int(request_count_24h) + int(events_24h)
    if total <= 0:
        return "low"
    if total < 20:
        return "moderate"
    return "strong"


def _derive_recommended_learning(
    top_mode_24h: str,
    intervention_rate_24h: float,
    pii_warned_rate_24h: float,
) -> Dict[str, str]:
    if pii_warned_rate_24h >= 0.05:
        return {
            "title": "Privacy-aware AI use",
            "reason": "Recent activity suggests staff would benefit from reinforcement on privacy-aware prompting and information handling.",
        }

    if intervention_rate_24h >= 0.05:
        if top_mode_24h == "client_comm":
            return {
                "title": "Safe AI use in client communications",
                "reason": "Recent activity suggests reinforcement is most useful around governed drafting for client-facing content.",
            }
        if top_mode_24h == "clinical_note":
            return {
                "title": "Governed drafting for clinical notes",
                "reason": "Recent activity suggests reinforcement is most useful around governed drafting for internal note workflows.",
            }
        return {
            "title": "Governance basics and safe AI use",
            "reason": "Recent activity suggests reinforcement on safe use and governance boundaries would be helpful.",
        }

    return {
        "title": "Governance receipts and policy explainers",
        "reason": "Current signals do not indicate elevated friction; baseline reinforcement on receipts, explainers, and safe AI use remains appropriate.",
    }


def _row_mapping(db: Session, sql: str, params: Dict[str, Any]) -> Dict[str, Any]:
    row = db.execute(text(sql), params).mappings().first()
    return dict(row) if row else {}


def _build_limitations(signal_quality: str) -> List[str]:
    limitations: List[str] = [
        "This trust snapshot is derived from metadata-only governance and operational evidence.",
        "ANCHOR does not rely on stored raw prompts or outputs for this trust surface.",
        "This surface is an operational trust summary and should not be presented as a legal certification or formal compliance attestation.",
    ]

    if signal_quality == "low":
        limitations.append(
            "Recent evidence volume is low, so the current trust state should be interpreted as a light-signal operational view."
        )

    return limitations


# ---------------------------
# Main builder
# ---------------------------

def build_trust_snapshot(
    db: Session,
    clinic_id: str,
    evidence_window_hours: int = 24,
) -> Dict[str, Any]:
    now_utc = datetime.now(timezone.utc)
    cutoff = now_utc - timedelta(hours=max(1, int(evidence_window_hours)))

    clinic = _row_mapping(
        db,
        """
        SELECT
            clinic_id::text AS clinic_id,
            clinic_name,
            clinic_slug,
            COALESCE(active_status, true) AS active_status
        FROM public.clinics
        WHERE clinic_id = :clinic_id::uuid
        LIMIT 1
        """,
        {"clinic_id": clinic_id},
    )

    policy = _row_mapping(
        db,
        """
        SELECT
            active_policy_version
        FROM public.clinic_policy_state
        WHERE clinic_id = :clinic_id::uuid
        LIMIT 1
        """,
        {"clinic_id": clinic_id},
    )

    gov = _row_mapping(
        db,
        """
        SELECT
            COUNT(*)::int AS events_24h,
            COALESCE(SUM(CASE WHEN decision IN ('replaced', 'blocked', 'modified') THEN 1 ELSE 0 END), 0)::int AS interventions_24h,
            COALESCE(AVG(CASE WHEN decision IN ('replaced', 'blocked', 'modified') THEN 1.0 ELSE 0.0 END), 0.0) AS intervention_rate_24h,
            COALESCE(SUM(CASE WHEN pii_action = 'warn' THEN 1 ELSE 0 END), 0)::int AS pii_warned_24h,
            COALESCE(AVG(CASE WHEN pii_action = 'warn' THEN 1.0 ELSE 0.0 END), 0.0) AS pii_warned_rate_24h
        FROM public.clinic_governance_events
        WHERE clinic_id = :clinic_id::uuid
          AND created_at >= :cutoff
        """,
        {"clinic_id": clinic_id, "cutoff": cutoff},
    )

    ops = _row_mapping(
        db,
        """
        SELECT
            COUNT(*)::int AS request_count_24h,
            COALESCE(AVG(CASE WHEN status_code >= 500 THEN 1.0 ELSE 0.0 END), 0.0) AS rate_5xx,
            COALESCE(percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms), 0)::int AS p95_latency_ms,
            COALESCE(AVG(CASE WHEN governance_replaced THEN 1.0 ELSE 0.0 END), 0.0) AS gov_replaced_rate,
            COALESCE(AVG(CASE WHEN pii_warned THEN 1.0 ELSE 0.0 END), 0.0) AS ops_pii_warned_rate_24h
        FROM public.ops_metrics_events
        WHERE clinic_id = :clinic_id::uuid
          AND created_at >= :cutoff
        """,
        {"clinic_id": clinic_id, "cutoff": cutoff},
    )

    top_mode = _row_mapping(
        db,
        """
        SELECT
            mode,
            COUNT(*)::int AS n
        FROM public.ops_metrics_events
        WHERE clinic_id = :clinic_id::uuid
          AND created_at >= :cutoff
        GROUP BY mode
        ORDER BY COUNT(*) DESC, mode ASC
        LIMIT 1
        """,
        {"clinic_id": clinic_id, "cutoff": cutoff},
    )

    top_route = _row_mapping(
        db,
        """
        SELECT
            route,
            COUNT(*)::int AS n
        FROM public.ops_metrics_events
        WHERE clinic_id = :clinic_id::uuid
          AND created_at >= :cutoff
        GROUP BY route
        ORDER BY COUNT(*) DESC, route ASC
        LIMIT 1
        """,
        {"clinic_id": clinic_id, "cutoff": cutoff},
    )

    request_count_24h = _to_int(ops.get("request_count_24h"))
    events_24h = _to_int(gov.get("events_24h"))
    interventions_24h = _to_int(gov.get("interventions_24h"))
    intervention_rate_24h = _to_float(gov.get("intervention_rate_24h"))
    pii_warned_24h = _to_int(gov.get("pii_warned_24h"))
    pii_warned_rate_24h = _to_float(gov.get("pii_warned_rate_24h"))

    rate_5xx = _to_float(ops.get("rate_5xx"))
    p95_latency_ms = _to_float(ops.get("p95_latency_ms"))
    gov_replaced_rate = _to_float(ops.get("gov_replaced_rate"))

    top_mode_24h = _clean_label(top_mode.get("mode"))
    top_route_24h = _clean_label(top_route.get("route"))

    trust_state = _derive_trust_state(
        rate_5xx=rate_5xx,
        p95_latency_ms=p95_latency_ms,
        gov_replaced_rate=gov_replaced_rate,
    )
    signal_quality = _derive_signal_quality(
        request_count_24h=request_count_24h,
        events_24h=events_24h,
    )

    recommended_learning = _derive_recommended_learning(
        top_mode_24h=top_mode_24h,
        intervention_rate_24h=intervention_rate_24h,
        pii_warned_rate_24h=pii_warned_rate_24h,
    )

    snapshot: Dict[str, Any] = {
        "snapshot_version": "1.0",
        "generated_at": now_utc.isoformat(),
        "evidence_window": {
            "hours": int(evidence_window_hours),
            "from": cutoff.isoformat(),
            "to": now_utc.isoformat(),
        },
        "clinic": {
            "clinic_id": clinic.get("clinic_id") or clinic_id,
            "clinic_name": clinic.get("clinic_name") or "Clinic",
            "clinic_slug": clinic.get("clinic_slug") or "",
            "active_status": bool(clinic.get("active_status", True)),
        },
        "governance": {
            "policy_version": _to_int(policy.get("active_policy_version")),
            "policy_versioning": True,
            "governance_receipts_active": True,
            "metadata_only_accountability": True,
            "stores_raw_content": False,
            "override_model": "append_only_admin_audit",
            "events_24h": events_24h,
            "interventions_24h": interventions_24h,
            "intervention_rate_24h": intervention_rate_24h,
        },
        "privacy": {
            "privacy_controls_active": True,
            "privacy_controls_label": "Metadata-only accountability with privacy-aware controls",
            "hashed_ip_ua_logging": True,
            "stores_raw_prompt_output": False,
            "pii_warned_24h": pii_warned_24h,
            "pii_warned_rate_24h": pii_warned_rate_24h,
        },
        "tenancy": {
            "hard_multi_tenancy": True,
            "rls_forced": True,
            "request_scoped_context": True,
            "clinic_scoped_portal_access": True,
            "tenant_isolation_testing_in_operating_model": True,
        },
        "operations": {
            "trust_state": trust_state,
            "signal_quality": signal_quality,
            "request_count_24h": request_count_24h,
            "events_24h": events_24h,
            "interventions_24h": interventions_24h,
            "intervention_rate_24h": intervention_rate_24h,
            "pii_warned_24h": pii_warned_24h,
            "pii_warned_rate_24h": pii_warned_rate_24h,
            "rate_5xx": rate_5xx,
            "p95_latency_ms": int(p95_latency_ms),
            "gov_replaced_rate": gov_replaced_rate,
            "top_mode_24h": top_mode_24h,
            "top_route_24h": top_route_24h,
        },
        "learning": {
            "enabled": True,
            "cards_available": True,
            "explainers_available": True,
            "dashboard_tie_in": True,
            "receipts_related_learning": True,
            "recommended_learning": recommended_learning,
        },
        "limitations": _build_limitations(signal_quality=signal_quality),
    }

    return snapshot
