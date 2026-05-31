# app/trust_snapshot.py
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session


logger = logging.getLogger(__name__)


SLO_MAX_5XX_RATE = 0.01
SLO_MAX_P95_LATENCY_MS = 1000
SLO_MAX_GOV_REPLACED_RATE = 0.10

RED_MAX_5XX_RATE = 0.05
RED_MAX_P95_LATENCY_MS = 3000
RED_MAX_GOV_REPLACED_RATE = 0.30


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


def _clean_optional_label(value: Optional[str]) -> Optional[str]:
    value = (value or "").strip()
    return value if value else None


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
    top_mode_24h: Optional[str],
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


def _safe_row_mapping(
    db: Session,
    sql: str,
    params: Dict[str, Any],
    query_name: str,
) -> Dict[str, Any]:
    try:
        row = db.execute(text(sql), params).mappings().first()
        return dict(row) if row else {}
    except Exception:
        logger.exception("trust_snapshot query failed: %s", query_name)
        return {}


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


def _resolve_policy_version(db: Session, clinic_id: str) -> int:
    row = _safe_row_mapping(
        db,
        """
        SELECT
            COALESCE(active_policy_version, 0)::int AS active_policy_version
        FROM public.clinic_policy_state
        WHERE clinic_id = CAST(:clinic_id AS uuid)
        LIMIT 1
        """,
        {"clinic_id": clinic_id},
        "policy_state_lookup",
    )
    active_policy_version = _to_int(row.get("active_policy_version"), default=0)
    if active_policy_version > 0:
        return active_policy_version

    row = _safe_row_mapping(
        db,
        """
        SELECT
            COALESCE(MAX(policy_version), 0)::int AS latest_policy_version
        FROM public.clinic_governance_events
        WHERE clinic_id = CAST(:clinic_id AS uuid)
        """,
        {"clinic_id": clinic_id},
        "policy_version_from_governance_history",
    )
    latest_policy_version = _to_int(row.get("latest_policy_version"), default=0)
    if latest_policy_version > 0:
        return latest_policy_version

    return 1


_GOVERNANCE_POLICY_NOTE = (
    "Governance policy evidence is metadata-only. It records active "
    "AI-use policy versions and staff acknowledgement coverage. It is "
    "not legal advice, a certification mark, a competence assessment, "
    "or a guarantee of regulatory compliance."
)


def _build_governance_policy_block(
    db: Session,
    clinic_id: str,
) -> Dict[str, Any]:
    """Aggregate metadata-only governance policy + staff attestation
    evidence for the Trust posture surface.

    No policy body text. No staff names/emails. No void reasons.
    """
    expected_row = _safe_row_mapping(
        db,
        """
        SELECT COUNT(*)::int AS c
        FROM public.clinic_users
        WHERE clinic_id = CAST(:clinic_id AS uuid)
          AND active_status = true
        """,
        {"clinic_id": clinic_id},
        "governance_policy_expected_users",
    )
    expected_user_count = _to_int(expected_row.get("c"), default=0)

    try:
        rows = list(
            db.execute(
                text(
                    """
                    SELECT
                        cpv.clinic_policy_version_id,
                        cpv.policy_template_id,
                        cpv.clinic_policy_version,
                        cpv.title_snapshot,
                        cpv.activated_at,
                        cpv.updated_at,
                        pt.template_slug,
                        COUNT(pa.attestation_id)
                            FILTER (WHERE pa.is_voided = false)::int
                            AS attestation_count,
                        COUNT(DISTINCT pa.user_id)
                            FILTER (WHERE pa.is_voided = false)::int
                            AS distinct_user_count,
                        MAX(pa.acknowledged_at)
                            FILTER (WHERE pa.is_voided = false)
                            AS most_recent_acknowledged_at
                    FROM public.clinic_policy_versions cpv
                    LEFT JOIN public.policy_templates pt
                        ON pt.template_id = cpv.policy_template_id
                    LEFT JOIN public.policy_attestations pa
                        ON pa.clinic_policy_version_id
                                = cpv.clinic_policy_version_id
                        AND pa.clinic_id = cpv.clinic_id
                    WHERE cpv.clinic_id = CAST(:clinic_id AS uuid)
                      AND cpv.status = 'active'
                    GROUP BY
                        cpv.clinic_policy_version_id,
                        cpv.policy_template_id,
                        cpv.clinic_policy_version,
                        cpv.title_snapshot,
                        cpv.activated_at,
                        cpv.updated_at,
                        pt.template_slug
                    ORDER BY cpv.activated_at DESC NULLS LAST
                    """
                ),
                {"clinic_id": clinic_id},
            ).mappings().all()
        )
    except Exception:
        logger.exception("trust_snapshot query failed: governance_policy_active")
        rows = []

    active_policies: List[Dict[str, Any]] = []
    coverage_rates: List[float] = []
    total_attestation_count = 0
    last_policy_update_at: Optional[datetime] = None
    most_recent_acknowledged_at: Optional[datetime] = None

    for raw in rows:
        r = dict(raw)
        attestation_count = _to_int(r.get("attestation_count"))
        distinct_user_count = _to_int(r.get("distinct_user_count"))
        outstanding = max(expected_user_count - distinct_user_count, 0)
        coverage_rate = (
            (distinct_user_count / expected_user_count)
            if expected_user_count > 0
            else 0.0
        )
        coverage_rates.append(coverage_rate)
        total_attestation_count += attestation_count

        activated_at = r.get("activated_at")
        updated_at = r.get("updated_at")
        candidate_update = activated_at or updated_at
        if candidate_update is not None and (
            last_policy_update_at is None
            or candidate_update > last_policy_update_at
        ):
            last_policy_update_at = candidate_update

        row_mra = r.get("most_recent_acknowledged_at")
        if row_mra is not None and (
            most_recent_acknowledged_at is None
            or row_mra > most_recent_acknowledged_at
        ):
            most_recent_acknowledged_at = row_mra

        active_policies.append(
            {
                "policy_template_id": str(r["policy_template_id"]),
                "clinic_policy_version_id": str(
                    r["clinic_policy_version_id"]
                ),
                "clinic_policy_version": int(r["clinic_policy_version"]),
                "title": str(r.get("title_snapshot") or ""),
                "template_slug": r.get("template_slug"),
                "activated_at": (
                    activated_at.isoformat() if activated_at else None
                ),
                "attestation_coverage": {
                    "attestation_count": attestation_count,
                    "distinct_user_count": distinct_user_count,
                    "expected_user_count": expected_user_count,
                    "outstanding_user_count": outstanding,
                    "coverage_rate": coverage_rate,
                    "most_recent_acknowledged_at": (
                        row_mra.isoformat() if row_mra else None
                    ),
                },
            }
        )

    distinct_row = _safe_row_mapping(
        db,
        """
        SELECT COUNT(DISTINCT pa.user_id)::int AS c
        FROM public.policy_attestations pa
        JOIN public.clinic_policy_versions cpv
            ON cpv.clinic_policy_version_id = pa.clinic_policy_version_id
           AND cpv.clinic_id = pa.clinic_id
        WHERE pa.clinic_id = CAST(:clinic_id AS uuid)
          AND pa.is_voided = false
          AND cpv.status = 'active'
        """,
        {"clinic_id": clinic_id},
        "governance_policy_distinct_users",
    )
    total_distinct_users_attested = _to_int(distinct_row.get("c"), default=0)

    active_policy_count = len(active_policies)
    average_coverage_rate = (
        sum(coverage_rates) / active_policy_count
        if active_policy_count > 0
        else 0.0
    )
    total_outstanding_user_count = max(
        expected_user_count - total_distinct_users_attested, 0
    )

    return {
        "active_policy_count": active_policy_count,
        "active_policies": active_policies,
        "total_attestation_count": total_attestation_count,
        "total_distinct_users_attested": total_distinct_users_attested,
        "expected_user_count": expected_user_count,
        "outstanding_user_count": total_outstanding_user_count,
        "average_coverage_rate": average_coverage_rate,
        "last_policy_update_at": (
            last_policy_update_at.isoformat()
            if last_policy_update_at
            else None
        ),
        "most_recent_acknowledged_at": (
            most_recent_acknowledged_at.isoformat()
            if most_recent_acknowledged_at
            else None
        ),
        "raw_policy_body_included": False,
        "governance_note": _GOVERNANCE_POLICY_NOTE,
    }


def build_trust_snapshot(
    db: Session,
    clinic_id: str,
    evidence_window_hours: int = 24,
) -> Dict[str, Any]:
    now_utc = datetime.now(timezone.utc)
    cutoff = now_utc - timedelta(hours=max(1, int(evidence_window_hours)))

    clinic = _safe_row_mapping(
        db,
        """
        SELECT
            CAST(clinic_id AS text) AS clinic_id,
            clinic_name,
            clinic_slug,
            COALESCE(active_status, true) AS active_status
        FROM public.clinics
        WHERE clinic_id = CAST(:clinic_id AS uuid)
        LIMIT 1
        """,
        {"clinic_id": clinic_id},
        "clinic_lookup",
    )

    gov = _safe_row_mapping(
        db,
        """
        SELECT
            COUNT(*)::int AS events_24h,
            COALESCE(SUM(CASE WHEN decision IN ('replaced', 'blocked', 'modified') THEN 1 ELSE 0 END), 0)::int AS interventions_24h,
            COALESCE(AVG(CASE WHEN decision IN ('replaced', 'blocked', 'modified') THEN 1.0 ELSE 0.0 END), 0.0) AS intervention_rate_24h,
            COALESCE(SUM(CASE WHEN pii_action = 'warn' THEN 1 ELSE 0 END), 0)::int AS pii_warned_24h,
            COALESCE(AVG(CASE WHEN pii_action = 'warn' THEN 1.0 ELSE 0.0 END), 0.0) AS pii_warned_rate_24h,
            COALESCE(MAX(policy_version), 0)::int AS latest_policy_version
        FROM public.clinic_governance_events
        WHERE clinic_id = CAST(:clinic_id AS uuid)
          AND created_at >= :cutoff
        """,
        {"clinic_id": clinic_id, "cutoff": cutoff},
        "governance_summary",
    )

    ops = _safe_row_mapping(
        db,
        """
        SELECT
            COUNT(*)::int AS request_count_24h,
            COALESCE(AVG(CASE WHEN status_code >= 500 THEN 1.0 ELSE 0.0 END), 0.0) AS rate_5xx,
            COALESCE(percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms), 0)::int AS p95_latency_ms,
            COALESCE(AVG(CASE WHEN governance_replaced THEN 1.0 ELSE 0.0 END), 0.0) AS gov_replaced_rate,
            COALESCE(AVG(CASE WHEN pii_warned THEN 1.0 ELSE 0.0 END), 0.0) AS ops_pii_warned_rate_24h
        FROM public.ops_metrics_events
        WHERE clinic_id = CAST(:clinic_id AS uuid)
          AND created_at >= :cutoff
        """,
        {"clinic_id": clinic_id, "cutoff": cutoff},
        "ops_summary",
    )

    top_mode = _safe_row_mapping(
        db,
        """
        SELECT
            mode,
            COUNT(*)::int AS n
        FROM public.ops_metrics_events
        WHERE clinic_id = CAST(:clinic_id AS uuid)
          AND created_at >= :cutoff
        GROUP BY mode
        ORDER BY COUNT(*) DESC, mode ASC
        LIMIT 1
        """,
        {"clinic_id": clinic_id, "cutoff": cutoff},
        "top_mode",
    )

    top_route = _safe_row_mapping(
        db,
        """
        SELECT
            route,
            COUNT(*)::int AS n
        FROM public.ops_metrics_events
        WHERE clinic_id = CAST(:clinic_id AS uuid)
          AND created_at >= :cutoff
        GROUP BY route
        ORDER BY COUNT(*) DESC, route ASC
        LIMIT 1
        """,
        {"clinic_id": clinic_id, "cutoff": cutoff},
        "top_route",
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

    top_mode_24h = _clean_optional_label(top_mode.get("mode"))
    top_route_24h = _clean_optional_label(top_route.get("route"))

    if request_count_24h <= 0:
        top_mode_24h = None
        top_route_24h = None

    observed_policy_version = _resolve_policy_version(db=db, clinic_id=clinic_id)

    trust_state = _derive_trust_state(
        rate_5xx=rate_5xx,
        p95_latency_ms=p95_latency_ms,
        gov_replaced_rate=gov_replaced_rate,
    )
    signal_quality = _derive_signal_quality(
        request_count_24h=request_count_24h,
        events_24h=events_24h,
    )

    governance_policy_block = _build_governance_policy_block(
        db=db, clinic_id=clinic_id,
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
            "policy_version": observed_policy_version,
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
        "governance_policy": governance_policy_block,
        "limitations": _build_limitations(signal_quality=signal_quality),
    }

    return snapshot
