from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import SessionLocal, set_rls_context, clear_rls_context
from app.auth_and_rls import require_clinic_user


router = APIRouter(prefix="/v1/portal/intelligence", tags=["portal-intelligence"])


# -------------------------------------------------------------------
# Clinic-scoped DB dependency (RLS-aware)
# -------------------------------------------------------------------
def _extract_clinic_id(clinic_ctx: Any) -> str:
    if isinstance(clinic_ctx, dict):
        clinic_id = clinic_ctx.get("clinic_id")
    else:
        clinic_id = getattr(clinic_ctx, "clinic_id", None)

    if not clinic_id:
        raise HTTPException(status_code=401, detail="Missing clinic context")

    return str(clinic_id)


def _extract_clinic_user_id(clinic_ctx: Any) -> str:
    if isinstance(clinic_ctx, dict):
        clinic_user_id = clinic_ctx.get("clinic_user_id")
    else:
        clinic_user_id = getattr(clinic_ctx, "clinic_user_id", None)

    if not clinic_user_id:
        raise HTTPException(status_code=401, detail="Missing clinic user context")

    return str(clinic_user_id)


def get_clinic_scoped_db(
    clinic_ctx: Any = Depends(require_clinic_user),
) -> Iterable[Session]:
    db = SessionLocal()
    try:
        clinic_id = _extract_clinic_id(clinic_ctx)
        clinic_user_id = _extract_clinic_user_id(clinic_ctx)
        set_rls_context(
            db,
            clinic_id=clinic_id,
            clinic_user_id=clinic_user_id,
        )
        yield db
    finally:
        try:
            clear_rls_context(db)
        except Exception:
            pass
        db.close()


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
_ALLOWED_WINDOWS = {"7d", "30d"}
_ALLOWED_DIMENSIONS = {"all", "mode", "route", "reason_code", "risk_grade", "pii_action"}
_INTERVENTION_DECISIONS = ("replaced", "modified", "blocked")

_LEARN_MAPPING = {
    "mode:client_comm": "/learn/explainers/client-communication-safety",
    "mode:clinical_note": "/learn/explainers/clinical-note-governance",
    "mode:internal_summary": "/learn/explainers/internal-summary-safe-use",
    "reason_code:PII_WARNING": "/learn/cards/privacy-safe-ai-use",
    "reason_code:LOW_CONFIDENCE_REWRITE": "/learn/cards/reviewing-ai-rewrites",
    "pii_action:warn": "/learn/cards/privacy-safe-ai-use",
    "route:/v1/portal/assist": "/learn/explainers/using-assisted-workflows-safely",
}

_GOVERNANCE_DIM_SQL = {
    "mode": "COALESCE(mode, 'unknown')",
    "reason_code": "COALESCE(reason_code, 'unknown')",
    "risk_grade": "COALESCE(risk_grade, 'unknown')",
    "pii_action": "COALESCE(pii_action, 'unknown')",
}

_ROUTE_DIM_SQL = "COALESCE(route, 'unknown')"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_window(window: str) -> timedelta:
    if window not in _ALLOWED_WINDOWS:
        raise HTTPException(status_code=400, detail=f"window must be one of {sorted(_ALLOWED_WINDOWS)}")
    return timedelta(days=7 if window == "7d" else 30)


def _recent_delta_for_window(window: str) -> timedelta:
    return timedelta(days=2 if window == "7d" else 7)


def _safe_div(n: float, d: float) -> float:
    if not d:
        return 0.0
    return float(n) / float(d)


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _severity_label(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _normalize_dimension(dimension: str) -> str:
    if dimension not in _ALLOWED_DIMENSIONS:
        raise HTTPException(status_code=400, detail=f"dimension must be one of {sorted(_ALLOWED_DIMENSIONS)}")
    return dimension


def _build_governance_dimension_query(dim_expr: str) -> str:
    return f"""
    WITH filtered AS (
        SELECT
            {dim_expr} AS segment_key,
            created_at,
            decision,
            pii_action
        FROM clinic_governance_events
        WHERE clinic_id = :clinic_id
          AND created_at >= :start_ts
          AND created_at < :end_ts
    ),
    agg AS (
        SELECT
            segment_key,
            COUNT(*) AS event_count,
            COUNT(*) FILTER (
                WHERE decision IN ('replaced', 'modified', 'blocked')
            ) AS intervention_count,
            COUNT(*) FILTER (
                WHERE pii_action = 'warn'
            ) AS pii_warned_count,
            COUNT(*) FILTER (
                WHERE created_at >= :recent_start
            ) AS recent_event_count,
            COUNT(*) FILTER (
                WHERE created_at >= :recent_start
                  AND decision IN ('replaced', 'modified', 'blocked')
            ) AS recent_intervention_count,
            COUNT(*) FILTER (
                WHERE created_at < :recent_start
            ) AS baseline_event_count,
            COUNT(*) FILTER (
                WHERE created_at < :recent_start
                  AND decision IN ('replaced', 'modified', 'blocked')
            ) AS baseline_intervention_count
        FROM filtered
        GROUP BY segment_key
    )
    SELECT
        segment_key,
        event_count,
        intervention_count,
        pii_warned_count,
        recent_event_count,
        recent_intervention_count,
        baseline_event_count,
        baseline_intervention_count
    FROM agg
    ORDER BY event_count DESC, segment_key ASC
    """


def _build_route_dimension_query() -> str:
    return f"""
    WITH filtered AS (
        SELECT
            {_ROUTE_DIM_SQL} AS segment_key,
            created_at,
            governance_replaced,
            pii_warned
        FROM ops_metrics_events
        WHERE clinic_id = :clinic_id
          AND created_at >= :start_ts
          AND created_at < :end_ts
    ),
    agg AS (
        SELECT
            segment_key,
            COUNT(*) AS event_count,
            COUNT(*) FILTER (
                WHERE governance_replaced = true
            ) AS intervention_count,
            COUNT(*) FILTER (
                WHERE pii_warned = true
            ) AS pii_warned_count,
            COUNT(*) FILTER (
                WHERE created_at >= :recent_start
            ) AS recent_event_count,
            COUNT(*) FILTER (
                WHERE created_at >= :recent_start
                  AND governance_replaced = true
            ) AS recent_intervention_count,
            COUNT(*) FILTER (
                WHERE created_at < :recent_start
            ) AS baseline_event_count,
            COUNT(*) FILTER (
                WHERE created_at < :recent_start
                  AND governance_replaced = true
            ) AS baseline_intervention_count
        FROM filtered
        GROUP BY segment_key
    )
    SELECT
        segment_key,
        event_count,
        intervention_count,
        pii_warned_count,
        recent_event_count,
        recent_intervention_count,
        baseline_event_count,
        baseline_intervention_count
    FROM agg
    ORDER BY event_count DESC, segment_key ASC
    """


def _load_dimension_rows(
    db: Session,
    clinic_id: str,
    start_ts: datetime,
    end_ts: datetime,
    recent_start: datetime,
    dimension: str,
) -> List[Dict[str, Any]]:
    if dimension == "route":
        sql = _build_route_dimension_query()
    else:
        dim_expr = _GOVERNANCE_DIM_SQL[dimension]
        sql = _build_governance_dimension_query(dim_expr)

    rows = db.execute(
        text(sql),
        {
            "clinic_id": clinic_id,
            "start_ts": start_ts,
            "end_ts": end_ts,
            "recent_start": recent_start,
        },
    ).mappings().all()

    return [dict(r) for r in rows]


def _build_hotspot_summary(item: Dict[str, Any]) -> str:
    dimension = item["dimension"]
    key = item["key"]
    severity = item.get("severity") or "unknown"

    if dimension == "mode":
        return f"{key} shows {severity} governance friction concentration in the selected window."
    if dimension == "route":
        return f"{key} shows {severity} operational governance friction in the selected window."
    if dimension == "reason_code":
        return f"{key} is a repeated governance intervention driver in the selected window."
    if dimension == "risk_grade":
        return f"{key} risk-grade events show meaningful concentration in the selected window."
    if dimension == "pii_action":
        return f"{key} privacy action events show repeated concentration in the selected window."
    return f"{key} shows governance concentration in the selected window."


def _score_hotspots(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not items:
        return items

    max_event_share = max((float(x["event_share"]) for x in items), default=0.0) or 1.0
    max_spike = max((float(x["recency_spike_ratio"]) for x in items), default=0.0) or 1.0

    for item in items:
        intervention_rate_norm = _clamp(float(item["intervention_rate"]), 0.0, 1.0)
        event_share_norm = _clamp(float(item["event_share"]) / max_event_share, 0.0, 1.0)
        pii_warned_rate_norm = _clamp(float(item["pii_warned_rate"]), 0.0, 1.0)
        recency_spike_norm = _clamp(float(item["recency_spike_ratio"]) / max_spike, 0.0, 1.0)

        severity_score = round(
            (35 * intervention_rate_norm)
            + (25 * event_share_norm)
            + (20 * pii_warned_rate_norm)
            + (20 * recency_spike_norm)
        )

        item["severity_score"] = int(severity_score)
        item["severity"] = _severity_label(int(severity_score))
        item["summary"] = _build_hotspot_summary(item)

    items.sort(
        key=lambda x: (
            int(x["severity_score"]),
            float(x["intervention_rate"]),
            int(x["event_count"]),
        ),
        reverse=True,
    )
    return items


def _build_hotspots_for_dimension(
    db: Session,
    clinic_id: str,
    start_ts: datetime,
    end_ts: datetime,
    recent_start: datetime,
    dimension: str,
) -> List[Dict[str, Any]]:
    raw_rows = _load_dimension_rows(db, clinic_id, start_ts, end_ts, recent_start, dimension)

    # Privacy-aware suppression threshold
    filtered_rows = [r for r in raw_rows if int(r["event_count"]) >= 5]
    total_events = sum(int(r["event_count"]) for r in filtered_rows)
    total_interventions = sum(int(r["intervention_count"]) for r in filtered_rows)

    items: List[Dict[str, Any]] = []
    for row in filtered_rows:
        event_count = int(row["event_count"])
        intervention_count = int(row["intervention_count"])
        pii_warned_count = int(row["pii_warned_count"])

        recent_event_count = int(row["recent_event_count"])
        recent_intervention_count = int(row["recent_intervention_count"])
        baseline_event_count = int(row["baseline_event_count"])
        baseline_intervention_count = int(row["baseline_intervention_count"])

        recent_rate = _safe_div(recent_intervention_count, recent_event_count)
        baseline_rate = _safe_div(baseline_intervention_count, baseline_event_count)
        recency_spike_ratio = recent_rate / max(baseline_rate, 0.01)

        item = {
            "dimension": dimension,
            "key": str(row["segment_key"]),
            "event_count": event_count,
            "event_share": round(_safe_div(event_count, total_events), 4),
            "intervention_count": intervention_count,
            "intervention_rate": round(_safe_div(intervention_count, event_count), 4),
            "pii_warned_count": pii_warned_count,
            "pii_warned_rate": round(_safe_div(pii_warned_count, event_count), 4),
            "recency_spike_ratio": round(_clamp(recency_spike_ratio, 0.0, 3.0), 2),
            "share_of_all_interventions": round(_safe_div(intervention_count, total_interventions), 4),
            "summary": "",
        }

        items.append(item)

    return _score_hotspots(items)


def _build_all_hotspots(
    db: Session,
    clinic_id: str,
    start_ts: datetime,
    end_ts: datetime,
    recent_start: datetime,
) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for dimension in ("mode", "route", "reason_code", "risk_grade", "pii_action"):
        items.extend(_build_hotspots_for_dimension(db, clinic_id, start_ts, end_ts, recent_start, dimension))

    items = _score_hotspots(items)
    return items


def _build_recommendations(hotspots: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str, str]] = set()

    for h in hotspots:
        dimension = h["dimension"]
        key = h["key"]
        severity = h["severity"]
        intervention_count = int(h["intervention_count"])
        intervention_rate = float(h["intervention_rate"])
        share_of_all_interventions = float(h.get("share_of_all_interventions", 0.0))
        pii_warned_rate = float(h["pii_warned_rate"])

        # Learning recommendation
        if dimension == "mode" and (severity == "high" or intervention_rate >= 0.12):
            target = _LEARN_MAPPING.get(f"mode:{key}")
            rec = {
                "type": "learning",
                "priority": "high" if severity == "high" else "medium",
                "title": f"Reinforce safe AI use in {key} workflows",
                "why": f"{key} has elevated governance intervention concentration in the selected period.",
                "based_on": {"dimension": dimension, "key": key},
                "target_path": target,
            }
            sig = (rec["type"], dimension, key)
            if sig not in seen:
                seen.add(sig)
                items.append(rec)

        # Policy review recommendation
        if dimension == "reason_code" and intervention_count > 0 and (
            share_of_all_interventions >= 0.25 or severity == "high"
        ):
            rec = {
                "type": "policy_review",
                "priority": "high" if severity == "high" else "medium",
                "title": f"Review policy wording for {key}",
                "why": f"{key} is a recurring intervention driver across the selected window.",
                "based_on": {"dimension": dimension, "key": key},
                "target_path": "/privacy-policy",
            }
            sig = (rec["type"], dimension, key)
            if sig not in seen:
                seen.add(sig)
                items.append(rec)

        # Privacy training recommendation
        if (dimension == "pii_action" and key == "warn") or pii_warned_rate >= 0.03:
            rec = {
                "type": "privacy_training",
                "priority": "medium" if severity != "high" else "high",
                "title": "Refresh privacy-safe AI use guidance",
                "why": "PII warnings exceed advisory thresholds in the selected period.",
                "based_on": {"dimension": dimension, "key": key},
                "target_path": _LEARN_MAPPING.get("pii_action:warn", "/learn/cards/privacy-safe-ai-use"),
            }
            sig = (rec["type"], dimension, key)
            if sig not in seen:
                seen.add(sig)
                items.append(rec)

        # Workflow guidance recommendation
        if dimension == "route" and (severity == "high" or intervention_rate >= 0.12):
            rec = {
                "type": "workflow_guidance",
                "priority": "high" if severity == "high" else "medium",
                "title": f"Review workflow guidance for {key}",
                "why": f"{key} has elevated governance friction relative to peer routes.",
                "based_on": {"dimension": dimension, "key": key},
                "target_path": _LEARN_MAPPING.get(f"route:{key}", "/governance-events"),
            }
            sig = (rec["type"], dimension, key)
            if sig not in seen:
                seen.add(sig)
                items.append(rec)

    priority_rank = {"high": 3, "medium": 2, "low": 1}
    items.sort(key=lambda x: priority_rank.get(x["priority"], 0), reverse=True)
    return items[:8]


def _top_value(
    db: Session,
    clinic_id: str,
    start_ts: datetime,
    end_ts: datetime,
    table: str,
    column: str,
) -> Optional[str]:
    sql = f"""
    SELECT COALESCE({column}, 'unknown') AS key
    FROM {table}
    WHERE clinic_id = :clinic_id
      AND created_at >= :start_ts
      AND created_at < :end_ts
    GROUP BY 1
    ORDER BY COUNT(*) DESC, 1 ASC
    LIMIT 1
    """
    row = db.execute(
        text(sql),
        {"clinic_id": clinic_id, "start_ts": start_ts, "end_ts": end_ts},
    ).mappings().first()

    return str(row["key"]) if row else None


def _overall_metrics(db: Session, clinic_id: str, start_ts: datetime, end_ts: datetime) -> Dict[str, Any]:
    base = db.execute(
        text(
            """
            SELECT
                COUNT(*) AS events,
                COUNT(*) FILTER (
                    WHERE decision IN ('replaced', 'modified', 'blocked')
                ) AS interventions,
                COUNT(*) FILTER (
                    WHERE pii_action = 'warn'
                ) AS pii_warned
            FROM clinic_governance_events
            WHERE clinic_id = :clinic_id
              AND created_at >= :start_ts
              AND created_at < :end_ts
            """
        ),
        {"clinic_id": clinic_id, "start_ts": start_ts, "end_ts": end_ts},
    ).mappings().first()

    events = int(base["events"] or 0)
    interventions = int(base["interventions"] or 0)
    pii_warned = int(base["pii_warned"] or 0)

    return {
        "events": events,
        "intervention_rate": round(_safe_div(interventions, events), 4),
        "pii_warned_rate": round(_safe_div(pii_warned, events), 4),
        "top_mode": _top_value(db, clinic_id, start_ts, end_ts, "clinic_governance_events", "mode"),
        "top_route": _top_value(db, clinic_id, start_ts, end_ts, "ops_metrics_events", "route"),
        "top_reason_code": _top_value(db, clinic_id, start_ts, end_ts, "clinic_governance_events", "reason_code"),
    }


# -------------------------------------------------------------------
# Endpoints
# -------------------------------------------------------------------
@router.get("/summary")
def get_intelligence_summary(
    window: str = Query(default="30d"),
    clinic_ctx: Any = Depends(require_clinic_user),
    db: Session = Depends(get_clinic_scoped_db),
) -> Dict[str, Any]:
    delta = _parse_window(window)
    clinic_id = _extract_clinic_id(clinic_ctx)
    end_ts = _utcnow()
    start_ts = end_ts - delta
    recent_start = end_ts - _recent_delta_for_window(window)

    hotspots = _build_all_hotspots(db, clinic_id, start_ts, end_ts, recent_start)
    recommendations = _build_recommendations(hotspots)
    overall = _overall_metrics(db, clinic_id, start_ts, end_ts)

    headline_hotspot = hotspots[0] if hotspots else None
    headline_action = recommendations[0] if recommendations else None

    return {
        "generated_at": end_ts.isoformat(),
        "window": window,
        "overall": overall,
        "headline_hotspot": headline_hotspot,
        "headline_action": headline_action,
    }


@router.get("/hotspots")
def get_intelligence_hotspots(
    window: str = Query(default="30d"),
    dimension: str = Query(default="all"),
    limit: int = Query(default=10, ge=1, le=50),
    clinic_ctx: Any = Depends(require_clinic_user),
    db: Session = Depends(get_clinic_scoped_db),
) -> Dict[str, Any]:
    delta = _parse_window(window)
    dimension = _normalize_dimension(dimension)
    clinic_id = _extract_clinic_id(clinic_ctx)
    end_ts = _utcnow()
    start_ts = end_ts - delta
    recent_start = end_ts - _recent_delta_for_window(window)

    if dimension == "all":
        items = _build_all_hotspots(db, clinic_id, start_ts, end_ts, recent_start)
    else:
        items = _build_hotspots_for_dimension(db, clinic_id, start_ts, end_ts, recent_start, dimension)

    return {
        "generated_at": end_ts.isoformat(),
        "window": window,
        "limit": limit,
        "items": items[:limit],
    }


@router.get("/recommendations")
def get_intelligence_recommendations(
    window: str = Query(default="30d"),
    clinic_ctx: Any = Depends(require_clinic_user),
    db: Session = Depends(get_clinic_scoped_db),
) -> Dict[str, Any]:
    delta = _parse_window(window)
    clinic_id = _extract_clinic_id(clinic_ctx)
    end_ts = _utcnow()
    start_ts = end_ts - delta
    recent_start = end_ts - _recent_delta_for_window(window)

    hotspots = _build_all_hotspots(db, clinic_id, start_ts, end_ts, recent_start)
    recommendations = _build_recommendations(hotspots)

    return {
        "generated_at": end_ts.isoformat(),
        "window": window,
        "items": recommendations,
    }
