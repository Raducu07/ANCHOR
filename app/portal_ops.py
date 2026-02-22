# app/portal_ops.py

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

# Canonical logic (single source of truth)
from app.portal_ops_health import _where_clause, _trust_state_from_24h

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal Ops"],
    dependencies=[Depends(require_clinic_user)],
)


class PortalOpsKpisResponse(BaseModel):
    status: str = "ok"
    window_hours: int = Field(..., ge=1, le=168)

    # NOTE: kept as "events_24h" for UI stability; value is actually events in `window_hours`.
    events_24h: int
    events_per_hour: float

    # Reliability + performance (CEO metrics)
    rate_5xx_24h: float
    p95_latency_ms_24h: Optional[int] = None

    # Interventions: true governance transforms only (governance_replaced)
    interventions_24h: int
    intervention_rate_24h: float

    # PII hygiene: warned (not an intervention)
    pii_warned_24h: int
    pii_warned_rate_24h: float

    # “What’s driving load?” (dashboard gold)
    top_route_24h: Optional[str] = None
    top_route_events_24h: int = 0

    top_mode_24h: Optional[str] = None
    top_mode_events_24h: int = 0

    health_state: str
    last_event_at: Optional[str] = None
    as_of: str


@router.get("/ops/kpis", response_model=PortalOpsKpisResponse)
def portal_ops_kpis(
    db: Session = Depends(get_db),
    window_hours: int = 24,
    mode: str = "__all__",
    route: str = "__all__",
) -> PortalOpsKpisResponse:
    """
    UI-ready KPI surface for the portal dashboard (clinic-scoped via RLS).

    - Reads ops_metrics_events only (telemetry-only, no content).
    - Derives health_state using canonical logic from portal_ops_health.py
      to avoid threshold drift.
    - Adds top_route/top_mode contributors for instant "what's driving load" visibility.
    """
    try:
        window_hours = int(window_hours)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid window_hours")

    if window_hours < 1:
        window_hours = 1
    if window_hours > 168:
        window_hours = 168

    where_sql, base_params, _m, _r = _where_clause(mode, route)
    params: Dict[str, Any] = dict(base_params)
    params["hours"] = window_hours

    # -----------------------------
    # A) Aggregate KPIs (single query)
    # -----------------------------
    row = (
        db.execute(
            text(
                f"""
                SELECT
                  COUNT(*)::bigint AS events_total,
                  MAX(created_at) AS last_event_at,
                  SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END)::bigint AS errors_5xx,
                  percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS latency_p95_ms,
                  SUM(CASE WHEN governance_replaced THEN 1 ELSE 0 END)::bigint AS governance_replaced,
                  SUM(CASE WHEN pii_warned THEN 1 ELSE 0 END)::bigint AS pii_warned
                FROM ops_metrics_events
                WHERE {where_sql}
                  AND created_at >= now() - make_interval(hours => :hours)
                """
            ),
            params,
        )
        .mappings()
        .first()
        or {}
    )

    events_total = int(row.get("events_total") or 0)
    errors_5xx = int(row.get("errors_5xx") or 0)
    interventions = int(row.get("governance_replaced") or 0)
    pii_warned = int(row.get("pii_warned") or 0)

    rate_5xx = float(errors_5xx / events_total) if events_total > 0 else 0.0
    intervention_rate = float(interventions / events_total) if events_total > 0 else 0.0
    pii_rate = float(pii_warned / events_total) if events_total > 0 else 0.0

    p95 = row.get("latency_p95_ms")
    p95_ms: Optional[int] = int(p95) if p95 is not None else None

    health_state, _reasons = _trust_state_from_24h(
        events_total=events_total,
        rate_5xx=rate_5xx,
        p95_latency_ms=p95_ms,
        gov_rate=intervention_rate,
    )

    # last_event_at is a datetime or None
    le = row.get("last_event_at")
    last_event_at: Optional[str] = None
    if le is not None and hasattr(le, "isoformat"):
        last_event_at = le.astimezone(timezone.utc).isoformat()

    events_per_hour = float(events_total) / float(window_hours) if window_hours > 0 else 0.0

    # -----------------------------
    # B) Top contributors (only if we have data)
    # -----------------------------
    top_route: Optional[str] = None
    top_route_events: int = 0
    top_mode: Optional[str] = None
    top_mode_events: int = 0

    if events_total > 0:
        rrow = (
            db.execute(
                text(
                    f"""
                    SELECT route, COUNT(*)::bigint AS events
                    FROM ops_metrics_events
                    WHERE {where_sql}
                      AND created_at >= now() - make_interval(hours => :hours)
                    GROUP BY route
                    ORDER BY events DESC, route ASC
                    LIMIT 1
                    """
                ),
                params,
            )
            .mappings()
            .first()
        )
        if rrow:
            top_route = str(rrow.get("route")) if rrow.get("route") is not None else None
            top_route_events = int(rrow.get("events") or 0)

        mrow = (
            db.execute(
                text(
                    f"""
                    SELECT mode, COUNT(*)::bigint AS events
                    FROM ops_metrics_events
                    WHERE {where_sql}
                      AND created_at >= now() - make_interval(hours => :hours)
                    GROUP BY mode
                    ORDER BY events DESC, mode ASC
                    LIMIT 1
                    """
                ),
                params,
            )
            .mappings()
            .first()
        )
        if mrow:
            top_mode = str(mrow.get("mode")) if mrow.get("mode") is not None else None
            top_mode_events = int(mrow.get("events") or 0)

    now_iso = datetime.now(timezone.utc).isoformat()

    return PortalOpsKpisResponse(
        window_hours=window_hours,
        events_24h=events_total,
        events_per_hour=round(events_per_hour, 3),
        rate_5xx_24h=round(rate_5xx, 4),
        p95_latency_ms_24h=p95_ms,
        interventions_24h=interventions,
        intervention_rate_24h=round(intervention_rate, 4),
        pii_warned_24h=pii_warned,
        pii_warned_rate_24h=round(pii_rate, 4),
        top_route_24h=top_route,
        top_route_events_24h=top_route_events,
        top_mode_24h=top_mode,
        top_mode_events_24h=top_mode_events,
        health_state=health_state,
        last_event_at=last_event_at,
        as_of=now_iso,
    )
