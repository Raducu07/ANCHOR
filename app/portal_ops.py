# app/portal_ops.py
from typing import Optional, Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.auth_and_rls import require_clinic_user

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal Ops"],
    dependencies=[Depends(require_clinic_user)],
)

_ALLOWED_MODES = {"clinical_note", "client_comm", "internal_summary"}
_ALL = "__all__"


class PortalOpsSummaryResponse(BaseModel):
    status: str = "ok"
    hours: int
    mode: str
    route: str

    events_total: int
    errors_5xx: int
    rate_5xx: float

    latency_avg_ms: Optional[float] = None
    latency_p50_ms: Optional[int] = None
    latency_p95_ms: Optional[int] = None

    governance_replaced: int
    governance_replaced_rate: float


@router.get("/ops/summary", response_model=PortalOpsSummaryResponse)
def portal_ops_summary(
    db: Session = Depends(get_db),
    hours: int = 24,
    mode: str = _ALL,
    route: str = _ALL,
) -> PortalOpsSummaryResponse:
    """
    Clinic-scoped ops summary for the portal (RLS enforced).
    Reads ops_metrics_events only (telemetry-only, no content).
    """
    try:
        hours = int(hours)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid hours")

    # Bound it so nobody asks for 10 years
    if hours < 1:
        hours = 1
    if hours > 168:  # 7 days
        hours = 168

    m = (mode or _ALL).strip()
    r = (route or _ALL).strip()

    where = ["clinic_id = app_current_clinic_id()", "created_at >= now() - make_interval(hours => :hours)"]
    params: Dict[str, Any] = {"hours": hours}

    if m != _ALL:
        if m not in _ALLOWED_MODES:
            raise HTTPException(status_code=400, detail="invalid mode")
        where.append("mode = :mode")
        params["mode"] = m

    if r != _ALL:
        # allow any route string; caller must pass exact match
        where.append("route = :route")
        params["route"] = r

    where_sql = " AND ".join(where)

    sql = f"""
    SELECT
      COUNT(*)::bigint AS events_total,
      SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END)::bigint AS errors_5xx,
      AVG(latency_ms)::float AS latency_avg_ms,
      -- percentile_disc returns a value from the dataset (good for integer ms)
      percentile_disc(0.50) WITHIN GROUP (ORDER BY latency_ms) AS latency_p50_ms,
      percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS latency_p95_ms,
      SUM(CASE WHEN governance_replaced THEN 1 ELSE 0 END)::bigint AS governance_replaced
    FROM ops_metrics_events
    WHERE {where_sql}
    """

    row = db.execute(text(sql), params).mappings().first() or {}

    events_total = int(row.get("events_total") or 0)
    errors_5xx = int(row.get("errors_5xx") or 0)
    gov_rep = int(row.get("governance_replaced") or 0)

    rate_5xx = float(errors_5xx / events_total) if events_total > 0 else 0.0
    gov_rep_rate = float(gov_rep / events_total) if events_total > 0 else 0.0

    # Latency fields can be NULL when no rows
    latency_avg_ms = row.get("latency_avg_ms")
    latency_p50_ms = row.get("latency_p50_ms")
    latency_p95_ms = row.get("latency_p95_ms")

    return PortalOpsSummaryResponse(
        hours=hours,
        mode=m,
        route=r,
        events_total=events_total,
        errors_5xx=errors_5xx,
        rate_5xx=rate_5xx,
        latency_avg_ms=float(latency_avg_ms) if latency_avg_ms is not None else None,
        latency_p50_ms=int(latency_p50_ms) if latency_p50_ms is not None else None,
        latency_p95_ms=int(latency_p95_ms) if latency_p95_ms is not None else None,
        governance_replaced=gov_rep,
        governance_replaced_rate=gov_rep_rate,
    )

    
from datetime import datetime, timezone

class PortalOpsKpisResponse(BaseModel):
    status: str = "ok"
    window_hours: int = Field(..., ge=1, le=168)
    events_24h: int
    intervention_rate_24h: float
    pii_warned_rate_24h: Optional[float] = None
    health_state: str
    as_of: str


def _derive_health_state(
    rate_5xx: float,
    p95_latency_ms: Optional[int],
    intervention_rate: float,
    pii_warn_rate: Optional[float],
) -> str:
    """
    Deterministic 'traffic light' health.
    Tune thresholds later without changing response shape.
    """

    # Hard failures
    if rate_5xx > 0.02:
        return "red"
    if p95_latency_ms is not None and p95_latency_ms > 2500:
        return "red"
    if intervention_rate > 0.20:
        return "red"

    # Warnings
    if rate_5xx > 0.01:
        return "yellow"
    if p95_latency_ms is not None and p95_latency_ms > 1200:
        return "yellow"
    if intervention_rate > 0.10:
        return "yellow"
    if pii_warn_rate is not None and pii_warn_rate > 0.25:
        return "yellow"

    return "green"


@router.get("/ops/kpis", response_model=PortalOpsKpisResponse)
def portal_ops_kpis(
    db: Session = Depends(get_db),
    window_hours: int = 24,
    mode: str = _ALL,
    route: str = _ALL,
) -> PortalOpsKpisResponse:
    """
    Clinic-scoped KPI surface for the portal dashboard (RLS enforced).
    Returns a stable UI-ready shape (cards).
    """

    try:
        window_hours = int(window_hours)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid window_hours")

    if window_hours < 1:
        window_hours = 1
    if window_hours > 168:
        window_hours = 168

    # Reuse the same filter logic as summary
    m = (mode or _ALL).strip()
    r = (route or _ALL).strip()

    where = ["clinic_id = app_current_clinic_id()", "created_at >= now() - make_interval(hours => :hours)"]
    params: Dict[str, Any] = {"hours": window_hours}

    if m != _ALL:
        if m not in _ALLOWED_MODES:
            raise HTTPException(status_code=400, detail="invalid mode")
        where.append("mode = :mode")
        params["mode"] = m

    if r != _ALL:
        where.append("route = :route")
        params["route"] = r

    where_sql = " AND ".join(where)

    # --- Base KPIs from ops_metrics_events ---
    sql_ops = f"""
    SELECT
      COUNT(*)::bigint AS events_total,
      SUM(CASE WHEN governance_replaced THEN 1 ELSE 0 END)::bigint AS governance_replaced,
      SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END)::bigint AS errors_5xx,
      percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS latency_p95_ms
    FROM ops_metrics_events
    WHERE {where_sql}
    """
    row = db.execute(text(sql_ops), params).mappings().first() or {}

    events_total = int(row.get("events_total") or 0)
    gov_rep = int(row.get("governance_replaced") or 0)
    errors_5xx = int(row.get("errors_5xx") or 0)
    p95_latency_ms = row.get("latency_p95_ms")
    p95_latency_ms = int(p95_latency_ms) if p95_latency_ms is not None else None

    rate_5xx = float(errors_5xx / events_total) if events_total > 0 else 0.0
    intervention_rate = float(gov_rep / events_total) if events_total > 0 else 0.0

    # --- Optional PII warned rate from governance_events (if your schema supports pii_action) ---
    pii_warn_rate: Optional[float] = None
    try:
        sql_pii = """
        SELECT COUNT(*)::bigint AS pii_warned
        FROM governance_events
        WHERE clinic_id = app_current_clinic_id()
          AND created_at >= now() - make_interval(hours => :hours)
          AND pii_action = 'warn'
        """
        pii_warned = db.execute(text(sql_pii), {"hours": window_hours}).scalar() or 0
        pii_warned = int(pii_warned)
        pii_warn_rate = float(pii_warned / events_total) if events_total > 0 else 0.0
    except Exception:
        # If governance_events or pii_action isn't present yet, we keep it None.
        pii_warn_rate = None

    health_state = _derive_health_state(
        rate_5xx=rate_5xx,
        p95_latency_ms=p95_latency_ms,
        intervention_rate=intervention_rate,
        pii_warn_rate=pii_warn_rate,
    )

    now_iso = datetime.now(timezone.utc).isoformat()

    return PortalOpsKpisResponse(
        window_hours=window_hours,
        events_24h=events_total,
        intervention_rate_24h=round(intervention_rate, 4),
        pii_warned_rate_24h=round(pii_warn_rate, 4) if pii_warn_rate is not None else None,
        health_state=health_state,
        as_of=now_iso,
    )
