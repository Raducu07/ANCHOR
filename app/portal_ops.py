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
