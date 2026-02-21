# app/portal_ops_timeseries.py
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal Ops Timeseries"],
    dependencies=[Depends(require_clinic_user)],
)

_ALLOWED_MODES = {"clinical_note", "client_comm", "internal_summary"}
_ALL = "__all__"


class OpsTimeseriesPoint(BaseModel):
    bucket_start_utc: str
    events_total: int
    errors_5xx: int
    rate_5xx: float
    latency_p50_ms: Optional[int] = None
    latency_p95_ms: Optional[int] = None
    governance_replaced: int
    governance_replaced_rate: float


class PortalOpsTimeseriesResponse(BaseModel):
    status: str = "ok"
    hours: int
    bucket_sec: int
    route: str
    mode: str
    limit: int
    points: List[OpsTimeseriesPoint]


@router.get("/ops/timeseries", response_model=PortalOpsTimeseriesResponse)
def portal_ops_timeseries(
    db: Session = Depends(get_db),
    hours: int = 24,
    bucket_sec: int = 300,
    route: str = _ALL,
    mode: str = _ALL,
    limit: int = 500,
) -> PortalOpsTimeseriesResponse:
    """
    Clinic-scoped ops timeseries from ops_metrics_events (RLS enforced).
    Buckets by created_at into bucket_sec intervals.
    """

    # ---- sanitize inputs ----
    try:
        hours = int(hours)
        bucket_sec = int(bucket_sec)
        limit = int(limit)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid numeric parameters")

    if hours < 1:
        hours = 1
    if hours > 168:  # 7 days
        hours = 168

    # bucket bounds
    if bucket_sec < 60:
        bucket_sec = 60
    if bucket_sec > 3600:
        bucket_sec = 3600

    if limit < 1:
        limit = 1
    if limit > 2000:
        limit = 2000

    r = (route or _ALL).strip()
    m = (mode or _ALL).strip()

    where = [
        "clinic_id = app_current_clinic_id()",
        "created_at >= now() - make_interval(hours => :hours)",
    ]
    params: Dict[str, Any] = {
        "hours": hours,
        "bucket_sec": bucket_sec,
        "limit": limit,
    }

    if m != _ALL:
        if m not in _ALLOWED_MODES:
            raise HTTPException(status_code=400, detail="invalid mode")
        where.append("mode = :mode")
        params["mode"] = m

    if r != _ALL:
        where.append("route = :route")
        params["route"] = r

    where_sql = " AND ".join(where)

    # ---- bucket query ----
    # bucket_start is computed as a UTC timestamptz aligned to bucket_sec seconds.
    sql = f"""
    WITH base AS (
      SELECT
        to_timestamp(
          floor(extract(epoch from created_at) / :bucket_sec) * :bucket_sec
        ) AT TIME ZONE 'UTC' AS bucket_start_utc,
        status_code,
        latency_ms,
        governance_replaced
      FROM ops_metrics_events
      WHERE {where_sql}
    )
    SELECT
      bucket_start_utc,
      COUNT(*)::bigint AS events_total,
      SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END)::bigint AS errors_5xx,
      -- percentiles can be NULL if no rows, but here each group has >=1 row
      percentile_disc(0.50) WITHIN GROUP (ORDER BY latency_ms) AS latency_p50_ms,
      percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS latency_p95_ms,
      SUM(CASE WHEN governance_replaced THEN 1 ELSE 0 END)::bigint AS governance_replaced
    FROM base
    GROUP BY bucket_start_utc
    ORDER BY bucket_start_utc DESC
    LIMIT :limit
    """

    rows = db.execute(text(sql), params).mappings().all()

    points: List[OpsTimeseriesPoint] = []
    for row in rows:
        events_total = int(row.get("events_total") or 0)
        errors_5xx = int(row.get("errors_5xx") or 0)
        gov_rep = int(row.get("governance_replaced") or 0)

        rate_5xx = float(errors_5xx / events_total) if events_total > 0 else 0.0
        gov_rate = float(gov_rep / events_total) if events_total > 0 else 0.0

        # bucket_start_utc is a timestamp (naive after AT TIME ZONE); format ISO
        b = row.get("bucket_start_utc")
        bucket_iso = b.isoformat() + "+00:00" if hasattr(b, "isoformat") and b else ""

        p50 = row.get("latency_p50_ms")
        p95 = row.get("latency_p95_ms")

        points.append(
            OpsTimeseriesPoint(
                bucket_start_utc=bucket_iso,
                events_total=events_total,
                errors_5xx=errors_5xx,
                rate_5xx=rate_5xx,
                latency_p50_ms=int(p50) if p50 is not None else None,
                latency_p95_ms=int(p95) if p95 is not None else None,
                governance_replaced=gov_rep,
                governance_replaced_rate=gov_rate,
            )
        )

    return PortalOpsTimeseriesResponse(
        hours=hours,
        bucket_sec=bucket_sec,
        route=r,
        mode=m,
        limit=limit,
        points=points,
    )
