# app/portal_ops_timeseries.py
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

router = APIRouter(
    prefix="/v1/portal/ops",
    tags=["Portal Ops"],
    dependencies=[Depends(require_clinic_user)],
)


class TimeseriesPoint(BaseModel):
    bucket_start_utc: str
    events_total: int
    errors_5xx: int
    rate_5xx: float
    latency_p50_ms: int
    latency_p95_ms: int
    governance_replaced: int
    governance_replaced_rate: float
    pii_warned: int
    pii_warned_rate: float


class OpsTimeseriesResponse(BaseModel):
    status: str = "ok"
    hours: int
    bucket_sec: int
    route: str
    mode: str
    limit: int
    points: List[TimeseriesPoint]


@router.get("/timeseries", response_model=OpsTimeseriesResponse)
def portal_ops_timeseries(
    hours: int = 24,
    bucket_sec: int = 300,
    route: str = "__all__",
    mode: str = "__all__",
    limit: int = 500,
    db: Session = Depends(get_db),
) -> OpsTimeseriesResponse:
    hours = max(1, min(720, int(hours)))
    bucket_sec = max(60, min(3600, int(bucket_sec)))
    limit = max(1, min(2000, int(limit)))
    route = (route or "__all__").strip()
    mode = (mode or "__all__").strip()

    route_filter = "" if route == "__all__" else "AND route = :route"
    mode_filter = "" if mode == "__all__" else "AND mode = :mode"

    rows = db.execute(
        text(
            f"""
            WITH base AS (
              SELECT
                date_bin(
                  (:bucket_sec || ' seconds')::interval,
                  created_at,
                  (now() at time zone 'utc') - (:hours || ' hours')::interval
                ) AS bucket_start,
                status_code,
                latency_ms,
                governance_replaced,
                pii_warned
              FROM ops_metrics_events
              WHERE clinic_id = app_current_clinic_id()
                AND created_at >= (now() - (:hours || ' hours')::interval)
                {route_filter}
                {mode_filter}
            ),
            agg AS (
              SELECT
                bucket_start,
                COUNT(*)::int AS events_total,
                SUM(CASE WHEN status_code >= 500 AND status_code <= 599 THEN 1 ELSE 0 END)::int AS errors_5xx,
                COALESCE(percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms)::int, 0) AS latency_p50_ms,
                COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms)::int, 0) AS latency_p95_ms,
                SUM(CASE WHEN governance_replaced THEN 1 ELSE 0 END)::int AS governance_replaced,
                SUM(CASE WHEN pii_warned THEN 1 ELSE 0 END)::int AS pii_warned
              FROM base
              GROUP BY bucket_start
              ORDER BY bucket_start DESC
              LIMIT :limit
            )
            SELECT
              bucket_start,
              events_total,
              errors_5xx,
              CASE WHEN events_total > 0 THEN (errors_5xx::float / events_total::float) ELSE 0.0 END AS rate_5xx,
              latency_p50_ms,
              latency_p95_ms,
              governance_replaced,
              CASE WHEN events_total > 0 THEN (governance_replaced::float / events_total::float) ELSE 0.0 END AS governance_replaced_rate,
              pii_warned,
              CASE WHEN events_total > 0 THEN (pii_warned::float / events_total::float) ELSE 0.0 END AS pii_warned_rate
            FROM agg
            """
        ),
        {
            "hours": hours,
            "bucket_sec": bucket_sec,
            "route": route,
            "mode": mode,
            "limit": limit,
        },
    ).mappings().all()

    points: List[TimeseriesPoint] = []
    for r in rows:
        points.append(
            TimeseriesPoint(
                bucket_start_utc=str(r["bucket_start"]),
                events_total=int(r["events_total"] or 0),
                errors_5xx=int(r["errors_5xx"] or 0),
                rate_5xx=float(r["rate_5xx"] or 0.0),
                latency_p50_ms=int(r["latency_p50_ms"] or 0),
                latency_p95_ms=int(r["latency_p95_ms"] or 0),
                governance_replaced=int(r["governance_replaced"] or 0),
                governance_replaced_rate=float(r["governance_replaced_rate"] or 0.0),
                pii_warned=int(r["pii_warned"] or 0),
                pii_warned_rate=float(r["pii_warned_rate"] or 0.0),
            )
        )

    return OpsTimeseriesResponse(
        hours=hours,
        bucket_sec=bucket_sec,
        route=route,
        mode=mode,
        limit=limit,
        points=points,
    )
