# app/portal_ops_summary.py
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

router = APIRouter(
    prefix="/v1/portal/ops",
    tags=["Portal Ops"],
    dependencies=[Depends(require_clinic_user)],
)


class OpsSummaryResponse(BaseModel):
    status: str = "ok"
    hours: int
    mode: str
    route: str
    events_total: int
    errors_5xx: int
    rate_5xx: float
    latency_avg_ms: float
    latency_p50_ms: int
    latency_p95_ms: int
    governance_replaced: int
    governance_replaced_rate: float
    pii_warned: int
    pii_warned_rate: float


@router.get("/summary", response_model=OpsSummaryResponse)
def portal_ops_summary(
    request: Request,
    hours: int = 24,
    route: str = "__all__",
    mode: str = "__all__",
    db: Session = Depends(get_db),
) -> OpsSummaryResponse:
    hours = max(1, min(720, int(hours)))
    route = (route or "__all__").strip()
    mode = (mode or "__all__").strip()

    # time window in SQL
    window_sql = "now() - (:hours || ' hours')::interval"

    # filters
    route_filter = "" if route == "__all__" else "AND route = :route"
    mode_filter = "" if mode == "__all__" else "AND mode = :mode"

    row = db.execute(
        text(
            f"""
            WITH base AS (
              SELECT
                status_code,
                latency_ms,
                governance_replaced,
                pii_warned
              FROM ops_metrics_events
              WHERE clinic_id = app_current_clinic_id()
                AND created_at >= {window_sql}
                {route_filter}
                {mode_filter}
            ),
            agg AS (
              SELECT
                COUNT(*)::int AS events_total,
                SUM(CASE WHEN status_code >= 500 AND status_code <= 599 THEN 1 ELSE 0 END)::int AS errors_5xx,
                AVG(latency_ms)::float AS latency_avg_ms,
                COALESCE(
                  percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms)::int,
                  0
                ) AS latency_p50_ms,
                COALESCE(
                  percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms)::int,
                  0
                ) AS latency_p95_ms,
                SUM(CASE WHEN governance_replaced THEN 1 ELSE 0 END)::int AS governance_replaced,
                SUM(CASE WHEN pii_warned THEN 1 ELSE 0 END)::int AS pii_warned
              FROM base
            )
            SELECT * FROM agg
            """
        ),
        {
            "hours": hours,
            "route": route,
            "mode": mode,
        },
    ).mappings().first()

    if not row:
        return OpsSummaryResponse(
            hours=hours,
            mode=mode,
            route=route,
            events_total=0,
            errors_5xx=0,
            rate_5xx=0.0,
            latency_avg_ms=0.0,
            latency_p50_ms=0,
            latency_p95_ms=0,
            governance_replaced=0,
            governance_replaced_rate=0.0,
            pii_warned=0,
            pii_warned_rate=0.0,
        )

    events_total = int(row["events_total"] or 0)
    errors_5xx = int(row["errors_5xx"] or 0)
    latency_avg_ms = float(row["latency_avg_ms"] or 0.0)
    latency_p50_ms = int(row["latency_p50_ms"] or 0)
    latency_p95_ms = int(row["latency_p95_ms"] or 0)
    governance_replaced = int(row["governance_replaced"] or 0)
    pii_warned = int(row["pii_warned"] or 0)

    rate_5xx = (errors_5xx / events_total) if events_total > 0 else 0.0
    governance_replaced_rate = (governance_replaced / events_total) if events_total > 0 else 0.0
    pii_warned_rate = (pii_warned / events_total) if events_total > 0 else 0.0

    return OpsSummaryResponse(
        hours=hours,
        mode=mode,
        route=route,
        events_total=events_total,
        errors_5xx=errors_5xx,
        rate_5xx=float(rate_5xx),
        latency_avg_ms=float(latency_avg_ms),
        latency_p50_ms=latency_p50_ms,
        latency_p95_ms=latency_p95_ms,
        governance_replaced=governance_replaced,
        governance_replaced_rate=float(governance_replaced_rate),
        pii_warned=pii_warned,
        pii_warned_rate=float(pii_warned_rate),
    )
