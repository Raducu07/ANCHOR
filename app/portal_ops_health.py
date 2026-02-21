# app/portal_ops_health.py
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal Ops Health"],
    dependencies=[Depends(require_clinic_user)],
)

_ALLOWED_MODES = {"clinical_note", "client_comm", "internal_summary"}
_ALL = "__all__"

# -----------------------------
# 🔒 Locked SLO targets
# -----------------------------
SLO_MAX_5XX_RATE = 0.01
SLO_MAX_P95_LATENCY_MS = 1000
SLO_MAX_GOV_REPLACED_RATE = 0.10

RED_5XX_RATE = 0.05
RED_P95_LATENCY_MS = 3000
RED_GOV_REPLACED_RATE = 0.30

MIN_REQUEST_COUNT = 10

WINDOWS_HOURS = [1, 6, 24]


class Thresholds(BaseModel):
    max_5xx_rate: float
    max_p95_latency_ms: int
    max_governance_replaced_rate: float
    red_5xx_rate: float
    red_p95_latency_ms: int
    red_governance_replaced_rate: float
    min_request_count: int


class WindowBurn(BaseModel):
    window_hours: int
    events_total: int
    rate_5xx: float
    p95_latency_ms: Optional[int] = None
    governance_replaced_rate: float
    burn_5xx: float
    burn_latency: Optional[float] = None
    burn_governance: float
    burn_max: float


class TimeseriesPoint(BaseModel):
    bucket_start_utc: str
    events_total: int
    errors_5xx: int
    rate_5xx: float
    latency_p50_ms: Optional[int] = None
    latency_p95_ms: Optional[int] = None
    governance_replaced: int
    governance_replaced_rate: float


class Contributors(BaseModel):
    top_routes_by_events: List[Dict[str, Any]] = Field(default_factory=list)
    top_routes_by_5xx: List[Dict[str, Any]] = Field(default_factory=list)
    top_routes_by_p95_latency: List[Dict[str, Any]] = Field(default_factory=list)
    top_routes_by_gov_rate: List[Dict[str, Any]] = Field(default_factory=list)

    top_modes_by_events: List[Dict[str, Any]] = Field(default_factory=list)
    top_modes_by_5xx: List[Dict[str, Any]] = Field(default_factory=list)
    top_modes_by_p95_latency: List[Dict[str, Any]] = Field(default_factory=list)
    top_modes_by_gov_rate: List[Dict[str, Any]] = Field(default_factory=list)


class PortalOpsHealthResponse(BaseModel):
    status: str = "ok"
    hours: int
    bucket_sec: int
    mode: str
    route: str

    trust_state: str
    message: str
    reasons: List[str] = Field(default_factory=list)

    thresholds: Thresholds
    windows: List[WindowBurn]
    timeseries: List[TimeseriesPoint]
    contributors: Contributors


def _ui_message(trust_state: str, reasons: List[str]) -> str:
    if trust_state == "green":
        return "Healthy"
    if trust_state == "red":
        return "At risk"
    # yellow
    if "no_data" in reasons or any(r.startswith("low_data") for r in reasons):
        return "Collecting data"
    if any("5xx" in r for r in reasons):
        return "Degraded: elevated errors"
    if any("latency" in r for r in reasons):
        return "Degraded: elevated latency"
    if any("gov" in r for r in reasons):
        return "Degraded: elevated interventions"
    return "Degraded"


def _trust_state_from_24h(
    events_total: int,
    rate_5xx: float,
    p95_latency_ms: Optional[int],
    gov_rate: float,
) -> (str, List[str]):
    reasons: List[str] = []
    if events_total == 0:
        reasons.append("no_data")
        return "yellow", reasons

    if events_total < MIN_REQUEST_COUNT:
        reasons.append(f"low_data: events_total<{MIN_REQUEST_COUNT}")

    # Red
    if rate_5xx >= RED_5XX_RATE:
        reasons.append("red_5xx_rate")
        return "red", reasons
    if p95_latency_ms is not None and p95_latency_ms >= RED_P95_LATENCY_MS:
        reasons.append("red_p95_latency")
        return "red", reasons
    if gov_rate >= RED_GOV_REPLACED_RATE:
        reasons.append("red_gov_replaced_rate")
        return "red", reasons

    # Green only if enough data
    green_ok = (
        rate_5xx <= SLO_MAX_5XX_RATE
        and (p95_latency_ms is None or p95_latency_ms <= SLO_MAX_P95_LATENCY_MS)
        and gov_rate <= SLO_MAX_GOV_REPLACED_RATE
    )

    if events_total < MIN_REQUEST_COUNT:
        return "yellow", reasons

    return ("green", reasons) if green_ok else ("yellow", reasons)


def _where_clause(mode: str, route: str) -> (str, Dict[str, Any]):
    where = ["clinic_id = app_current_clinic_id()"]
    params: Dict[str, Any] = {}

    m = (mode or _ALL).strip()
    r = (route or _ALL).strip()

    if m != _ALL:
        if m not in _ALLOWED_MODES:
            raise HTTPException(status_code=400, detail="invalid mode")
        where.append("mode = :mode")
        params["mode"] = m

    if r != _ALL:
        where.append("route = :route")
        params["route"] = r

    return " AND ".join(where), params


@router.get("/ops/health", response_model=PortalOpsHealthResponse)
def portal_ops_health(
    db: Session = Depends(get_db),
    hours: int = 24,
    bucket_sec: int = 300,
    mode: str = _ALL,
    route: str = _ALL,
    limit: int = 50,
    limit_contributors: int = 5,
) -> PortalOpsHealthResponse:
    """
    One-call Health endpoint for the clinic portal.
    Combines:
      - trust_state/message
      - error budget windows (1/6/24h)
      - timeseries (last N buckets)
      - contributors (routes/modes by key issues)
    """
    try:
        hours = int(hours)
        bucket_sec = int(bucket_sec)
        limit = int(limit)
        limit_contributors = int(limit_contributors)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid numeric parameters")

    if hours < 1:
        hours = 1
    if hours > 168:
        hours = 168

    if bucket_sec < 60:
        bucket_sec = 60
    if bucket_sec > 3600:
        bucket_sec = 3600

    if limit < 1:
        limit = 1
    if limit > 2000:
        limit = 2000

    if limit_contributors < 1:
        limit_contributors = 1
    if limit_contributors > 25:
        limit_contributors = 25

    where_sql, base_params = _where_clause(mode, route)

    # -----------------------------
    # A) Error budget windows (1/6/24h)
    # -----------------------------
    windows: List[WindowBurn] = []
    for wh in WINDOWS_HOURS:
        params = dict(base_params)
        params["hours"] = wh

        row = db.execute(
            text(
                f"""
                SELECT
                  COUNT(*)::bigint AS events_total,
                  SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END)::bigint AS errors_5xx,
                  percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS latency_p95_ms,
                  SUM(CASE WHEN governance_replaced THEN 1 ELSE 0 END)::bigint AS governance_replaced
                FROM ops_metrics_events
                WHERE {where_sql}
                  AND created_at >= now() - make_interval(hours => :hours)
                """
            ),
            params,
        ).mappings().first() or {}

        events_total = int(row.get("events_total") or 0)
        errors_5xx = int(row.get("errors_5xx") or 0)
        gov_rep = int(row.get("governance_replaced") or 0)

        rate_5xx = float(errors_5xx / events_total) if events_total > 0 else 0.0
        gov_rate = float(gov_rep / events_total) if events_total > 0 else 0.0

        p95 = row.get("latency_p95_ms")
        p95_ms = int(p95) if p95 is not None else None

        burn_5xx = (rate_5xx / SLO_MAX_5XX_RATE) if SLO_MAX_5XX_RATE > 0 else 0.0
        burn_gov = (gov_rate / SLO_MAX_GOV_REPLACED_RATE) if SLO_MAX_GOV_REPLACED_RATE > 0 else 0.0
        burn_lat = (float(p95_ms) / float(SLO_MAX_P95_LATENCY_MS)) if (p95_ms is not None and SLO_MAX_P95_LATENCY_MS > 0) else None

        burn_max = max(
            float(burn_5xx),
            float(burn_gov),
            float(burn_lat) if burn_lat is not None else 0.0,
        )

        windows.append(
            WindowBurn(
                window_hours=wh,
                events_total=events_total,
                rate_5xx=rate_5xx,
                p95_latency_ms=p95_ms,
                governance_replaced_rate=gov_rate,
                burn_5xx=float(burn_5xx),
                burn_latency=float(burn_lat) if burn_lat is not None else None,
                burn_governance=float(burn_gov),
                burn_max=float(burn_max),
            )
        )

    # Trust state derived from 24h window
    w24 = windows[-1] if windows else None
    trust_state, reasons = _trust_state_from_24h(
        events_total=w24.events_total if w24 else 0,
        rate_5xx=w24.rate_5xx if w24 else 0.0,
        p95_latency_ms=w24.p95_latency_ms if w24 else None,
        gov_rate=w24.governance_replaced_rate if w24 else 0.0,
    )
    message = _ui_message(trust_state, reasons)

    # -----------------------------
    # B) Timeseries (bucketed)
    # -----------------------------
    ts_params = dict(base_params)
    ts_params.update({"hours": hours, "bucket_sec": bucket_sec, "limit": limit})

    ts_rows = db.execute(
        text(
            f"""
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
                AND created_at >= now() - make_interval(hours => :hours)
            )
            SELECT
              bucket_start_utc,
              COUNT(*)::bigint AS events_total,
              SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END)::bigint AS errors_5xx,
              percentile_disc(0.50) WITHIN GROUP (ORDER BY latency_ms) AS latency_p50_ms,
              percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS latency_p95_ms,
              SUM(CASE WHEN governance_replaced THEN 1 ELSE 0 END)::bigint AS governance_replaced
            FROM base
            GROUP BY bucket_start_utc
            ORDER BY bucket_start_utc DESC
            LIMIT :limit
            """
        ),
        ts_params,
    ).mappings().all()

    timeseries: List[TimeseriesPoint] = []
    for row in ts_rows:
        events_total = int(row.get("events_total") or 0)
        errors_5xx = int(row.get("errors_5xx") or 0)
        gov_rep = int(row.get("governance_replaced") or 0)

        rate_5xx = float(errors_5xx / events_total) if events_total > 0 else 0.0
        gov_rate = float(gov_rep / events_total) if events_total > 0 else 0.0

        b = row.get("bucket_start_utc")
        bucket_iso = b.isoformat() + "+00:00" if hasattr(b, "isoformat") and b else ""

        p50 = row.get("latency_p50_ms")
        p95 = row.get("latency_p95_ms")

        timeseries.append(
            TimeseriesPoint(
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

    # -----------------------------
    # C) Contributors (24h)
    # -----------------------------
    contrib = Contributors()
    c_params = dict(base_params)
    c_params["lim"] = limit_contributors

    # Top routes by events
    contrib.top_routes_by_events = [
        {"route": str(x["route"]), "events": int(x["events"])}
        for x in db.execute(
            text(
                f"""
                SELECT route, COUNT(*)::bigint AS events
                FROM ops_metrics_events
                WHERE {where_sql}
                  AND created_at >= now() - make_interval(hours => 24)
                GROUP BY route
                ORDER BY events DESC
                LIMIT :lim
                """
            ),
            c_params,
        ).mappings().all()
    ]

    # Top routes by 5xx
    contrib.top_routes_by_5xx = [
        {"route": str(x["route"]), "errors_5xx": int(x["errors_5xx"])}
        for x in db.execute(
            text(
                f"""
                SELECT route,
                       SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END)::bigint AS errors_5xx
                FROM ops_metrics_events
                WHERE {where_sql}
                  AND created_at >= now() - make_interval(hours => 24)
                GROUP BY route
                HAVING SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END) > 0
                ORDER BY errors_5xx DESC
                LIMIT :lim
                """
            ),
            c_params,
        ).mappings().all()
    ]

    # Top routes by p95 latency (requires enough rows; still fine)
    contrib.top_routes_by_p95_latency = [
        {"route": str(x["route"]), "p95_latency_ms": int(x["p95_latency_ms"])}
        for x in db.execute(
            text(
                f"""
                SELECT route,
                       percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95_latency_ms,
                       COUNT(*)::bigint AS events
                FROM ops_metrics_events
                WHERE {where_sql}
                  AND created_at >= now() - make_interval(hours => 24)
                GROUP BY route
                ORDER BY p95_latency_ms DESC NULLS LAST
                LIMIT :lim
                """
            ),
            c_params,
        ).mappings().all()
    ]

    # Top routes by governance rate
    contrib.top_routes_by_gov_rate = [
        {"route": str(x["route"]), "governance_replaced_rate": float(x["gov_rate"]), "events": int(x["events"])}
        for x in db.execute(
            text(
                f"""
                SELECT route,
                       COUNT(*)::bigint AS events,
                       (SUM(CASE WHEN governance_replaced THEN 1 ELSE 0 END)::float / NULLIF(COUNT(*)::float, 0)) AS gov_rate
                FROM ops_metrics_events
                WHERE {where_sql}
                  AND created_at >= now() - make_interval(hours => 24)
                GROUP BY route
                ORDER BY gov_rate DESC NULLS LAST
                LIMIT :lim
                """
            ),
            c_params,
        ).mappings().all()
    ]

    # Modes equivalents
    contrib.top_modes_by_events = [
        {"mode": str(x["mode"]), "events": int(x["events"])}
        for x in db.execute(
            text(
                f"""
                SELECT mode, COUNT(*)::bigint AS events
                FROM ops_metrics_events
                WHERE {where_sql}
                  AND created_at >= now() - make_interval(hours => 24)
                GROUP BY mode
                ORDER BY events DESC
                LIMIT :lim
                """
            ),
            c_params,
        ).mappings().all()
    ]

    contrib.top_modes_by_5xx = [
        {"mode": str(x["mode"]), "errors_5xx": int(x["errors_5xx"])}
        for x in db.execute(
            text(
                f"""
                SELECT mode,
                       SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END)::bigint AS errors_5xx
                FROM ops_metrics_events
                WHERE {where_sql}
                  AND created_at >= now() - make_interval(hours => 24)
                GROUP BY mode
                HAVING SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END) > 0
                ORDER BY errors_5xx DESC
                LIMIT :lim
                """
            ),
            c_params,
        ).mappings().all()
    ]

    contrib.top_modes_by_p95_latency = [
        {"mode": str(x["mode"]), "p95_latency_ms": int(x["p95_latency_ms"])}
        for x in db.execute(
            text(
                f"""
                SELECT mode,
                       percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95_latency_ms
                FROM ops_metrics_events
                WHERE {where_sql}
                  AND created_at >= now() - make_interval(hours => 24)
                GROUP BY mode
                ORDER BY p95_latency_ms DESC NULLS LAST
                LIMIT :lim
                """
            ),
            c_params,
        ).mappings().all()
    ]

    contrib.top_modes_by_gov_rate = [
        {"mode": str(x["mode"]), "governance_replaced_rate": float(x["gov_rate"]), "events": int(x["events"])}
        for x in db.execute(
            text(
                f"""
                SELECT mode,
                       COUNT(*)::bigint AS events,
                       (SUM(CASE WHEN governance_replaced THEN 1 ELSE 0 END)::float / NULLIF(COUNT(*)::float, 0)) AS gov_rate
                FROM ops_metrics_events
                WHERE {where_sql}
                  AND created_at >= now() - make_interval(hours => 24)
                GROUP BY mode
                ORDER BY gov_rate DESC NULLS LAST
                LIMIT :lim
                """
            ),
            c_params,
        ).mappings().all()
    ]

    return PortalOpsHealthResponse(
        hours=hours,
        bucket_sec=bucket_sec,
        mode=(mode or _ALL).strip(),
        route=(route or _ALL).strip(),
        trust_state=trust_state,
        message=message,
        reasons=reasons,
        thresholds=Thresholds(
            max_5xx_rate=SLO_MAX_5XX_RATE,
            max_p95_latency_ms=SLO_MAX_P95_LATENCY_MS,
            max_governance_replaced_rate=SLO_MAX_GOV_REPLACED_RATE,
            red_5xx_rate=RED_5XX_RATE,
            red_p95_latency_ms=RED_P95_LATENCY_MS,
            red_governance_replaced_rate=RED_GOV_REPLACED_RATE,
            min_request_count=MIN_REQUEST_COUNT,
        ),
        windows=windows,
        timeseries=timeseries,
        contributors=contrib,
    )
