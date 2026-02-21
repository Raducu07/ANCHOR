# app/portal_error_budget.py
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal Error Budget"],
    dependencies=[Depends(require_clinic_user)],
)

_ALLOWED_MODES = {"clinical_note", "client_comm", "internal_summary"}
_ALL = "__all__"

# -----------------------------
# 🔒 Locked SLO targets
# -----------------------------
SLO_MAX_5XX_RATE = 0.01                # 1%
SLO_MAX_P95_LATENCY_MS = 1000          # 1000ms
SLO_MAX_GOV_REPLACED_RATE = 0.10       # 10%

# Severe thresholds (red)
RED_5XX_RATE = 0.05
RED_P95_LATENCY_MS = 3000
RED_GOV_REPLACED_RATE = 0.30

MIN_REQUEST_COUNT = 10

# Windows (hours) for burn calculation
WINDOWS_HOURS: List[int] = [1, 6, 24]


class WindowBurn(BaseModel):
    window_hours: int
    events_total: int

    rate_5xx: float
    p95_latency_ms: Optional[int] = None

    governance_replaced_rate: float
    pii_warned_rate: float

    burn_5xx: float
    burn_latency: Optional[float] = None
    burn_governance: float

    burn_max: float


class Contributors(BaseModel):
    top_routes_by_events: List[Dict[str, Any]] = Field(default_factory=list)
    top_modes_by_events: List[Dict[str, Any]] = Field(default_factory=list)


class PortalErrorBudgetResponse(BaseModel):
    status: str = "ok"
    mode: str
    route: str

    trust_state: str  # green | yellow | red
    message: str
    reasons: List[str] = Field(default_factory=list)

    slo_targets: Dict[str, Any]
    windows: List[WindowBurn]

    contributors: Contributors


def _ui_message(trust_state: str, reasons: List[str]) -> str:
    if trust_state == "green":
        return "Healthy"
    if trust_state == "red":
        return "At risk"
    # yellow
    if any(r.startswith("low_data") for r in reasons) or "no_data" in reasons:
        return "Collecting data"
    if any("5xx" in r for r in reasons):
        return "Degraded: elevated errors"
    if any("latency" in r for r in reasons):
        return "Degraded: elevated latency"
    if any("gov" in r for r in reasons):
        return "Degraded: elevated interventions"
    return "Degraded"


def _compute_trust_state_from_latest(
    events_total: int,
    rate_5xx: float,
    p95_latency_ms: Optional[int],
    gov_rate: float,
) -> Tuple[str, List[str]]:
    reasons: List[str] = []
    low_data = events_total < MIN_REQUEST_COUNT

    if low_data:
        reasons.append(f"low_data: events_total<{MIN_REQUEST_COUNT}")

    if events_total == 0:
        reasons.append("no_data")
        return "yellow", reasons

    # ---- RED conditions ----
    if rate_5xx >= RED_5XX_RATE:
        reasons.append("red_5xx_rate")
        return "red", reasons
    if p95_latency_ms is not None and p95_latency_ms >= RED_P95_LATENCY_MS:
        reasons.append("red_p95_latency")
        return "red", reasons
    if gov_rate >= RED_GOV_REPLACED_RATE:
        reasons.append("red_gov_replaced_rate")
        return "red", reasons

    green_ok = (
        rate_5xx <= SLO_MAX_5XX_RATE
        and (p95_latency_ms is None or p95_latency_ms <= SLO_MAX_P95_LATENCY_MS)
        and gov_rate <= SLO_MAX_GOV_REPLACED_RATE
    )

    if low_data:
        return "yellow", reasons

    return ("green", reasons) if green_ok else ("yellow", reasons)


@router.get("/ops/error-budget", response_model=PortalErrorBudgetResponse)
def portal_error_budget(
    db: Session = Depends(get_db),
    mode: str = _ALL,
    route: str = _ALL,
    limit_contributors: int = 5,
) -> PortalErrorBudgetResponse:
    """
    Clinic-scoped error-budget/burn view.
    Computes burn rates over windows: 1h/6h/24h.

    NOTE:
      - governance_replaced_rate is TRUE interventions only (blocked/replaced)
      - pii_warned_rate is hygiene-only (PII detected)
    """
    m = (mode or _ALL).strip()
    r = (route or _ALL).strip()

    if m != _ALL and m not in _ALLOWED_MODES:
        raise HTTPException(status_code=400, detail="invalid mode")

    limit_contributors = int(limit_contributors)
    if limit_contributors < 1:
        limit_contributors = 1
    if limit_contributors > 25:
        limit_contributors = 25

    # Filter clause (clinic enforced by RLS)
    base_where = ["clinic_id = app_current_clinic_id()"]
    params_base: Dict[str, Any] = {}

    if m != _ALL:
        base_where.append("mode = :mode")
        params_base["mode"] = m
    if r != _ALL:
        base_where.append("route = :route")
        params_base["route"] = r

    base_where_sql = " AND ".join(base_where)

    windows: List[WindowBurn] = []

    for wh in WINDOWS_HOURS:
        params = dict(params_base)
        params["hours"] = wh

        sql = f"""
        SELECT
          COUNT(*)::bigint AS events_total,
          SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END)::bigint AS errors_5xx,
          percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS latency_p95_ms,
          SUM(CASE WHEN governance_replaced THEN 1 ELSE 0 END)::bigint AS governance_replaced,
          SUM(CASE WHEN pii_warned THEN 1 ELSE 0 END)::bigint AS pii_warned
        FROM ops_metrics_events
        WHERE {base_where_sql}
          AND created_at >= now() - make_interval(hours => :hours)
        """

        row = db.execute(text(sql), params).mappings().first() or {}

        events_total = int(row.get("events_total") or 0)
        errors_5xx = int(row.get("errors_5xx") or 0)
        gov_rep = int(row.get("governance_replaced") or 0)
        pii_warned = int(row.get("pii_warned") or 0)

        rate_5xx = float(errors_5xx / events_total) if events_total > 0 else 0.0
        gov_rate = float(gov_rep / events_total) if events_total > 0 else 0.0
        pii_rate = float(pii_warned / events_total) if events_total > 0 else 0.0

        p95 = row.get("latency_p95_ms")
        p95_ms = int(p95) if p95 is not None else None

        # Burn rates: observed / target (higher is worse)
        burn_5xx = (rate_5xx / SLO_MAX_5XX_RATE) if SLO_MAX_5XX_RATE > 0 else 0.0
        burn_gov = (gov_rate / SLO_MAX_GOV_REPLACED_RATE) if SLO_MAX_GOV_REPLACED_RATE > 0 else 0.0
        burn_lat = None
        if p95_ms is not None and SLO_MAX_P95_LATENCY_MS > 0:
            burn_lat = float(p95_ms) / float(SLO_MAX_P95_LATENCY_MS)

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
                pii_warned_rate=pii_rate,
                burn_5xx=float(burn_5xx),
                burn_latency=float(burn_lat) if burn_lat is not None else None,
                burn_governance=float(burn_gov),
                burn_max=float(burn_max),
            )
        )

    latest = windows[-1] if windows else None
    trust_state, reasons = _compute_trust_state_from_latest(
        events_total=latest.events_total if latest else 0,
        rate_5xx=latest.rate_5xx if latest else 0.0,
        p95_latency_ms=latest.p95_latency_ms if latest else None,
        gov_rate=latest.governance_replaced_rate if latest else 0.0,
    )

    # Contributors (cheap; clinic scoped by RLS)
    contrib = Contributors()

    row_routes = db.execute(
        text(
            f"""
            SELECT route, COUNT(*)::bigint AS events
            FROM ops_metrics_events
            WHERE {base_where_sql}
              AND created_at >= now() - make_interval(hours => 24)
            GROUP BY route
            ORDER BY events DESC
            LIMIT :lim
            """
        ),
        {**params_base, "lim": limit_contributors},
    ).mappings().all()

    contrib.top_routes_by_events = [
        {"route": str(x["route"]), "events": int(x["events"])} for x in row_routes
    ]

    row_modes = db.execute(
        text(
            f"""
            SELECT mode, COUNT(*)::bigint AS events
            FROM ops_metrics_events
            WHERE {base_where_sql}
              AND created_at >= now() - make_interval(hours => 24)
            GROUP BY mode
            ORDER BY events DESC
            LIMIT :lim
            """
        ),
        {**params_base, "lim": limit_contributors},
    ).mappings().all()

    contrib.top_modes_by_events = [
        {"mode": str(x["mode"]), "events": int(x["events"])} for x in row_modes
    ]

    message = _ui_message(trust_state, reasons)

    return PortalErrorBudgetResponse(
        mode=m,
        route=r,
        trust_state=trust_state,
        message=message,
        reasons=reasons,
        slo_targets={
            "max_5xx_rate": SLO_MAX_5XX_RATE,
            "max_p95_latency_ms": SLO_MAX_P95_LATENCY_MS,
            "max_governance_replaced_rate": SLO_MAX_GOV_REPLACED_RATE,
            "red_5xx_rate": RED_5XX_RATE,
            "red_p95_latency_ms": RED_P95_LATENCY_MS,
            "red_governance_replaced_rate": RED_GOV_REPLACED_RATE,
            "min_request_count": MIN_REQUEST_COUNT,
        },
        windows=windows,
        contributors=contrib,
    )
