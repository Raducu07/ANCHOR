# app/portal_trust_state.py
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal Trust State"],
    dependencies=[Depends(require_clinic_user)],
)

_ALLOWED_MODES = {"clinical_note", "client_comm", "internal_summary"}
_ALL = "__all__"

# -----------------------------
# 🔒 Locked SLO thresholds
# -----------------------------
MAX_5XX_RATE_GREEN = 0.01
MAX_P95_LATENCY_MS_GREEN = 1000
MAX_GOV_REPLACED_RATE_GREEN = 0.10

RED_5XX_RATE = 0.05
RED_P95_LATENCY_MS = 3000
RED_GOV_REPLACED_RATE = 0.30

MIN_REQUEST_COUNT = 10  # reduced from 20 for early clinics


class Thresholds(BaseModel):
    max_5xx_rate_green: float
    max_p95_latency_ms_green: int
    max_governance_replaced_rate_green: float
    red_5xx_rate: float
    red_p95_latency_ms: int
    red_governance_replaced_rate: float
    min_request_count: int


class PortalTrustStateResponse(BaseModel):
    status: str = "ok"
    hours: int
    mode: str
    route: str

    trust_state: str  # green | yellow | red
    reasons: List[str] = Field(default_factory=list)

    events_total: int
    rate_5xx: float
    latency_p95_ms: Optional[int] = None
    governance_replaced_rate: float

    thresholds: Thresholds


@router.get("/ops/trust-state", response_model=PortalTrustStateResponse)
def portal_trust_state(
    db: Session = Depends(get_db),
    hours: int = 24,
    mode: str = _ALL,
    route: str = _ALL,
) -> PortalTrustStateResponse:
    """
    Clinic-scoped trust state (RLS enforced).
    Uses locked SLO thresholds.
    """
    try:
        hours = int(hours)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid hours")

    if hours < 1:
        hours = 1
    if hours > 168:
        hours = 168

    m = (mode or _ALL).strip()
    r = (route or _ALL).strip()

    where = [
        "clinic_id = app_current_clinic_id()",
        "created_at >= now() - make_interval(hours => :hours)",
    ]
    params: Dict[str, Any] = {"hours": hours}

    if m != _ALL:
        if m not in _ALLOWED_MODES:
            raise HTTPException(status_code=400, detail="invalid mode")
        where.append("mode = :mode")
        params["mode"] = m

    if r != _ALL:
        where.append("route = :route")
        params["route"] = r

    where_sql = " AND ".join(where)

    sql = f"""
    SELECT
      COUNT(*)::bigint AS events_total,
      SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END)::bigint AS errors_5xx,
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
    gov_rate = float(gov_rep / events_total) if events_total > 0 else 0.0

    p95 = row.get("latency_p95_ms")
    latency_p95_ms = int(p95) if p95 is not None else None

    reasons: List[str] = []
    low_data = events_total < MIN_REQUEST_COUNT

    if low_data:
        reasons.append(f"low_data: events_total<{MIN_REQUEST_COUNT}")

    # ---- RED conditions ----
    is_red = False
    if events_total > 0:
        if rate_5xx >= RED_5XX_RATE:
            is_red = True
            reasons.append("red_5xx_rate")
        if latency_p95_ms is not None and latency_p95_ms >= RED_P95_LATENCY_MS:
            is_red = True
            reasons.append("red_p95_latency")
        if gov_rate >= RED_GOV_REPLACED_RATE:
            is_red = True
            reasons.append("red_gov_replaced_rate")

    if is_red:
        trust_state = "red"
    else:
        if events_total == 0:
            trust_state = "yellow"
            reasons.append("no_data")
        else:
            green_ok = (
                rate_5xx <= MAX_5XX_RATE_GREEN
                and (latency_p95_ms is None or latency_p95_ms <= MAX_P95_LATENCY_MS_GREEN)
                and gov_rate <= MAX_GOV_REPLACED_RATE_GREEN
            )

            if low_data:
                trust_state = "yellow"
            else:
                trust_state = "green" if green_ok else "yellow"

    return PortalTrustStateResponse(
        hours=hours,
        mode=m,
        route=r,
        trust_state=trust_state,
        reasons=reasons,
        events_total=events_total,
        rate_5xx=rate_5xx,
        latency_p95_ms=latency_p95_ms,
        governance_replaced_rate=gov_rate,
        thresholds=Thresholds(
            max_5xx_rate_green=MAX_5XX_RATE_GREEN,
            max_p95_latency_ms_green=MAX_P95_LATENCY_MS_GREEN,
            max_governance_replaced_rate_green=MAX_GOV_REPLACED_RATE_GREEN,
            red_5xx_rate=RED_5XX_RATE,
            red_p95_latency_ms=RED_P95_LATENCY_MS,
            red_governance_replaced_rate=RED_GOV_REPLACED_RATE,
            min_request_count=MIN_REQUEST_COUNT,
        ),
    )
