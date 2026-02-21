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


class Thresholds(BaseModel):
    max_5xx_rate_green: float = 0.01
    max_p95_latency_ms_green: int = 1000
    max_governance_replaced_rate_green: float = 0.10

    red_5xx_rate: float = 0.05
    red_p95_latency_ms: int = 3000
    red_governance_replaced_rate: float = 0.30

    min_request_count: int = 20


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
    # allow overriding thresholds if needed later (still safe defaults)
    max_5xx_rate_green: float = 0.01,
    max_p95_latency_ms_green: int = 1000,
    max_governance_replaced_rate_green: float = 0.10,
    red_5xx_rate: float = 0.05,
    red_p95_latency_ms: int = 3000,
    red_governance_replaced_rate: float = 0.30,
    min_request_count: int = 20,
) -> PortalTrustStateResponse:
    """
    Clinic-scoped trust state for the portal (RLS enforced).
    Returns a green/yellow/red state based on error rate, p95 latency,
    and governance intervention rate.
    """
    try:
        hours = int(hours)
        max_p95_latency_ms_green = int(max_p95_latency_ms_green)
        red_p95_latency_ms = int(red_p95_latency_ms)
        min_request_count = int(min_request_count)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid numeric parameters")

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

    thresholds = Thresholds(
        max_5xx_rate_green=float(max_5xx_rate_green),
        max_p95_latency_ms_green=int(max_p95_latency_ms_green),
        max_governance_replaced_rate_green=float(max_governance_replaced_rate_green),
        red_5xx_rate=float(red_5xx_rate),
        red_p95_latency_ms=int(red_p95_latency_ms),
        red_governance_replaced_rate=float(red_governance_replaced_rate),
        min_request_count=int(min_request_count),
    )

    reasons: List[str] = []

    # If too few data points, we still return a state, but mark it
    low_data = events_total < min_request_count
    if low_data:
        reasons.append(f"low_data: events_total<{min_request_count}")

    # RED conditions
    is_red = False
    if events_total > 0:
        if rate_5xx >= red_5xx_rate:
            is_red = True
            reasons.append(f"red_5xx_rate: {rate_5xx:.4f}>={red_5xx_rate:.4f}")
        if latency_p95_ms is not None and latency_p95_ms >= red_p95_latency_ms:
            is_red = True
            reasons.append(f"red_p95_latency: {latency_p95_ms}>={red_p95_latency_ms}")
        if gov_rate >= red_governance_replaced_rate:
            is_red = True
            reasons.append(f"red_gov_replaced_rate: {gov_rate:.4f}>={red_governance_replaced_rate:.4f}")

    if is_red:
        trust_state = "red"
    else:
        # GREEN conditions (only if we have any data; if none, treat as yellow with low_data)
        if events_total == 0:
            trust_state = "yellow"
            reasons.append("no_data")
        else:
            green_ok = True
            if rate_5xx > max_5xx_rate_green:
                green_ok = False
                reasons.append(f"warn_5xx_rate: {rate_5xx:.4f}>{max_5xx_rate_green:.4f}")
            if latency_p95_ms is not None and latency_p95_ms > max_p95_latency_ms_green:
                green_ok = False
                reasons.append(f"warn_p95_latency: {latency_p95_ms}>{max_p95_latency_ms_green}")
            if gov_rate > max_governance_replaced_rate_green:
                green_ok = False
                reasons.append(f"warn_gov_replaced_rate: {gov_rate:.4f}>{max_governance_replaced_rate_green:.4f}")

            # If low data, don’t claim green; keep it yellow unless clearly bad (red handled above)
            if low_data:
                trust_state = "yellow" if green_ok else "yellow"
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
        thresholds=thresholds,
    )
