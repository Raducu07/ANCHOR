# app/portal_dashboard.py
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.auth_and_rls import require_clinic_user
from app.portal_read import ReceiptV1, _hash_policy_json, _get_clinic_policy_json, _set_rls_context

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal Dashboard"],
    dependencies=[Depends(require_clinic_user)],
)

# -----------------------------
# Models
# -----------------------------
class DashboardSubmissionItem(BaseModel):
    request_id: str
    clinic_user_id: str
    mode: str
    decision: str
    risk_grade: Optional[str] = None
    reason_code: Optional[str] = None
    pii_detected: bool = False
    pii_action: Optional[str] = None
    policy_version: Optional[int] = None
    neutrality_version: Optional[str] = None
    created_at_utc: str


class DashboardKpis(BaseModel):
    window_hours: int
    events_24h: int
    events_per_hour: float
    interventions_24h: int
    intervention_rate_24h: float
    pii_warned_24h: int
    pii_warned_rate_24h: float
    top_mode_24h: Optional[str] = None
    top_route_24h: str = "/v1/portal/submit"
    derived_from: str = "clinic_governance_events"


class DashboardTrustState(BaseModel):
    health_state: str  # green|yellow|red
    reasons: List[str] = Field(default_factory=list)
    derived_from: str = "derived_v1"


class PortalDashboardResponse(BaseModel):
    now_utc: str
    clinic_id: Optional[str] = None
    trust_state: DashboardTrustState
    kpis_24h: DashboardKpis
    recent_submissions: List[DashboardSubmissionItem]
    latest_receipt: Optional[ReceiptV1] = None
    latest_signed_receipt_url: Optional[str] = None


# -----------------------------
# SQL (RLS enforced by explicit set_config)
# -----------------------------
_SQL_RECENT = """
SELECT
  request_id,
  clinic_id,
  user_id AS clinic_user_id,
  mode,
  decision,
  risk_grade,
  reason_code,
  pii_detected,
  pii_action,
  policy_version,
  neutrality_version,
  governance_score,
  created_at
FROM clinic_governance_events
WHERE clinic_id = app_current_clinic_id()
ORDER BY created_at DESC, request_id DESC
LIMIT :limit
"""

_SQL_KPIS_24H = """
WITH w AS (
  SELECT *
  FROM clinic_governance_events
  WHERE clinic_id = app_current_clinic_id()
    AND created_at >= (now() AT TIME ZONE 'utc') - INTERVAL '24 hours'
)
SELECT
  (SELECT COUNT(*) FROM w) AS events_24h,
  (SELECT COUNT(*) FROM w WHERE decision IN ('replaced','blocked')) AS interventions_24h,
  (SELECT COUNT(*) FROM w WHERE COALESCE(pii_action,'') = 'warn') AS pii_warned_24h,
  (SELECT mode FROM w GROUP BY mode ORDER BY COUNT(*) DESC, mode ASC LIMIT 1) AS top_mode_24h
"""


def _iso(dt: Any) -> str:
    if dt is None:
        return ""
    try:
        return dt.isoformat()
    except Exception:
        return str(dt)


def _derive_trust_state(*, events: int, interventions: int, pii_warned: int) -> DashboardTrustState:
    reasons: List[str] = []
    health = "green"

    intervention_rate = (interventions / events) if events > 0 else 0.0
    pii_warn_rate = (pii_warned / events) if events > 0 else 0.0

    if events >= 10 and intervention_rate >= 0.25:
        health = "red"
        reasons.append(f"high_intervention_rate_24h={intervention_rate:.2f}")

    if events >= 3 and pii_warn_rate >= 0.50 and health != "red":
        health = "yellow"
        reasons.append(f"high_pii_warn_rate_24h={pii_warn_rate:.2f}")

    if events == 0:
        health = "yellow"
        reasons.append("no_events_24h")

    return DashboardTrustState(health_state=health, reasons=reasons)


def _build_latest_receipt(db: Session, row: Dict[str, Any]) -> ReceiptV1:
    created_at_utc = _iso(row.get("created_at"))

    pv = int(row.get("policy_version") or 0)
    policy_json = _get_clinic_policy_json(db, policy_version=pv)
    ph = _hash_policy_json(policy_json)
    policy_id = f"clinic_policy:{pv}"

    return ReceiptV1(
        request_id=str(row["request_id"]),
        clinic_id=str(row["clinic_id"]),
        clinic_user_id=str(row["clinic_user_id"]),
        mode=str(row["mode"]),
        decision=str(row["decision"]),
        risk_grade=(str(row["risk_grade"]) if row.get("risk_grade") is not None else None),
        reason_code=(str(row["reason_code"]) if row.get("reason_code") is not None else None),
        pii_detected=bool(row.get("pii_detected") or False),
        pii_action=(str(row["pii_action"]) if row.get("pii_action") is not None else None),
        pii_types=list(row.get("pii_types") or []),
        policy_version=pv,
        policy_hash=ph,
        policy_id=policy_id,
        neutrality_version=(str(row["neutrality_version"]) if row.get("neutrality_version") is not None else None),
        governance_score=(float(row["governance_score"]) if row.get("governance_score") is not None else None),

        # Dashboard doesn't need override fields; keep defaults
        override_flag=False,
        override_reason=None,
        override_at_utc=None,

        # Keep consistent with portal_read receipt output
        jwt_iss="anchor",
        jwt_aud="anchor-portal",
        created_at_utc=created_at_utc,
    )


@router.get("/dashboard", response_model=PortalDashboardResponse)
def portal_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    limit: int = 20,
) -> PortalDashboardResponse:
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    _set_rls_context(db, clinic_id=clinic_id, clinic_user_id=clinic_user_id)

    limit = int(limit)
    if limit < 1:
        limit = 1
    if limit > 100:
        limit = 100

    now_utc = datetime.now(timezone.utc).isoformat()

    rows = db.execute(text(_SQL_RECENT), {"limit": limit}).mappings().all()

    recent: List[DashboardSubmissionItem] = []
    latest_row: Optional[Dict[str, Any]] = None

    for idx, r in enumerate(rows):
        if idx == 0:
            latest_row = dict(r)

        recent.append(
            DashboardSubmissionItem(
                request_id=str(r["request_id"]),
                clinic_user_id=str(r["clinic_user_id"]),
                mode=str(r["mode"]),
                decision=str(r["decision"]),
                risk_grade=(str(r["risk_grade"]) if r.get("risk_grade") is not None else None),
                reason_code=(str(r["reason_code"]) if r.get("reason_code") is not None else None),
                pii_detected=bool(r.get("pii_detected") or False),
                pii_action=(str(r["pii_action"]) if r.get("pii_action") is not None else None),
                policy_version=(int(r["policy_version"]) if r.get("policy_version") is not None else None),
                neutrality_version=(str(r["neutrality_version"]) if r.get("neutrality_version") is not None else None),
                created_at_utc=_iso(r.get("created_at")),
            )
        )

    kpi_row = db.execute(text(_SQL_KPIS_24H)).mappings().first() or {}

    events_24h = int(kpi_row.get("events_24h") or 0)
    interventions_24h = int(kpi_row.get("interventions_24h") or 0)
    pii_warned_24h = int(kpi_row.get("pii_warned_24h") or 0)

    top_mode = kpi_row.get("top_mode_24h")
    top_mode_24h = str(top_mode) if top_mode is not None else None

    events_per_hour = float(events_24h) / 24.0
    intervention_rate_24h = (float(interventions_24h) / float(events_24h)) if events_24h > 0 else 0.0
    pii_warned_rate_24h = (float(pii_warned_24h) / float(events_24h)) if events_24h > 0 else 0.0

    kpis = DashboardKpis(
        window_hours=24,
        events_24h=events_24h,
        events_per_hour=events_per_hour,
        interventions_24h=interventions_24h,
        intervention_rate_24h=intervention_rate_24h,
        pii_warned_24h=pii_warned_24h,
        pii_warned_rate_24h=pii_warned_rate_24h,
        top_mode_24h=top_mode_24h,
    )

    trust_state = _derive_trust_state(
        events=events_24h,
        interventions=interventions_24h,
        pii_warned=pii_warned_24h,
    )

    latest_receipt = _build_latest_receipt(db, latest_row) if latest_row else None

    latest_signed_receipt_url = None
    if latest_receipt is not None:
        latest_signed_receipt_url = f"/v1/portal/receipt/{latest_receipt.request_id}/signed"

    return PortalDashboardResponse(
        now_utc=now_utc,
        clinic_id=str(clinic_id) if clinic_id is not None else None,
        trust_state=trust_state,
        kpis_24h=kpis,
        recent_submissions=recent,
        latest_receipt=latest_receipt,
        latest_signed_receipt_url=latest_signed_receipt_url,
    )
