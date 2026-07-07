# app/billing_foundations.py
#
# M5.8 - Billing and Activation Foundations (code-wise completion,
# sandbox-only). Authorised by the 2026-07-05 founder code-completion
# decision record.
#
# Hard boundaries:
#   * NO live billing, NO charge capability, NO payment instrument
#     fields, NO Stripe SDK dependency, NO live webhook secrets.
#   * The API can only set activation_status 'internal_demo' or
#     'pilot_candidate'. 'active_limited' / 'active_verified' exist in
#     the model (Roadmap v2.6 M5.8) but are refused here: they require
#     the security + legal gates and a founder decision.
#   * stripe_mode is never settable through this API and the schema
#     cannot store 'live'.
#   * The Stripe webhook endpoint is a STRUCTURE-ONLY skeleton: it is
#     disabled by default, refuses outright in production, verifies
#     nothing, processes nothing, stores nothing, and logs only the
#     event type string (metadata-only).

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.anchor_logging import get_app_env, log_event
from app.auth_and_rls import require_clinic_user
from app.db import get_db

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/v1/portal/billing",
    tags=["Billing Foundations"],
    dependencies=[Depends(require_clinic_user)],
)

# Unauthenticated by nature (webhooks); separately mounted and hard-gated.
webhook_router = APIRouter(tags=["Billing Foundations"])

_BILLING_ADMIN_ROLES = {"admin", "owner", "practice_manager"}

BILLING_WEBHOOK_FLAG_ENV = "ANCHOR_BILLING_WEBHOOK_ENABLED"
_TRUTHY = {"1", "true", "yes", "on"}

SANDBOX_NOTE = (
    "Billing foundations are sandbox-only. No live billing, no charges, "
    "no payment details, and no activation of paid service."
)

# The only activation states this API may set. The gated states require
# the 2A-D security + legal gates and an explicit founder decision.
_API_SETTABLE_ACTIVATION = {"internal_demo", "pilot_candidate"}
_API_SETTABLE_READINESS = {"not_ready", "sandbox_only", "ready_pending_gates"}

_DEFAULT_STATE: Dict[str, Any] = {
    "plan_slug": "internal_demo",
    "activation_status": "internal_demo",
    "billing_readiness": "not_ready",
    "stripe_mode": "disabled",
    "updated_at": None,
}


def _ctx(request: Request) -> Dict[str, str]:
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    role = getattr(request.state, "role", "") or ""
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")
    return {
        "clinic_id": str(clinic_id),
        "clinic_user_id": str(clinic_user_id),
        "role": str(role),
        "ip_hash": getattr(request.state, "ip_hash", None) or "",
    }


def _require_admin(role: str) -> None:
    if role not in _BILLING_ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="forbidden_not_admin")


def _insert_admin_audit_event(
    db: Session,
    *,
    clinic_id: str,
    admin_user_id: str,
    action: str,
    ip_hash: Optional[str],
    meta: Dict[str, Any],
) -> None:
    """Append-only metadata-only audit row (governance_policy /
    assistant_policy M6.10 precedent). NO ON CONFLICT against the
    partial admin_audit_events_idem_uq index. meta carries sandbox
    posture values only - no billing secrets, payment details, or card
    data exist anywhere in this module to log."""
    db.execute(
        text(
            """
            INSERT INTO admin_audit_events (
                clinic_id,
                admin_user_id,
                action,
                target_id,
                ip_hash,
                meta
            )
            VALUES (
                CAST(:clinic_id AS uuid),
                CAST(:admin_user_id AS uuid),
                :action,
                NULL,
                :ip_hash,
                CAST(:meta AS jsonb)
            )
            """
        ),
        {
            "clinic_id": clinic_id,
            "admin_user_id": admin_user_id,
            "action": action,
            "ip_hash": ip_hash or None,
            "meta": json.dumps(meta),
        },
    )


def _webhook_enabled() -> bool:
    raw = (os.getenv(BILLING_WEBHOOK_FLAG_ENV, "") or "").strip().lower()
    return raw in _TRUTHY


# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------

class BillingPlan(BaseModel):
    plan_slug: str
    version: str
    title: str
    summary: str
    monthly_price_pence: Optional[int] = None
    currency: str
    display_order: int


class BillingStateResponse(BaseModel):
    plan_slug: str
    activation_status: str
    billing_readiness: str
    stripe_mode: str
    updated_at: Optional[datetime] = None
    plans: List[BillingPlan]
    sandbox_note: str


class BillingStateUpdate(BaseModel):
    plan_slug: Optional[str] = Field(default=None, max_length=64)
    activation_status: Optional[str] = Field(default=None, max_length=32)
    billing_readiness: Optional[str] = Field(default=None, max_length=32)


# ---------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------

def _load_state(db: Session, clinic_id: str) -> Dict[str, Any]:
    row = db.execute(
        text(
            """
            SELECT plan_slug, activation_status, billing_readiness,
                   stripe_mode, updated_at
            FROM clinic_billing_state
            WHERE clinic_id = CAST(:clinic_id AS uuid)
            LIMIT 1
            """
        ),
        {"clinic_id": clinic_id},
    ).mappings().first()
    if not row:
        return dict(_DEFAULT_STATE)
    return dict(row)


def _load_plans(db: Session) -> List[BillingPlan]:
    rows = db.execute(
        text(
            """
            SELECT plan_slug, version, title, summary,
                   monthly_price_pence, currency, display_order
            FROM billing_plans
            WHERE is_active = true
            ORDER BY display_order, plan_slug
            """
        ),
        {},
    ).mappings().all()
    return [
        BillingPlan(
            plan_slug=str(r["plan_slug"]),
            version=str(r["version"]),
            title=str(r["title"]),
            summary=str(r["summary"]),
            monthly_price_pence=(
                int(r["monthly_price_pence"])
                if r.get("monthly_price_pence") is not None
                else None
            ),
            currency=str(r["currency"]),
            display_order=int(r["display_order"]),
        )
        for r in rows
    ]


def _plan_exists(db: Session, plan_slug: str) -> bool:
    row = db.execute(
        text(
            "SELECT 1 AS one FROM billing_plans "
            "WHERE plan_slug = :plan_slug AND is_active = true LIMIT 1"
        ),
        {"plan_slug": plan_slug},
    ).mappings().first()
    return bool(row)


# ---------------------------------------------------------------------
# Portal endpoints
# ---------------------------------------------------------------------

@router.get("/state", response_model=BillingStateResponse)
def billing_state(
    request: Request,
    db: Session = Depends(get_db),
) -> BillingStateResponse:
    ctx = _ctx(request)
    state = _load_state(db, ctx["clinic_id"])
    return BillingStateResponse(
        plan_slug=str(state["plan_slug"]),
        activation_status=str(state["activation_status"]),
        billing_readiness=str(state["billing_readiness"]),
        stripe_mode=str(state["stripe_mode"]),
        updated_at=state.get("updated_at"),
        plans=_load_plans(db),
        sandbox_note=SANDBOX_NOTE,
    )


@router.put("/state", response_model=BillingStateResponse)
def update_billing_state(
    payload: BillingStateUpdate,
    request: Request,
    db: Session = Depends(get_db),
) -> BillingStateResponse:
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    current = _load_state(db, ctx["clinic_id"])

    activation = payload.activation_status or str(current["activation_status"])
    if activation not in _API_SETTABLE_ACTIVATION:
        # 'active_limited' / 'active_verified' (and anything unknown)
        # are refused here by design.
        raise HTTPException(
            status_code=403,
            detail="activation_gated_requires_founder_and_gates",
        )

    readiness = payload.billing_readiness or str(current["billing_readiness"])
    if readiness not in _API_SETTABLE_READINESS:
        raise HTTPException(status_code=400, detail="invalid_billing_readiness")

    plan_slug = payload.plan_slug or str(current["plan_slug"])
    if not _plan_exists(db, plan_slug):
        raise HTTPException(status_code=404, detail="plan_not_found")

    row = db.execute(
        text(
            """
            INSERT INTO clinic_billing_state (
                clinic_id, plan_slug, activation_status,
                billing_readiness, updated_by_user_id
            )
            VALUES (
                CAST(:clinic_id AS uuid), :plan_slug, :activation_status,
                :billing_readiness, CAST(:updated_by AS uuid)
            )
            ON CONFLICT (clinic_id) DO UPDATE
            SET plan_slug = EXCLUDED.plan_slug,
                activation_status = EXCLUDED.activation_status,
                billing_readiness = EXCLUDED.billing_readiness,
                updated_by_user_id = EXCLUDED.updated_by_user_id,
                updated_at = now()
            RETURNING plan_slug, activation_status, billing_readiness,
                      stripe_mode, updated_at
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "plan_slug": plan_slug,
            "activation_status": activation,
            "billing_readiness": readiness,
            "updated_by": ctx["clinic_user_id"],
        },
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=500, detail="billing_state_failed")

    _insert_admin_audit_event(
        db,
        clinic_id=ctx["clinic_id"],
        admin_user_id=ctx["clinic_user_id"],
        action="billing_state_updated",
        ip_hash=ctx["ip_hash"],
        meta={
            "previous_plan_slug": str(current["plan_slug"]),
            "previous_activation_status": str(current["activation_status"]),
            "previous_billing_readiness": str(current["billing_readiness"]),
            "plan_slug": plan_slug,
            "activation_status": activation,
            "billing_readiness": readiness,
        },
    )

    return BillingStateResponse(
        plan_slug=str(row["plan_slug"]),
        activation_status=str(row["activation_status"]),
        billing_readiness=str(row["billing_readiness"]),
        stripe_mode=str(row["stripe_mode"]),
        updated_at=row.get("updated_at"),
        plans=_load_plans(db),
        sandbox_note=SANDBOX_NOTE,
    )


# ---------------------------------------------------------------------
# Webhook structure (skeleton; disabled by default; prod-refusing)
# ---------------------------------------------------------------------

@webhook_router.post("/v1/billing/webhook/stripe")
async def stripe_webhook_skeleton(request: Request) -> Dict[str, Any]:
    """Structure-only sandbox webhook. Verifies nothing, processes
    nothing, stores nothing. Logs only the event type string. Refuses
    in production and is disabled by default everywhere else."""
    if get_app_env() == "prod":
        raise HTTPException(status_code=503, detail="billing_webhook_disabled")
    if not _webhook_enabled():
        raise HTTPException(status_code=503, detail="billing_webhook_disabled")

    event_type = "unknown"
    try:
        body = await request.json()
        if isinstance(body, dict):
            raw_type = body.get("type")
            if isinstance(raw_type, str) and raw_type.strip():
                event_type = raw_type.strip()[:128]
    except Exception:
        event_type = "unparseable"

    log_event(
        logging.INFO,
        "billing.webhook.sandbox_received",
        event_type=event_type,
        processed=False,
    )
    return {"received": True, "mode": "sandbox", "processed": False}
