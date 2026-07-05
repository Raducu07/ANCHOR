# app/portal_onboarding.py
#
# M5.7 - Assisted Onboarding foundations (code-wise completion, gated).
# Authorised by the 2026-07-05 founder code-completion decision record.
#
# Two read-only, tenant-scoped surfaces:
#   * GET /v1/portal/onboarding/checklist - metadata-only readiness
#     checklist aggregating the governance surfaces a new clinic works
#     through (policy, attestation, literacy, self-assessment,
#     transparency, assistant policy). Any authenticated clinic user.
#   * GET /v1/portal/onboarding/invites - invite lifecycle visibility
#     (pending / used / expired). Clinic-admin roles only. Never returns
#     token hashes or any token material.
#
# Doctrine:
#   * Read-only: no endpoint here writes anything.
#   * Metadata-only: counts, timestamps, statuses. No policy bodies, no
#     assessment answers, no clinical content.
#   * Each checklist block soft-fails independently (house pattern from
#     app/trust_snapshot.py): a failed query yields an honest
#     "unavailable" item, never a 500 and never a fabricated zero
#     presented as fact.
#   * This is not clinic activation. No real clinic onboarding, paid
#     pilot, or billing behaviour is introduced or implied. The
#     checklist does not certify readiness or compliance.

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/v1/portal/onboarding",
    tags=["Onboarding"],
    dependencies=[Depends(require_clinic_user)],
)

# Clinic-admin roles, matching the existing app convention
# (governance_policy._GOVERNANCE_POLICY_ADMIN_ROLES et al.).
_ONBOARDING_ADMIN_ROLES = {"admin", "owner", "practice_manager"}

GOVERNANCE_NOTE = (
    "Metadata-only readiness guidance for setting up governed AI use. "
    "It does not certify compliance and does not replace professional "
    "judgement."
)


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
    }


def _require_admin(role: str) -> None:
    if role not in _ONBOARDING_ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="forbidden_not_admin")


def _safe_count(
    db: Session,
    sql: str,
    params: Dict[str, Any],
    label: str,
) -> Optional[int]:
    """Run one COUNT query; return None (never raise) on failure so a
    single unavailable surface cannot take down the whole checklist."""
    try:
        row = db.execute(text(sql), params).mappings().first()
    except Exception:
        logger.exception("onboarding checklist query failed: %s", label)
        return None
    if not row:
        return 0
    try:
        return int(row.get("c") or 0)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------

class OnboardingChecklistItem(BaseModel):
    key: str
    title: str
    done: bool
    available: bool
    count: Optional[int] = None
    guidance: str


class OnboardingChecklistResponse(BaseModel):
    generated_at: datetime
    completed_count: int
    total_count: int
    items: List[OnboardingChecklistItem]
    governance_note: str


class OnboardingInvite(BaseModel):
    invite_id: str
    email: str
    role: str
    status: str  # pending | used | expired
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    used_at: Optional[datetime] = None


class OnboardingInviteListResponse(BaseModel):
    invites: List[OnboardingInvite]
    pending_count: int
    used_count: int
    expired_count: int
    governance_note: str


# ---------------------------------------------------------------------
# Checklist definition
# ---------------------------------------------------------------------
#
# (key, title, SQL, informational_only, guidance). SQL must select a
# single ::int count aliased `c` and bind :clinic_id only.

_CHECKLIST_QUERIES: List[Dict[str, Any]] = [
    {
        "key": "admin_account_active",
        "title": "Governance owner signed in",
        "sql": (
            "SELECT COUNT(*)::int AS c FROM clinic_users "
            "WHERE clinic_id = CAST(:clinic_id AS uuid) "
            "AND active_status = true "
            "AND role IN ('admin','owner','practice_manager')"
        ),
        "informational": False,
        "guidance": (
            "An active clinic admin account is the anchor for every "
            "other setup step."
        ),
    },
    {
        "key": "team_invites_sent",
        "title": "Team members invited",
        "sql": (
            "SELECT COUNT(*)::int AS c FROM clinic_user_invites "
            "WHERE clinic_id = CAST(:clinic_id AS uuid)"
        ),
        "informational": False,
        "guidance": (
            "Invite the staff who will use or oversee AI tools so "
            "attestation and learning evidence can build per person."
        ),
    },
    {
        "key": "ai_use_policy_active",
        "title": "AI use policy activated",
        "sql": (
            "SELECT COUNT(*)::int AS c FROM clinic_policy_versions "
            "WHERE clinic_id = CAST(:clinic_id AS uuid) "
            "AND status = 'active'"
        ),
        "informational": False,
        "guidance": (
            "Activate an AI use policy from the Policy Library so staff "
            "have a current version to read and attest to."
        ),
    },
    {
        "key": "staff_attestations_recorded",
        "title": "Staff attestations recorded",
        "sql": (
            "SELECT COUNT(*)::int AS c FROM policy_attestations "
            "WHERE clinic_id = CAST(:clinic_id AS uuid) "
            "AND is_voided = false"
        ),
        "informational": False,
        "guidance": (
            "Each staff attestation is metadata-only evidence that the "
            "active policy has been read and understood."
        ),
    },
    {
        "key": "ai_literacy_recorded",
        "title": "AI literacy activity recorded",
        "sql": (
            "SELECT COUNT(*)::int AS c FROM learning_completions "
            "WHERE clinic_id = CAST(:clinic_id AS uuid) "
            "AND is_voided = false"
        ),
        "informational": False,
        "guidance": (
            "CPD-recordable AI literacy modules build metadata-only "
            "learning evidence for the team."
        ),
    },
    {
        "key": "self_assessment_submitted",
        "title": "Governance self-assessment submitted",
        "sql": (
            "SELECT COUNT(*)::int AS c FROM clinic_self_assessments "
            "WHERE clinic_id = CAST(:clinic_id AS uuid) "
            "AND status = 'submitted'"
        ),
        "informational": False,
        "guidance": (
            "The self-assessment snapshots where the clinic stands "
            "against governance readiness themes."
        ),
    },
    {
        "key": "client_transparency_published",
        "title": "Client transparency statement published",
        "sql": (
            "SELECT COUNT(*)::int AS c "
            "FROM client_transparency_public_versions "
            "WHERE clinic_id = CAST(:clinic_id AS uuid) "
            "AND publication_status = 'published'"
        ),
        "informational": False,
        "guidance": (
            "Publish a client-safe statement describing how the clinic "
            "uses AI within governed boundaries."
        ),
    },
    {
        "key": "assistant_policy_active",
        "title": "Assistant policy reviewed and activated",
        "sql": (
            "SELECT COUNT(*)::int AS c FROM assistant_policy_settings "
            "WHERE clinic_id = CAST(:clinic_id AS uuid) "
            "AND is_active = true"
        ),
        "informational": False,
        "guidance": (
            "Review the Assistant policy controls (limits, validation "
            "profile) and activate a clinic-specific version."
        ),
    },
    {
        "key": "incident_reporting_ready",
        "title": "Incident / near-miss reporting available",
        "sql": (
            "SELECT COUNT(*)::int AS c FROM ai_incidents "
            "WHERE clinic_id = CAST(:clinic_id AS uuid)"
        ),
        # Reporting is available platform-wide from day one; the count
        # is context, not a to-do. Zero incidents is an honest zero,
        # not a gap.
        "informational": True,
        "guidance": (
            "Near-miss and incident logging is available from day one; "
            "records here are incident-linked governance records, not "
            "statutory reports."
        ),
    },
]


# ---------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------

@router.get("/checklist", response_model=OnboardingChecklistResponse)
def onboarding_checklist(
    request: Request,
    db: Session = Depends(get_db),
) -> OnboardingChecklistResponse:
    ctx = _ctx(request)
    params = {"clinic_id": ctx["clinic_id"]}

    items: List[OnboardingChecklistItem] = []
    completed = 0
    for spec in _CHECKLIST_QUERIES:
        count = _safe_count(db, str(spec["sql"]), params, str(spec["key"]))
        available = count is not None
        if bool(spec["informational"]):
            done = available
        else:
            done = bool(available and count and count > 0)
        if done:
            completed += 1
        items.append(
            OnboardingChecklistItem(
                key=str(spec["key"]),
                title=str(spec["title"]),
                done=done,
                available=available,
                count=count,
                guidance=str(spec["guidance"]),
            )
        )

    return OnboardingChecklistResponse(
        generated_at=datetime.now(timezone.utc),
        completed_count=completed,
        total_count=len(items),
        items=items,
        governance_note=GOVERNANCE_NOTE,
    )


@router.get("/invites", response_model=OnboardingInviteListResponse)
def onboarding_invites(
    request: Request,
    db: Session = Depends(get_db),
) -> OnboardingInviteListResponse:
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    rows = db.execute(
        text(
            """
            SELECT invite_id, email, role, created_at, expires_at, used_at
            FROM clinic_user_invites
            WHERE clinic_id = CAST(:clinic_id AS uuid)
            ORDER BY created_at DESC NULLS LAST
            LIMIT 200
            """
        ),
        {"clinic_id": ctx["clinic_id"]},
    ).mappings().all()

    now = datetime.now(timezone.utc)
    invites: List[OnboardingInvite] = []
    pending = used = expired = 0

    for raw in rows:
        r = dict(raw)
        used_at = r.get("used_at")
        expires_at = r.get("expires_at")
        if expires_at is not None and getattr(expires_at, "tzinfo", None) is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if used_at is not None:
            status = "used"
            used += 1
        elif expires_at is not None and expires_at <= now:
            status = "expired"
            expired += 1
        else:
            status = "pending"
            pending += 1

        invites.append(
            OnboardingInvite(
                invite_id=str(r["invite_id"]),
                email=str(r.get("email") or ""),
                role=str(r.get("role") or ""),
                status=status,
                created_at=r.get("created_at"),
                expires_at=expires_at,
                used_at=used_at,
            )
        )

    return OnboardingInviteListResponse(
        invites=invites,
        pending_count=pending,
        used_count=used,
        expired_count=expired,
        governance_note=GOVERNANCE_NOTE,
    )
