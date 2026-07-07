# app/learn_maturity.py
#
# M4.6 - Learn Maturity and Enablement (code-wise completion, gated).
# Authorised by the 2026-07-05 founder code-completion decision record.
# Additive module: app/learn_v1.py is untouched.
#
# Surfaces:
#   * self-check / scenario questions per module (reinforcement only)
#   * role-based learning paths with per-user progress
#   * renewal / refresh status for the caller
#   * leadership renewal overview (clinic-admin roles only)
#   * per-clinic renewal cadence setting
#
# Non-certifying doctrine (hard boundary for this module):
#   * Self-checks are reinforcement, NOT competence assessment. There is
#     no pass/fail, no grade, no certificate, and every response carries
#     SELF_CHECK_NOTE saying so.
#   * No RCVS-accredited / certified CPD / regulator-approved wording
#     anywhere. CPD remains "CPD-recordable AI literacy activity".
#
# Metadata-only doctrine:
#   * Attempts store aggregate counts only - never per-question answers,
#     never free text.
#   * No clinical content anywhere in this module.

from __future__ import annotations

import calendar
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/v1/learn",
    tags=["Learn Maturity"],
    dependencies=[Depends(require_clinic_user)],
)

# Matches learn_v1.LEARN_ADMIN_ROLES / the wider app convention.
_LEARN_MATURITY_ADMIN_ROLES = {"admin", "owner", "practice_manager"}

SELF_CHECK_NOTE = (
    "Self-check reinforcement only. Not a competence assessment, not a "
    "pass or fail result, not certified or accredited CPD, and not "
    "regulator-approved training."
)

DEFAULT_RENEWAL_MONTHS = 12
DUE_SOON_WINDOW_DAYS = 60

RENEWAL_STATUS_CURRENT = "current"
RENEWAL_STATUS_DUE_SOON = "due_soon"
RENEWAL_STATUS_OVERDUE = "overdue"


# ---------------------------------------------------------------------
# Context / helpers
# ---------------------------------------------------------------------

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
    if role not in _LEARN_MATURITY_ADMIN_ROLES:
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
    partial admin_audit_events_idem_uq index. meta carries the renewal
    cadence only - never learner answers, scores framed as competence,
    or any learning content."""
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


def _as_uuid(value: Any, *, field: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except Exception:
        raise HTTPException(status_code=400, detail=f"invalid_{field}")


def _add_months(dt: datetime, months: int) -> datetime:
    """Calendar-correct month addition (clamps to month end)."""
    month_index = dt.month - 1 + months
    year = dt.year + month_index // 12
    month = month_index % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def _as_aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if getattr(dt, "tzinfo", None) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _renewal_status(due_at: datetime, now: datetime) -> str:
    if due_at <= now:
        return RENEWAL_STATUS_OVERDUE
    if due_at <= now + timedelta(days=DUE_SOON_WINDOW_DAYS):
        return RENEWAL_STATUS_DUE_SOON
    return RENEWAL_STATUS_CURRENT


def _clinic_renewal_months(db: Session, clinic_id: str) -> int:
    try:
        row = db.execute(
            text(
                "SELECT renewal_months FROM learning_renewal_policies "
                "WHERE clinic_id = CAST(:clinic_id AS uuid) LIMIT 1"
            ),
            {"clinic_id": clinic_id},
        ).mappings().first()
    except Exception:
        logger.exception("learn_maturity renewal policy lookup failed")
        return DEFAULT_RENEWAL_MONTHS
    if not row:
        return DEFAULT_RENEWAL_MONTHS
    try:
        months = int(row["renewal_months"])
    except (KeyError, TypeError, ValueError):
        return DEFAULT_RENEWAL_MONTHS
    return months if 1 <= months <= 60 else DEFAULT_RENEWAL_MONTHS


def _module_row(db: Session, module_id: str) -> Dict[str, Any]:
    row = db.execute(
        text(
            "SELECT version, is_active FROM learning_modules "
            "WHERE module_id = CAST(:module_id AS uuid) LIMIT 1"
        ),
        {"module_id": module_id},
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="module_not_found")
    if not bool(row["is_active"]):
        raise HTTPException(status_code=404, detail="module_not_found")
    return dict(row)


# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------

class SelfCheckQuestion(BaseModel):
    check_id: str
    check_slug: str
    kind: str
    prompt: str
    options: List[str]
    display_order: int


class SelfCheckListResponse(BaseModel):
    module_id: str
    questions: List[SelfCheckQuestion]
    self_check_note: str


class SelfCheckAnswer(BaseModel):
    check_id: str
    selected_option_index: int = Field(..., ge=0)


class SelfCheckAttemptRequest(BaseModel):
    answers: List[SelfCheckAnswer] = Field(..., min_length=1, max_length=50)


class SelfCheckFeedback(BaseModel):
    check_id: str
    correct: bool
    correct_option_index: int
    explanation: str


class SelfCheckAttemptResponse(BaseModel):
    attempt_id: str
    module_id: str
    module_version: str
    questions_total: int
    questions_correct: int
    completed_at: datetime
    feedback: List[SelfCheckFeedback]
    self_check_note: str


class LearningPathProgress(BaseModel):
    path_id: str
    path_slug: str
    version: str
    title: str
    summary: str
    role_applicability: List[str]
    module_slugs: List[str]
    completed_module_slugs: List[str]
    completed_count: int
    total_count: int


class LearningPathListResponse(BaseModel):
    paths: List[LearningPathProgress]
    self_check_note: str


class RenewalEntry(BaseModel):
    module_id: str
    module_slug: str
    title: str
    latest_completed_at: datetime
    due_at: datetime
    status: str


class MyRenewalsResponse(BaseModel):
    renewal_months: int
    entries: List[RenewalEntry]
    self_check_note: str


class RenewalOverviewUser(BaseModel):
    user_id: str
    modules_completed: int
    current_count: int
    due_soon_count: int
    overdue_count: int


class RenewalOverviewResponse(BaseModel):
    renewal_months: int
    users: List[RenewalOverviewUser]
    total_current: int
    total_due_soon: int
    total_overdue: int
    self_check_note: str


class RenewalPolicyUpdate(BaseModel):
    renewal_months: int = Field(..., ge=1, le=60)


class RenewalPolicyResponse(BaseModel):
    renewal_months: int
    updated_at: Optional[datetime] = None
    self_check_note: str


# ---------------------------------------------------------------------
# Self-check questions
# ---------------------------------------------------------------------

@router.get(
    "/checks/modules/{module_id}", response_model=SelfCheckListResponse
)
def list_module_checks(
    module_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> SelfCheckListResponse:
    _ctx(request)
    mid = _as_uuid(module_id, field="module_id")
    _module_row(db, mid)

    rows = db.execute(
        text(
            """
            SELECT check_id, check_slug, kind, prompt, options, display_order
            FROM learning_module_checks
            WHERE module_id = CAST(:module_id AS uuid)
              AND is_active = true
            ORDER BY display_order, check_slug
            """
        ),
        {"module_id": mid},
    ).mappings().all()

    questions = [
        SelfCheckQuestion(
            check_id=str(r["check_id"]),
            check_slug=str(r["check_slug"]),
            kind=str(r["kind"]),
            prompt=str(r["prompt"]),
            options=list(r["options"] or []),
            display_order=int(r["display_order"]),
        )
        for r in rows
    ]
    return SelfCheckListResponse(
        module_id=mid,
        questions=questions,
        self_check_note=SELF_CHECK_NOTE,
    )


@router.post(
    "/checks/modules/{module_id}/attempts",
    response_model=SelfCheckAttemptResponse,
)
def submit_self_check_attempt(
    module_id: str,
    payload: SelfCheckAttemptRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> SelfCheckAttemptResponse:
    ctx = _ctx(request)
    mid = _as_uuid(module_id, field="module_id")
    module = _module_row(db, mid)

    rows = db.execute(
        text(
            """
            SELECT check_id, options, correct_option_index, explanation
            FROM learning_module_checks
            WHERE module_id = CAST(:module_id AS uuid)
              AND is_active = true
            """
        ),
        {"module_id": mid},
    ).mappings().all()
    marking: Dict[str, Dict[str, Any]] = {
        str(r["check_id"]): dict(r) for r in rows
    }
    if not marking:
        raise HTTPException(status_code=404, detail="no_active_checks")

    answered_ids = [
        _as_uuid(a.check_id, field="check_id") for a in payload.answers
    ]
    if len(set(answered_ids)) != len(answered_ids):
        raise HTTPException(status_code=400, detail="duplicate_check_answer")
    if set(answered_ids) != set(marking.keys()):
        raise HTTPException(status_code=400, detail="incomplete_self_check")

    feedback: List[SelfCheckFeedback] = []
    correct_count = 0
    for answer, check_id in zip(payload.answers, answered_ids):
        spec = marking[check_id]
        options = list(spec["options"] or [])
        if answer.selected_option_index >= len(options):
            raise HTTPException(
                status_code=400, detail="invalid_option_index"
            )
        correct_index = int(spec["correct_option_index"])
        is_correct = answer.selected_option_index == correct_index
        if is_correct:
            correct_count += 1
        feedback.append(
            SelfCheckFeedback(
                check_id=check_id,
                correct=is_correct,
                correct_option_index=correct_index,
                explanation=str(spec["explanation"]),
            )
        )

    inserted = db.execute(
        text(
            """
            INSERT INTO learning_check_attempts (
                clinic_id, user_id, module_id, module_version,
                questions_total, questions_correct
            )
            VALUES (
                CAST(:clinic_id AS uuid), CAST(:user_id AS uuid),
                CAST(:module_id AS uuid), :module_version,
                :questions_total, :questions_correct
            )
            RETURNING attempt_id, completed_at
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "user_id": ctx["clinic_user_id"],
            "module_id": mid,
            "module_version": str(module["version"]),
            "questions_total": len(feedback),
            "questions_correct": correct_count,
        },
    ).mappings().first()
    if not inserted:
        raise HTTPException(status_code=500, detail="attempt_insert_failed")

    return SelfCheckAttemptResponse(
        attempt_id=str(inserted["attempt_id"]),
        module_id=mid,
        module_version=str(module["version"]),
        questions_total=len(feedback),
        questions_correct=correct_count,
        completed_at=_as_aware(inserted["completed_at"]) or datetime.now(timezone.utc),
        feedback=feedback,
        self_check_note=SELF_CHECK_NOTE,
    )


# ---------------------------------------------------------------------
# Role-based learning paths
# ---------------------------------------------------------------------

@router.get("/paths", response_model=LearningPathListResponse)
def list_learning_paths(
    request: Request,
    db: Session = Depends(get_db),
) -> LearningPathListResponse:
    ctx = _ctx(request)

    path_rows = db.execute(
        text(
            """
            SELECT path_id, path_slug, version, title, summary,
                   role_applicability, module_slugs, display_order
            FROM learning_role_paths
            WHERE is_active = true
            ORDER BY display_order, path_slug
            """
        ),
        {},
    ).mappings().all()

    completed_rows = db.execute(
        text(
            """
            SELECT DISTINCT lm.module_slug AS module_slug
            FROM learning_completions lc
            JOIN learning_modules lm ON lm.module_id = lc.module_id
            WHERE lc.clinic_id = CAST(:clinic_id AS uuid)
              AND lc.user_id = CAST(:user_id AS uuid)
              AND lc.is_voided = false
            """
        ),
        {"clinic_id": ctx["clinic_id"], "user_id": ctx["clinic_user_id"]},
    ).mappings().all()
    completed_slugs = {str(r["module_slug"]) for r in completed_rows}

    paths: List[LearningPathProgress] = []
    for r in path_rows:
        module_slugs = list(r["module_slugs"] or [])
        done = [s for s in module_slugs if s in completed_slugs]
        paths.append(
            LearningPathProgress(
                path_id=str(r["path_id"]),
                path_slug=str(r["path_slug"]),
                version=str(r["version"]),
                title=str(r["title"]),
                summary=str(r["summary"]),
                role_applicability=list(r["role_applicability"] or []),
                module_slugs=module_slugs,
                completed_module_slugs=done,
                completed_count=len(done),
                total_count=len(module_slugs),
            )
        )
    return LearningPathListResponse(
        paths=paths, self_check_note=SELF_CHECK_NOTE
    )


# ---------------------------------------------------------------------
# Renewal / refresh
# ---------------------------------------------------------------------

@router.get("/renewals/me", response_model=MyRenewalsResponse)
def my_renewals(
    request: Request,
    db: Session = Depends(get_db),
) -> MyRenewalsResponse:
    ctx = _ctx(request)
    months = _clinic_renewal_months(db, ctx["clinic_id"])
    now = datetime.now(timezone.utc)

    rows = db.execute(
        text(
            """
            SELECT lc.module_id, lm.module_slug, lm.title,
                   MAX(lc.completed_at) AS latest_completed_at
            FROM learning_completions lc
            JOIN learning_modules lm ON lm.module_id = lc.module_id
            WHERE lc.clinic_id = CAST(:clinic_id AS uuid)
              AND lc.user_id = CAST(:user_id AS uuid)
              AND lc.is_voided = false
            GROUP BY lc.module_id, lm.module_slug, lm.title
            ORDER BY lm.module_slug
            """
        ),
        {"clinic_id": ctx["clinic_id"], "user_id": ctx["clinic_user_id"]},
    ).mappings().all()

    entries: List[RenewalEntry] = []
    for r in rows:
        latest = _as_aware(r["latest_completed_at"])
        if latest is None:
            continue
        due_at = _add_months(latest, months)
        entries.append(
            RenewalEntry(
                module_id=str(r["module_id"]),
                module_slug=str(r["module_slug"]),
                title=str(r["title"]),
                latest_completed_at=latest,
                due_at=due_at,
                status=_renewal_status(due_at, now),
            )
        )
    return MyRenewalsResponse(
        renewal_months=months,
        entries=entries,
        self_check_note=SELF_CHECK_NOTE,
    )


@router.get("/renewals/overview", response_model=RenewalOverviewResponse)
def renewal_overview(
    request: Request,
    db: Session = Depends(get_db),
) -> RenewalOverviewResponse:
    ctx = _ctx(request)
    _require_admin(ctx["role"])
    months = _clinic_renewal_months(db, ctx["clinic_id"])
    now = datetime.now(timezone.utc)

    rows = db.execute(
        text(
            """
            SELECT lc.user_id, lc.module_id,
                   MAX(lc.completed_at) AS latest_completed_at
            FROM learning_completions lc
            WHERE lc.clinic_id = CAST(:clinic_id AS uuid)
              AND lc.is_voided = false
            GROUP BY lc.user_id, lc.module_id
            """
        ),
        {"clinic_id": ctx["clinic_id"]},
    ).mappings().all()

    per_user: Dict[str, Dict[str, int]] = {}
    totals = {
        RENEWAL_STATUS_CURRENT: 0,
        RENEWAL_STATUS_DUE_SOON: 0,
        RENEWAL_STATUS_OVERDUE: 0,
    }
    for r in rows:
        latest = _as_aware(r["latest_completed_at"])
        if latest is None:
            continue
        status = _renewal_status(_add_months(latest, months), now)
        user_id = str(r["user_id"])
        bucket = per_user.setdefault(
            user_id,
            {
                "modules_completed": 0,
                RENEWAL_STATUS_CURRENT: 0,
                RENEWAL_STATUS_DUE_SOON: 0,
                RENEWAL_STATUS_OVERDUE: 0,
            },
        )
        bucket["modules_completed"] += 1
        bucket[status] += 1
        totals[status] += 1

    users = [
        RenewalOverviewUser(
            user_id=user_id,
            modules_completed=bucket["modules_completed"],
            current_count=bucket[RENEWAL_STATUS_CURRENT],
            due_soon_count=bucket[RENEWAL_STATUS_DUE_SOON],
            overdue_count=bucket[RENEWAL_STATUS_OVERDUE],
        )
        for user_id, bucket in sorted(per_user.items())
    ]
    return RenewalOverviewResponse(
        renewal_months=months,
        users=users,
        total_current=totals[RENEWAL_STATUS_CURRENT],
        total_due_soon=totals[RENEWAL_STATUS_DUE_SOON],
        total_overdue=totals[RENEWAL_STATUS_OVERDUE],
        self_check_note=SELF_CHECK_NOTE,
    )


@router.put("/renewal-policy", response_model=RenewalPolicyResponse)
def set_renewal_policy(
    payload: RenewalPolicyUpdate,
    request: Request,
    db: Session = Depends(get_db),
) -> RenewalPolicyResponse:
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    row = db.execute(
        text(
            """
            INSERT INTO learning_renewal_policies (
                clinic_id, renewal_months, updated_by_user_id
            )
            VALUES (
                CAST(:clinic_id AS uuid), :renewal_months,
                CAST(:updated_by AS uuid)
            )
            ON CONFLICT (clinic_id) DO UPDATE
            SET renewal_months = EXCLUDED.renewal_months,
                updated_by_user_id = EXCLUDED.updated_by_user_id,
                updated_at = now()
            RETURNING renewal_months, updated_at
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "renewal_months": payload.renewal_months,
            "updated_by": ctx["clinic_user_id"],
        },
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=500, detail="renewal_policy_failed")

    _insert_admin_audit_event(
        db,
        clinic_id=ctx["clinic_id"],
        admin_user_id=ctx["clinic_user_id"],
        action="learn_renewal_policy_updated",
        ip_hash=ctx["ip_hash"],
        meta={"renewal_months": int(payload.renewal_months)},
    )

    return RenewalPolicyResponse(
        renewal_months=int(row["renewal_months"]),
        updated_at=_as_aware(row.get("updated_at")),
        self_check_note=SELF_CHECK_NOTE,
    )
