# app/self_assessment.py
#
# Phase 2A-3.2 - RCVS-aligned AI Governance Self-Assessment endpoints.
#
# Scope:
#   * List/get global self_assessment_templates and their ordered
#     questions (ANCHOR-curated catalogue).
#   * Create a draft clinic self-assessment.
#   * Upsert bounded enum answers onto a draft.
#   * Submit a draft (freezes aggregate snapshots; supersedes any
#     prior submitted row for the same clinic/template).
#   * Archive a draft / superseded row.
#   * List clinic self-assessments and read the latest.
#
# What this is NOT:
#   * Not a scoring engine. There is no pass/fail / score /
#     competence outcome.
#   * Not a substitute for professional judgement or legal advice.
#   * Not a write surface for raw clinical content. Answers are a
#     bounded enum and evidence_links are a bounded enum.
#
# Doctrine:
#   * Self-assessment is a dated metadata-only governance artefact.
#     It supports governance review and produces readiness evidence.
#     Human professional review remains required.
#   * Bodies use `ConfigDict(extra="forbid")`. Any attempt to send
#     notes / free_text / reflection / score / pass_fail /
#     competence_grade / compliance_status / staff_certified /
#     clinical_safety_proof / legal_approval / clinic_id / user_id is
#     rejected at the parser.
#   * Submission freezes aggregate counts in jsonb snapshots
#     (readiness_summary, linked_evidence_counts). Snapshots hold
#     aggregate counts only - NOT raw answers, NOT staff identifiers.
#   * Append-only audit. Admin actions (create / answer-upsert /
#     submit / archive) write a single metadata-only row to
#     admin_audit_events. We do NOT use the partial-index
#     conflict-target inference pattern that caused M6.10.1B / TD-BE.
#
# Authorisation:
#   * `require_clinic_user` (router dependency): all endpoints need a
#     valid clinic JWT.
#   * Admin-tier write endpoints require role in
#     `_SELF_ASSESSMENT_ADMIN_ROLES`. Matches the existing
#     {admin, owner, practice_manager} convention shared with
#     governance_policy.py and learn_v1.py.

from __future__ import annotations

import json
import logging
import uuid as _uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db


logger = logging.getLogger(__name__)


# Admin-tier roles permitted to create / answer / submit / archive a
# clinic self-assessment. Mirrors governance_policy._GOVERNANCE_POLICY_ADMIN_ROLES.
_SELF_ASSESSMENT_ADMIN_ROLES = {"admin", "owner", "practice_manager"}

# Bounded enums - kept in Python for `extra="forbid"` Pydantic guards.
# Mirrored in the CHECK constraints created by the 2A-3.1 schema migration.
_ANSWER_VALUES = ("yes", "partial", "planned", "no", "not_applicable")
_EVIDENCE_LINK_VALUES = (
    "policy_library",
    "staff_attestation",
    "learn_cpd",
    "assistant_receipts",
    "trust_posture",
    "manual_review",
)

_STATUS_DRAFT = "draft"
_STATUS_SUBMITTED = "submitted"
_STATUS_SUPERSEDED = "superseded"
_STATUS_ARCHIVED = "archived"
_ALL_STATUSES = {
    _STATUS_DRAFT, _STATUS_SUBMITTED, _STATUS_SUPERSEDED, _STATUS_ARCHIVED,
}


# Column groups used in SELECT statements.
_TEMPLATE_COLS = (
    "template_id, template_slug, template_version, title, summary, "
    "rcvs_principle_mappings, eu_ai_act_article_mappings, is_active, "
    "superseded_by, created_at, updated_at"
)

_QUESTION_COLS = (
    "question_id, template_id, question_slug, question_order, theme, "
    "prompt_text, guidance_reference, evidence_link_hints, "
    "rcvs_principle_mappings, eu_ai_act_article_mappings, created_at"
)

_ASSESSMENT_COLS = (
    "assessment_id, clinic_id, template_id, template_version_snapshot, "
    "clinic_assessment_version, status, created_by_user_id, "
    "submitted_by_user_id, submitted_at, superseded_at, "
    "total_questions_snapshot, answered_questions_snapshot, "
    "readiness_summary_snapshot, linked_evidence_counts_snapshot, "
    "created_at, updated_at"
)

_ANSWER_COLS = (
    "answer_id, clinic_id, assessment_id, question_id, "
    "question_slug_snapshot, theme_snapshot, answer_value, "
    "evidence_links, answered_by_user_id, answered_at, updated_at"
)


_GOVERNANCE_NOTE = (
    "Self-assessment records are metadata-only clinic governance "
    "artefacts. They support governance review and provide readiness "
    "evidence. They do not replace professional judgement "
    "or legal advice. "
    "Human review remains required."
)


# ---------------------------------------------------------------------
# Pydantic response / request models
# ---------------------------------------------------------------------


class SelfAssessmentTemplate(BaseModel):
    template_id: _uuid.UUID
    template_slug: str
    template_version: str
    title: str
    summary: str
    rcvs_principle_mappings: List[str] = Field(default_factory=list)
    eu_ai_act_article_mappings: List[str] = Field(default_factory=list)
    is_active: bool
    superseded_by: Optional[_uuid.UUID] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


class SelfAssessmentQuestion(BaseModel):
    question_id: _uuid.UUID
    template_id: _uuid.UUID
    question_slug: str
    question_order: int
    theme: str
    prompt_text: str
    guidance_reference: Optional[str] = None
    evidence_link_hints: List[str] = Field(default_factory=list)
    rcvs_principle_mappings: List[str] = Field(default_factory=list)
    eu_ai_act_article_mappings: List[str] = Field(default_factory=list)
    created_at: datetime


class SelfAssessmentTemplateListResponse(BaseModel):
    templates: List[SelfAssessmentTemplate]
    governance_note: str = _GOVERNANCE_NOTE


class SelfAssessmentTemplateDetailResponse(BaseModel):
    template: SelfAssessmentTemplate
    questions: List[SelfAssessmentQuestion]
    governance_note: str = _GOVERNANCE_NOTE


class SelfAssessmentQuestionListResponse(BaseModel):
    questions: List[SelfAssessmentQuestion]
    governance_note: str = _GOVERNANCE_NOTE


class SelfAssessmentAnswer(BaseModel):
    answer_id: _uuid.UUID
    assessment_id: _uuid.UUID
    question_id: _uuid.UUID
    question_slug_snapshot: str
    theme_snapshot: str
    answer_value: str
    evidence_links: List[str] = Field(default_factory=list)
    answered_by_user_id: _uuid.UUID
    answered_at: datetime
    updated_at: Optional[datetime] = None


class ClinicSelfAssessment(BaseModel):
    assessment_id: _uuid.UUID
    clinic_id: _uuid.UUID
    template_id: _uuid.UUID
    template_version_snapshot: str
    clinic_assessment_version: int
    status: str
    created_by_user_id: _uuid.UUID
    submitted_by_user_id: Optional[_uuid.UUID] = None
    submitted_at: Optional[datetime] = None
    superseded_at: Optional[datetime] = None
    total_questions_snapshot: Optional[int] = None
    answered_questions_snapshot: Optional[int] = None
    readiness_summary_snapshot: Optional[Dict[str, int]] = None
    linked_evidence_counts_snapshot: Optional[Dict[str, int]] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


class ClinicSelfAssessmentResponse(BaseModel):
    assessment: ClinicSelfAssessment
    governance_note: str = _GOVERNANCE_NOTE


class ClinicSelfAssessmentListResponse(BaseModel):
    assessments: List[ClinicSelfAssessment]
    limit: int
    governance_note: str = _GOVERNANCE_NOTE


class ClinicSelfAssessmentDetailResponse(BaseModel):
    assessment: ClinicSelfAssessment
    answers: List[SelfAssessmentAnswer]
    governance_note: str = _GOVERNANCE_NOTE


class LatestSelfAssessmentEntry(BaseModel):
    template_id: _uuid.UUID
    assessment_id: _uuid.UUID
    clinic_assessment_version: int
    status: str
    template_version_snapshot: str
    submitted_at: Optional[datetime] = None
    superseded_at: Optional[datetime] = None
    total_questions_snapshot: Optional[int] = None
    answered_questions_snapshot: Optional[int] = None
    readiness_summary_snapshot: Optional[Dict[str, int]] = None
    linked_evidence_counts_snapshot: Optional[Dict[str, int]] = None


class LatestSelfAssessmentResponse(BaseModel):
    latest: List[LatestSelfAssessmentEntry]
    governance_note: str = _GOVERNANCE_NOTE


class SelfAssessmentCreateRequest(BaseModel):
    """Bounded create body. `extra='forbid'` rejects any attempt to set
    clinic_id, user_id, score, pass_fail, competence_grade,
    compliance_status, staff_certified, clinical_safety_proof,
    legal_approval, notes, free_text, reflection, etc. The schema
    cannot carry those concepts."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    template_slug: str = Field(..., min_length=1, max_length=200)
    template_version: Optional[str] = Field(default=None, max_length=64)


class SelfAssessmentAnswerUpsertRequest(BaseModel):
    """Bounded answer body. Same `extra='forbid'` doctrine guard."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    answer_value: str = Field(..., min_length=1, max_length=32)
    evidence_links: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------

router = APIRouter(
    prefix="/v1/governance/self-assessment",
    tags=["Governance Self-Assessment"],
    dependencies=[Depends(require_clinic_user)],
)


# ---------------------------------------------------------------------
# Helpers
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
    if role not in _SELF_ASSESSMENT_ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="forbidden_not_admin")


def _validate_answer_value(value: str) -> str:
    if value not in _ANSWER_VALUES:
        raise HTTPException(
            status_code=400, detail="self_assessment_invalid_answer_value"
        )
    return value


def _validate_evidence_links(values: List[str]) -> List[str]:
    cleaned: List[str] = []
    for v in values:
        if v not in _EVIDENCE_LINK_VALUES:
            raise HTTPException(
                status_code=400,
                detail="self_assessment_invalid_evidence_link",
            )
        if v not in cleaned:
            cleaned.append(v)
    return cleaned


def _template_from_row(row: Dict[str, Any]) -> SelfAssessmentTemplate:
    return SelfAssessmentTemplate(
        template_id=row["template_id"],
        template_slug=row["template_slug"],
        template_version=row["template_version"],
        title=row["title"],
        summary=row["summary"],
        rcvs_principle_mappings=list(row.get("rcvs_principle_mappings") or []),
        eu_ai_act_article_mappings=list(
            row.get("eu_ai_act_article_mappings") or []
        ),
        is_active=bool(row["is_active"]),
        superseded_by=row.get("superseded_by"),
        created_at=row["created_at"],
        updated_at=row.get("updated_at"),
    )


def _question_from_row(row: Dict[str, Any]) -> SelfAssessmentQuestion:
    return SelfAssessmentQuestion(
        question_id=row["question_id"],
        template_id=row["template_id"],
        question_slug=row["question_slug"],
        question_order=int(row["question_order"]),
        theme=row["theme"],
        prompt_text=row["prompt_text"],
        guidance_reference=row.get("guidance_reference"),
        evidence_link_hints=list(row.get("evidence_link_hints") or []),
        rcvs_principle_mappings=list(row.get("rcvs_principle_mappings") or []),
        eu_ai_act_article_mappings=list(
            row.get("eu_ai_act_article_mappings") or []
        ),
        created_at=row["created_at"],
    )


def _coerce_jsonb_dict(value: Any) -> Optional[Dict[str, int]]:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return None
    if not isinstance(value, dict):
        return None
    out: Dict[str, int] = {}
    for k, v in value.items():
        try:
            out[str(k)] = int(v)
        except Exception:
            continue
    return out


def _assessment_from_row(row: Dict[str, Any]) -> ClinicSelfAssessment:
    return ClinicSelfAssessment(
        assessment_id=row["assessment_id"],
        clinic_id=row["clinic_id"],
        template_id=row["template_id"],
        template_version_snapshot=row["template_version_snapshot"],
        clinic_assessment_version=int(row["clinic_assessment_version"]),
        status=row["status"],
        created_by_user_id=row["created_by_user_id"],
        submitted_by_user_id=row.get("submitted_by_user_id"),
        submitted_at=row.get("submitted_at"),
        superseded_at=row.get("superseded_at"),
        total_questions_snapshot=(
            int(row["total_questions_snapshot"])
            if row.get("total_questions_snapshot") is not None
            else None
        ),
        answered_questions_snapshot=(
            int(row["answered_questions_snapshot"])
            if row.get("answered_questions_snapshot") is not None
            else None
        ),
        readiness_summary_snapshot=_coerce_jsonb_dict(
            row.get("readiness_summary_snapshot")
        ),
        linked_evidence_counts_snapshot=_coerce_jsonb_dict(
            row.get("linked_evidence_counts_snapshot")
        ),
        created_at=row["created_at"],
        updated_at=row.get("updated_at"),
    )


def _answer_from_row(row: Dict[str, Any]) -> SelfAssessmentAnswer:
    return SelfAssessmentAnswer(
        answer_id=row["answer_id"],
        assessment_id=row["assessment_id"],
        question_id=row["question_id"],
        question_slug_snapshot=row["question_slug_snapshot"],
        theme_snapshot=row["theme_snapshot"],
        answer_value=row["answer_value"],
        evidence_links=list(row.get("evidence_links") or []),
        answered_by_user_id=row["answered_by_user_id"],
        answered_at=row["answered_at"],
        updated_at=row.get("updated_at"),
    )


def _insert_audit_event(
    db: Session,
    *,
    clinic_id: str,
    admin_user_id: str,
    action: str,
    target_id: str,
    ip_hash: Optional[str],
    meta: Dict[str, Any],
) -> None:
    """Append-only metadata-only audit. NO ON CONFLICT against the
    partial admin_audit_events_idem_uq index."""
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
                CAST(:target_id AS uuid),
                :ip_hash,
                CAST(:meta AS jsonb)
            )
            """
        ),
        {
            "clinic_id": clinic_id,
            "admin_user_id": admin_user_id,
            "action": action,
            "target_id": target_id,
            "ip_hash": ip_hash or None,
            "meta": json.dumps(meta),
        },
    )


def _fetch_template_by_slug(
    db: Session, *, slug: str, version: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    params: Dict[str, Any] = {"template_slug": slug}
    where = "WHERE template_slug = :template_slug"
    if version is not None:
        where += " AND template_version = :template_version"
        params["template_version"] = version
    row = db.execute(
        text(
            f"SELECT {_TEMPLATE_COLS} FROM self_assessment_templates "
            f"{where} ORDER BY template_version DESC LIMIT 1"
        ),
        params,
    ).mappings().first()
    return dict(row) if row else None


def _fetch_questions_for_template(
    db: Session, *, template_id: str
) -> List[Dict[str, Any]]:
    rows = db.execute(
        text(
            f"""
            SELECT {_QUESTION_COLS}
            FROM self_assessment_questions
            WHERE template_id = CAST(:template_id AS uuid)
            ORDER BY question_order ASC
            """
        ),
        {"template_id": template_id},
    ).mappings().all()
    return [dict(r) for r in rows]


def _fetch_assessment_for_clinic(
    db: Session, *, clinic_id: str, assessment_id: str
) -> Optional[Dict[str, Any]]:
    row = db.execute(
        text(
            f"""
            SELECT {_ASSESSMENT_COLS}
            FROM clinic_self_assessments
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND assessment_id = CAST(:assessment_id AS uuid)
            LIMIT 1
            """
        ),
        {"clinic_id": clinic_id, "assessment_id": assessment_id},
    ).mappings().first()
    return dict(row) if row else None


def _fetch_answers_for_assessment(
    db: Session, *, clinic_id: str, assessment_id: str
) -> List[Dict[str, Any]]:
    rows = db.execute(
        text(
            f"""
            SELECT {_ANSWER_COLS}
            FROM clinic_self_assessment_answers
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND assessment_id = CAST(:assessment_id AS uuid)
            ORDER BY answered_at ASC
            """
        ),
        {"clinic_id": clinic_id, "assessment_id": assessment_id},
    ).mappings().all()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------
# 1. Templates
# ---------------------------------------------------------------------


@router.get("/templates", response_model=SelfAssessmentTemplateListResponse)
def list_templates(
    request: Request,
    db: Session = Depends(get_db),
) -> SelfAssessmentTemplateListResponse:
    """List ANCHOR-curated active self-assessment templates."""
    _ctx(request)
    rows = db.execute(
        text(
            f"SELECT {_TEMPLATE_COLS} FROM self_assessment_templates "
            "WHERE is_active = true ORDER BY title"
        ),
        {},
    ).mappings().all()
    return SelfAssessmentTemplateListResponse(
        templates=[_template_from_row(dict(r)) for r in rows],
    )


@router.get(
    "/templates/{template_slug}",
    response_model=SelfAssessmentTemplateDetailResponse,
)
def get_template(
    template_slug: str,
    request: Request,
    db: Session = Depends(get_db),
) -> SelfAssessmentTemplateDetailResponse:
    """Get one active template plus its ordered questions."""
    _ctx(request)
    tpl = _fetch_template_by_slug(db, slug=template_slug)
    if not tpl or not bool(tpl["is_active"]):
        raise HTTPException(
            status_code=404, detail="self_assessment_template_not_found"
        )
    qrows = _fetch_questions_for_template(db, template_id=str(tpl["template_id"]))
    return SelfAssessmentTemplateDetailResponse(
        template=_template_from_row(tpl),
        questions=[_question_from_row(r) for r in qrows],
    )


@router.get(
    "/templates/{template_slug}/questions",
    response_model=SelfAssessmentQuestionListResponse,
)
def list_template_questions(
    template_slug: str,
    request: Request,
    db: Session = Depends(get_db),
) -> SelfAssessmentQuestionListResponse:
    _ctx(request)
    tpl = _fetch_template_by_slug(db, slug=template_slug)
    if not tpl or not bool(tpl["is_active"]):
        raise HTTPException(
            status_code=404, detail="self_assessment_template_not_found"
        )
    qrows = _fetch_questions_for_template(db, template_id=str(tpl["template_id"]))
    return SelfAssessmentQuestionListResponse(
        questions=[_question_from_row(r) for r in qrows],
    )


# ---------------------------------------------------------------------
# 2. Create draft assessment
# ---------------------------------------------------------------------


@router.post(
    "/assessments",
    response_model=ClinicSelfAssessmentResponse,
    status_code=201,
)
def create_draft_assessment(
    payload: SelfAssessmentCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> ClinicSelfAssessmentResponse:
    """Create a draft self-assessment for the current clinic.

    If a draft already exists for this (clinic, template), return the
    existing draft (201 with the existing row), mirroring the
    governance_policy.py idempotency convention. Caller-supplied
    clinic_id / user_id are impossible because the body schema forbids
    them; both are always derived from request.state.
    """
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    tpl = _fetch_template_by_slug(
        db, slug=payload.template_slug, version=payload.template_version
    )
    if not tpl:
        raise HTTPException(
            status_code=404, detail="self_assessment_template_not_found"
        )
    if not bool(tpl["is_active"]):
        raise HTTPException(
            status_code=400, detail="self_assessment_template_inactive"
        )

    # Existing draft for this (clinic, template)? Idempotent return.
    existing = db.execute(
        text(
            f"""
            SELECT {_ASSESSMENT_COLS}
            FROM clinic_self_assessments
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND template_id = CAST(:template_id AS uuid)
              AND status = 'draft'
            LIMIT 1
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "template_id": str(tpl["template_id"]),
        },
    ).mappings().first()
    if existing:
        return ClinicSelfAssessmentResponse(
            assessment=_assessment_from_row(dict(existing))
        )

    # Next monotonic clinic_assessment_version.
    max_row = db.execute(
        text(
            """
            SELECT COALESCE(MAX(clinic_assessment_version), 0) AS v
            FROM clinic_self_assessments
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND template_id = CAST(:template_id AS uuid)
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "template_id": str(tpl["template_id"]),
        },
    ).mappings().first()
    next_version = int((max_row or {}).get("v") or 0) + 1

    new_row = db.execute(
        text(
            f"""
            INSERT INTO clinic_self_assessments (
                clinic_id,
                template_id,
                template_version_snapshot,
                clinic_assessment_version,
                status,
                created_by_user_id
            )
            VALUES (
                CAST(:clinic_id AS uuid),
                CAST(:template_id AS uuid),
                :template_version_snapshot,
                :clinic_assessment_version,
                'draft',
                CAST(:created_by_user_id AS uuid)
            )
            RETURNING {_ASSESSMENT_COLS}
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "template_id": str(tpl["template_id"]),
            "template_version_snapshot": str(tpl["template_version"]),
            "clinic_assessment_version": next_version,
            "created_by_user_id": ctx["clinic_user_id"],
        },
    ).mappings().first()
    if not new_row:
        raise HTTPException(status_code=500, detail="internal_server_error")

    new_row_d = dict(new_row)
    _insert_audit_event(
        db,
        clinic_id=ctx["clinic_id"],
        admin_user_id=ctx["clinic_user_id"],
        action="self_assessment_created",
        target_id=str(new_row_d["assessment_id"]),
        ip_hash=ctx["ip_hash"],
        meta={
            "assessment_id": str(new_row_d["assessment_id"]),
            "template_slug": payload.template_slug,
            "template_version": str(tpl["template_version"]),
            "clinic_assessment_version": next_version,
        },
    )
    logger.info(
        "self_assessment_created",
        extra={
            "clinic_id": ctx["clinic_id"],
            "assessment_id": str(new_row_d["assessment_id"]),
            "template_slug": payload.template_slug,
        },
    )
    return ClinicSelfAssessmentResponse(
        assessment=_assessment_from_row(new_row_d)
    )


# ---------------------------------------------------------------------
# 3. List & read assessments (latest declared BEFORE /{id} so the
#    literal "latest" segment isn't captured as a path parameter).
# ---------------------------------------------------------------------


@router.get(
    "/assessments/latest",
    response_model=LatestSelfAssessmentResponse,
)
def latest_self_assessments(
    request: Request,
    db: Session = Depends(get_db),
) -> LatestSelfAssessmentResponse:
    """Latest submitted/superseded assessment per template. Empty
    array if none exists. Reads `v_clinic_latest_self_assessment`."""
    ctx = _ctx(request)
    rows = db.execute(
        text(
            """
            SELECT
                template_id, assessment_id, clinic_assessment_version,
                status, template_version_snapshot,
                submitted_at, superseded_at,
                total_questions_snapshot, answered_questions_snapshot,
                readiness_summary_snapshot, linked_evidence_counts_snapshot
            FROM v_clinic_latest_self_assessment
            WHERE clinic_id = CAST(:clinic_id AS uuid)
            """
        ),
        {"clinic_id": ctx["clinic_id"]},
    ).mappings().all()
    entries: List[LatestSelfAssessmentEntry] = []
    for r in rows:
        rd = dict(r)
        entries.append(
            LatestSelfAssessmentEntry(
                template_id=rd["template_id"],
                assessment_id=rd["assessment_id"],
                clinic_assessment_version=int(rd["clinic_assessment_version"]),
                status=rd["status"],
                template_version_snapshot=rd["template_version_snapshot"],
                submitted_at=rd.get("submitted_at"),
                superseded_at=rd.get("superseded_at"),
                total_questions_snapshot=(
                    int(rd["total_questions_snapshot"])
                    if rd.get("total_questions_snapshot") is not None
                    else None
                ),
                answered_questions_snapshot=(
                    int(rd["answered_questions_snapshot"])
                    if rd.get("answered_questions_snapshot") is not None
                    else None
                ),
                readiness_summary_snapshot=_coerce_jsonb_dict(
                    rd.get("readiness_summary_snapshot")
                ),
                linked_evidence_counts_snapshot=_coerce_jsonb_dict(
                    rd.get("linked_evidence_counts_snapshot")
                ),
            )
        )
    return LatestSelfAssessmentResponse(latest=entries)


@router.get(
    "/assessments",
    response_model=ClinicSelfAssessmentListResponse,
)
def list_assessments(
    request: Request,
    db: Session = Depends(get_db),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=25, ge=1, le=100),
) -> ClinicSelfAssessmentListResponse:
    """List clinic self-assessments. Draft visibility is admin-tier
    only (mirrors the governance_policy convention for not exposing
    draft records to general staff)."""
    ctx = _ctx(request)
    if status is not None and status not in _ALL_STATUSES:
        raise HTTPException(status_code=400, detail="invalid_status")
    if status == _STATUS_DRAFT and ctx["role"] not in _SELF_ASSESSMENT_ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="forbidden_not_admin")

    clauses = ["clinic_id = CAST(:clinic_id AS uuid)"]
    params: Dict[str, Any] = {"clinic_id": ctx["clinic_id"], "limit": int(limit)}
    if status is not None:
        clauses.append("status = :status")
        params["status"] = status
    elif ctx["role"] not in _SELF_ASSESSMENT_ADMIN_ROLES:
        # Non-admin readers do not see draft rows in the unfiltered list.
        clauses.append("status <> 'draft'")

    where_clause = " AND ".join(clauses)
    rows = db.execute(
        text(
            f"""
            SELECT {_ASSESSMENT_COLS}
            FROM clinic_self_assessments
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT :limit
            """
        ),
        params,
    ).mappings().all()
    items = [_assessment_from_row(dict(r)) for r in rows]
    return ClinicSelfAssessmentListResponse(
        assessments=items, limit=int(limit)
    )


@router.get(
    "/assessments/{assessment_id}",
    response_model=ClinicSelfAssessmentDetailResponse,
)
def get_assessment(
    assessment_id: _uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> ClinicSelfAssessmentDetailResponse:
    """Get one clinic-scoped assessment plus its answers. RLS enforces
    clinic scope. Draft rows are admin-tier only."""
    ctx = _ctx(request)
    target = _fetch_assessment_for_clinic(
        db, clinic_id=ctx["clinic_id"], assessment_id=str(assessment_id)
    )
    if not target:
        raise HTTPException(
            status_code=404, detail="self_assessment_not_found"
        )
    if (
        target["status"] == _STATUS_DRAFT
        and ctx["role"] not in _SELF_ASSESSMENT_ADMIN_ROLES
    ):
        # Draft is in-progress admin material; hide with the same 404
        # envelope so existence isn't enumerable by staff.
        raise HTTPException(
            status_code=404, detail="self_assessment_not_found"
        )

    arows = _fetch_answers_for_assessment(
        db, clinic_id=ctx["clinic_id"], assessment_id=str(assessment_id)
    )
    return ClinicSelfAssessmentDetailResponse(
        assessment=_assessment_from_row(target),
        answers=[_answer_from_row(r) for r in arows],
    )


# ---------------------------------------------------------------------
# 4. Upsert answer
# ---------------------------------------------------------------------


@router.put(
    "/assessments/{assessment_id}/answers/{question_slug}",
    response_model=SelfAssessmentAnswer,
)
def upsert_answer(
    assessment_id: _uuid.UUID,
    question_slug: str,
    payload: SelfAssessmentAnswerUpsertRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> SelfAssessmentAnswer:
    """Upsert one answer onto a draft assessment.

    Bounded enum guards:
      * `answer_value` must be in `_ANSWER_VALUES` (also enforced by
        the DB CHECK).
      * `evidence_links` entries must be in `_EVIDENCE_LINK_VALUES`.

    The body shape forbids any of the doctrine-banned concepts (notes,
    free_text, reflection, score, pass_fail, competence_grade,
    compliance_status, staff_certified, clinical_safety_proof,
    legal_approval, clinic_id, user_id) - rejected at the parser via
    `extra='forbid'`.
    """
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    answer_value = _validate_answer_value(payload.answer_value)
    evidence_links = _validate_evidence_links(payload.evidence_links)

    # Load the target assessment (clinic-scoped).
    target = _fetch_assessment_for_clinic(
        db, clinic_id=ctx["clinic_id"], assessment_id=str(assessment_id)
    )
    if not target:
        raise HTTPException(
            status_code=404, detail="self_assessment_not_found"
        )
    if target["status"] != _STATUS_DRAFT:
        raise HTTPException(
            status_code=400, detail="self_assessment_not_in_draft"
        )

    # Resolve question_id from (template_id, question_slug).
    qrow = db.execute(
        text(
            f"""
            SELECT {_QUESTION_COLS}
            FROM self_assessment_questions
            WHERE template_id = CAST(:template_id AS uuid)
              AND question_slug = :question_slug
            LIMIT 1
            """
        ),
        {
            "template_id": str(target["template_id"]),
            "question_slug": question_slug,
        },
    ).mappings().first()
    if not qrow:
        raise HTTPException(
            status_code=404, detail="self_assessment_question_not_found"
        )
    qd = dict(qrow)

    # Try update first; if no row, insert.
    upd_row = db.execute(
        text(
            f"""
            UPDATE clinic_self_assessment_answers
            SET answer_value = :answer_value,
                evidence_links = CAST(:evidence_links AS text[]),
                answered_by_user_id = CAST(:actor AS uuid),
                answered_at = now(),
                updated_at = now()
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND assessment_id = CAST(:assessment_id AS uuid)
              AND question_id = CAST(:question_id AS uuid)
            RETURNING {_ANSWER_COLS}
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "assessment_id": str(assessment_id),
            "question_id": str(qd["question_id"]),
            "answer_value": answer_value,
            "evidence_links": evidence_links,
            "actor": ctx["clinic_user_id"],
        },
    ).mappings().first()

    if upd_row:
        result_row = dict(upd_row)
    else:
        ins_row = db.execute(
            text(
                f"""
                INSERT INTO clinic_self_assessment_answers (
                    clinic_id,
                    assessment_id,
                    question_id,
                    question_slug_snapshot,
                    theme_snapshot,
                    answer_value,
                    evidence_links,
                    answered_by_user_id
                )
                VALUES (
                    CAST(:clinic_id AS uuid),
                    CAST(:assessment_id AS uuid),
                    CAST(:question_id AS uuid),
                    :question_slug_snapshot,
                    :theme_snapshot,
                    :answer_value,
                    CAST(:evidence_links AS text[]),
                    CAST(:actor AS uuid)
                )
                RETURNING {_ANSWER_COLS}
                """
            ),
            {
                "clinic_id": ctx["clinic_id"],
                "assessment_id": str(assessment_id),
                "question_id": str(qd["question_id"]),
                "question_slug_snapshot": str(qd["question_slug"]),
                "theme_snapshot": str(qd["theme"]),
                "answer_value": answer_value,
                "evidence_links": evidence_links,
                "actor": ctx["clinic_user_id"],
            },
        ).mappings().first()
        if not ins_row:
            raise HTTPException(status_code=500, detail="internal_server_error")
        result_row = dict(ins_row)

    _insert_audit_event(
        db,
        clinic_id=ctx["clinic_id"],
        admin_user_id=ctx["clinic_user_id"],
        action="self_assessment_answer_upserted",
        target_id=str(assessment_id),
        ip_hash=ctx["ip_hash"],
        meta={
            "assessment_id": str(assessment_id),
            "question_slug": question_slug,
            "answer_value": answer_value,
            "evidence_links": list(evidence_links),
        },
    )
    return _answer_from_row(result_row)


# ---------------------------------------------------------------------
# 5. Submit
# ---------------------------------------------------------------------


@router.post(
    "/assessments/{assessment_id}/submit",
    response_model=ClinicSelfAssessmentResponse,
)
def submit_assessment(
    assessment_id: _uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> ClinicSelfAssessmentResponse:
    """Submit a draft assessment.

    Rules:
      * Only draft can be submitted.
      * All seeded questions on the template must have an answer.
      * Freezes aggregate snapshots; does NOT copy raw answers.
      * Supersedes any prior submitted row for the same
        (clinic, template).
    """
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    target = _fetch_assessment_for_clinic(
        db, clinic_id=ctx["clinic_id"], assessment_id=str(assessment_id)
    )
    if not target:
        raise HTTPException(
            status_code=404, detail="self_assessment_not_found"
        )
    if target["status"] != _STATUS_DRAFT:
        raise HTTPException(
            status_code=400, detail="self_assessment_not_in_draft"
        )

    # Load all questions for this template and all current answers.
    qrows = _fetch_questions_for_template(
        db, template_id=str(target["template_id"])
    )
    total_questions = len(qrows)
    if total_questions == 0:
        # Defensive: a template with no questions is not submittable.
        raise HTTPException(
            status_code=400, detail="self_assessment_template_has_no_questions"
        )

    arows = _fetch_answers_for_assessment(
        db,
        clinic_id=ctx["clinic_id"],
        assessment_id=str(assessment_id),
    )
    answered_qids = {str(a["question_id"]) for a in arows}
    required_qids = {str(q["question_id"]) for q in qrows}
    missing = required_qids - answered_qids
    if missing:
        raise HTTPException(
            status_code=400, detail="self_assessment_unanswered_questions"
        )

    # Aggregate counts (NOT raw answers).
    readiness_counts: Dict[str, int] = {v: 0 for v in _ANSWER_VALUES}
    evidence_counts: Dict[str, int] = {v: 0 for v in _EVIDENCE_LINK_VALUES}
    answered_questions = 0
    for a in arows:
        if str(a["question_id"]) not in required_qids:
            # Stale answer for a question not in current template - skip.
            continue
        answered_questions += 1
        av = str(a.get("answer_value") or "")
        if av in readiness_counts:
            readiness_counts[av] += 1
        for ev in list(a.get("evidence_links") or []):
            if ev in evidence_counts:
                evidence_counts[ev] += 1

    # Supersede prior submitted row for same (clinic, template).
    db.execute(
        text(
            """
            UPDATE clinic_self_assessments
            SET status = 'superseded',
                superseded_at = now(),
                updated_at = now()
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND template_id = CAST(:template_id AS uuid)
              AND status = 'submitted'
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "template_id": str(target["template_id"]),
        },
    )

    # Promote the draft.
    new_row = db.execute(
        text(
            f"""
            UPDATE clinic_self_assessments
            SET status = 'submitted',
                submitted_by_user_id = CAST(:actor AS uuid),
                submitted_at = now(),
                total_questions_snapshot = :total_questions,
                answered_questions_snapshot = :answered_questions,
                readiness_summary_snapshot = CAST(:readiness AS jsonb),
                linked_evidence_counts_snapshot = CAST(:evidence AS jsonb),
                updated_at = now()
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND assessment_id = CAST(:assessment_id AS uuid)
              AND status = 'draft'
            RETURNING {_ASSESSMENT_COLS}
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "assessment_id": str(assessment_id),
            "actor": ctx["clinic_user_id"],
            "total_questions": total_questions,
            "answered_questions": answered_questions,
            "readiness": json.dumps(readiness_counts),
            "evidence": json.dumps(evidence_counts),
        },
    ).mappings().first()
    if not new_row:
        raise HTTPException(
            status_code=409, detail="self_assessment_state_changed"
        )

    new_row_d = dict(new_row)
    tpl = db.execute(
        text(
            f"SELECT {_TEMPLATE_COLS} FROM self_assessment_templates "
            "WHERE template_id = CAST(:template_id AS uuid) LIMIT 1"
        ),
        {"template_id": str(target["template_id"])},
    ).mappings().first()
    template_slug = str(tpl["template_slug"]) if tpl else ""
    template_version = (
        str(tpl["template_version"]) if tpl else
        str(new_row_d.get("template_version_snapshot") or "")
    )

    _insert_audit_event(
        db,
        clinic_id=ctx["clinic_id"],
        admin_user_id=ctx["clinic_user_id"],
        action="self_assessment_submitted",
        target_id=str(assessment_id),
        ip_hash=ctx["ip_hash"],
        meta={
            "assessment_id": str(assessment_id),
            "template_slug": template_slug,
            "template_version": template_version,
            "readiness_summary_counts": readiness_counts,
            "linked_evidence_counts": evidence_counts,
        },
    )
    logger.info(
        "self_assessment_submitted",
        extra={
            "clinic_id": ctx["clinic_id"],
            "assessment_id": str(assessment_id),
        },
    )
    return ClinicSelfAssessmentResponse(
        assessment=_assessment_from_row(new_row_d)
    )


# ---------------------------------------------------------------------
# 6. Archive
# ---------------------------------------------------------------------


@router.post(
    "/assessments/{assessment_id}/archive",
    response_model=ClinicSelfAssessmentResponse,
)
def archive_assessment(
    assessment_id: _uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> ClinicSelfAssessmentResponse:
    """Archive a draft or superseded assessment. Current submitted
    rows cannot be archived directly - they must be superseded by
    submitting a replacement first. Idempotent on already-archived."""
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    target = _fetch_assessment_for_clinic(
        db, clinic_id=ctx["clinic_id"], assessment_id=str(assessment_id)
    )
    if not target:
        raise HTTPException(
            status_code=404, detail="self_assessment_not_found"
        )
    if target["status"] == _STATUS_SUBMITTED:
        raise HTTPException(
            status_code=400,
            detail="self_assessment_submitted_archive_not_allowed",
        )
    if target["status"] == _STATUS_ARCHIVED:
        return ClinicSelfAssessmentResponse(
            assessment=_assessment_from_row(target)
        )

    new_row = db.execute(
        text(
            f"""
            UPDATE clinic_self_assessments
            SET status = 'archived',
                updated_at = now()
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND assessment_id = CAST(:assessment_id AS uuid)
              AND status IN ('draft','superseded')
            RETURNING {_ASSESSMENT_COLS}
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "assessment_id": str(assessment_id),
        },
    ).mappings().first()
    if not new_row:
        raise HTTPException(
            status_code=409, detail="self_assessment_state_changed"
        )

    new_row_d = dict(new_row)
    _insert_audit_event(
        db,
        clinic_id=ctx["clinic_id"],
        admin_user_id=ctx["clinic_user_id"],
        action="self_assessment_archived",
        target_id=str(assessment_id),
        ip_hash=ctx["ip_hash"],
        meta={
            "assessment_id": str(assessment_id),
            "previous_status": str(target["status"]),
            "status": _STATUS_ARCHIVED,
        },
    )
    logger.info(
        "self_assessment_archived",
        extra={
            "clinic_id": ctx["clinic_id"],
            "assessment_id": str(assessment_id),
            "previous_status": str(target["status"]),
        },
    )
    return ClinicSelfAssessmentResponse(
        assessment=_assessment_from_row(new_row_d)
    )
