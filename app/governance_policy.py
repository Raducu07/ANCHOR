# app/governance_policy.py
#
# Phase 2A-2.2 - Governance Policy Library endpoints.
#
# Scope:
#   * List/get global policy_templates (ANCHOR-curated catalogue).
#   * Adopt a template into a clinic as a versioned clinic_policy_versions
#     row (draft -> active -> superseded/archived).
#   * List clinic policies / list active clinic policies.
#   * Activate / archive clinic policy versions.
#
# What this is NOT:
#   * Not the Assistant runtime policy. See app/portal_assistant.py for
#     `/v1/assistant/policy*`. Runtime configuration and organisational
#     AI-use policy are deliberately separate surfaces.
#   * Not Staff Attestation. Attestation endpoints are 2A-2.3.
#   * Not a Trust delta. Trust integration is 2A-2.4.
#
# Doctrine:
#   * Metadata only. Policy body text is NEVER stored in the DB and is
#     NEVER returned by these endpoints. The template `content_reference`
#     points at a markdown file shipped under docs/governance/policies/.
#   * Append-only audit. Admin actions (create / activate / archive) write
#     a single metadata-only row to admin_audit_events. We do NOT use the
#     partial-index conflict-target inference pattern that caused the
#     M6.10.1B / TD-BE production 500 - audit inserts here are pure
#     append-only with no ON CONFLICT clause.
#   * `role_applicability` on templates is AUDIENCE METADATA, not an
#     access-control role.
#   * Activation is governance evidence. It is not legal approval,
#     regulatory compliance, certification, or a staff-competence
#     guarantee.
#
# Authorisation:
#   * `require_clinic_user` (router dependency): all endpoints need a
#     valid clinic JWT.
#   * Admin-tier endpoints additionally require role in
#     `_GOVERNANCE_POLICY_ADMIN_ROLES`. Matches the existing
#     {admin, owner, practice_manager} convention.

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


# Roles permitted to manage clinic policy versions. Mirrors
# portal_assistant._POLICY_ADMIN_ROLES and learn_v1.LEARN_ADMIN_ROLES.
_GOVERNANCE_POLICY_ADMIN_ROLES = {"admin", "owner", "practice_manager"}

# Allowed status values, mirrored in the CHECK constraint on
# clinic_policy_versions.status.
_STATUS_DRAFT = "draft"
_STATUS_ACTIVE = "active"
_STATUS_SUPERSEDED = "superseded"
_STATUS_ARCHIVED = "archived"
_ALL_STATUSES = {
    _STATUS_DRAFT, _STATUS_ACTIVE, _STATUS_SUPERSEDED, _STATUS_ARCHIVED,
}


_TEMPLATE_COLS = (
    "template_id, template_slug, template_version, title, summary, "
    "category, role_applicability, jurisdiction_tags, source_basis, "
    "content_reference, content_sha256, is_active, superseded_by, "
    "created_at, updated_at"
)

_CPV_COLS = (
    "clinic_policy_version_id, clinic_id, policy_template_id, "
    "template_version_snapshot, clinic_policy_version, status, "
    "title_snapshot, summary_snapshot, content_sha256_snapshot, "
    "effective_from, created_by_user_id, activated_by_user_id, "
    "activated_at, superseded_at, created_at, updated_at"
)


# ---------------------------------------------------------------------
# Pydantic response / request models
# ---------------------------------------------------------------------

_GOVERNANCE_NOTE = (
    "Governance policy artefacts are metadata-only. Activating a clinic "
    "policy version is governance evidence, not legal approval, "
    "regulatory certification, or a staff-competence guarantee. "
    "Human review remains required."
)


class PolicyTemplate(BaseModel):
    """Metadata-only view of a global policy_templates row."""

    template_id: _uuid.UUID
    template_slug: str
    template_version: str
    title: str
    summary: str
    category: str
    role_applicability: List[str] = Field(default_factory=list)
    jurisdiction_tags: List[str] = Field(default_factory=list)
    source_basis: List[str] = Field(default_factory=list)
    content_reference: str
    content_sha256: Optional[str] = None
    is_active: bool
    superseded_by: Optional[_uuid.UUID] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


class PolicyTemplateListResponse(BaseModel):
    templates: List[PolicyTemplate]
    governance_note: str = _GOVERNANCE_NOTE


class ClinicPolicyVersion(BaseModel):
    """Metadata-only view of a clinic_policy_versions row.

    Carries no policy body text. The snapshotted title/summary/hash
    survive template churn upstream.
    """

    clinic_policy_version_id: _uuid.UUID
    clinic_id: _uuid.UUID
    policy_template_id: _uuid.UUID
    template_version_snapshot: str
    clinic_policy_version: int
    status: str
    title_snapshot: str
    summary_snapshot: str
    content_sha256_snapshot: Optional[str] = None
    effective_from: Optional[datetime] = None
    created_by_user_id: _uuid.UUID
    activated_by_user_id: Optional[_uuid.UUID] = None
    activated_at: Optional[datetime] = None
    superseded_at: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


class ClinicPolicyVersionResponse(BaseModel):
    policy: ClinicPolicyVersion
    governance_note: str = _GOVERNANCE_NOTE


class ClinicPolicyVersionListResponse(BaseModel):
    policies: List[ClinicPolicyVersion]
    limit: int
    governance_note: str = _GOVERNANCE_NOTE


class ClinicPolicyCreateRequest(BaseModel):
    """Bounded create body. `extra='forbid'` rejects any attempt to set
    fields not in this allow-list - including `policy_body`, `policy_text`,
    `compliance_status`, `competence_grade`, `score`, `pass_fail`,
    `staff_certified`, `clinical_safety_proof`, `legal_approval`, etc.
    Doctrine guard is the parser; there is no runtime list of forbidden
    names because the schema CANNOT carry them."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    template_slug: str = Field(..., min_length=1, max_length=200)
    template_version: Optional[str] = Field(default=None, max_length=64)


# ---------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------

router = APIRouter(
    prefix="/v1/governance/policy",
    tags=["Governance Policy"],
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
    if role not in _GOVERNANCE_POLICY_ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="forbidden_not_admin")


def _template_from_row(row: Dict[str, Any]) -> PolicyTemplate:
    return PolicyTemplate(
        template_id=row["template_id"],
        template_slug=row["template_slug"],
        template_version=row["template_version"],
        title=row["title"],
        summary=row["summary"],
        category=row["category"],
        role_applicability=list(row.get("role_applicability") or []),
        jurisdiction_tags=list(row.get("jurisdiction_tags") or []),
        source_basis=list(row.get("source_basis") or []),
        content_reference=row["content_reference"],
        content_sha256=row.get("content_sha256"),
        is_active=bool(row["is_active"]),
        superseded_by=row.get("superseded_by"),
        created_at=row["created_at"],
        updated_at=row.get("updated_at"),
    )


def _cpv_from_row(row: Dict[str, Any]) -> ClinicPolicyVersion:
    return ClinicPolicyVersion(
        clinic_policy_version_id=row["clinic_policy_version_id"],
        clinic_id=row["clinic_id"],
        policy_template_id=row["policy_template_id"],
        template_version_snapshot=row["template_version_snapshot"],
        clinic_policy_version=int(row["clinic_policy_version"]),
        status=row["status"],
        title_snapshot=row["title_snapshot"],
        summary_snapshot=row["summary_snapshot"],
        content_sha256_snapshot=row.get("content_sha256_snapshot"),
        effective_from=row.get("effective_from"),
        created_by_user_id=row["created_by_user_id"],
        activated_by_user_id=row.get("activated_by_user_id"),
        activated_at=row.get("activated_at"),
        superseded_at=row.get("superseded_at"),
        created_at=row["created_at"],
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
    partial admin_audit_events_idem_uq index - the natural keys here
    (clinic_policy_version_id + action) are monotonic and cannot
    legitimately collide within a single transaction.
    """
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


# ---------------------------------------------------------------------
# 1 / 2. Templates
# ---------------------------------------------------------------------


@router.get("/templates", response_model=PolicyTemplateListResponse)
def list_policy_templates(
    request: Request,
    db: Session = Depends(get_db),
    include_inactive: bool = Query(default=False),
    category: Optional[str] = Query(default=None, max_length=64),
) -> PolicyTemplateListResponse:
    """List ANCHOR-curated global policy templates (metadata only)."""
    ctx = _ctx(request)
    if include_inactive:
        # Inactive templates are admin-only - they're catalogue history,
        # not a current adoption choice.
        _require_admin(ctx["role"])

    clauses: List[str] = []
    params: Dict[str, Any] = {}
    if not include_inactive:
        clauses.append("is_active = true")
    if category:
        clauses.append("category = :category")
        params["category"] = category

    where_clause = ""
    if clauses:
        where_clause = "WHERE " + " AND ".join(clauses)

    rows = db.execute(
        text(
            f"SELECT {_TEMPLATE_COLS} FROM policy_templates "
            f"{where_clause} ORDER BY title"
        ),
        params,
    ).mappings().all()

    return PolicyTemplateListResponse(
        templates=[_template_from_row(dict(r)) for r in rows],
    )


@router.get("/templates/{template_slug}", response_model=PolicyTemplate)
def get_policy_template(
    template_slug: str,
    request: Request,
    db: Session = Depends(get_db),
) -> PolicyTemplate:
    """Get one template by slug. Active templates are visible to all
    authenticated clinic users. Inactive templates exist (history) but
    return 404 to non-admin callers - same envelope as `not found` so
    no signal about catalogue contents leaks to staff."""
    ctx = _ctx(request)
    row = db.execute(
        text(
            f"SELECT {_TEMPLATE_COLS} FROM policy_templates "
            "WHERE template_slug = :template_slug LIMIT 1"
        ),
        {"template_slug": template_slug},
    ).mappings().first()
    if not row:
        raise HTTPException(
            status_code=404, detail="governance_policy_template_not_found"
        )
    if not bool(row["is_active"]) and ctx["role"] not in _GOVERNANCE_POLICY_ADMIN_ROLES:
        # Hide inactive templates from staff with the same 404 a missing
        # slug returns. Admins can still fetch them via this endpoint.
        raise HTTPException(
            status_code=404, detail="governance_policy_template_not_found"
        )
    return _template_from_row(dict(row))


# ---------------------------------------------------------------------
# 3. Create clinic policy from template
# ---------------------------------------------------------------------


@router.post(
    "/clinic-policies",
    response_model=ClinicPolicyVersionResponse,
    status_code=201,
)
def create_clinic_policy(
    payload: ClinicPolicyCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> ClinicPolicyVersionResponse:
    """Adopt a global template into the clinic as a NEW draft clinic
    policy version. Does NOT activate."""
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    # Find the template.
    params: Dict[str, Any] = {"template_slug": payload.template_slug}
    where = "WHERE template_slug = :template_slug"
    if payload.template_version is not None:
        where += " AND template_version = :template_version"
        params["template_version"] = payload.template_version
    template_row = db.execute(
        text(
            f"SELECT {_TEMPLATE_COLS} FROM policy_templates {where} LIMIT 1"
        ),
        params,
    ).mappings().first()
    if not template_row:
        raise HTTPException(
            status_code=404, detail="governance_policy_template_not_found"
        )
    if not bool(template_row["is_active"]):
        raise HTTPException(
            status_code=400, detail="governance_policy_template_inactive"
        )

    # Next monotonic version for this (clinic_id, policy_template_id).
    max_row = db.execute(
        text(
            """
            SELECT COALESCE(MAX(clinic_policy_version), 0) AS v
            FROM clinic_policy_versions
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND policy_template_id = CAST(:policy_template_id AS uuid)
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "policy_template_id": str(template_row["template_id"]),
        },
    ).mappings().first()
    next_version = int((max_row or {}).get("v") or 0) + 1

    insert_params = {
        "clinic_id": ctx["clinic_id"],
        "policy_template_id": str(template_row["template_id"]),
        "template_version_snapshot": str(template_row["template_version"]),
        "clinic_policy_version": next_version,
        "title_snapshot": str(template_row["title"]),
        "summary_snapshot": str(template_row["summary"]),
        "content_sha256_snapshot": template_row.get("content_sha256"),
        "created_by_user_id": ctx["clinic_user_id"],
    }

    new_row = db.execute(
        text(
            f"""
            INSERT INTO clinic_policy_versions (
                clinic_id,
                policy_template_id,
                template_version_snapshot,
                clinic_policy_version,
                status,
                title_snapshot,
                summary_snapshot,
                content_sha256_snapshot,
                created_by_user_id
            )
            VALUES (
                CAST(:clinic_id AS uuid),
                CAST(:policy_template_id AS uuid),
                :template_version_snapshot,
                :clinic_policy_version,
                'draft',
                :title_snapshot,
                :summary_snapshot,
                :content_sha256_snapshot,
                CAST(:created_by_user_id AS uuid)
            )
            RETURNING {_CPV_COLS}
            """
        ),
        insert_params,
    ).mappings().first()
    if not new_row:
        # Defensive - INSERT ... RETURNING should always emit a row.
        raise HTTPException(status_code=500, detail="internal_server_error")

    new_row_d = dict(new_row)
    _insert_audit_event(
        db,
        clinic_id=ctx["clinic_id"],
        admin_user_id=ctx["clinic_user_id"],
        action="governance_policy_created",
        target_id=str(new_row_d["clinic_policy_version_id"]),
        ip_hash=ctx["ip_hash"],
        meta={
            "template_slug": payload.template_slug,
            "template_version_snapshot": str(template_row["template_version"]),
            "clinic_policy_version": next_version,
            "status": _STATUS_DRAFT,
        },
    )
    logger.info(
        "governance_policy_created",
        extra={
            "clinic_id": ctx["clinic_id"],
            "clinic_policy_version_id": str(new_row_d["clinic_policy_version_id"]),
            "template_slug": payload.template_slug,
            "clinic_policy_version": next_version,
        },
    )
    return ClinicPolicyVersionResponse(policy=_cpv_from_row(new_row_d))


# ---------------------------------------------------------------------
# 5. Active clinic policies (declared BEFORE /{cpv_id}/... so the
#    literal "active" segment isn't captured as a path parameter).
# ---------------------------------------------------------------------


@router.get(
    "/clinic-policies/active",
    response_model=ClinicPolicyVersionListResponse,
)
def list_active_clinic_policies(
    request: Request,
    db: Session = Depends(get_db),
) -> ClinicPolicyVersionListResponse:
    """List the currently-active clinic policy versions for the clinic
    (one row per template). Visible to all authenticated clinic users."""
    ctx = _ctx(request)
    rows = db.execute(
        text(
            f"""
            SELECT {_CPV_COLS}
            FROM clinic_policy_versions
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND status = 'active'
            ORDER BY activated_at DESC
            """
        ),
        {"clinic_id": ctx["clinic_id"]},
    ).mappings().all()
    items = [_cpv_from_row(dict(r)) for r in rows]
    return ClinicPolicyVersionListResponse(policies=items, limit=len(items))


# ---------------------------------------------------------------------
# 4. List clinic policies (with filters)
# ---------------------------------------------------------------------


@router.get(
    "/clinic-policies",
    response_model=ClinicPolicyVersionListResponse,
)
def list_clinic_policies(
    request: Request,
    db: Session = Depends(get_db),
    limit: int = Query(default=25, ge=1, le=100),
    status: Optional[str] = Query(default=None),
    template_slug: Optional[str] = Query(default=None, max_length=200),
) -> ClinicPolicyVersionListResponse:
    """List clinic policy versions for the clinic. Metadata only."""
    ctx = _ctx(request)
    if status is not None and status not in _ALL_STATUSES:
        raise HTTPException(status_code=400, detail="invalid_status")

    clauses = ["cpv.clinic_id = CAST(:clinic_id AS uuid)"]
    params: Dict[str, Any] = {"clinic_id": ctx["clinic_id"], "limit": int(limit)}
    if status is not None:
        clauses.append("cpv.status = :status")
        params["status"] = status
    if template_slug is not None:
        clauses.append("pt.template_slug = :template_slug")
        params["template_slug"] = template_slug

    where_clause = " AND ".join(clauses)
    rows = db.execute(
        text(
            f"""
            SELECT
                cpv.clinic_policy_version_id, cpv.clinic_id,
                cpv.policy_template_id, cpv.template_version_snapshot,
                cpv.clinic_policy_version, cpv.status,
                cpv.title_snapshot, cpv.summary_snapshot,
                cpv.content_sha256_snapshot, cpv.effective_from,
                cpv.created_by_user_id, cpv.activated_by_user_id,
                cpv.activated_at, cpv.superseded_at,
                cpv.created_at, cpv.updated_at
            FROM clinic_policy_versions cpv
            LEFT JOIN policy_templates pt
                ON pt.template_id = cpv.policy_template_id
            WHERE {where_clause}
            ORDER BY cpv.created_at DESC
            LIMIT :limit
            """
        ),
        params,
    ).mappings().all()

    items = [_cpv_from_row(dict(r)) for r in rows]
    return ClinicPolicyVersionListResponse(policies=items, limit=int(limit))


# ---------------------------------------------------------------------
# 6. Activate clinic policy version
# ---------------------------------------------------------------------


def _fetch_cpv_for_clinic(
    db: Session, *, clinic_id: str, cpv_id: str
) -> Optional[Dict[str, Any]]:
    row = db.execute(
        text(
            f"""
            SELECT {_CPV_COLS}
            FROM clinic_policy_versions
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND clinic_policy_version_id = CAST(:cpv_id AS uuid)
            LIMIT 1
            """
        ),
        {"clinic_id": clinic_id, "cpv_id": cpv_id},
    ).mappings().first()
    return dict(row) if row else None


@router.post(
    "/clinic-policies/{cpv_id}/activate",
    response_model=ClinicPolicyVersionResponse,
)
def activate_clinic_policy(
    cpv_id: _uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> ClinicPolicyVersionResponse:
    """Activate a draft clinic policy version. Supersedes any existing
    active row for the same (clinic, template). Idempotent for a row
    already in `active` status."""
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    target = _fetch_cpv_for_clinic(
        db, clinic_id=ctx["clinic_id"], cpv_id=str(cpv_id)
    )
    if not target:
        raise HTTPException(
            status_code=404, detail="governance_policy_version_not_found"
        )

    if target["status"] == _STATUS_ACTIVE:
        # Idempotent no-op.
        return ClinicPolicyVersionResponse(policy=_cpv_from_row(target))

    if target["status"] != _STATUS_DRAFT:
        # Superseded / archived rows cannot be brought back to life in v1.
        raise HTTPException(
            status_code=400, detail="governance_policy_not_in_draft"
        )

    # Supersede any currently-active row for the same template within
    # this clinic. Same statement-level transaction as the upcoming
    # INSERT/UPDATE so the partial unique index cannot reject the
    # transition.
    db.execute(
        text(
            """
            UPDATE clinic_policy_versions
            SET status = 'superseded',
                superseded_at = now(),
                updated_at = now()
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND policy_template_id = CAST(:policy_template_id AS uuid)
              AND status = 'active'
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "policy_template_id": str(target["policy_template_id"]),
        },
    )

    new_row = db.execute(
        text(
            f"""
            UPDATE clinic_policy_versions
            SET status = 'active',
                activated_by_user_id = CAST(:actor AS uuid),
                activated_at = now(),
                effective_from = COALESCE(effective_from, now()),
                updated_at = now()
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND clinic_policy_version_id = CAST(:cpv_id AS uuid)
              AND status = 'draft'
            RETURNING {_CPV_COLS}
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "cpv_id": str(cpv_id),
            "actor": ctx["clinic_user_id"],
        },
    ).mappings().first()
    if not new_row:
        # Defensive: target was draft on the read above, so this only
        # fires under a concurrent state change. Treat as conflict.
        raise HTTPException(
            status_code=409, detail="governance_policy_state_changed"
        )

    new_row_d = dict(new_row)
    _insert_audit_event(
        db,
        clinic_id=ctx["clinic_id"],
        admin_user_id=ctx["clinic_user_id"],
        action="governance_policy_activated",
        target_id=str(new_row_d["clinic_policy_version_id"]),
        ip_hash=ctx["ip_hash"],
        meta={
            "policy_template_id": str(new_row_d["policy_template_id"]),
            "clinic_policy_version": int(new_row_d["clinic_policy_version"]),
            "template_version_snapshot": str(
                new_row_d["template_version_snapshot"]
            ),
            "status": _STATUS_ACTIVE,
            "previous_status": _STATUS_DRAFT,
        },
    )
    logger.info(
        "governance_policy_activated",
        extra={
            "clinic_id": ctx["clinic_id"],
            "clinic_policy_version_id": str(new_row_d["clinic_policy_version_id"]),
            "clinic_policy_version": int(new_row_d["clinic_policy_version"]),
        },
    )
    return ClinicPolicyVersionResponse(policy=_cpv_from_row(new_row_d))


# ---------------------------------------------------------------------
# 7. Archive clinic policy version
# ---------------------------------------------------------------------


@router.post(
    "/clinic-policies/{cpv_id}/archive",
    response_model=ClinicPolicyVersionResponse,
)
def archive_clinic_policy(
    cpv_id: _uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> ClinicPolicyVersionResponse:
    """Archive a draft or superseded clinic policy version. Active rows
    cannot be archived directly - they must be superseded by activating
    a replacement first. Idempotent for rows already archived."""
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    target = _fetch_cpv_for_clinic(
        db, clinic_id=ctx["clinic_id"], cpv_id=str(cpv_id)
    )
    if not target:
        raise HTTPException(
            status_code=404, detail="governance_policy_version_not_found"
        )

    if target["status"] == _STATUS_ACTIVE:
        raise HTTPException(
            status_code=400,
            detail="governance_policy_active_archive_not_allowed",
        )

    if target["status"] == _STATUS_ARCHIVED:
        # Idempotent no-op.
        return ClinicPolicyVersionResponse(policy=_cpv_from_row(target))

    new_row = db.execute(
        text(
            f"""
            UPDATE clinic_policy_versions
            SET status = 'archived',
                updated_at = now()
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND clinic_policy_version_id = CAST(:cpv_id AS uuid)
              AND status IN ('draft','superseded')
            RETURNING {_CPV_COLS}
            """
        ),
        {"clinic_id": ctx["clinic_id"], "cpv_id": str(cpv_id)},
    ).mappings().first()
    if not new_row:
        raise HTTPException(
            status_code=409, detail="governance_policy_state_changed"
        )

    new_row_d = dict(new_row)
    _insert_audit_event(
        db,
        clinic_id=ctx["clinic_id"],
        admin_user_id=ctx["clinic_user_id"],
        action="governance_policy_archived",
        target_id=str(new_row_d["clinic_policy_version_id"]),
        ip_hash=ctx["ip_hash"],
        meta={
            "policy_template_id": str(new_row_d["policy_template_id"]),
            "clinic_policy_version": int(new_row_d["clinic_policy_version"]),
            "previous_status": str(target["status"]),
            "status": _STATUS_ARCHIVED,
        },
    )
    logger.info(
        "governance_policy_archived",
        extra={
            "clinic_id": ctx["clinic_id"],
            "clinic_policy_version_id": str(new_row_d["clinic_policy_version_id"]),
            "previous_status": str(target["status"]),
        },
    )
    return ClinicPolicyVersionResponse(policy=_cpv_from_row(new_row_d))
