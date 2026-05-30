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

_ATTESTATION_COLS = (
    "attestation_id, clinic_id, clinic_policy_version_id, user_id, "
    "attestation_statement_version, acknowledged_at, "
    "acknowledgement_method, policy_content_sha256_snapshot, "
    "is_voided, void_reason, voided_at, voided_by_user_id, created_at"
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
# Phase 2A-2.3 - Staff Attestation models
# ---------------------------------------------------------------------

DEFAULT_ATTESTATION_STATEMENT_VERSION = "attestation_statement_v1"
DEFAULT_ACKNOWLEDGEMENT_METHOD = "in_app_button_click"


class PolicyAttestation(BaseModel):
    """Metadata-only view of a policy_attestations row.

    Carries no policy body text and no free-text staff reflection. The
    optional `template_slug` / `policy_title_snapshot` /
    `policy_clinic_policy_version` fields are populated by the admin
    listing endpoint via a JOIN; the self-listing and attest endpoints
    leave them null (the caller already knows which policy they acted
    on).
    """

    attestation_id: _uuid.UUID
    clinic_policy_version_id: _uuid.UUID
    user_id: _uuid.UUID
    attestation_statement_version: str
    acknowledged_at: datetime
    acknowledgement_method: str
    policy_content_sha256_snapshot: Optional[str] = None
    is_voided: bool
    void_reason: Optional[str] = None
    voided_at: Optional[datetime] = None
    voided_by_user_id: Optional[_uuid.UUID] = None
    created_at: datetime

    # Optional joined policy metadata (admin listing only).
    template_slug: Optional[str] = None
    policy_title_snapshot: Optional[str] = None
    policy_clinic_policy_version: Optional[int] = None


class PolicyAttestationResponse(BaseModel):
    attestation: PolicyAttestation
    governance_note: str = _GOVERNANCE_NOTE


class PolicyAttestationListResponse(BaseModel):
    attestations: List[PolicyAttestation]
    limit: int
    governance_note: str = _GOVERNANCE_NOTE


class OutstandingPolicyListResponse(BaseModel):
    policies: List[ClinicPolicyVersion]
    count: int
    governance_note: str = _GOVERNANCE_NOTE


class PolicyAttestationCreateRequest(BaseModel):
    """Bounded attest body. `extra='forbid'` rejects any attempt to
    send `policy_body`, `policy_text`, `competence_grade`, `score`,
    `pass_fail`, `staff_reflection`, `compliance_status`,
    `staff_certified`, `clinical_safety_proof`, `legal_approval`, etc.
    The attestation surface CANNOT carry those concepts.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    attestation_statement_version: Optional[str] = Field(
        default=None, max_length=64
    )
    acknowledgement_method: Optional[str] = Field(default=None, max_length=64)


class PolicyAttestationVoidRequest(BaseModel):
    """Bounded void body. Requires a non-empty `void_reason`. Other
    fields are rejected at the parser level."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    void_reason: str = Field(..., min_length=1, max_length=1000)


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


# ---------------------------------------------------------------------
# Phase 2A-2.3 - Staff Attestation endpoints
# ---------------------------------------------------------------------
#
# Doctrine recap for this section:
#   * Self-attestation is per-user evidence. It is NOT an admin action,
#     so the attest endpoint does NOT write admin_audit_events. Only
#     the admin-side void writes an audit event.
#   * Attestation is separate from Learn / CPD. Attesting to a policy
#     does NOT mark a Learn module complete and does NOT accrue CPD
#     minutes. Neither path is imported or invoked here.
#   * The DB unique constraint `(clinic_id, clinic_policy_version_id,
#     user_id)` (defined in 20260530_01) means re-attestation after a
#     void requires a fresh `clinic_policy_version`. We do NOT migrate
#     the schema in this slice; attesting against a previously-voided
#     row returns 409 attestation_previously_voided so admin can issue
#     a new clinic policy version to require re-acknowledgement.
#   * `GET /me/outstanding` defines "outstanding" as "active policies
#     for which this user has NO row in policy_attestations" - voided
#     or not. That keeps the user out of a 409 deadlock and makes
#     admin-initiated re-attestation an explicit ops step (issue a new
#     clinic policy version).


def _attestation_from_row(row: Dict[str, Any]) -> PolicyAttestation:
    return PolicyAttestation(
        attestation_id=row["attestation_id"],
        clinic_policy_version_id=row["clinic_policy_version_id"],
        user_id=row["user_id"],
        attestation_statement_version=row["attestation_statement_version"],
        acknowledged_at=row["acknowledged_at"],
        acknowledgement_method=row["acknowledgement_method"],
        policy_content_sha256_snapshot=row.get("policy_content_sha256_snapshot"),
        is_voided=bool(row["is_voided"]),
        void_reason=row.get("void_reason"),
        voided_at=row.get("voided_at"),
        voided_by_user_id=row.get("voided_by_user_id"),
        created_at=row["created_at"],
        template_slug=row.get("template_slug"),
        policy_title_snapshot=row.get("policy_title_snapshot"),
        policy_clinic_policy_version=(
            int(row["policy_clinic_policy_version"])
            if row.get("policy_clinic_policy_version") is not None
            else None
        ),
    )


def _select_attestation_for_clinic(
    db: Session, *, clinic_id: str, attestation_id: str
) -> Optional[Dict[str, Any]]:
    row = db.execute(
        text(
            f"""
            SELECT {_ATTESTATION_COLS}
            FROM policy_attestations
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND attestation_id = CAST(:attestation_id AS uuid)
            LIMIT 1
            """
        ),
        {"clinic_id": clinic_id, "attestation_id": attestation_id},
    ).mappings().first()
    return dict(row) if row else None


# A. GET /me/outstanding ----------------------------------------------


@router.get(
    "/me/outstanding",
    response_model=OutstandingPolicyListResponse,
)
def list_outstanding_policies_for_me(
    request: Request,
    db: Session = Depends(get_db),
) -> OutstandingPolicyListResponse:
    """Active clinic policy versions the caller has NOT yet attested
    to. "Not yet attested" means no policy_attestations row exists at
    all - a previously-voided row counts as "user already had a turn"
    (see module doctrine note)."""
    ctx = _ctx(request)
    rows = db.execute(
        text(
            f"""
            SELECT {_CPV_COLS}
            FROM clinic_policy_versions cpv
            WHERE cpv.clinic_id = CAST(:clinic_id AS uuid)
              AND cpv.status = 'active'
              AND NOT EXISTS (
                  SELECT 1
                  FROM policy_attestations pa
                  WHERE pa.clinic_id = cpv.clinic_id
                    AND pa.clinic_policy_version_id = cpv.clinic_policy_version_id
                    AND pa.user_id = CAST(:user_id AS uuid)
              )
            ORDER BY cpv.activated_at DESC
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "user_id": ctx["clinic_user_id"],
        },
    ).mappings().all()
    items = [_cpv_from_row(dict(r)) for r in rows]
    return OutstandingPolicyListResponse(policies=items, count=len(items))


# B. POST /clinic-policies/{cpv_id}/attest ----------------------------


@router.post(
    "/clinic-policies/{cpv_id}/attest",
    response_model=PolicyAttestationResponse,
    status_code=201,
)
def attest_to_clinic_policy(
    cpv_id: _uuid.UUID,
    payload: PolicyAttestationCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> PolicyAttestationResponse:
    """Self-attestation by the authenticated user. Idempotent if the
    user has already attested (non-voided). Returns 409 if a prior
    attestation exists but is voided (see module doctrine)."""
    ctx = _ctx(request)

    # Fetch the target clinic policy version (clinic-scoped).
    target = _fetch_cpv_for_clinic(
        db, clinic_id=ctx["clinic_id"], cpv_id=str(cpv_id)
    )
    if not target:
        raise HTTPException(
            status_code=404, detail="governance_policy_version_not_found"
        )
    if target["status"] != _STATUS_ACTIVE:
        raise HTTPException(
            status_code=400, detail="governance_policy_not_active"
        )

    # Idempotency: look up existing row for (clinic, cpv, user).
    existing = db.execute(
        text(
            f"""
            SELECT {_ATTESTATION_COLS}
            FROM policy_attestations
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND clinic_policy_version_id = CAST(:cpv_id AS uuid)
              AND user_id = CAST(:user_id AS uuid)
            LIMIT 1
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "cpv_id": str(cpv_id),
            "user_id": ctx["clinic_user_id"],
        },
    ).mappings().first()
    if existing:
        existing_d = dict(existing)
        if existing_d.get("is_voided"):
            raise HTTPException(
                status_code=409, detail="attestation_previously_voided"
            )
        # Non-voided row present: idempotent 201 with existing.
        return PolicyAttestationResponse(
            attestation=_attestation_from_row(existing_d),
        )

    statement_version = (
        payload.attestation_statement_version
        or DEFAULT_ATTESTATION_STATEMENT_VERSION
    )
    method = payload.acknowledgement_method or DEFAULT_ACKNOWLEDGEMENT_METHOD

    new_row = db.execute(
        text(
            f"""
            INSERT INTO policy_attestations (
                clinic_id,
                clinic_policy_version_id,
                user_id,
                attestation_statement_version,
                acknowledgement_method,
                policy_content_sha256_snapshot,
                ip_hash
            )
            VALUES (
                CAST(:clinic_id AS uuid),
                CAST(:cpv_id AS uuid),
                CAST(:user_id AS uuid),
                :attestation_statement_version,
                :acknowledgement_method,
                :policy_content_sha256_snapshot,
                :ip_hash
            )
            RETURNING {_ATTESTATION_COLS}
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "cpv_id": str(cpv_id),
            "user_id": ctx["clinic_user_id"],
            "attestation_statement_version": statement_version,
            "acknowledgement_method": method,
            "policy_content_sha256_snapshot": target.get(
                "content_sha256_snapshot"
            ),
            "ip_hash": ctx["ip_hash"] or None,
        },
    ).mappings().first()
    if not new_row:
        raise HTTPException(status_code=500, detail="internal_server_error")

    new_row_d = dict(new_row)
    logger.info(
        "governance_policy_attested",
        extra={
            "clinic_id": ctx["clinic_id"],
            "clinic_policy_version_id": str(cpv_id),
            "attestation_id": str(new_row_d["attestation_id"]),
        },
    )
    return PolicyAttestationResponse(
        attestation=_attestation_from_row(new_row_d),
    )


# C. GET /me/attestations ---------------------------------------------


@router.get(
    "/me/attestations",
    response_model=PolicyAttestationListResponse,
)
def list_my_attestations(
    request: Request,
    db: Session = Depends(get_db),
    include_voided: bool = Query(default=False),
    limit: int = Query(default=25, ge=1, le=100),
) -> PolicyAttestationListResponse:
    """Caller's own policy attestations. Self-only - the user_id bind
    is taken from request.state.clinic_user_id, never from a query
    parameter."""
    ctx = _ctx(request)
    clauses = [
        "clinic_id = CAST(:clinic_id AS uuid)",
        "user_id = CAST(:user_id AS uuid)",
    ]
    params: Dict[str, Any] = {
        "clinic_id": ctx["clinic_id"],
        "user_id": ctx["clinic_user_id"],
        "limit": int(limit),
    }
    if not include_voided:
        clauses.append("is_voided = false")

    rows = db.execute(
        text(
            f"""
            SELECT {_ATTESTATION_COLS}
            FROM policy_attestations
            WHERE {' AND '.join(clauses)}
            ORDER BY acknowledged_at DESC
            LIMIT :limit
            """
        ),
        params,
    ).mappings().all()
    return PolicyAttestationListResponse(
        attestations=[_attestation_from_row(dict(r)) for r in rows],
        limit=int(limit),
    )


# D. GET /attestations (admin) ----------------------------------------


@router.get(
    "/attestations",
    response_model=PolicyAttestationListResponse,
)
def list_clinic_attestations(
    request: Request,
    db: Session = Depends(get_db),
    clinic_policy_version_id: Optional[_uuid.UUID] = Query(default=None),
    template_slug: Optional[str] = Query(default=None, max_length=200),
    user_id: Optional[_uuid.UUID] = Query(default=None),
    include_voided: bool = Query(default=False),
    limit: int = Query(default=25, ge=1, le=100),
) -> PolicyAttestationListResponse:
    """Admin-tier clinic-wide attestation listing. Metadata only - the
    response carries `user_id` UUIDs but no email/name; resolving them
    is a frontend concern."""
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    clauses = ["pa.clinic_id = CAST(:clinic_id AS uuid)"]
    params: Dict[str, Any] = {
        "clinic_id": ctx["clinic_id"],
        "limit": int(limit),
    }
    if clinic_policy_version_id is not None:
        clauses.append("pa.clinic_policy_version_id = CAST(:cpv_id AS uuid)")
        params["cpv_id"] = str(clinic_policy_version_id)
    if template_slug is not None:
        clauses.append("pt.template_slug = :template_slug")
        params["template_slug"] = template_slug
    if user_id is not None:
        clauses.append("pa.user_id = CAST(:user_id AS uuid)")
        params["user_id"] = str(user_id)
    if not include_voided:
        clauses.append("pa.is_voided = false")

    where_clause = " AND ".join(clauses)
    rows = db.execute(
        text(
            f"""
            SELECT
                pa.attestation_id, pa.clinic_id,
                pa.clinic_policy_version_id, pa.user_id,
                pa.attestation_statement_version, pa.acknowledged_at,
                pa.acknowledgement_method,
                pa.policy_content_sha256_snapshot,
                pa.is_voided, pa.void_reason, pa.voided_at,
                pa.voided_by_user_id, pa.created_at,
                pt.template_slug AS template_slug,
                cpv.title_snapshot AS policy_title_snapshot,
                cpv.clinic_policy_version AS policy_clinic_policy_version
            FROM policy_attestations pa
            JOIN clinic_policy_versions cpv
                ON cpv.clinic_policy_version_id = pa.clinic_policy_version_id
               AND cpv.clinic_id = pa.clinic_id
            LEFT JOIN policy_templates pt
                ON pt.template_id = cpv.policy_template_id
            WHERE {where_clause}
            ORDER BY pa.acknowledged_at DESC
            LIMIT :limit
            """
        ),
        params,
    ).mappings().all()

    return PolicyAttestationListResponse(
        attestations=[_attestation_from_row(dict(r)) for r in rows],
        limit=int(limit),
    )


# E. POST /attestations/{attestation_id}/void --------------------------


@router.post(
    "/attestations/{attestation_id}/void",
    response_model=PolicyAttestationResponse,
)
def void_attestation(
    attestation_id: _uuid.UUID,
    payload: PolicyAttestationVoidRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> PolicyAttestationResponse:
    """Admin-tier void with reason. Append-only audit row written.
    Idempotent for an already-voided attestation (no duplicate audit
    event)."""
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    reason = (payload.void_reason or "").strip()
    if not reason:
        raise HTTPException(
            status_code=400, detail="attestation_void_reason_required"
        )

    target = _select_attestation_for_clinic(
        db,
        clinic_id=ctx["clinic_id"],
        attestation_id=str(attestation_id),
    )
    if not target:
        raise HTTPException(
            status_code=404, detail="attestation_not_found"
        )

    if bool(target.get("is_voided")):
        # Idempotent no-op: do NOT write a duplicate audit event.
        return PolicyAttestationResponse(
            attestation=_attestation_from_row(target),
        )

    new_row = db.execute(
        text(
            f"""
            UPDATE policy_attestations
            SET is_voided = true,
                void_reason = :void_reason,
                voided_at = now(),
                voided_by_user_id = CAST(:actor AS uuid)
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND attestation_id = CAST(:attestation_id AS uuid)
              AND is_voided = false
            RETURNING {_ATTESTATION_COLS}
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "attestation_id": str(attestation_id),
            "void_reason": reason,
            "actor": ctx["clinic_user_id"],
        },
    ).mappings().first()
    if not new_row:
        # Concurrent state change between read and write.
        raise HTTPException(
            status_code=409, detail="attestation_state_changed"
        )

    new_row_d = dict(new_row)
    _insert_audit_event(
        db,
        clinic_id=ctx["clinic_id"],
        admin_user_id=ctx["clinic_user_id"],
        action="governance_policy_attestation_voided",
        target_id=str(new_row_d["attestation_id"]),
        ip_hash=ctx["ip_hash"],
        meta={
            "attestation_id": str(new_row_d["attestation_id"]),
            "clinic_policy_version_id": str(
                new_row_d["clinic_policy_version_id"]
            ),
            "user_id": str(new_row_d["user_id"]),
            "void_reason_present": True,
        },
    )
    logger.info(
        "governance_policy_attestation_voided",
        extra={
            "clinic_id": ctx["clinic_id"],
            "attestation_id": str(new_row_d["attestation_id"]),
        },
    )
    return PolicyAttestationResponse(
        attestation=_attestation_from_row(new_row_d),
    )
