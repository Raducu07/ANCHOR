# app/client_transparency.py
#
# Phase 2A-4.2 - Client-Facing Transparency Layer endpoints.
#
# Scope of this slice:
#   * List / get global client_transparency_templates (ANCHOR-curated).
#   * Adopt a template into a clinic as a versioned draft profile
#     (status: draft / active / superseded / archived).
#   * List clinic profiles + active profile lookup.
#   * Edit draft, activate, archive.
#
# Out of scope (deferred to 2A-4.3):
#   * Publish / public-version endpoints.
#   * Trust posture / Trust Pack integration.
#
# Doctrine:
#   * Metadata-only. Template body text lives in markdown shipped
#     under docs/governance/client_transparency/<slug>-<version>.md.
#     These endpoints expose only the `content_reference` path.
#   * Clinic-authored free text on profiles is bounded by the schema's
#     length CHECKs (120 / 1500) AND by a conservative server-side
#     blocklist heuristic (see `_check_text_safety`). Errors do not
#     disclose which pattern matched.
#   * Permitted / prohibited category arrays must be non-empty subsets
#     of the template's canonical defaults (text[] in the catalogue).
#   * The three "*_statement_enabled" booleans are accepted in
#     requests but LOCKED TRUE at the handler layer in v1 - mirrors
#     `require_human_review` on the Assistant runtime policy. The
#     column exists so future doctrine can relax it; v1 cannot.
#   * v1 founder rule: ONE active client transparency profile per
#     clinic (NOT one per template). Activation supersedes any
#     existing active row for the clinic, regardless of template.
#   * Append-only audit. NO ON CONFLICT against the partial
#     admin_audit_events_idem_uq index (M6.10.1B / TD-BE).
#   * No staff names/emails in responses or audit meta.
#   * No publish endpoints in this slice.

from __future__ import annotations

import json
import logging
import re
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


# Roles permitted to manage client transparency profiles. Mirrors
# governance_policy._GOVERNANCE_POLICY_ADMIN_ROLES.
_CLIENT_TRANSPARENCY_ADMIN_ROLES = {"admin", "owner", "practice_manager"}


_STATUS_DRAFT = "draft"
_STATUS_ACTIVE = "active"
_STATUS_SUPERSEDED = "superseded"
_STATUS_ARCHIVED = "archived"
_ALL_STATUSES = {
    _STATUS_DRAFT, _STATUS_ACTIVE, _STATUS_SUPERSEDED, _STATUS_ARCHIVED,
}


_TEMPLATE_COLS = (
    "template_id, template_slug, template_version, title, summary, "
    "default_sections, default_permitted_categories, "
    "default_prohibited_categories, rcvs_principle_mappings, "
    "eu_ai_act_article_mappings, content_reference, content_sha256, "
    "is_active, superseded_by, created_at, updated_at"
)

_PROFILE_COLS = (
    "clinic_profile_id, clinic_id, client_transparency_template_id, "
    "template_version_snapshot, clinic_profile_version, status, "
    "display_title, plain_language_summary, "
    "permitted_use_categories, prohibited_use_categories, "
    "human_review_statement_enabled, privacy_statement_enabled, "
    "client_explanation_statement_enabled, content_sha256_snapshot, "
    "created_by_user_id, activated_by_user_id, activated_at, "
    "superseded_at, effective_from, created_at, updated_at"
)


# ---------------------------------------------------------------------
# Governance note
# ---------------------------------------------------------------------

_GOVERNANCE_NOTE = (
    "Client transparency profiles are metadata-only governance artefacts. "
    "They support plain-language client communication about bounded, "
    "human-reviewed AI use. They are not legal advice, a consent form, "
    "a clinical record, or a compliance certificate. Human professional "
    "review remains required."
)


# ---------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------


class ClientTransparencyTemplate(BaseModel):
    template_id: _uuid.UUID
    template_slug: str
    template_version: str
    title: str
    summary: str
    default_sections: Dict[str, Any]
    default_permitted_categories: List[str] = Field(default_factory=list)
    default_prohibited_categories: List[str] = Field(default_factory=list)
    rcvs_principle_mappings: List[str] = Field(default_factory=list)
    eu_ai_act_article_mappings: List[str] = Field(default_factory=list)
    content_reference: str
    content_sha256: Optional[str] = None
    is_active: bool
    superseded_by: Optional[_uuid.UUID] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


class ClientTransparencyTemplateListResponse(BaseModel):
    templates: List[ClientTransparencyTemplate]
    governance_note: str = _GOVERNANCE_NOTE


class ClientTransparencyTemplateResponse(BaseModel):
    template: ClientTransparencyTemplate
    governance_note: str = _GOVERNANCE_NOTE


class ClientTransparencyProfile(BaseModel):
    clinic_profile_id: _uuid.UUID
    clinic_id: _uuid.UUID
    client_transparency_template_id: _uuid.UUID
    template_version_snapshot: str
    clinic_profile_version: int
    status: str

    display_title: str
    plain_language_summary: str
    permitted_use_categories: List[str] = Field(default_factory=list)
    prohibited_use_categories: List[str] = Field(default_factory=list)

    # Locked-true in v1. Surfaced in the response so frontend can show
    # them as "always on" indicators.
    human_review_statement_enabled: bool
    privacy_statement_enabled: bool
    client_explanation_statement_enabled: bool

    content_sha256_snapshot: Optional[str] = None
    effective_from: Optional[datetime] = None
    created_by_user_id: _uuid.UUID
    activated_by_user_id: Optional[_uuid.UUID] = None
    activated_at: Optional[datetime] = None
    superseded_at: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


class ClientTransparencyProfileResponse(BaseModel):
    profile: ClientTransparencyProfile
    governance_note: str = _GOVERNANCE_NOTE


class ClientTransparencyProfileListResponse(BaseModel):
    profiles: List[ClientTransparencyProfile]
    limit: int
    governance_note: str = _GOVERNANCE_NOTE


class ClientTransparencyProfileCreateRequest(BaseModel):
    """Bounded create body. `extra='forbid'` rejects any attempt to
    set fields not in this allow-list - including `policy_body`,
    `policy_text`, `consent_text`, `legal_consent`, `compliance_status`,
    `clinical_safety_proof`, `staff_certified`, etc. The transparency
    schema CANNOT carry those concepts."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    template_slug: str = Field(..., min_length=1, max_length=200)
    template_version: Optional[str] = Field(default=None, max_length=64)

    display_title: str = Field(..., min_length=1, max_length=120)
    plain_language_summary: str = Field(..., min_length=1, max_length=1500)

    permitted_use_categories: List[str] = Field(..., min_length=1, max_length=20)
    prohibited_use_categories: List[str] = Field(..., min_length=1, max_length=20)

    # Locked-true at the handler layer in v1. Accepted in the body for
    # forward-compat; the handler ignores submitted values and inserts
    # `true` for all three (the schema column defaults are also true).
    human_review_statement_enabled: Optional[bool] = None
    privacy_statement_enabled: Optional[bool] = None
    client_explanation_statement_enabled: Optional[bool] = None


class ClientTransparencyProfileUpdateRequest(BaseModel):
    """Bounded PUT body for draft edits. All fields optional, but at
    least one must be present. `extra='forbid'`."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    display_title: Optional[str] = Field(default=None, min_length=1, max_length=120)
    plain_language_summary: Optional[str] = Field(
        default=None, min_length=1, max_length=1500
    )
    permitted_use_categories: Optional[List[str]] = Field(
        default=None, min_length=1, max_length=20
    )
    prohibited_use_categories: Optional[List[str]] = Field(
        default=None, min_length=1, max_length=20
    )

    # Locked-true; accepted but ignored.
    human_review_statement_enabled: Optional[bool] = None
    privacy_statement_enabled: Optional[bool] = None
    client_explanation_statement_enabled: Optional[bool] = None


# ---------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------

router = APIRouter(
    prefix="/v1/governance/client-transparency",
    tags=["Governance Client Transparency"],
    dependencies=[Depends(require_clinic_user)],
)


# ---------------------------------------------------------------------
# Context / role helpers
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
    if role not in _CLIENT_TRANSPARENCY_ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="forbidden_not_admin")


# ---------------------------------------------------------------------
# Text safety heuristic
# ---------------------------------------------------------------------
#
# The two clinic-authored free-text fields (`display_title`,
# `plain_language_summary`) are PUBLIC DISCLOSURE TEXT. They are NOT
# clinical content, NOT case material, NOT client/patient identifiers.
# This helper rejects obvious identifier-shaped or prompt/output-shaped
# tokens that would suggest the clinic is trying to embed case or
# identifier content. Heuristic, not perfect: it raises the bar but is
# not a substitute for the doctrine that this surface is for public
# disclosure copy.
#
# The error body returns a stable code and a generic message. It does
# NOT echo which rule matched (so the surface is not probeable as a
# leak-detector for the clinic's blocklist).

_BLOCKLIST_PATTERNS: List[re.Pattern] = [
    # Email-shaped tokens.
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", re.IGNORECASE),
    # Long digit runs >=10 consecutive digits (NHS / microchip / phone shape).
    re.compile(r"\d{10,}"),
    # Phone-shaped: 4+ groups of 2-4 digits joined by spaces / dashes /
    # parens (e.g. +44 7700 900 123). Counts 8+ digits total in pattern.
    re.compile(r"(?:[+(]?\d{2,4}[)\s-]+){3,}\d{2,}"),
    # Bare URLs (http/https/www).
    re.compile(r"\bhttps?://\S+", re.IGNORECASE),
    re.compile(r"\bwww\.\S+", re.IGNORECASE),
    # Prompt / chat-template markers.
    re.compile(r"<\|im_(?:start|end)\|>", re.IGNORECASE),
    re.compile(r"\{\{[^}]{0,80}\}\}"),  # mustache-style template injection
    re.compile(r"<system>|</system>", re.IGNORECASE),
    re.compile(r"```", re.IGNORECASE),
    # ISO 15-digit pet microchip (ISO 11784): exactly 15 digits, possibly
    # already caught by "\d{10,}" - keep explicit for clarity.
    re.compile(r"\b\d{15}\b"),
    # MRCVS / RCVS membership number shape: "MRCVS 12345" / "RCVS 12345"
    re.compile(r"\bM?RCVS\s*\d{3,}\b", re.IGNORECASE),
]


def _check_text_safety(*, display_title: Optional[str],
                       plain_language_summary: Optional[str]) -> None:
    """Reject obvious identifier-shaped or prompt-injection-shaped
    tokens in the two clinic-authored free-text fields. Raises
    HTTPException(400, 'client_transparency_text_blocked') without
    disclosing which rule matched."""
    for value in (display_title, plain_language_summary):
        if value is None:
            continue
        for pat in _BLOCKLIST_PATTERNS:
            if pat.search(value):
                raise HTTPException(
                    status_code=400,
                    detail="client_transparency_text_blocked",
                )


# ---------------------------------------------------------------------
# Row -> model helpers
# ---------------------------------------------------------------------


def _template_from_row(row: Dict[str, Any]) -> ClientTransparencyTemplate:
    default_sections = row.get("default_sections")
    if isinstance(default_sections, str):
        try:
            default_sections = json.loads(default_sections)
        except Exception:
            default_sections = {}
    if not isinstance(default_sections, dict):
        default_sections = {}
    return ClientTransparencyTemplate(
        template_id=row["template_id"],
        template_slug=row["template_slug"],
        template_version=row["template_version"],
        title=row["title"],
        summary=row["summary"],
        default_sections=default_sections,
        default_permitted_categories=list(
            row.get("default_permitted_categories") or []
        ),
        default_prohibited_categories=list(
            row.get("default_prohibited_categories") or []
        ),
        rcvs_principle_mappings=list(row.get("rcvs_principle_mappings") or []),
        eu_ai_act_article_mappings=list(
            row.get("eu_ai_act_article_mappings") or []
        ),
        content_reference=row["content_reference"],
        content_sha256=row.get("content_sha256"),
        is_active=bool(row["is_active"]),
        superseded_by=row.get("superseded_by"),
        created_at=row["created_at"],
        updated_at=row.get("updated_at"),
    )


def _profile_from_row(row: Dict[str, Any]) -> ClientTransparencyProfile:
    return ClientTransparencyProfile(
        clinic_profile_id=row["clinic_profile_id"],
        clinic_id=row["clinic_id"],
        client_transparency_template_id=row["client_transparency_template_id"],
        template_version_snapshot=row["template_version_snapshot"],
        clinic_profile_version=int(row["clinic_profile_version"]),
        status=row["status"],
        display_title=row["display_title"],
        plain_language_summary=row["plain_language_summary"],
        permitted_use_categories=list(row.get("permitted_use_categories") or []),
        prohibited_use_categories=list(row.get("prohibited_use_categories") or []),
        human_review_statement_enabled=bool(
            row.get("human_review_statement_enabled", True)
        ),
        privacy_statement_enabled=bool(
            row.get("privacy_statement_enabled", True)
        ),
        client_explanation_statement_enabled=bool(
            row.get("client_explanation_statement_enabled", True)
        ),
        content_sha256_snapshot=row.get("content_sha256_snapshot"),
        effective_from=row.get("effective_from"),
        created_by_user_id=row["created_by_user_id"],
        activated_by_user_id=row.get("activated_by_user_id"),
        activated_at=row.get("activated_at"),
        superseded_at=row.get("superseded_at"),
        created_at=row["created_at"],
        updated_at=row.get("updated_at"),
    )


def _select_template_by_slug(
    db: Session, *, template_slug: str, template_version: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    params: Dict[str, Any] = {"template_slug": template_slug}
    clauses = ["template_slug = :template_slug"]
    if template_version is not None:
        clauses.append("template_version = :template_version")
        params["template_version"] = template_version
    row = db.execute(
        text(
            f"SELECT {_TEMPLATE_COLS} FROM client_transparency_templates "
            f"WHERE {' AND '.join(clauses)} LIMIT 1"
        ),
        params,
    ).mappings().first()
    return dict(row) if row else None


def _select_profile_for_clinic(
    db: Session, *, clinic_id: str, clinic_profile_id: str,
) -> Optional[Dict[str, Any]]:
    row = db.execute(
        text(
            f"""
            SELECT {_PROFILE_COLS}
            FROM clinic_client_transparency_profiles
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND clinic_profile_id = CAST(:clinic_profile_id AS uuid)
            LIMIT 1
            """
        ),
        {"clinic_id": clinic_id, "clinic_profile_id": clinic_profile_id},
    ).mappings().first()
    return dict(row) if row else None


def _validate_category_subsets(
    *,
    submitted_permitted: List[str],
    submitted_prohibited: List[str],
    template_default_permitted: List[str],
    template_default_prohibited: List[str],
) -> None:
    permitted_set = set(template_default_permitted)
    prohibited_set = set(template_default_prohibited)
    for c in submitted_permitted:
        if c not in permitted_set:
            raise HTTPException(
                status_code=400, detail="client_transparency_invalid_category"
            )
    for c in submitted_prohibited:
        if c not in prohibited_set:
            raise HTTPException(
                status_code=400, detail="client_transparency_invalid_category"
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
    partial admin_audit_events_idem_uq index - same posture as
    governance_policy._insert_audit_event."""
    db.execute(
        text(
            """
            INSERT INTO admin_audit_events (
                clinic_id, admin_user_id, action, target_id, ip_hash, meta
            ) VALUES (
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


@router.get(
    "/templates", response_model=ClientTransparencyTemplateListResponse
)
def list_templates(
    request: Request,
    db: Session = Depends(get_db),
    include_inactive: bool = Query(default=False),
) -> ClientTransparencyTemplateListResponse:
    """List ANCHOR-curated global client transparency templates."""
    ctx = _ctx(request)
    if include_inactive:
        _require_admin(ctx["role"])

    where = "" if include_inactive else "WHERE is_active = true"
    rows = db.execute(
        text(
            f"SELECT {_TEMPLATE_COLS} FROM client_transparency_templates "
            f"{where} ORDER BY title"
        ),
    ).mappings().all()
    return ClientTransparencyTemplateListResponse(
        templates=[_template_from_row(dict(r)) for r in rows],
    )


@router.get(
    "/templates/{template_slug}",
    response_model=ClientTransparencyTemplateResponse,
)
def get_template(
    template_slug: str,
    request: Request,
    db: Session = Depends(get_db),
) -> ClientTransparencyTemplateResponse:
    """Get one template by slug. Inactive templates are hidden from
    non-admin callers with the same 404 a missing slug returns."""
    ctx = _ctx(request)
    row = _select_template_by_slug(db, template_slug=template_slug)
    if not row:
        raise HTTPException(
            status_code=404,
            detail="client_transparency_template_not_found",
        )
    if not bool(row["is_active"]) and ctx["role"] not in _CLIENT_TRANSPARENCY_ADMIN_ROLES:
        raise HTTPException(
            status_code=404,
            detail="client_transparency_template_not_found",
        )
    return ClientTransparencyTemplateResponse(
        template=_template_from_row(row),
    )


# ---------------------------------------------------------------------
# 3. Create clinic profile (draft) from template
# ---------------------------------------------------------------------


@router.post(
    "/profiles",
    response_model=ClientTransparencyProfileResponse,
    status_code=201,
)
def create_profile(
    payload: ClientTransparencyProfileCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> ClientTransparencyProfileResponse:
    """Create a NEW draft client transparency profile from a template.
    Does NOT activate."""
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    # 1. Find the template.
    template_row = _select_template_by_slug(
        db,
        template_slug=payload.template_slug,
        template_version=payload.template_version,
    )
    if not template_row:
        raise HTTPException(
            status_code=404,
            detail="client_transparency_template_not_found",
        )
    if not bool(template_row["is_active"]):
        raise HTTPException(
            status_code=400,
            detail="client_transparency_template_inactive",
        )

    # 2. Validate categories.
    _validate_category_subsets(
        submitted_permitted=payload.permitted_use_categories,
        submitted_prohibited=payload.prohibited_use_categories,
        template_default_permitted=list(
            template_row.get("default_permitted_categories") or []
        ),
        template_default_prohibited=list(
            template_row.get("default_prohibited_categories") or []
        ),
    )

    # 3. Text-safety blocklist on clinic-authored fields.
    _check_text_safety(
        display_title=payload.display_title,
        plain_language_summary=payload.plain_language_summary,
    )

    # 4. Next monotonic version for this (clinic, template).
    max_row = db.execute(
        text(
            """
            SELECT COALESCE(MAX(clinic_profile_version), 0) AS v
            FROM clinic_client_transparency_profiles
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND client_transparency_template_id = CAST(:template_id AS uuid)
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "template_id": str(template_row["template_id"]),
        },
    ).mappings().first()
    next_version = int((max_row or {}).get("v") or 0) + 1

    # 5. INSERT. Statement booleans are stored as TRUE regardless of
    #    submitted value (locked-true in v1).
    new_row = db.execute(
        text(
            f"""
            INSERT INTO clinic_client_transparency_profiles (
                clinic_id,
                client_transparency_template_id,
                template_version_snapshot,
                clinic_profile_version,
                status,
                display_title,
                plain_language_summary,
                permitted_use_categories,
                prohibited_use_categories,
                human_review_statement_enabled,
                privacy_statement_enabled,
                client_explanation_statement_enabled,
                content_sha256_snapshot,
                created_by_user_id
            )
            VALUES (
                CAST(:clinic_id AS uuid),
                CAST(:template_id AS uuid),
                :template_version_snapshot,
                :clinic_profile_version,
                'draft',
                :display_title,
                :plain_language_summary,
                CAST(:permitted_use_categories AS text[]),
                CAST(:prohibited_use_categories AS text[]),
                true,
                true,
                true,
                :content_sha256_snapshot,
                CAST(:created_by_user_id AS uuid)
            )
            RETURNING {_PROFILE_COLS}
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "template_id": str(template_row["template_id"]),
            "template_version_snapshot": str(template_row["template_version"]),
            "clinic_profile_version": next_version,
            "display_title": payload.display_title,
            "plain_language_summary": payload.plain_language_summary,
            "permitted_use_categories": payload.permitted_use_categories,
            "prohibited_use_categories": payload.prohibited_use_categories,
            "content_sha256_snapshot": template_row.get("content_sha256"),
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
        action="governance_client_transparency_profile_created",
        target_id=str(new_row_d["clinic_profile_id"]),
        ip_hash=ctx["ip_hash"],
        meta={
            "template_slug": str(template_row["template_slug"]),
            "template_version_snapshot": str(template_row["template_version"]),
            "clinic_profile_version": next_version,
            "status": _STATUS_DRAFT,
            "permitted_category_count": len(payload.permitted_use_categories),
            "prohibited_category_count": len(payload.prohibited_use_categories),
        },
    )
    logger.info(
        "governance_client_transparency_profile_created",
        extra={
            "clinic_id": ctx["clinic_id"],
            "clinic_profile_id": str(new_row_d["clinic_profile_id"]),
            "template_slug": payload.template_slug,
        },
    )
    return ClientTransparencyProfileResponse(
        profile=_profile_from_row(new_row_d),
    )


# ---------------------------------------------------------------------
# 5. /profiles/active (declared BEFORE /profiles/{clinic_profile_id})
# ---------------------------------------------------------------------


@router.get(
    "/profiles/active",
    response_model=ClientTransparencyProfileResponse,
)
def get_active_profile(
    request: Request,
    db: Session = Depends(get_db),
) -> ClientTransparencyProfileResponse:
    """Return the clinic's single active client transparency profile."""
    ctx = _ctx(request)
    row = db.execute(
        text(
            f"""
            SELECT {_PROFILE_COLS}
            FROM clinic_client_transparency_profiles
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND status = 'active'
            LIMIT 1
            """
        ),
        {"clinic_id": ctx["clinic_id"]},
    ).mappings().first()
    if not row:
        raise HTTPException(
            status_code=404,
            detail="client_transparency_profile_not_found",
        )
    return ClientTransparencyProfileResponse(
        profile=_profile_from_row(dict(row)),
    )


# ---------------------------------------------------------------------
# 4. List clinic profiles
# ---------------------------------------------------------------------


@router.get(
    "/profiles",
    response_model=ClientTransparencyProfileListResponse,
)
def list_profiles(
    request: Request,
    db: Session = Depends(get_db),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=25, ge=1, le=100),
) -> ClientTransparencyProfileListResponse:
    ctx = _ctx(request)
    if status is not None and status not in _ALL_STATUSES:
        raise HTTPException(status_code=400, detail="invalid_status")

    clauses = ["clinic_id = CAST(:clinic_id AS uuid)"]
    params: Dict[str, Any] = {"clinic_id": ctx["clinic_id"], "limit": int(limit)}
    if status is not None:
        clauses.append("status = :status")
        params["status"] = status

    where_clause = " AND ".join(clauses)
    rows = db.execute(
        text(
            f"""
            SELECT {_PROFILE_COLS}
            FROM clinic_client_transparency_profiles
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT :limit
            """
        ),
        params,
    ).mappings().all()
    return ClientTransparencyProfileListResponse(
        profiles=[_profile_from_row(dict(r)) for r in rows],
        limit=int(limit),
    )


# ---------------------------------------------------------------------
# 6. Get clinic profile by id
# ---------------------------------------------------------------------


@router.get(
    "/profiles/{clinic_profile_id}",
    response_model=ClientTransparencyProfileResponse,
)
def get_profile(
    clinic_profile_id: _uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> ClientTransparencyProfileResponse:
    ctx = _ctx(request)
    row = _select_profile_for_clinic(
        db,
        clinic_id=ctx["clinic_id"],
        clinic_profile_id=str(clinic_profile_id),
    )
    if not row:
        raise HTTPException(
            status_code=404,
            detail="client_transparency_profile_not_found",
        )
    return ClientTransparencyProfileResponse(
        profile=_profile_from_row(row),
    )


# ---------------------------------------------------------------------
# 7. PUT update draft profile
# ---------------------------------------------------------------------


@router.put(
    "/profiles/{clinic_profile_id}",
    response_model=ClientTransparencyProfileResponse,
)
def update_profile(
    clinic_profile_id: _uuid.UUID,
    payload: ClientTransparencyProfileUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> ClientTransparencyProfileResponse:
    """Edit a draft profile. Non-draft rows are rejected."""
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    target = _select_profile_for_clinic(
        db,
        clinic_id=ctx["clinic_id"],
        clinic_profile_id=str(clinic_profile_id),
    )
    if not target:
        raise HTTPException(
            status_code=404,
            detail="client_transparency_profile_not_found",
        )
    if target["status"] != _STATUS_DRAFT:
        raise HTTPException(
            status_code=409,
            detail="client_transparency_profile_not_draft",
        )

    patch = payload.model_dump(exclude_unset=True)
    # The locked-true booleans are accepted but never written.
    for locked in (
        "human_review_statement_enabled",
        "privacy_statement_enabled",
        "client_explanation_statement_enabled",
    ):
        patch.pop(locked, None)

    # Require at least one editable field.
    editable_keys = {
        "display_title",
        "plain_language_summary",
        "permitted_use_categories",
        "prohibited_use_categories",
    }
    if not (set(patch.keys()) & editable_keys):
        raise HTTPException(
            status_code=400,
            detail="client_transparency_update_empty",
        )

    # Category validation against the snapshotted template defaults.
    if (
        "permitted_use_categories" in patch
        or "prohibited_use_categories" in patch
    ):
        template_row = db.execute(
            text(
                "SELECT default_permitted_categories, "
                "default_prohibited_categories "
                "FROM client_transparency_templates "
                "WHERE template_id = CAST(:template_id AS uuid) LIMIT 1"
            ),
            {"template_id": str(target["client_transparency_template_id"])},
        ).mappings().first()
        if not template_row:
            # Defensive: FK should prevent this.
            raise HTTPException(
                status_code=500, detail="internal_server_error"
            )
        _validate_category_subsets(
            submitted_permitted=patch.get(
                "permitted_use_categories", list(target.get("permitted_use_categories") or []),
            ),
            submitted_prohibited=patch.get(
                "prohibited_use_categories", list(target.get("prohibited_use_categories") or []),
            ),
            template_default_permitted=list(
                template_row.get("default_permitted_categories") or []
            ),
            template_default_prohibited=list(
                template_row.get("default_prohibited_categories") or []
            ),
        )

    # Text-safety on any updated free-text field.
    _check_text_safety(
        display_title=patch.get("display_title"),
        plain_language_summary=patch.get("plain_language_summary"),
    )

    # Build the UPDATE. Only touch supplied editable columns.
    sets: List[str] = ["updated_at = now()"]
    params: Dict[str, Any] = {
        "clinic_id": ctx["clinic_id"],
        "clinic_profile_id": str(clinic_profile_id),
    }
    if "display_title" in patch:
        sets.append("display_title = :display_title")
        params["display_title"] = patch["display_title"]
    if "plain_language_summary" in patch:
        sets.append("plain_language_summary = :plain_language_summary")
        params["plain_language_summary"] = patch["plain_language_summary"]
    if "permitted_use_categories" in patch:
        sets.append(
            "permitted_use_categories = CAST(:permitted_use_categories AS text[])"
        )
        params["permitted_use_categories"] = patch["permitted_use_categories"]
    if "prohibited_use_categories" in patch:
        sets.append(
            "prohibited_use_categories = CAST(:prohibited_use_categories AS text[])"
        )
        params["prohibited_use_categories"] = patch["prohibited_use_categories"]

    new_row = db.execute(
        text(
            f"""
            UPDATE clinic_client_transparency_profiles
            SET {', '.join(sets)}
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND clinic_profile_id = CAST(:clinic_profile_id AS uuid)
              AND status = 'draft'
            RETURNING {_PROFILE_COLS}
            """
        ),
        params,
    ).mappings().first()
    if not new_row:
        raise HTTPException(
            status_code=409,
            detail="client_transparency_profile_state_changed",
        )
    return ClientTransparencyProfileResponse(
        profile=_profile_from_row(dict(new_row)),
    )


# ---------------------------------------------------------------------
# 8. Activate
# ---------------------------------------------------------------------


@router.post(
    "/profiles/{clinic_profile_id}/activate",
    response_model=ClientTransparencyProfileResponse,
)
def activate_profile(
    clinic_profile_id: _uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> ClientTransparencyProfileResponse:
    """Activate a draft. Supersedes ANY existing active profile for
    the clinic (founder v1 rule: one active per clinic). Idempotent
    on an already-active target."""
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    target = _select_profile_for_clinic(
        db,
        clinic_id=ctx["clinic_id"],
        clinic_profile_id=str(clinic_profile_id),
    )
    if not target:
        raise HTTPException(
            status_code=404,
            detail="client_transparency_profile_not_found",
        )

    if target["status"] == _STATUS_ACTIVE:
        return ClientTransparencyProfileResponse(
            profile=_profile_from_row(target),
        )
    if target["status"] != _STATUS_DRAFT:
        raise HTTPException(
            status_code=400,
            detail="client_transparency_profile_not_in_draft",
        )

    # Supersede ANY existing active row for the clinic (NOT just for
    # the same template - v1 founder rule). Same-transaction so the
    # partial unique index on (clinic_id) WHERE status='active' cannot
    # reject the upcoming activation.
    db.execute(
        text(
            """
            UPDATE clinic_client_transparency_profiles
            SET status = 'superseded',
                superseded_at = now(),
                updated_at = now()
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND status = 'active'
            """
        ),
        {"clinic_id": ctx["clinic_id"]},
    )

    new_row = db.execute(
        text(
            f"""
            UPDATE clinic_client_transparency_profiles
            SET status = 'active',
                activated_by_user_id = CAST(:actor AS uuid),
                activated_at = now(),
                effective_from = COALESCE(effective_from, now()),
                updated_at = now()
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND clinic_profile_id = CAST(:clinic_profile_id AS uuid)
              AND status = 'draft'
            RETURNING {_PROFILE_COLS}
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "clinic_profile_id": str(clinic_profile_id),
            "actor": ctx["clinic_user_id"],
        },
    ).mappings().first()
    if not new_row:
        raise HTTPException(
            status_code=409,
            detail="client_transparency_profile_state_changed",
        )
    new_row_d = dict(new_row)

    _insert_audit_event(
        db,
        clinic_id=ctx["clinic_id"],
        admin_user_id=ctx["clinic_user_id"],
        action="governance_client_transparency_profile_activated",
        target_id=str(new_row_d["clinic_profile_id"]),
        ip_hash=ctx["ip_hash"],
        meta={
            "client_transparency_template_id": str(
                new_row_d["client_transparency_template_id"]
            ),
            "clinic_profile_version": int(new_row_d["clinic_profile_version"]),
            "template_version_snapshot": str(
                new_row_d["template_version_snapshot"]
            ),
            "status": _STATUS_ACTIVE,
            "previous_status": _STATUS_DRAFT,
        },
    )
    logger.info(
        "governance_client_transparency_profile_activated",
        extra={
            "clinic_id": ctx["clinic_id"],
            "clinic_profile_id": str(new_row_d["clinic_profile_id"]),
        },
    )
    return ClientTransparencyProfileResponse(
        profile=_profile_from_row(new_row_d),
    )


# ---------------------------------------------------------------------
# 9. Archive
# ---------------------------------------------------------------------


@router.post(
    "/profiles/{clinic_profile_id}/archive",
    response_model=ClientTransparencyProfileResponse,
)
def archive_profile(
    clinic_profile_id: _uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> ClientTransparencyProfileResponse:
    """Archive a draft or superseded profile. Active profiles are
    rejected. Idempotent on already-archived."""
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    target = _select_profile_for_clinic(
        db,
        clinic_id=ctx["clinic_id"],
        clinic_profile_id=str(clinic_profile_id),
    )
    if not target:
        raise HTTPException(
            status_code=404,
            detail="client_transparency_profile_not_found",
        )

    if target["status"] == _STATUS_ACTIVE:
        raise HTTPException(
            status_code=400,
            detail="client_transparency_active_profile_cannot_be_archived",
        )
    if target["status"] == _STATUS_ARCHIVED:
        return ClientTransparencyProfileResponse(
            profile=_profile_from_row(target),
        )

    new_row = db.execute(
        text(
            f"""
            UPDATE clinic_client_transparency_profiles
            SET status = 'archived',
                updated_at = now()
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND clinic_profile_id = CAST(:clinic_profile_id AS uuid)
              AND status IN ('draft','superseded')
            RETURNING {_PROFILE_COLS}
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "clinic_profile_id": str(clinic_profile_id),
        },
    ).mappings().first()
    if not new_row:
        raise HTTPException(
            status_code=409,
            detail="client_transparency_profile_state_changed",
        )
    new_row_d = dict(new_row)

    _insert_audit_event(
        db,
        clinic_id=ctx["clinic_id"],
        admin_user_id=ctx["clinic_user_id"],
        action="governance_client_transparency_profile_archived",
        target_id=str(new_row_d["clinic_profile_id"]),
        ip_hash=ctx["ip_hash"],
        meta={
            "client_transparency_template_id": str(
                new_row_d["client_transparency_template_id"]
            ),
            "clinic_profile_version": int(new_row_d["clinic_profile_version"]),
            "previous_status": str(target["status"]),
            "status": _STATUS_ARCHIVED,
        },
    )
    logger.info(
        "governance_client_transparency_profile_archived",
        extra={
            "clinic_id": ctx["clinic_id"],
            "clinic_profile_id": str(new_row_d["clinic_profile_id"]),
            "previous_status": str(target["status"]),
        },
    )
    return ClientTransparencyProfileResponse(
        profile=_profile_from_row(new_row_d),
    )
