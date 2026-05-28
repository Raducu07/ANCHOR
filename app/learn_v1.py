# app/learn_v1.py
#
# Phase 2A-1 — CPD-Recordable AI Literacy endpoints.
#
# Doctrine:
#   * Metadata only. No raw learning content is read from or written to the DB.
#   * Tenant isolation is enforced by RLS (app_current_clinic_id()) applied via
#     get_db; read queries trust RLS for clinic scoping.
#   * Completion corrections use void-with-reason, never delete/overwrite.
#   * role_applicability is audience metadata, NOT an access-control role.
#
# Authorisation:
#   * `me` endpoints act on the authenticated user.
#   * user/{user_id}, export generation, and completion-void require clinic-admin
#     (LEARN_ADMIN_ROLES). Practical live admin role is `admin`; the broader set
#     is kept for forward compatibility and matches the existing app convention.

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db
from app.learn_models import (
    CPDExport,
    CPDRecord,
    LearningCompletion,
    LearningCompletionCreate,
    LearningCompletionVoid,
    LearningModule,
)

router = APIRouter(
    prefix="/v1/learn",
    tags=["Learn"],
    dependencies=[Depends(require_clinic_user)],
)

# Clinic-admin roles for Learn admin actions. Matches the existing app
# convention (portal_assistant._POLICY_ADMIN_ROLES). NOT a DB role enum change.
LEARN_ADMIN_ROLES = {"admin", "owner", "practice_manager"}

EXPORT_VERSION = "v1"

_MODULE_COLS = (
    "module_id, module_slug, version, title, summary, learning_objectives, "
    "role_applicability, cpd_minutes, category, rcvs_principle_mappings, "
    "eu_ai_act_article_mappings, content_reference, is_active"
)

_COMPLETION_COLS = (
    "completion_id, user_id, module_id, module_version, completed_at, "
    "acknowledgement_provided, cpd_minutes_credited, is_voided, void_reason, "
    "voided_at, voided_by_user_id"
)

_EXPORT_COLS = (
    "export_id, user_id, generated_by_user_id, export_version, export_hash, "
    "generated_at"
)


# ---------------------------------------------------------------------
# Context / auth helpers
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
    }


def _require_admin(role: str) -> None:
    if role not in LEARN_ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="forbidden_not_admin")


def _as_uuid(value: Any, *, field: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except Exception:
        raise HTTPException(status_code=400, detail=f"invalid_{field}")


# ---------------------------------------------------------------------
# Row -> model mappers
# ---------------------------------------------------------------------
def _module_from_row(row: Dict[str, Any]) -> LearningModule:
    return LearningModule(
        module_id=row["module_id"],
        module_slug=row["module_slug"],
        version=row["version"],
        title=row["title"],
        summary=row["summary"],
        learning_objectives=list(row["learning_objectives"] or []),
        role_applicability=list(row["role_applicability"] or []),
        cpd_minutes=int(row["cpd_minutes"]),
        category=row["category"],
        rcvs_principle_mappings=list(row["rcvs_principle_mappings"] or []),
        eu_ai_act_article_mappings=list(row["eu_ai_act_article_mappings"] or []),
        content_reference=row["content_reference"],
        is_active=bool(row["is_active"]),
    )


def _completion_from_row(row: Dict[str, Any]) -> LearningCompletion:
    return LearningCompletion(
        completion_id=row["completion_id"],
        user_id=row["user_id"],
        module_id=row["module_id"],
        module_version=row["module_version"],
        completed_at=row["completed_at"],
        acknowledgement_provided=bool(row["acknowledgement_provided"]),
        cpd_minutes_credited=int(row["cpd_minutes_credited"]),
        is_voided=bool(row["is_voided"]),
        void_reason=row.get("void_reason"),
        voided_at=row.get("voided_at"),
        voided_by_user_id=row.get("voided_by_user_id"),
    )


# ---------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------
@router.get("/modules", response_model=List[LearningModule])
def list_modules(
    request: Request,
    role: Optional[str] = Query(default=None, max_length=64),
    category: Optional[str] = Query(default=None, max_length=64),
    db: Session = Depends(get_db),
) -> List[LearningModule]:
    _ctx(request)
    clauses = ["is_active = true"]
    params: Dict[str, Any] = {}
    if category:
        clauses.append("category = :category")
        params["category"] = category
    if role:
        # role_applicability is an audience-tag array; membership test only.
        clauses.append(":role = ANY(role_applicability)")
        params["role"] = role

    sql = (
        f"SELECT {_MODULE_COLS} FROM learning_modules "
        f"WHERE {' AND '.join(clauses)} ORDER BY title"
    )
    rows = db.execute(text(sql), params).mappings().all()
    return [_module_from_row(r) for r in rows]


@router.get("/modules/{module_id}", response_model=LearningModule)
def get_module(
    module_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> LearningModule:
    _ctx(request)
    mid = _as_uuid(module_id, field="module_id")
    row = db.execute(
        text(
            f"SELECT {_MODULE_COLS} FROM learning_modules "
            "WHERE module_id = :module_id LIMIT 1"
        ),
        {"module_id": mid},
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="module_not_found")
    return _module_from_row(row)


# ---------------------------------------------------------------------
# Completions
# ---------------------------------------------------------------------
@router.post("/completions", response_model=LearningCompletion, status_code=201)
def record_completion(
    payload: LearningCompletionCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> LearningCompletion:
    ctx = _ctx(request)
    mid = _as_uuid(payload.module_id, field="module_id")

    module = db.execute(
        text(
            "SELECT module_id, version, cpd_minutes, is_active "
            "FROM learning_modules WHERE module_id = :module_id LIMIT 1"
        ),
        {"module_id": mid},
    ).mappings().first()
    if not module:
        raise HTTPException(status_code=404, detail="module_not_found")
    if not bool(module["is_active"]):
        raise HTTPException(status_code=400, detail="module_inactive")

    insert_params = {
        "completion_id": str(uuid.uuid4()),
        "clinic_id": ctx["clinic_id"],
        "user_id": ctx["clinic_user_id"],
        "module_id": mid,
        # Snapshot version + minutes from the module at completion time.
        "module_version": str(module["version"]),
        "acknowledgement_provided": bool(payload.acknowledgement_provided),
        "cpd_minutes_credited": int(module["cpd_minutes"]),
    }
    try:
        row = db.execute(
            text(
                f"""
                INSERT INTO learning_completions (
                    completion_id, clinic_id, user_id, module_id, module_version,
                    acknowledgement_provided, cpd_minutes_credited
                ) VALUES (
                    :completion_id, :clinic_id, :user_id, :module_id, :module_version,
                    :acknowledgement_provided, :cpd_minutes_credited
                )
                RETURNING {_COMPLETION_COLS}
                """
            ),
            insert_params,
        ).mappings().first()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="completion_already_recorded")

    return _completion_from_row(row)


@router.post(
    "/completions/{completion_id}/void",
    response_model=LearningCompletion,
)
def void_completion(
    completion_id: str,
    payload: LearningCompletionVoid,
    request: Request,
    db: Session = Depends(get_db),
) -> LearningCompletion:
    ctx = _ctx(request)
    _require_admin(ctx["role"])
    cid = _as_uuid(completion_id, field="completion_id")

    row = db.execute(
        text(
            f"""
            UPDATE learning_completions
            SET is_voided = true,
                void_reason = :void_reason,
                voided_at = now(),
                voided_by_user_id = :actor
            WHERE completion_id = :completion_id
              AND is_voided = false
            RETURNING {_COMPLETION_COLS}
            """
        ),
        {
            "completion_id": cid,
            "void_reason": payload.void_reason,
            "actor": ctx["clinic_user_id"],
        },
    ).mappings().first()
    if not row:
        raise HTTPException(
            status_code=404, detail="completion_not_found_or_already_voided"
        )
    return _completion_from_row(row)


def _list_completions(db: Session, user_id: str) -> List[LearningCompletion]:
    rows = db.execute(
        text(
            f"SELECT {_COMPLETION_COLS} FROM learning_completions "
            "WHERE user_id = :user_id ORDER BY completed_at DESC"
        ),
        {"user_id": user_id},
    ).mappings().all()
    return [_completion_from_row(r) for r in rows]


@router.get("/completions/me", response_model=List[LearningCompletion])
def list_my_completions(
    request: Request,
    db: Session = Depends(get_db),
) -> List[LearningCompletion]:
    ctx = _ctx(request)
    return _list_completions(db, ctx["clinic_user_id"])


@router.get(
    "/completions/users/{user_id}", response_model=List[LearningCompletion]
)
def list_user_completions(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> List[LearningCompletion]:
    ctx = _ctx(request)
    _require_admin(ctx["role"])
    uid = _as_uuid(user_id, field="user_id")
    return _list_completions(db, uid)


# ---------------------------------------------------------------------
# CPD record
# ---------------------------------------------------------------------
def _build_cpd_record(db: Session, user_id: str) -> CPDRecord:
    agg = db.execute(
        text(
            """
            SELECT total_modules_completed, total_cpd_minutes,
                   first_completion_at, most_recent_completion_at
            FROM v_cpd_records
            WHERE user_id = :user_id
            LIMIT 1
            """
        ),
        {"user_id": user_id},
    ).mappings().first()

    completions_rows = db.execute(
        text(
            f"SELECT {_COMPLETION_COLS} FROM learning_completions "
            "WHERE user_id = :user_id AND is_voided = false "
            "ORDER BY completed_at DESC"
        ),
        {"user_id": user_id},
    ).mappings().all()

    return CPDRecord(
        user_id=user_id,
        total_modules_completed=int(agg["total_modules_completed"]) if agg else 0,
        total_cpd_minutes=int(agg["total_cpd_minutes"]) if agg else 0,
        first_completion_at=agg["first_completion_at"] if agg else None,
        most_recent_completion_at=agg["most_recent_completion_at"] if agg else None,
        completions=[_completion_from_row(r) for r in completions_rows],
    )


@router.get("/cpd/me", response_model=CPDRecord)
def my_cpd_record(
    request: Request,
    db: Session = Depends(get_db),
) -> CPDRecord:
    ctx = _ctx(request)
    return _build_cpd_record(db, ctx["clinic_user_id"])


@router.get("/cpd/users/{user_id}", response_model=CPDRecord)
def user_cpd_record(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> CPDRecord:
    ctx = _ctx(request)
    _require_admin(ctx["role"])
    uid = _as_uuid(user_id, field="user_id")
    return _build_cpd_record(db, uid)


# ---------------------------------------------------------------------
# CPD exports (immutable metadata snapshots)
# ---------------------------------------------------------------------
def _canonical_json(payload: Dict[str, Any]) -> str:
    """Deterministic JSON for hashing: sorted keys, no insignificant whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _build_export_payload(
    record: CPDRecord, *, clinic_id: str, generated_by_user_id: str, generated_at: str
) -> Dict[str, Any]:
    return {
        "export_version": EXPORT_VERSION,
        "clinic_id": clinic_id,
        "user_id": str(record.user_id),
        "generated_by_user_id": generated_by_user_id,
        "generated_at": generated_at,
        "cpd_summary": {
            "total_modules_completed": record.total_modules_completed,
            "total_cpd_minutes": record.total_cpd_minutes,
            "first_completion_at": (
                record.first_completion_at.isoformat()
                if record.first_completion_at
                else None
            ),
            "most_recent_completion_at": (
                record.most_recent_completion_at.isoformat()
                if record.most_recent_completion_at
                else None
            ),
        },
        "completions": [
            {
                "module_id": str(c.module_id),
                "module_version": c.module_version,
                "completed_at": c.completed_at.isoformat(),
                "cpd_minutes_credited": c.cpd_minutes_credited,
                "acknowledgement_provided": c.acknowledgement_provided,
            }
            for c in record.completions
        ],
    }


@router.post(
    "/cpd/users/{user_id}/exports", response_model=CPDExport, status_code=201
)
def create_cpd_export(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> CPDExport:
    ctx = _ctx(request)
    _require_admin(ctx["role"])
    uid = _as_uuid(user_id, field="user_id")

    record = _build_cpd_record(db, uid)
    generated_at = datetime.now(timezone.utc).isoformat()
    payload = _build_export_payload(
        record,
        clinic_id=ctx["clinic_id"],
        generated_by_user_id=ctx["clinic_user_id"],
        generated_at=generated_at,
    )
    export_hash = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()

    row = db.execute(
        text(
            f"""
            INSERT INTO cpd_exports (
                export_id, clinic_id, user_id, generated_by_user_id,
                export_version, export_hash, export_payload
            ) VALUES (
                :export_id, :clinic_id, :user_id, :generated_by_user_id,
                :export_version, :export_hash, CAST(:export_payload AS JSONB)
            )
            RETURNING {_EXPORT_COLS}
            """
        ),
        {
            "export_id": str(uuid.uuid4()),
            "clinic_id": ctx["clinic_id"],
            "user_id": uid,
            "generated_by_user_id": ctx["clinic_user_id"],
            "export_version": EXPORT_VERSION,
            "export_hash": export_hash,
            "export_payload": json.dumps(payload),
        },
    ).mappings().first()

    return CPDExport(
        export_id=row["export_id"],
        user_id=row["user_id"],
        generated_by_user_id=row["generated_by_user_id"],
        export_version=row["export_version"],
        export_hash=row["export_hash"],
        generated_at=row["generated_at"],
    )


@router.get(
    "/cpd/users/{user_id}/exports", response_model=List[CPDExport]
)
def list_cpd_exports(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> List[CPDExport]:
    ctx = _ctx(request)
    _require_admin(ctx["role"])
    uid = _as_uuid(user_id, field="user_id")
    rows = db.execute(
        text(
            f"SELECT {_EXPORT_COLS} FROM cpd_exports "
            "WHERE user_id = :user_id ORDER BY generated_at DESC"
        ),
        {"user_id": uid},
    ).mappings().all()
    return [
        CPDExport(
            export_id=r["export_id"],
            user_id=r["user_id"],
            generated_by_user_id=r["generated_by_user_id"],
            export_version=r["export_version"],
            export_hash=r["export_hash"],
            generated_at=r["generated_at"],
        )
        for r in rows
    ]


def _authorize_export_access(ctx: Dict[str, str], export_user_id: str) -> None:
    # Admins may read any export in the clinic; a user may read their own.
    if ctx["role"] in LEARN_ADMIN_ROLES:
        return
    if str(export_user_id) == ctx["clinic_user_id"]:
        return
    raise HTTPException(status_code=403, detail="forbidden_not_admin")


@router.get("/cpd/exports/{export_id}", response_model=CPDExport)
def get_cpd_export(
    export_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> CPDExport:
    ctx = _ctx(request)
    eid = _as_uuid(export_id, field="export_id")
    row = db.execute(
        text(
            f"SELECT {_EXPORT_COLS} FROM cpd_exports "
            "WHERE export_id = :export_id LIMIT 1"
        ),
        {"export_id": eid},
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="export_not_found")
    _authorize_export_access(ctx, row["user_id"])
    return CPDExport(
        export_id=row["export_id"],
        user_id=row["user_id"],
        generated_by_user_id=row["generated_by_user_id"],
        export_version=row["export_version"],
        export_hash=row["export_hash"],
        generated_at=row["generated_at"],
    )


@router.get("/cpd/exports/{export_id}/payload")
def get_cpd_export_payload(
    export_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    ctx = _ctx(request)
    eid = _as_uuid(export_id, field="export_id")
    row = db.execute(
        text(
            "SELECT user_id, export_payload FROM cpd_exports "
            "WHERE export_id = :export_id LIMIT 1"
        ),
        {"export_id": eid},
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="export_not_found")
    _authorize_export_access(ctx, row["user_id"])
    payload = row["export_payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return payload
