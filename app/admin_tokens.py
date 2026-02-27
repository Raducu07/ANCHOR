# app/admin_tokens.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.admin_auth import (
    AdminContext,
    generate_admin_token_plaintext,
    hash_admin_token,
    require_admin,
    write_admin_audit_event,
)
from app.db import SessionLocal

router = APIRouter(prefix="/v1/admin", tags=["admin"])


class CreateAdminTokenRequest(BaseModel):
    label: str = Field(default="",
                       description="Human label for this token (e.g. 'prod-deploy', 'ci-smoke').")
    expires_in_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=3650,
        description="Optional TTL in days. If omitted, token does not expire.",
    )


class CreateAdminTokenResponse(BaseModel):
    status: str = "ok"
    token_id: str
    token: str
    created_at: str
    expires_at: Optional[str] = None
    note: str = "Token is shown once. Store it securely; it cannot be recovered later."


@router.post("/tokens", response_model=CreateAdminTokenResponse)
def admin_create_token(
    body: CreateAdminTokenRequest,
    ctx: AdminContext = Depends(require_admin),
) -> CreateAdminTokenResponse:
    token_plain = generate_admin_token_plaintext()
    token_hash = hash_admin_token(token_plain)

    now = datetime.now(timezone.utc)
    expires_at = None
    if body.expires_in_days is not None:
        expires_at = now + timedelta(days=int(body.expires_in_days))

    with SessionLocal() as db:
        row = db.execute(
            text(
                """
                INSERT INTO admin_tokens (token_hash, label, expires_at)
                VALUES (:h, :label, :expires_at)
                RETURNING token_id, created_at, expires_at
                """
            ),
            {"h": token_hash, "label": (body.label or "").strip(), "expires_at": expires_at},
        ).mappings().first()
        db.commit()

    if not row:
        raise HTTPException(status_code=500, detail="Failed to create admin token")

    write_admin_audit_event(
        action="admin.tokens.create",
        method="POST",
        route="/v1/admin/tokens",
        status_code=200,
        admin_token_id=ctx.token_id,
        request_id=ctx.request_id,
        ip_hash=ctx.ip_hash,
        ua_hash=ctx.ua_hash,
        meta={"created_token_id": str(row["token_id"]), "expires_at": (row["expires_at"].isoformat() if row["expires_at"] else None)},
    )

    return CreateAdminTokenResponse(
        token_id=str(row["token_id"]),
        token=token_plain,
        created_at=row["created_at"].isoformat(),
        expires_at=(row["expires_at"].isoformat() if row["expires_at"] else None),
    )


@router.get("/tokens")
def admin_list_tokens(
    limit: int = 200,
    ctx: AdminContext = Depends(require_admin),
) -> Dict[str, Any]:
    limit = max(1, min(1000, int(limit)))

    with SessionLocal() as db:
        rows = db.execute(
            text(
                """
                SELECT token_id, label, created_at, expires_at, disabled_at, last_used_at, last_used_ip_hash
                FROM admin_tokens
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {"limit": limit},
        ).mappings().all()

    write_admin_audit_event(
        action="admin.tokens.list",
        method="GET",
        route="/v1/admin/tokens",
        status_code=200,
        admin_token_id=ctx.token_id,
        request_id=ctx.request_id,
        ip_hash=ctx.ip_hash,
        ua_hash=ctx.ua_hash,
        meta={"limit": limit},
    )

    return {"status": "ok", "count": len(rows), "tokens": [dict(r) for r in rows]}


@router.post("/tokens/{token_id}/disable")
def admin_disable_token(
    token_id: str,
    ctx: AdminContext = Depends(require_admin),
) -> Dict[str, Any]:
    with SessionLocal() as db:
        res = db.execute(
            text(
                """
                UPDATE admin_tokens
                SET disabled_at = now()
                WHERE token_id = :tid AND disabled_at IS NULL
                """
            ),
            {"tid": token_id},
        )
        db.commit()

    write_admin_audit_event(
        action="admin.tokens.disable",
        method="POST",
        route=f"/v1/admin/tokens/{token_id}/disable",
        status_code=200,
        admin_token_id=ctx.token_id,
        request_id=ctx.request_id,
        ip_hash=ctx.ip_hash,
        ua_hash=ctx.ua_hash,
        meta={"disabled_token_id": token_id, "rows_affected": int(res.rowcount or 0)},
    )

    return {"status": "ok", "token_id": token_id, "disabled": True, "rows_affected": int(res.rowcount or 0)}
