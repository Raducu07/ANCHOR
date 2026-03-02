# app/admin_audit.py
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text

from app.admin_auth import AdminContext, require_admin, write_admin_audit_event
from app.db import SessionLocal

router = APIRouter(prefix="/v1/admin", tags=["admin"])


@router.get("/audit-events")
def admin_list_audit_events(
    request: Request,
    limit: int = 200,
    since: Optional[str] = None,  # ISO8601 timestamp string
    action: Optional[str] = None,
    ctx: AdminContext = Depends(require_admin),
) -> Dict[str, Any]:
    """
    Admin-only list of platform_admin_audit_events (metadata-only).
    Rate limiting + auth auditing are enforced in require_admin.
    """
    limit = max(1, min(1000, int(limit)))

    params: Dict[str, Any] = {"limit": limit}
    where = []

    if since:
        where.append("created_at >= :since::timestamptz")
        params["since"] = since

    if action:
        where.append("action = :action")
        params["action"] = action.strip()

    where_sql = ""
    if where:
        where_sql = "WHERE " + " AND ".join(where)

    with SessionLocal() as db:
        rows = db.execute(
            text(
                f"""
                SELECT
                  event_id, created_at, admin_token_id, action,
                  method, route, status_code, request_id, ip_hash, ua_hash, meta
                FROM platform_admin_audit_events
                {where_sql}
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            params,
        ).mappings().all()

    # Optional: audit the fact we listed audit events (metadata-only)
    # (Auth success/fail auditing already occurs inside require_admin.)
    write_admin_audit_event(
        action="admin.audit.list",
        method=request.method.upper(),
        route=request.url.path,
        status_code=200,
        admin_token_id=ctx.token_id,
        request_id=ctx.request_id,
        ip_hash=ctx.ip_hash,
        ua_hash=ctx.ua_hash,
        meta={"limit": limit, "since": since, "action_filter": action},
    )

    return {"status": "ok", "count": len(rows), "events": [dict(r) for r in rows]}
