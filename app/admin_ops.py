# app/admin_ops.py
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.admin_auth import AdminContext, require_admin, write_admin_audit_event
from app.http_metrics import HTTP_METRICS, summarize_http_metrics

router = APIRouter(prefix="/v1/admin/ops", tags=["admin"])


class AdminHttpMetricsResponse(BaseModel):
    status: str = "ok"
    now_utc: str
    window_sec: int = Field(..., ge=30, le=86400)
    limit: int = Field(..., ge=1, le=200)
    metrics: Dict[str, Any]


@router.get("/http-metrics", response_model=AdminHttpMetricsResponse)
def admin_http_metrics(
    window_sec: int = 900,
    limit: int = 50,
    ctx: AdminContext = Depends(require_admin),
) -> AdminHttpMetricsResponse:
    window_sec = max(30, min(86400, int(window_sec)))
    limit = max(1, min(200, int(limit)))

    items = HTTP_METRICS.snapshot()
    metrics = summarize_http_metrics(items, window_sec=window_sec, limit=limit)

    write_admin_audit_event(
        action="admin.ops.http_metrics",
        method="GET",
        route="/v1/admin/ops/http-metrics",
        status_code=200,
        admin_token_id=ctx.token_id,
        request_id=ctx.request_id,
        ip_hash=ctx.ip_hash,
        ua_hash=ctx.ua_hash,
        meta={"window_sec": window_sec, "limit": limit, "events_total": int(metrics.get("events_total") or 0)},
    )

    return AdminHttpMetricsResponse(
        now_utc=datetime.now(timezone.utc).isoformat(),
        window_sec=window_sec,
        limit=limit,
        metrics=metrics,
    )
