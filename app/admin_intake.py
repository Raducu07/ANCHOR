from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import text

from app.admin_auth import AdminContext, require_admin, write_admin_audit_event
from app.anchor_logging import log_event
from app.db import SessionLocal
from app.intake_common import DEMO_REQUEST_STATUSES, START_REQUEST_STATUSES
from app.intake_schemas import UpdateIntakeRequest

router = APIRouter(prefix="/v1/admin/intake", tags=["admin"])


def _serialize_rows(rows: Iterable[Dict[str, Any]]) -> list[Dict[str, Any]]:
    items: list[Dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        for key, value in list(item.items()):
            if hasattr(value, "isoformat"):
                item[key] = value.isoformat()
            elif value is not None:
                item[key] = str(value) if key in {"id", "event_id"} else value
        items.append(item)
    return items


def _status_counts(table_name: str) -> Dict[str, int]:
    with SessionLocal() as db:
        rows = db.execute(
            text(
                f"""
                SELECT status, COUNT(*)::int AS count
                FROM {table_name}
                GROUP BY status
                ORDER BY status ASC
                """
            )
        ).mappings().all()
    return {str(row["status"]): int(row["count"]) for row in rows}


def _validate_status(kind: str, status: str) -> None:
    allowed = DEMO_REQUEST_STATUSES if kind == "demo" else START_REQUEST_STATUSES
    if status not in allowed:
        raise HTTPException(status_code=422, detail=f"invalid_status_for_{kind}")


def _chat_events_query(category: Optional[str], limit: int) -> tuple[str, Dict[str, Any]]:
    base_sql = """
        SELECT
          id AS event_id, created_at, session_id, question_text, question_text_redacted,
          question_category, matched_topic, answer_confidence, suggested_cta,
          source_page, utm_source, utm_medium, utm_campaign,
          contains_email, contains_phone
        FROM public_site_chat_events
    """

    normalized_category = (category or "").strip() or None
    params: Dict[str, Any] = {"limit": limit}

    if normalized_category is not None:
        params["category"] = normalized_category
        return (
            base_sql
            + """
        WHERE question_category = :category
        ORDER BY created_at DESC
        LIMIT :limit
        """,
            params,
        )

    return (
        base_sql
        + """
        ORDER BY created_at DESC
        LIMIT :limit
        """,
        params,
    )


def _requests_query(intake_type: Literal["demo", "start", "all"], status: Optional[str], limit: int) -> tuple[str, Dict[str, Any]]:
    normalized_status = (status or "").strip() or None
    params: Dict[str, Any] = {"limit": limit}

    if intake_type == "demo":
        base_sql = """
            SELECT
              'demo' AS kind,
              id, created_at, status, clinic_name, full_name, work_email, role,
              current_ai_use, primary_interest, biggest_concern, clinic_size, phone,
              message, consent, source_page, utm_source, utm_medium, utm_campaign, notes
            FROM demo_requests
        """
    elif intake_type == "start":
        base_sql = """
            SELECT
              'start' AS kind,
              id, created_at, status, clinic_name, full_name, work_email, role,
              current_ai_use, preferred_plan, rollout_timing, clinic_size, site_count,
              phone, message, consent, source_page, utm_source, utm_medium, utm_campaign, notes
            FROM start_requests
        """
    else:
        base_sql = """
            SELECT *
            FROM (
              SELECT
                'demo' AS kind,
                id, created_at, status, clinic_name, full_name, work_email, role,
                current_ai_use, primary_interest AS interest_or_plan, biggest_concern AS concern_or_timing,
                clinic_size, NULL::integer AS site_count, phone, message, consent,
                source_page, utm_source, utm_medium, utm_campaign, notes
              FROM demo_requests
              UNION ALL
              SELECT
                'start' AS kind,
                id, created_at, status, clinic_name, full_name, work_email, role,
                current_ai_use, preferred_plan AS interest_or_plan, rollout_timing AS concern_or_timing,
                clinic_size, site_count, phone, message, consent,
                source_page, utm_source, utm_medium, utm_campaign, notes
              FROM start_requests
            ) items
        """

    if normalized_status is not None:
        params["status"] = normalized_status
        return (
            base_sql
            + """
            WHERE status = :status
            ORDER BY created_at DESC
            LIMIT :limit
            """,
            params,
        )

    return (
        base_sql
        + """
        ORDER BY created_at DESC
        LIMIT :limit
        """,
        params,
    )


@router.get("/summary")
def admin_intake_summary(
    request: Request,
    ctx: AdminContext = Depends(require_admin),
) -> Dict[str, Any]:
    try:
        demo_counts = _status_counts("demo_requests")
        start_counts = _status_counts("start_requests")

        with SessionLocal() as db:
            recent = db.execute(
                text(
                    """
                    SELECT
                      (SELECT COUNT(*)::int FROM demo_requests WHERE created_at >= now() - interval '7 days') AS demo_last_7_days,
                      (SELECT COUNT(*)::int FROM demo_requests WHERE created_at >= now() - interval '30 days') AS demo_last_30_days,
                      (SELECT COUNT(*)::int FROM start_requests WHERE created_at >= now() - interval '7 days') AS start_last_7_days,
                      (SELECT COUNT(*)::int FROM start_requests WHERE created_at >= now() - interval '30 days') AS start_last_30_days,
                      (SELECT COUNT(*)::int FROM public_site_chat_events WHERE created_at >= now() - interval '7 days') AS chat_last_7_days,
                      (SELECT COUNT(*)::int FROM public_site_chat_events WHERE created_at >= now() - interval '30 days') AS chat_last_30_days
                    """
                )
            ).mappings().first()
    except Exception as exc:
        log_event(
            logging.ERROR,
            "admin.intake.summary_failed",
            request_id=ctx.request_id,
            error_type=type(exc).__name__,
            error=str(exc)[:240],
        )
        write_admin_audit_event(
            action="admin.intake.summary",
            method=request.method.upper(),
            route=request.url.path,
            status_code=500,
            admin_token_id=ctx.token_id,
            request_id=ctx.request_id,
            ip_hash=ctx.ip_hash,
            ua_hash=ctx.ua_hash,
            meta={"error_type": type(exc).__name__},
        )
        raise HTTPException(status_code=500, detail="admin_intake_summary_failed")

    write_admin_audit_event(
        action="admin.intake.summary",
        method=request.method.upper(),
        route=request.url.path,
        status_code=200,
        admin_token_id=ctx.token_id,
        request_id=ctx.request_id,
        ip_hash=ctx.ip_hash,
        ua_hash=ctx.ua_hash,
        meta={},
    )

    return {
        "status": "ok",
        "demo_requests": {
            "counts_by_status": demo_counts,
            "recent_totals": {
                "last_7_days": int(recent["demo_last_7_days"] or 0),
                "last_30_days": int(recent["demo_last_30_days"] or 0),
            },
        },
        "start_requests": {
            "counts_by_status": start_counts,
            "recent_totals": {
                "last_7_days": int(recent["start_last_7_days"] or 0),
                "last_30_days": int(recent["start_last_30_days"] or 0),
            },
        },
        "chat_events": {
            "recent_totals": {
                "last_7_days": int(recent["chat_last_7_days"] or 0),
                "last_30_days": int(recent["chat_last_30_days"] or 0),
            },
        },
    }


@router.get("/requests")
def admin_list_intake_requests(
    request: Request,
    intake_type: Literal["demo", "start", "all"] = Query(default="all", alias="type"),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: AdminContext = Depends(require_admin),
) -> Dict[str, Any]:
    sql_text, params = _requests_query(intake_type, status, limit)

    try:
        with SessionLocal() as db:
            rows = db.execute(text(sql_text), params).mappings().all()
    except Exception as exc:
        log_event(
            logging.ERROR,
            "admin.intake.requests_failed",
            request_id=ctx.request_id,
            intake_type=intake_type,
            status=((status or "").strip() or None),
            sql_variant=("filtered" if params.get("status") is not None else "unfiltered"),
            error_type=type(exc).__name__,
            error=str(exc)[:240],
        )
        write_admin_audit_event(
            action="admin.intake.requests.list",
            method=request.method.upper(),
            route=request.url.path,
            status_code=500,
            admin_token_id=ctx.token_id,
            request_id=ctx.request_id,
            ip_hash=ctx.ip_hash,
            ua_hash=ctx.ua_hash,
            meta={"type": intake_type, "status": status, "limit": limit, "error_type": type(exc).__name__},
        )
        raise HTTPException(status_code=500, detail="admin_intake_requests_failed")

    items = _serialize_rows(rows)
    write_admin_audit_event(
        action="admin.intake.requests.list",
        method=request.method.upper(),
        route=request.url.path,
        status_code=200,
        admin_token_id=ctx.token_id,
        request_id=ctx.request_id,
        ip_hash=ctx.ip_hash,
        ua_hash=ctx.ua_hash,
        meta={"type": intake_type, "status": status, "limit": limit, "count": len(items)},
    )

    return {"status": "ok", "type": intake_type, "count": len(items), "requests": items}


@router.get("/chat-events")
def admin_list_chat_events(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    category: Optional[str] = Query(default=None),
    ctx: AdminContext = Depends(require_admin),
) -> Dict[str, Any]:
    sql_text, params = _chat_events_query(category, limit)

    try:
        with SessionLocal() as db:
            rows = db.execute(text(sql_text), params).mappings().all()
    except Exception as exc:
        log_event(
            logging.ERROR,
            "admin.intake.chat_events_failed",
            request_id=ctx.request_id,
            limit=limit,
            category=((category or "").strip() or None),
            sql_variant=("filtered" if params.get("category") is not None else "unfiltered"),
            error_type=type(exc).__name__,
            error=str(exc)[:240],
        )
        write_admin_audit_event(
            action="admin.intake.chat_events.list",
            method=request.method.upper(),
            route=request.url.path,
            status_code=500,
            admin_token_id=ctx.token_id,
            request_id=ctx.request_id,
            ip_hash=ctx.ip_hash,
            ua_hash=ctx.ua_hash,
            meta={"limit": limit, "category": category, "error_type": type(exc).__name__},
        )
        raise HTTPException(status_code=500, detail="admin_intake_chat_events_failed")

    items = _serialize_rows(rows)
    write_admin_audit_event(
        action="admin.intake.chat_events.list",
        method=request.method.upper(),
        route=request.url.path,
        status_code=200,
        admin_token_id=ctx.token_id,
        request_id=ctx.request_id,
        ip_hash=ctx.ip_hash,
        ua_hash=ctx.ua_hash,
        meta={"limit": limit, "category": category, "count": len(items)},
    )

    return {"status": "ok", "count": len(items), "events": items}


@router.patch("/request/{kind}/{request_id}")
def admin_update_intake_request(
    kind: Literal["demo", "start"],
    request_id: str,
    body: UpdateIntakeRequest,
    request: Request,
    ctx: AdminContext = Depends(require_admin),
) -> Dict[str, Any]:
    if body.status is not None:
        _validate_status(kind, body.status)

    updates = body.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=422, detail="no_updates_provided")

    table_name = "demo_requests" if kind == "demo" else "start_requests"
    set_parts: list[str] = []
    params: Dict[str, Any] = {"request_id": request_id}

    if "status" in updates:
        set_parts.append("status = :status")
        params["status"] = updates["status"]

    if "notes" in updates:
        set_parts.append("notes = :notes")
        params["notes"] = updates["notes"]

    try:
        with SessionLocal() as db:
            row = db.execute(
                text(
                    f"""
                    UPDATE {table_name}
                    SET {", ".join(set_parts)}
                    WHERE id = CAST(:request_id AS uuid)
                    RETURNING id, created_at, status, notes
                    """
                ),
                params,
            ).mappings().first()
            db.commit()
    except Exception as exc:
        log_event(
            logging.ERROR,
            "admin.intake.request_update_failed",
            request_id=ctx.request_id,
            intake_kind=kind,
            intake_request_id=request_id,
            error_type=type(exc).__name__,
            error=str(exc)[:240],
        )
        write_admin_audit_event(
            action="admin.intake.request.update",
            method=request.method.upper(),
            route=request.url.path,
            status_code=500,
            admin_token_id=ctx.token_id,
            request_id=ctx.request_id,
            ip_hash=ctx.ip_hash,
            ua_hash=ctx.ua_hash,
            meta={"kind": kind, "request_id": request_id, "error_type": type(exc).__name__},
        )
        raise HTTPException(status_code=500, detail="admin_intake_request_update_failed")

    if not row:
        raise HTTPException(status_code=404, detail="intake_request_not_found")

    item = _serialize_rows([row])[0]
    write_admin_audit_event(
        action="admin.intake.request.update",
        method=request.method.upper(),
        route=request.url.path,
        status_code=200,
        admin_token_id=ctx.token_id,
        request_id=ctx.request_id,
        ip_hash=ctx.ip_hash,
        ua_hash=ctx.ua_hash,
        meta={"kind": kind, "request_id": request_id, "updated_fields": sorted(updates.keys())},
    )

    return {"status": "ok", "kind": kind, "request": item}
