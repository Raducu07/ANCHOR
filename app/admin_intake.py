from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
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


# ---------------------------------------------------------------------
# 2A-D.1 Patch 3: public intake retention prune endpoint
# ---------------------------------------------------------------------
#
# Doctrine:
#   * Public intake (demo_requests / start_requests / public_site_chat_events)
#     sits OUTSIDE the clinic-governance metadata-only perimeter. It holds
#     public contact PII and visitor free text. This endpoint exists so an
#     operator can age that personal data off without writing raw SQL.
#   * Admin-token gated. Audit-logged.
#   * Dry-run by default. Destructive runs require an explicit confirm
#     literal so a misclick does not erase rows.
#   * Per-call hard cap of 50_000 rows so a misconfigured cutoff cannot
#     lock a table.
#   * No scheduler / cron is introduced here — automation is deferred.
#
# Suggested operator-side defaults for `older_than_days` (NOT enforced):
#   * demo_requests   : 365
#   * start_requests  : 365
#   * public_site_chat_events : 90
# The caller must pass an explicit value; this comment is only guidance.

_PRUNE_TABLE_BY_KIND: Dict[str, str] = {
    # Internal allowlist mapping. The endpoint NEVER interpolates kind
    # strings directly into SQL; it looks the table name up here so the
    # set of touchable tables is bounded by code, not by request input.
    "demo": "demo_requests",
    "start": "start_requests",
    "chat": "public_site_chat_events",
}

_PRUNE_KINDS_ALL: tuple[str, ...] = ("demo", "start", "chat")

_PRUNE_CONFIRM_LITERAL = "I-UNDERSTAND"
_PRUNE_MAX_TOTAL_ROWS = 50_000


class _IntakePruneRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    kind: Literal["demo", "start", "chat", "all"] = Field(
        ...,
        description=(
            "Which public-intake table to prune. 'all' prunes demo, start, "
            "and chat in one call."
        ),
    )
    older_than_days: int = Field(
        ...,
        ge=1,
        le=3650,
        description="Rows with created_at < now() - this interval are eligible for prune.",
    )
    dry_run: bool = Field(
        default=True,
        description=(
            "When true (default) the endpoint only counts eligible rows. "
            "When false an explicit confirm literal is required."
        ),
    )
    confirm: Optional[str] = Field(
        default=None,
        max_length=64,
        description=(
            "When dry_run=false, must be set to 'I-UNDERSTAND' so a misclick "
            "does not erase rows."
        ),
    )

    @model_validator(mode="after")
    def _require_confirm_on_destructive(self) -> "_IntakePruneRequest":
        if not self.dry_run and self.confirm != _PRUNE_CONFIRM_LITERAL:
            raise ValueError("confirm must equal 'I-UNDERSTAND' when dry_run=false")
        return self


def _selected_kinds(kind: str) -> List[str]:
    if kind == "all":
        return list(_PRUNE_KINDS_ALL)
    return [kind]


def _count_eligible_rows(db, *, table_name: str, cutoff: datetime) -> int:
    """Count rows older than the cutoff. Caller is responsible for ensuring
    `table_name` came from the internal allowlist (`_PRUNE_TABLE_BY_KIND`)."""
    row = db.execute(
        text(
            f"SELECT COUNT(*)::int AS c FROM {table_name} WHERE created_at < :cutoff"
        ),
        {"cutoff": cutoff},
    ).mappings().first()
    return int((row or {}).get("c") or 0)


def _delete_eligible_rows(db, *, table_name: str, cutoff: datetime) -> int:
    """Delete rows older than the cutoff. Caller is responsible for ensuring
    `table_name` came from the internal allowlist."""
    result = db.execute(
        text(
            f"DELETE FROM {table_name} WHERE created_at < :cutoff"
        ),
        {"cutoff": cutoff},
    )
    return int(result.rowcount or 0)


@router.post("/prune")
def admin_intake_prune(
    body: _IntakePruneRequest,
    request: Request,
    ctx: AdminContext = Depends(require_admin),
) -> Dict[str, Any]:
    """Prune aged rows from the public intake tables. Dry-run by default.

    Behaviour:
      * `dry_run=true` (default): runs SELECT COUNT(*) per selected table,
        returns counts + cutoff; no DELETE is issued.
      * `dry_run=false`: requires `confirm="I-UNDERSTAND"`. Counts first.
        If the total across selected tables would exceed
        `_PRUNE_MAX_TOTAL_ROWS` (50_000), refuses with 409 *before* any
        DELETE. Otherwise issues `DELETE ... WHERE created_at < :cutoff`
        per table.
      * Both paths write an admin audit event with the resolved cutoff and
        per-table counts.
    """
    selected_kinds = _selected_kinds(body.kind)

    # Single resolved cutoff for the whole call so per-table reports use
    # the same time anchor.
    cutoff = datetime.now(timezone.utc) - timedelta(days=int(body.older_than_days))
    cutoff_iso = cutoff.isoformat()

    counts: Dict[str, int] = {}
    deleted: Dict[str, int] = {}

    try:
        with SessionLocal() as db:
            # Phase 1: count eligible rows per selected table. This runs
            # for both dry-run and destructive paths so the operator gets
            # a per-table picture either way.
            for kind in selected_kinds:
                table_name = _PRUNE_TABLE_BY_KIND[kind]
                counts[kind] = _count_eligible_rows(
                    db, table_name=table_name, cutoff=cutoff
                )

            total_eligible = sum(counts.values())

            if body.dry_run:
                db.rollback()
                outcome = "dry_run"
            else:
                # Hard cap: refuse BEFORE any DELETE if the total would
                # blow past the per-call budget. The operator can re-run
                # with a tighter cutoff.
                if total_eligible > _PRUNE_MAX_TOTAL_ROWS:
                    db.rollback()
                    write_admin_audit_event(
                        action="admin.intake.prune.rejected_cap",
                        method=request.method.upper(),
                        route=request.url.path,
                        status_code=409,
                        admin_token_id=ctx.token_id,
                        request_id=ctx.request_id,
                        ip_hash=ctx.ip_hash,
                        ua_hash=ctx.ua_hash,
                        meta={
                            "kind": body.kind,
                            "older_than_days": int(body.older_than_days),
                            "cutoff_utc": cutoff_iso,
                            "counts": counts,
                            "total_eligible": total_eligible,
                            "cap": _PRUNE_MAX_TOTAL_ROWS,
                        },
                    )
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            "intake_prune_rows_exceed_cap"
                        ),
                    )

                for kind in selected_kinds:
                    table_name = _PRUNE_TABLE_BY_KIND[kind]
                    deleted[kind] = _delete_eligible_rows(
                        db, table_name=table_name, cutoff=cutoff
                    )

                db.commit()
                outcome = "deleted"
    except HTTPException:
        raise
    except Exception as exc:
        log_event(
            logging.ERROR,
            "admin.intake.prune_failed",
            request_id=ctx.request_id,
            kind=body.kind,
            older_than_days=int(body.older_than_days),
            dry_run=bool(body.dry_run),
            error_type=type(exc).__name__,
            error=str(exc)[:240],
        )
        write_admin_audit_event(
            action="admin.intake.prune.error",
            method=request.method.upper(),
            route=request.url.path,
            status_code=500,
            admin_token_id=ctx.token_id,
            request_id=ctx.request_id,
            ip_hash=ctx.ip_hash,
            ua_hash=ctx.ua_hash,
            meta={
                "kind": body.kind,
                "older_than_days": int(body.older_than_days),
                "dry_run": bool(body.dry_run),
                "error_type": type(exc).__name__,
            },
        )
        raise HTTPException(status_code=500, detail="admin_intake_prune_failed")

    write_admin_audit_event(
        action="admin.intake.prune",
        method=request.method.upper(),
        route=request.url.path,
        status_code=200,
        admin_token_id=ctx.token_id,
        request_id=ctx.request_id,
        ip_hash=ctx.ip_hash,
        ua_hash=ctx.ua_hash,
        meta={
            "kind": body.kind,
            "older_than_days": int(body.older_than_days),
            "dry_run": bool(body.dry_run),
            "cutoff_utc": cutoff_iso,
            "counts": counts,
            "deleted": deleted,
            "outcome": outcome,
        },
    )

    return {
        "status": "ok",
        "outcome": outcome,
        "kind": body.kind,
        "older_than_days": int(body.older_than_days),
        "cutoff_utc": cutoff_iso,
        "dry_run": bool(body.dry_run),
        "counts": counts,
        "deleted": deleted,
        "cap": _PRUNE_MAX_TOTAL_ROWS,
    }
