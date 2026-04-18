from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import text

from app.anchor_logging import hash_with_salt, log_event
from app.db import SessionLocal
from app.intake_common import has_honeypot_value, redact_contact_details
from app.intake_notifications import NotificationDeliveryError, send_intake_notifications
from app.intake_schemas import (
    ChatLogResponse,
    DemoRequestCreate,
    IntakeCreateResponse,
    PublicSiteChatEventCreate,
    StartRequestCreate,
)

router = APIRouter(prefix="/v1/public", tags=["public"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID") or "")


def _iso_record(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row)
    for key, value in list(out.items()):
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
        elif value is not None:
            out[key] = str(value) if key == "id" else value
    return out


def _reject_honeypot(request: Request, *values: str | None) -> None:
    if has_honeypot_value(*values):
        log_event(
            logging.WARNING,
            "intake.honeypot_rejected",
            request_id=_request_id(request),
            path=request.url.path,
        )
        raise HTTPException(status_code=400, detail="invalid_submission")


@router.post("/demo-request", response_model=IntakeCreateResponse)
def create_demo_request(request: Request, body: DemoRequestCreate) -> IntakeCreateResponse:
    _reject_honeypot(request, body.website, body.company_website)

    params = {
        "full_name": body.full_name,
        "work_email": str(body.work_email),
        "clinic_name": body.clinic_name,
        "role": body.role,
        "current_ai_use": body.current_ai_use,
        "primary_interest": body.primary_interest,
        "biggest_concern": body.biggest_concern,
        "clinic_size": body.clinic_size,
        "phone": body.phone,
        "message": body.message,
        "consent": body.consent,
        "source_page": body.source_page,
        "utm_source": body.utm_source,
        "utm_medium": body.utm_medium,
        "utm_campaign": body.utm_campaign,
    }

    try:
        with SessionLocal() as db:
            row = db.execute(
                text(
                    """
                    INSERT INTO demo_requests (
                      full_name, work_email, clinic_name, role, current_ai_use, primary_interest,
                      biggest_concern, clinic_size, phone, message, consent, source_page,
                      utm_source, utm_medium, utm_campaign
                    )
                    VALUES (
                      :full_name, :work_email, :clinic_name, :role, :current_ai_use, :primary_interest,
                      :biggest_concern, :clinic_size, :phone, :message, :consent, :source_page,
                      :utm_source, :utm_medium, :utm_campaign
                    )
                    RETURNING id, created_at, clinic_name, work_email, full_name, status, source_page
                    """
                ),
                params,
            ).mappings().first()
            db.commit()
    except Exception as exc:
        log_event(
            logging.ERROR,
            "intake.demo.persist_failed",
            request_id=_request_id(request),
            source_page=body.source_page,
            email_hash=hash_with_salt(str(body.work_email).lower()),
            error_type=type(exc).__name__,
            error=str(exc)[:240],
        )
        raise HTTPException(status_code=500, detail="demo_request_persist_failed")

    if not row:
        raise HTTPException(status_code=500, detail="demo_request_persist_failed")

    record = _iso_record(dict(row))
    notification_status = "not_attempted"
    try:
        delivery = send_intake_notifications("demo", {**record, **params})
        notification_status = str(delivery.get("status") or "delivered")
    except NotificationDeliveryError as exc:
        notification_status = "delivery_failed_after_persist"
        log_event(
            logging.ERROR,
            "intake.demo.notification_failed",
            request_id=_request_id(request),
            intake_request_id=record["id"],
            error_type=type(exc).__name__,
            error=str(exc)[:240],
        )

    log_event(
        logging.INFO,
        "intake.demo.created",
        request_id=_request_id(request),
        intake_request_id=record["id"],
        source_page=record.get("source_page"),
        email_hash=hash_with_salt(str(body.work_email).lower()),
        notification_status=notification_status,
    )

    return IntakeCreateResponse(
        request_id=str(record["id"]),
        created_at=str(record["created_at"]),
        notification_status=notification_status,
    )


@router.post("/start-request", response_model=IntakeCreateResponse)
def create_start_request(request: Request, body: StartRequestCreate) -> IntakeCreateResponse:
    _reject_honeypot(request, body.website, body.company_website)

    params = {
        "clinic_name": body.clinic_name,
        "full_name": body.full_name,
        "work_email": str(body.work_email),
        "role": body.role,
        "preferred_plan": body.preferred_plan,
        "clinic_size": body.clinic_size,
        "current_ai_use": body.current_ai_use,
        "rollout_timing": body.rollout_timing,
        "phone": body.phone,
        "site_count": body.site_count,
        "message": body.message,
        "consent": body.consent,
        "source_page": body.source_page,
        "utm_source": body.utm_source,
        "utm_medium": body.utm_medium,
        "utm_campaign": body.utm_campaign,
    }

    try:
        with SessionLocal() as db:
            row = db.execute(
                text(
                    """
                    INSERT INTO start_requests (
                      clinic_name, full_name, work_email, role, preferred_plan, clinic_size,
                      current_ai_use, rollout_timing, phone, site_count, message, consent,
                      source_page, utm_source, utm_medium, utm_campaign
                    )
                    VALUES (
                      :clinic_name, :full_name, :work_email, :role, :preferred_plan, :clinic_size,
                      :current_ai_use, :rollout_timing, :phone, :site_count, :message, :consent,
                      :source_page, :utm_source, :utm_medium, :utm_campaign
                    )
                    RETURNING id, created_at, clinic_name, work_email, full_name, status, source_page
                    """
                ),
                params,
            ).mappings().first()
            db.commit()
    except Exception as exc:
        log_event(
            logging.ERROR,
            "intake.start.persist_failed",
            request_id=_request_id(request),
            source_page=body.source_page,
            email_hash=hash_with_salt(str(body.work_email).lower()),
            error_type=type(exc).__name__,
            error=str(exc)[:240],
        )
        raise HTTPException(status_code=500, detail="start_request_persist_failed")

    if not row:
        raise HTTPException(status_code=500, detail="start_request_persist_failed")

    record = _iso_record(dict(row))
    notification_status = "not_attempted"
    try:
        delivery = send_intake_notifications("start", {**record, **params})
        notification_status = str(delivery.get("status") or "delivered")
    except NotificationDeliveryError as exc:
        notification_status = "delivery_failed_after_persist"
        log_event(
            logging.ERROR,
            "intake.start.notification_failed",
            request_id=_request_id(request),
            intake_request_id=record["id"],
            error_type=type(exc).__name__,
            error=str(exc)[:240],
        )

    log_event(
        logging.INFO,
        "intake.start.created",
        request_id=_request_id(request),
        intake_request_id=record["id"],
        source_page=record.get("source_page"),
        email_hash=hash_with_salt(str(body.work_email).lower()),
        notification_status=notification_status,
    )

    return IntakeCreateResponse(
        request_id=str(record["id"]),
        created_at=str(record["created_at"]),
        notification_status=notification_status,
    )


@router.post("/site-chat/log", response_model=ChatLogResponse)
def log_public_site_chat_event(request: Request, body: PublicSiteChatEventCreate) -> ChatLogResponse:
    redacted, contains_email, contains_phone = redact_contact_details(body.question_text)

    params = {
        "session_id": body.session_id,
        "question_text": body.question_text,
        "question_text_redacted": redacted,
        "question_category": body.question_category,
        "matched_topic": body.matched_topic,
        "answer_confidence": body.answer_confidence,
        "suggested_cta": body.suggested_cta,
        "source_page": body.source_page,
        "utm_source": body.utm_source,
        "utm_medium": body.utm_medium,
        "utm_campaign": body.utm_campaign,
        "contains_email": contains_email,
        "contains_phone": contains_phone,
    }

    try:
        with SessionLocal() as db:
            row = db.execute(
                text(
                    """
                    INSERT INTO public_site_chat_events (
                      session_id, question_text, question_text_redacted, question_category,
                      matched_topic, answer_confidence, suggested_cta, source_page,
                      utm_source, utm_medium, utm_campaign, contains_email, contains_phone
                    )
                    VALUES (
                      :session_id, :question_text, :question_text_redacted, :question_category,
                      :matched_topic, :answer_confidence, :suggested_cta, :source_page,
                      :utm_source, :utm_medium, :utm_campaign, :contains_email, :contains_phone
                    )
                    RETURNING id, created_at
                    """
                ),
                params,
            ).mappings().first()
            db.commit()
    except Exception as exc:
        log_event(
            logging.ERROR,
            "intake.site_chat.persist_failed",
            request_id=_request_id(request),
            source_page=body.source_page,
            error_type=type(exc).__name__,
            error=str(exc)[:240],
        )
        raise HTTPException(status_code=500, detail="site_chat_log_persist_failed")

    if not row:
        raise HTTPException(status_code=500, detail="site_chat_log_persist_failed")

    event = _iso_record(dict(row))
    log_event(
        logging.INFO,
        "intake.site_chat.created",
        request_id=_request_id(request),
        event_id=event["id"],
        source_page=body.source_page,
        contains_email=contains_email,
        contains_phone=contains_phone,
        question_category=body.question_category,
        matched_topic=body.matched_topic,
    )

    return ChatLogResponse(event_id=str(event["id"]), created_at=str(event["created_at"]))
