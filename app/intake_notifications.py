from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List
from urllib import request
from urllib.error import URLError

from app.anchor_logging import log_event


class NotificationDeliveryError(RuntimeError):
    pass


def _post_json(url: str, payload: Dict[str, Any], *, timeout_s: int = 5) -> None:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    req = request.Request(
        url=url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=timeout_s) as resp:
        status_code = int(getattr(resp, "status", 200) or 200)
        if status_code >= 400:
            raise NotificationDeliveryError(f"webhook_http_{status_code}")


def _subject(kind: str, clinic_name: str) -> str:
    if kind == "demo":
        return f"New ANCHOR demo request - {clinic_name}"
    return f"New ANCHOR start request - {clinic_name}"


def _delivery_target(env_name: str) -> str:
    return (os.getenv(env_name) or "").strip()


def _deliver(
    *,
    event_name: str,
    target_name: str,
    url: str,
    payload: Dict[str, Any],
) -> Dict[str, str]:
    try:
        _post_json(url, payload)
        log_event(
            logging.INFO,
            event_name,
            target=target_name,
            delivery_status="delivered",
        )
        return {"target": target_name, "status": "delivered"}
    except (NotificationDeliveryError, URLError, TimeoutError, ValueError) as exc:
        log_event(
            logging.ERROR,
            event_name,
            target=target_name,
            delivery_status="failed",
            error_type=type(exc).__name__,
            error=str(exc)[:240],
        )
        raise NotificationDeliveryError(f"{target_name}:{type(exc).__name__}")


def send_intake_notifications(kind: str, record: Dict[str, Any]) -> Dict[str, Any]:
    clinic_name = str(record.get("clinic_name") or "").strip() or "Unknown clinic"
    payload_base = {
        "kind": kind,
        "subject": _subject(kind, clinic_name),
        "record": record,
    }

    results: List[Dict[str, str]] = []
    failures: List[str] = []

    notification_url = _delivery_target("ANCHOR_INTAKE_NOTIFICATION_WEBHOOK_URL")
    if notification_url:
        try:
            results.append(
                _deliver(
                    event_name="intake.notification.internal",
                    target_name="internal_notification",
                    url=notification_url,
                    payload={**payload_base, "delivery_type": "internal_notification"},
                )
            )
        except NotificationDeliveryError as exc:
            failures.append(str(exc))
    else:
        log_event(
            logging.INFO,
            "intake.notification.stubbed",
            target="internal_notification",
            reason="webhook_not_configured",
        )
        results.append({"target": "internal_notification", "status": "stubbed"})

    ack_url = _delivery_target("ANCHOR_INTAKE_ACK_WEBHOOK_URL")
    if ack_url:
        try:
            results.append(
                _deliver(
                    event_name="intake.notification.ack",
                    target_name="acknowledgement",
                    url=ack_url,
                    payload={
                        **payload_base,
                        "delivery_type": "acknowledgement",
                        "recipient_email": record.get("work_email"),
                    },
                )
            )
        except NotificationDeliveryError as exc:
            failures.append(str(exc))
    else:
        log_event(
            logging.INFO,
            "intake.notification.stubbed",
            target="acknowledgement",
            reason="webhook_not_configured",
        )
        results.append({"target": "acknowledgement", "status": "stubbed"})

    if failures:
        raise NotificationDeliveryError(",".join(failures))

    statuses = {item["status"] for item in results}
    if statuses == {"stubbed"}:
        overall = "stubbed"
    elif "stubbed" in statuses:
        overall = "partial_stubbed"
    else:
        overall = "delivered"

    return {"status": overall, "deliveries": results}
