from __future__ import annotations

from typing import Any, Dict, List

import pytest
from pydantic import ValidationError

from app.intake_common import MAX_CHAT_QUESTION_LENGTH, redact_contact_details
from app.intake_notifications import NotificationDeliveryError, send_intake_notifications
from app.intake_schemas import DemoRequestCreate, PublicSiteChatEventCreate, UpdateIntakeRequest


def test_redact_contact_details_marks_email_and_phone() -> None:
    redacted, contains_email, contains_phone = redact_contact_details(
        "Email me at sam@example.com or call +44 20 7946 0958 about ANCHOR"
    )

    assert contains_email is True
    assert contains_phone is True
    assert redacted is not None
    assert "[redacted-email]" in redacted
    assert "[redacted-phone]" in redacted


def test_public_site_chat_event_caps_question_length() -> None:
    # 2A-D.2 Patch 11D-b: under the post-Patch-3 schema, `question_text` is
    # capped at `MAX_CHAT_QUESTION_LENGTH=500` at the Pydantic field level
    # (Field(..., min_length=1, max_length=MAX_CHAT_QUESTION_LENGTH) in
    # `PublicSiteChatEventCreate`). Over-cap input is rejected at the wire
    # (HTTP 422 in the route; ValidationError when constructed directly),
    # NOT silently clamped — this is the deliberate Patch 3 tightening so
    # the schema and the DB CHECK on `public_site_chat_events.question_text`
    # agree. Exactly-cap input continues to validate cleanly.
    with pytest.raises(ValidationError):
        PublicSiteChatEventCreate(
            question_text="x" * (MAX_CHAT_QUESTION_LENGTH + 20)
        )

    at_cap = PublicSiteChatEventCreate(
        question_text="x" * MAX_CHAT_QUESTION_LENGTH
    )
    assert len(at_cap.question_text) == MAX_CHAT_QUESTION_LENGTH


def test_demo_request_requires_consent_and_accepts_honeypot_alias() -> None:
    with pytest.raises(ValidationError):
        DemoRequestCreate(
            full_name="Sam Vet",
            work_email="sam@example.com",
            clinic_name="Green Lane Vets",
            role="Practice Manager",
            current_ai_use="None yet",
            primary_interest="Governance",
            biggest_concern="Unsafe rollout",
            consent=False,
        )

    model = DemoRequestCreate(
        full_name="Sam Vet",
        work_email="sam@example.com",
        clinic_name="Green Lane Vets",
        role="Practice Manager",
        current_ai_use="None yet",
        primary_interest="Governance",
        biggest_concern="Unsafe rollout",
        consent=True,
        honeypot="bot-filled",
    )

    assert model.company_website == "bot-filled"


def test_update_intake_request_requires_a_change() -> None:
    with pytest.raises(ValidationError):
        UpdateIntakeRequest()

    model = UpdateIntakeRequest(notes="")
    assert model.notes is None


def test_notification_adapter_is_honestly_stubbed_when_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANCHOR_INTAKE_NOTIFICATION_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("ANCHOR_INTAKE_ACK_WEBHOOK_URL", raising=False)

    result = send_intake_notifications(
        "demo",
        {"clinic_name": "Green Lane Vets", "work_email": "sam@example.com"},
    )

    assert result["status"] == "stubbed"


def test_notification_adapter_posts_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: List[Dict[str, Any]] = []

    def fake_post(url: str, payload: Dict[str, Any], *, timeout_s: int = 5) -> None:
        calls.append({"url": url, "payload": payload, "timeout_s": timeout_s})

    monkeypatch.setenv("ANCHOR_INTAKE_NOTIFICATION_WEBHOOK_URL", "https://example.test/internal")
    monkeypatch.setenv("ANCHOR_INTAKE_ACK_WEBHOOK_URL", "https://example.test/ack")
    monkeypatch.setattr("app.intake_notifications._post_json", fake_post)

    result = send_intake_notifications(
        "start",
        {"clinic_name": "Green Lane Vets", "work_email": "sam@example.com"},
    )

    assert result["status"] == "delivered"
    assert [call["url"] for call in calls] == [
        "https://example.test/internal",
        "https://example.test/ack",
    ]


def test_notification_adapter_raises_on_delivery_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_post(url: str, payload: Dict[str, Any], *, timeout_s: int = 5) -> None:
        raise NotificationDeliveryError("boom")

    monkeypatch.setenv("ANCHOR_INTAKE_NOTIFICATION_WEBHOOK_URL", "https://example.test/internal")
    monkeypatch.delenv("ANCHOR_INTAKE_ACK_WEBHOOK_URL", raising=False)
    monkeypatch.setattr("app.intake_notifications._post_json", fake_post)

    with pytest.raises(NotificationDeliveryError):
        send_intake_notifications(
            "demo",
            {"clinic_name": "Green Lane Vets", "work_email": "sam@example.com"},
        )
