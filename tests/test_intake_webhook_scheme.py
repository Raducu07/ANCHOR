"""Intake webhook HTTPS-only enforcement tests.

2A-D.1 security seed follow-up (Finding B, hardening candidate): the
intake notification / acknowledgement webhook payloads carry public
intake contact PII, so a misconfigured non-HTTPS target must be refused
before any byte is sent.

Covers:
  * http:// notification target -> refused, no POST attempted, raises
  * http:// ack target -> refused, no POST attempted, raises
  * https:// target -> delivered via the (fake) POST helper
  * scheme check is case-insensitive (HTTPS:// allowed)
  * unset env vars -> stubbed behaviour unchanged
  * the refusal message never contains the URL value

No network I/O is performed - the POST helper is monkeypatched.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("DATABASE_URL", "postgresql://x:y@localhost:5432/z")
os.environ.setdefault("RATE_LIMIT_ENABLED", "0")
os.environ.setdefault("ANCHOR_JWT_SECRET", "test")

from app import intake_notifications as notif  # noqa: E402


_NOTIF_ENV = "ANCHOR_INTAKE_NOTIFICATION_WEBHOOK_URL"
_ACK_ENV = "ANCHOR_INTAKE_ACK_WEBHOOK_URL"

_RECORD: Dict[str, Any] = {
    "clinic_name": "Test Clinic",
    "work_email": "placeholder@example.invalid",
}


class _PostRecorder:
    def __init__(self) -> None:
        self.calls: List[str] = []

    def __call__(self, url: str, payload: Dict[str, Any], *, timeout_s: int = 5) -> None:
        self.calls.append(url)


@pytest.fixture()
def post_recorder(monkeypatch: pytest.MonkeyPatch) -> _PostRecorder:
    recorder = _PostRecorder()
    monkeypatch.setattr(notif, "_post_json", recorder)
    return recorder


def test_http_notification_target_is_refused_without_post(
    monkeypatch: pytest.MonkeyPatch, post_recorder: _PostRecorder
) -> None:
    monkeypatch.setenv(_NOTIF_ENV, "http://plain-http.example.invalid/hook")
    monkeypatch.delenv(_ACK_ENV, raising=False)

    with pytest.raises(notif.NotificationDeliveryError) as excinfo:
        notif.send_intake_notifications("demo", dict(_RECORD))

    assert post_recorder.calls == []
    assert "non_https_refused" in str(excinfo.value)
    # The URL value must never leak into the raised message.
    assert "plain-http.example.invalid" not in str(excinfo.value)


def test_http_ack_target_is_refused_without_post(
    monkeypatch: pytest.MonkeyPatch, post_recorder: _PostRecorder
) -> None:
    monkeypatch.delenv(_NOTIF_ENV, raising=False)
    monkeypatch.setenv(_ACK_ENV, "http://plain-http.example.invalid/ack")

    with pytest.raises(notif.NotificationDeliveryError) as excinfo:
        notif.send_intake_notifications("start", dict(_RECORD))

    assert post_recorder.calls == []
    assert "acknowledgement:non_https_refused" in str(excinfo.value)


def test_https_target_is_delivered(
    monkeypatch: pytest.MonkeyPatch, post_recorder: _PostRecorder
) -> None:
    monkeypatch.setenv(_NOTIF_ENV, "https://internal-queue.example.invalid/hook")
    monkeypatch.delenv(_ACK_ENV, raising=False)

    result = notif.send_intake_notifications("demo", dict(_RECORD))

    assert post_recorder.calls == [
        "https://internal-queue.example.invalid/hook"
    ]
    statuses = {d["target"]: d["status"] for d in result["deliveries"]}
    assert statuses["internal_notification"] == "delivered"
    assert statuses["acknowledgement"] == "stubbed"
    assert result["status"] == "partial_stubbed"


def test_uppercase_https_scheme_is_allowed(
    monkeypatch: pytest.MonkeyPatch, post_recorder: _PostRecorder
) -> None:
    monkeypatch.setenv(_NOTIF_ENV, "HTTPS://internal-queue.example.invalid/hook")
    monkeypatch.delenv(_ACK_ENV, raising=False)

    result = notif.send_intake_notifications("demo", dict(_RECORD))
    assert len(post_recorder.calls) == 1
    assert result["status"] == "partial_stubbed"


def test_unset_env_vars_remain_stubbed(
    monkeypatch: pytest.MonkeyPatch, post_recorder: _PostRecorder
) -> None:
    monkeypatch.delenv(_NOTIF_ENV, raising=False)
    monkeypatch.delenv(_ACK_ENV, raising=False)

    result = notif.send_intake_notifications("demo", dict(_RECORD))
    assert post_recorder.calls == []
    assert result["status"] == "stubbed"


@pytest.mark.parametrize(
    "bad_url",
    [
        "ftp://queue.example.invalid/hook",
        "file:///C:/temp/hook",
        "queue.example.invalid/hook",  # schemeless
    ],
)
def test_other_schemes_are_refused(
    monkeypatch: pytest.MonkeyPatch,
    post_recorder: _PostRecorder,
    bad_url: str,
) -> None:
    monkeypatch.setenv(_NOTIF_ENV, bad_url)
    monkeypatch.delenv(_ACK_ENV, raising=False)

    with pytest.raises(notif.NotificationDeliveryError):
        notif.send_intake_notifications("demo", dict(_RECORD))
    assert post_recorder.calls == []
