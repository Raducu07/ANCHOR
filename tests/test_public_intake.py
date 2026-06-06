"""
2A-D.1 backend security hardening — Patch 3 public intake tests.

Covers:
  * Rate-limit (`public_intake` group) on demo-request, start-request,
    site-chat/log.
  * Honeypot parity on site-chat/log.
  * Tightened validation: question_text >500 → 422 (not silently
    truncated); demo/start message >1000 → 422.
  * Existing demo/start honeypot still returns 400.

No real Postgres, no Anthropic, no notification webhooks, no live
generation. SessionLocal calls are sidestepped by patching the in-handler
SessionLocal context manager with a no-op DB that returns canned rows.
"""
from __future__ import annotations

import os
import sys
import uuid as _uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Deterministic limiter env BEFORE importing app.rate_limit.
os.environ.setdefault("RATE_LIMIT_ENABLED", "1")
os.environ.setdefault("RATE_LIMIT_SECRET", "test-secret-patch3")

from app import rate_limit as rl  # noqa: E402
from app import public_intake as public_intake_module  # noqa: E402
from app.public_intake import router as public_intake_router  # noqa: E402


# ---------------------------------------------------------------------
# Isolated, tight limiter so each test fires a 429 within a few calls.
# ---------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolated_limiter(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(
        rl, "LIMITER", rl.FixedWindowRateLimiter(secret="test-secret-patch3")
    )
    monkeypatch.setattr(
        rl,
        "RULES",
        {
            "auth": rl.RateLimitRule(window_s=60, limit=2),
            "invite": rl.RateLimitRule(window_s=60, limit=2),
            "receipt": rl.RateLimitRule(window_s=60, limit=2),
            "export": rl.RateLimitRule(window_s=60, limit=2),
            "assistant_submit": rl.RateLimitRule(window_s=60, limit=2),
            "public_intake": rl.RateLimitRule(window_s=60, limit=2),
            "admin": rl.RateLimitRule(window_s=60, limit=2),
            "admin_bootstrap": rl.RateLimitRule(window_s=60, limit=2),
        },
    )
    rl._reset_rate_limit_state_for_tests()
    yield
    rl._reset_rate_limit_state_for_tests()


# ---------------------------------------------------------------------
# Fake SessionLocal that records calls and returns a canned RETURNING row.
# ---------------------------------------------------------------------

class _FakeRow:
    def __init__(self, data: Dict[str, Any]):
        self._data = data

    def mappings(self) -> "_FakeRow":
        return self

    def first(self) -> Dict[str, Any]:
        return self._data


class _FakeDB:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Dict[str, Any]]] = []
        self.committed = False

    def execute(self, statement: Any, params: Dict[str, Any] | None = None):
        sql = str(getattr(statement, "text", statement))
        self.calls.append((sql, dict(params or {})))
        row = {
            "id": _uuid.uuid4(),
            "created_at": datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc),
            "clinic_name": params.get("clinic_name") if params else None,
            "work_email": params.get("work_email") if params else None,
            "full_name": params.get("full_name") if params else None,
            "status": "new",
            "source_page": params.get("source_page") if params else None,
        }
        return _FakeRow(row)

    def commit(self) -> None:
        self.committed = True


@contextmanager
def _fake_session_local_cm():
    yield _FakeDB()


@pytest.fixture(autouse=True)
def _patch_session_local_and_notifications(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Stub SessionLocal() context manager and the notification fan-out so
    handlers complete without Postgres / webhook IO. Notifications are
    coerced to a stubbed status."""

    class _DBFactory:
        def __call__(self):
            return _fake_session_local_cm()

    monkeypatch.setattr(public_intake_module, "SessionLocal", _DBFactory())
    monkeypatch.setattr(
        public_intake_module,
        "send_intake_notifications",
        lambda kind, record: {"status": "stubbed"},
    )
    yield


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(public_intake_router)
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------

def _demo_body(**overrides) -> Dict[str, Any]:
    base = {
        "full_name": "Test User",
        "work_email": "test@example.com",
        "clinic_name": "Test Vet",
        "role": "owner",
        "current_ai_use": "none",
        "primary_interest": "governance",
        "biggest_concern": "compliance posture",
        "consent": True,
    }
    base.update(overrides)
    return base


def _start_body(**overrides) -> Dict[str, Any]:
    base = {
        "clinic_name": "Test Vet",
        "full_name": "Test User",
        "work_email": "test@example.com",
        "role": "owner",
        "preferred_plan": "starter",
        "clinic_size": "1-5",
        "current_ai_use": "none",
        "rollout_timing": "this quarter",
        "consent": True,
    }
    base.update(overrides)
    return base


def _chat_body(**overrides) -> Dict[str, Any]:
    base = {
        "question_text": "How does ANCHOR handle policy templates?",
        "session_id": "s-1",
        "source_page": "/pricing",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------
# Rate limit tests
# ---------------------------------------------------------------------

def test_demo_request_429_after_public_intake_budget(client: TestClient) -> None:
    saw_429 = False
    for _ in range(5):
        resp = client.post("/v1/public/demo-request", json=_demo_body())
        if resp.status_code == 429:
            assert "Retry-After" in resp.headers
            saw_429 = True
            break
    assert saw_429, "Expected 429 from public_intake budget exhaustion"


def test_start_request_429_after_public_intake_budget(client: TestClient) -> None:
    saw_429 = False
    for _ in range(5):
        resp = client.post("/v1/public/start-request", json=_start_body())
        if resp.status_code == 429:
            assert "Retry-After" in resp.headers
            saw_429 = True
            break
    assert saw_429


def test_site_chat_log_429_after_public_intake_budget(client: TestClient) -> None:
    saw_429 = False
    for _ in range(5):
        resp = client.post("/v1/public/site-chat/log", json=_chat_body())
        if resp.status_code == 429:
            assert "Retry-After" in resp.headers
            saw_429 = True
            break
    assert saw_429


# ---------------------------------------------------------------------
# Honeypot tests
# ---------------------------------------------------------------------

def test_site_chat_log_honeypot_returns_400(client: TestClient) -> None:
    resp = client.post(
        "/v1/public/site-chat/log",
        json=_chat_body(website="https://spam.example.com"),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "invalid_submission"


def test_site_chat_log_honeypot_via_company_website_returns_400(client: TestClient) -> None:
    resp = client.post(
        "/v1/public/site-chat/log",
        json=_chat_body(company_website="spam"),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "invalid_submission"


def test_demo_request_honeypot_still_returns_400(client: TestClient) -> None:
    """Regression guard for the existing demo honeypot path."""
    resp = client.post(
        "/v1/public/demo-request",
        json=_demo_body(website="https://spam.example.com"),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "invalid_submission"


def test_start_request_honeypot_still_returns_400(client: TestClient) -> None:
    resp = client.post(
        "/v1/public/start-request",
        json=_start_body(company_website="https://spam.example.com"),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "invalid_submission"


# ---------------------------------------------------------------------
# Validation tightening tests
# ---------------------------------------------------------------------

def test_site_chat_question_text_over_500_is_rejected_422(client: TestClient) -> None:
    """Patch 3: the schema must reject >500-char question_text rather than
    silently clamping. (The DB CHECK was always 500; this aligns the wire.)"""
    body = _chat_body(question_text="x" * 501)
    resp = client.post("/v1/public/site-chat/log", json=body)
    assert resp.status_code == 422


def test_site_chat_question_text_exactly_500_is_accepted(client: TestClient) -> None:
    body = _chat_body(question_text="x" * 500)
    resp = client.post("/v1/public/site-chat/log", json=body)
    # 200 success or 429 if a prior test in this client run exhausted the
    # bucket — either way, NOT 422.
    assert resp.status_code != 422


def test_demo_request_message_over_1000_is_rejected_422(client: TestClient) -> None:
    body = _demo_body(message="m" * 1001)
    resp = client.post("/v1/public/demo-request", json=body)
    assert resp.status_code == 422


def test_demo_request_message_exactly_1000_is_accepted(client: TestClient) -> None:
    body = _demo_body(message="m" * 1000)
    resp = client.post("/v1/public/demo-request", json=body)
    assert resp.status_code != 422


def test_start_request_message_over_1000_is_rejected_422(client: TestClient) -> None:
    body = _start_body(message="m" * 1001)
    resp = client.post("/v1/public/start-request", json=body)
    assert resp.status_code == 422


def test_demo_request_biggest_concern_over_500_is_rejected_422(client: TestClient) -> None:
    """Regression guard: biggest_concern cap is still 500."""
    body = _demo_body(biggest_concern="c" * 501)
    resp = client.post("/v1/public/demo-request", json=body)
    assert resp.status_code == 422
