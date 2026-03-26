from __future__ import annotations

import os
from typing import Callable

import pytest
from fastapi import HTTPException
from starlette.requests import Request

# Make import-time limiter construction deterministic for local runs and CI.
os.environ.setdefault("RATE_LIMIT_ENABLED", "1")
os.environ.setdefault("RATE_LIMIT_SECRET", "test-secret")

from app import rate_limit as rl  # noqa: E402


def _make_request(
    path: str,
    *,
    ip: str = "203.0.113.10",
    ua: str = "pytest/anchor",
    clinic_id: str = "clinic-test",
    clinic_user_id: str = "user-test",
    role: str = "admin",
) -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": [
            (b"host", b"testserver"),
            (b"user-agent", ua.encode("utf-8")),
            (b"x-forwarded-for", ip.encode("utf-8")),
        ],
        "client": (ip, 12345),
        "server": ("testserver", 443),
    }
    req = Request(scope)
    req.state.clinic_id = clinic_id
    req.state.clinic_user_id = clinic_user_id
    req.state.role = role
    return req


def _hit_until_429(fn: Callable[[], None], *, max_calls: int = 50) -> int:
    ok = 0
    for _ in range(max_calls):
        try:
            fn()
            ok += 1
        except HTTPException as exc:
            assert exc.status_code == 429
            assert exc.detail == "rate_limited"
            assert "Retry-After" in (exc.headers or {})
            return ok
    raise AssertionError("Expected a 429 within max_calls")


@pytest.fixture(autouse=True)
def _isolated_limiter(monkeypatch):
    monkeypatch.setattr(rl, "LIMITER", rl.FixedWindowRateLimiter(secret="test-secret"))
    monkeypatch.setattr(
        rl,
        "RULES",
        {
            "auth": rl.RateLimitRule(window_s=60, limit=2),
            "invite": rl.RateLimitRule(window_s=60, limit=2),
            "receipt": rl.RateLimitRule(window_s=60, limit=2),
            "export": rl.RateLimitRule(window_s=60, limit=2),
            "admin": rl.RateLimitRule(window_s=60, limit=2),
            "admin_bootstrap": rl.RateLimitRule(window_s=60, limit=2),
        },
    )
    rl._reset_rate_limit_state_for_tests()
    yield
    rl._reset_rate_limit_state_for_tests()


def test_auth_limit_blocks_n_plus_one(monkeypatch):
    now = {"t": 1_700_000_000.0}
    monkeypatch.setattr(rl.time, "time", lambda: now["t"])

    request = _make_request("/v1/clinic/auth/login")
    ok = _hit_until_429(lambda: rl.enforce_ip(request, "auth"))

    assert ok == 2


def test_auth_limit_resets_after_window_rollover(monkeypatch):
    now = {"t": 1_700_000_000.0}
    monkeypatch.setattr(rl.time, "time", lambda: now["t"])

    request = _make_request("/v1/clinic/auth/login")

    ok = _hit_until_429(lambda: rl.enforce_ip(request, "auth"))
    assert ok == 2

    now["t"] += 61.0
    rl.enforce_ip(request, "auth")


def test_auth_and_invite_are_distinct_buckets(monkeypatch):
    now = {"t": 1_700_000_000.0}
    monkeypatch.setattr(rl.time, "time", lambda: now["t"])

    request = _make_request("/v1/clinic/auth/login")

    _hit_until_429(lambda: rl.enforce_ip(request, "auth"))
    rl.enforce_ip(request, "invite")


def test_receipt_and_export_are_distinct_authed_buckets(monkeypatch):
    now = {"t": 1_700_000_000.0}
    monkeypatch.setattr(rl.time, "time", lambda: now["t"])

    request = _make_request("/v1/portal/receipt/abc123")

    _hit_until_429(
        lambda: rl.enforce_authed(
            request,
            clinic_id=str(request.state.clinic_id),
            clinic_user_id=str(request.state.clinic_user_id),
            group="receipt",
        )
    )

    rl.enforce_authed(
        request,
        clinic_id=str(request.state.clinic_id),
        clinic_user_id=str(request.state.clinic_user_id),
        group="export",
    )


def test_admin_and_admin_bootstrap_are_distinct_groups(monkeypatch):
    now = {"t": 1_700_000_000.0}
    monkeypatch.setattr(rl.time, "time", lambda: now["t"])

    request = _make_request("/v1/admin/bootstrap/clinic")
    token = "pytest-admin-token"

    _hit_until_429(lambda: rl.enforce_admin_token(request, token))
    rl.enforce_admin_token_group(request, token, group="admin_bootstrap")