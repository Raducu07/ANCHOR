"""
2A-D.1 backend security hardening — Patch 1 tests.

Covers:
  B-1  CORS allow_origin_regex is gated to non-prod (no implicit localhost
       allow-list in production).
  M-2  ANCHOR_HASH_SALT / ANCHOR_LOG_SALT fail-closed in production when
       missing or equal to the default fallback literal.
  M-3  ANCHOR_ADMIN_PEPPER fail-closed in production when missing or equal
       to the default fallback literal.

These tests do not touch the database, do not start the lifespan, and do
not enable live generation. They exercise small pure helpers and the
fail-closed assertions directly.
"""
from __future__ import annotations

import re

import pytest

from app.admin_auth import (
    DEFAULT_ADMIN_PEPPER_LITERAL,
    _admin_mode,
    assert_admin_mode_for_prod,
    assert_admin_pepper_for_prod,
)
from app.anchor_logging import (
    DEFAULT_HASH_SALT_LITERAL,
    assert_hash_salt_for_prod,
)
from app.main import _LOCALHOST_CORS_REGEX, _compute_cors_origin_regex


# ---------------------------------------------------------------------
# B-1: CORS allow_origin_regex production gate
# ---------------------------------------------------------------------


def test_cors_origin_regex_is_none_in_prod() -> None:
    """In production we must NOT silently permit localhost / 127.0.0.1."""
    assert _compute_cors_origin_regex("prod") is None


def test_cors_origin_regex_is_none_in_prod_case_insensitive() -> None:
    assert _compute_cors_origin_regex("PROD") is None
    assert _compute_cors_origin_regex(" prod ") is None


def test_cors_origin_regex_allows_localhost_in_dev() -> None:
    """Local dev keeps the existing convenience regex so dev tooling works."""
    regex = _compute_cors_origin_regex("dev")
    assert regex == _LOCALHOST_CORS_REGEX

    pattern = re.compile(regex)
    assert pattern.match("http://localhost:5173")
    assert pattern.match("http://127.0.0.1:8000")
    assert pattern.match("https://localhost")
    # Sanity: a non-localhost origin should NOT match the dev regex either.
    assert not pattern.match("https://evil.example.com")


def test_cors_origin_regex_allows_localhost_in_test_and_staging() -> None:
    assert _compute_cors_origin_regex("test") == _LOCALHOST_CORS_REGEX
    assert _compute_cors_origin_regex("staging") == _LOCALHOST_CORS_REGEX
    assert _compute_cors_origin_regex("") == _LOCALHOST_CORS_REGEX


def test_prod_cors_localhost_origin_rejected_via_middleware(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Functional check: a freshly-configured CORSMiddleware in prod must not
    echo Access-Control-Allow-Origin for a localhost preflight, even though
    the CORS_ALLOW_ORIGINS list is set (to a non-localhost origin).
    """
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("CORS_ALLOW_ORIGINS", "https://portal.example.com")
    monkeypatch.setenv("CORS_ALLOW_CREDENTIALS", "true")
    # Ensure the prod-mode fail-closed checks don't fire when we never run
    # the lifespan — we only build the app object here.
    monkeypatch.setenv("ANCHOR_HASH_SALT", "prod-real-salt")
    monkeypatch.setenv("ANCHOR_ADMIN_PEPPER", "prod-real-pepper")

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.main import _configure_edge_middlewares

    app = FastAPI()
    _configure_edge_middlewares(app)

    @app.get("/ping")
    def ping():  # pragma: no cover - trivial
        return {"ok": True}

    client = TestClient(app)
    resp = client.options(
        "/ping",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    # Starlette returns 400 when no CORS handler accepts the origin.
    assert "access-control-allow-origin" not in {k.lower() for k in resp.headers.keys()}


def test_nonprod_cors_localhost_origin_accepted_via_middleware(monkeypatch: pytest.MonkeyPatch) -> None:
    """Local dev preserves localhost convenience — regression guard."""
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("CORS_ALLOW_ORIGINS", "https://portal.example.com")
    monkeypatch.setenv("CORS_ALLOW_CREDENTIALS", "true")

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.main import _configure_edge_middlewares

    app = FastAPI()
    _configure_edge_middlewares(app)

    @app.get("/ping")
    def ping():  # pragma: no cover - trivial
        return {"ok": True}

    client = TestClient(app)
    resp = client.options(
        "/ping",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    allow_origin = resp.headers.get("access-control-allow-origin")
    assert allow_origin == "http://localhost:5173"


# ---------------------------------------------------------------------
# M-2: hash salt fail-closed in prod
# ---------------------------------------------------------------------


def _clear_salt_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANCHOR_HASH_SALT", raising=False)
    monkeypatch.delenv("ANCHOR_LOG_SALT", raising=False)


def test_hash_salt_noop_outside_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-prod must keep working even with no salt configured (test suite
    relies on this)."""
    monkeypatch.setenv("APP_ENV", "dev")
    _clear_salt_env(monkeypatch)
    assert_hash_salt_for_prod()  # must not raise


def test_hash_salt_fail_closed_when_missing_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    _clear_salt_env(monkeypatch)
    with pytest.raises(RuntimeError, match="ANCHOR_HASH_SALT"):
        assert_hash_salt_for_prod()


def test_hash_salt_fail_closed_on_default_literal_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_HASH_SALT", DEFAULT_HASH_SALT_LITERAL)
    monkeypatch.delenv("ANCHOR_LOG_SALT", raising=False)
    with pytest.raises(RuntimeError, match="default fallback"):
        assert_hash_salt_for_prod()


def test_hash_salt_fail_closed_on_default_literal_via_legacy_env_in_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.delenv("ANCHOR_HASH_SALT", raising=False)
    monkeypatch.setenv("ANCHOR_LOG_SALT", DEFAULT_HASH_SALT_LITERAL)
    with pytest.raises(RuntimeError, match="default fallback"):
        assert_hash_salt_for_prod()


def test_hash_salt_passes_on_real_value_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_HASH_SALT", "rotated-prod-salt-v1")
    monkeypatch.delenv("ANCHOR_LOG_SALT", raising=False)
    assert_hash_salt_for_prod()  # must not raise


def test_hash_salt_legacy_env_accepted_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.delenv("ANCHOR_HASH_SALT", raising=False)
    monkeypatch.setenv("ANCHOR_LOG_SALT", "rotated-prod-salt-v1")
    assert_hash_salt_for_prod()  # must not raise


# ---------------------------------------------------------------------
# M-3: admin pepper fail-closed in prod
# ---------------------------------------------------------------------


def test_admin_pepper_noop_outside_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.delenv("ANCHOR_ADMIN_PEPPER", raising=False)
    assert_admin_pepper_for_prod()  # must not raise


def test_admin_pepper_fail_closed_when_missing_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.delenv("ANCHOR_ADMIN_PEPPER", raising=False)
    with pytest.raises(RuntimeError, match="ANCHOR_ADMIN_PEPPER"):
        assert_admin_pepper_for_prod()


def test_admin_pepper_fail_closed_on_default_literal_in_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_ADMIN_PEPPER", DEFAULT_ADMIN_PEPPER_LITERAL)
    with pytest.raises(RuntimeError, match="default fallback"):
        assert_admin_pepper_for_prod()


def test_admin_pepper_passes_on_real_value_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_ADMIN_PEPPER", "rotated-prod-admin-pepper-v1")
    assert_admin_pepper_for_prod()  # must not raise


# ---------------------------------------------------------------------
# 2A-D.1 Patch 4B (F-2): admin mode production lockdown
# ---------------------------------------------------------------------


def _clear_admin_mode_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANCHOR_ADMIN_MODE", raising=False)


# --- Resolution: _admin_mode() ----------------------------------------


def test_admin_mode_unset_in_prod_resolves_to_db(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    _clear_admin_mode_env(monkeypatch)
    assert _admin_mode() == "db"


def test_admin_mode_blank_in_prod_resolves_to_db(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_ADMIN_MODE", "   ")
    assert _admin_mode() == "db"


def test_admin_mode_unset_in_nonprod_keeps_hybrid_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-prod local/dev flows that rely on env-token bootstrap must
    continue to work — preserve the historical hybrid default."""
    monkeypatch.setenv("APP_ENV", "dev")
    _clear_admin_mode_env(monkeypatch)
    assert _admin_mode() == "hybrid"


def test_admin_mode_explicit_db_in_prod_is_db(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_ADMIN_MODE", "db")
    assert _admin_mode() == "db"


def test_admin_mode_explicit_hybrid_in_prod_is_hybrid_operator_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_ADMIN_MODE", "hybrid")
    assert _admin_mode() == "hybrid"


def test_admin_mode_explicit_env_in_nonprod_is_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-prod env-only mode remains operationally usable (e.g. for a
    local smoke test that doesn't have a DB token provisioned)."""
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("ANCHOR_ADMIN_MODE", "env")
    assert _admin_mode() == "env"


def test_admin_mode_unknown_value_in_prod_falls_back_to_db(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defensive resolution: a typo must not silently widen the allowed
    set. The startup assertion still refuses such a value."""
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_ADMIN_MODE", "DBMODE")
    assert _admin_mode() == "db"


def test_admin_mode_unknown_value_in_nonprod_falls_back_to_hybrid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("ANCHOR_ADMIN_MODE", "yolo")
    assert _admin_mode() == "hybrid"


# --- Startup assertion: assert_admin_mode_for_prod() ------------------


def test_admin_mode_assertion_noop_outside_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("ANCHOR_ADMIN_MODE", "env")
    assert_admin_mode_for_prod()  # must not raise


def test_admin_mode_assertion_passes_when_unset_in_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    _clear_admin_mode_env(monkeypatch)
    assert_admin_mode_for_prod()  # unset is fine; resolves to "db"


def test_admin_mode_assertion_passes_for_db_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_ADMIN_MODE", "db")
    assert_admin_mode_for_prod()


def test_admin_mode_assertion_passes_for_explicit_hybrid_in_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_ADMIN_MODE", "hybrid")
    assert_admin_mode_for_prod()


def test_admin_mode_assertion_rejects_env_in_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_ADMIN_MODE", "env")
    with pytest.raises(RuntimeError, match="env-only admin tokens"):
        assert_admin_mode_for_prod()


def test_admin_mode_assertion_rejects_unknown_value_in_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_ADMIN_MODE", "yolo")
    with pytest.raises(RuntimeError, match="not a valid admin mode"):
        assert_admin_mode_for_prod()
