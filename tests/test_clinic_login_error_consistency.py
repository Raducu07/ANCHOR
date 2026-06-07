"""
2A-D.1 Patch 5A — clinic login error-string consistency.

Pass-2 finding F-3: the four invalid-login paths in
`app.auth_and_rls.clinic_login` previously returned two distinct 401
detail strings ("invalid credentials" vs "invalid_credentials"), letting
a probe enumerate which clinic slugs exist on the platform.

These tests verify that ALL four invalid-login paths now return
`401 invalid_credentials`:

  1. unknown clinic slug (slug lookup returns nothing)
  2. clinic exists, email not registered
  3. clinic exists, email exists, password mismatch
  4. clinic exists, email exists, active_status=False (disabled user)

We do not touch Postgres. We stub `SessionLocal` and rate limiting so the
handler runs against a fake DB whose responses we control per test.
"""
from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Disable rate limiting for these focused login tests so back-to-back
# requests in the same test process don't hit the per-IP auth bucket.
os.environ.setdefault("RATE_LIMIT_ENABLED", "0")
os.environ.setdefault("RATE_LIMIT_SECRET", "test-secret-patch5a")
os.environ.setdefault("ANCHOR_JWT_SECRET", "test-jwt-secret-patch5a")
os.environ.setdefault("DATABASE_URL", "postgresql://anchor:anchor@localhost/anchor_test")

from app import auth_and_rls as auth_module  # noqa: E402
from app.auth_and_rls import router as clinic_auth_router  # noqa: E402


# ---------------------------------------------------------------------
# Fake DB modelled after the queries clinic_login issues:
#
#   1. SELECT clinic_id FROM public.clinic_slug_lookup WHERE clinic_slug=...
#   2. SELECT clinic_id FROM public.resolve_clinic_id_by_slug(...)
#   3. SET LOCAL ... (RLS context set) — no result needed
#   4. SELECT user_id, role, password_hash, active_status
#        FROM clinic_users WHERE clinic_id=... AND lower(email)=...
# ---------------------------------------------------------------------

CLINIC_UUID = "11111111-1111-4111-8111-111111111111"
USER_UUID = "22222222-2222-4222-8222-222222222222"


class _FakeMappingResult:
    def __init__(self, row: Optional[Dict[str, Any]]):
        self._row = row

    def first(self) -> Optional[Dict[str, Any]]:
        return self._row


class _FakeExecuteResult:
    def __init__(self, row: Optional[Dict[str, Any]]):
        self._row = row

    def mappings(self) -> _FakeMappingResult:
        return _FakeMappingResult(self._row)

    # The `_set_local_text` helper calls db.execute(text("SET LOCAL ...")) and
    # discards the return value; no further methods are required for that path.


class _FakeDB:
    """Configure `slug_lookup_row` and `user_row` per test."""

    def __init__(self) -> None:
        self.slug_lookup_row: Optional[Dict[str, Any]] = None
        self.resolver_fn_row: Optional[Dict[str, Any]] = None
        self.user_row: Optional[Dict[str, Any]] = None
        self.calls: List[str] = []
        self.committed = False
        self.rolled_back = False

    def execute(self, statement: Any, params: Optional[Dict[str, Any]] = None) -> _FakeExecuteResult:
        sql = str(getattr(statement, "text", statement))
        self.calls.append(sql)

        # SET LOCAL ... (RLS context). Discard.
        if sql.strip().upper().startswith("SET LOCAL"):
            return _FakeExecuteResult(row=None)
        if "RESET ALL" in sql.upper():
            return _FakeExecuteResult(row=None)

        # Slug lookup table path
        if "FROM public.clinic_slug_lookup" in sql:
            return _FakeExecuteResult(row=self.slug_lookup_row)

        # SECURITY DEFINER fallback
        if "resolve_clinic_id_by_slug" in sql:
            return _FakeExecuteResult(row=self.resolver_fn_row)

        # clinic_users lookup
        if "FROM clinic_users" in sql:
            return _FakeExecuteResult(row=self.user_row)

        return _FakeExecuteResult(row=None)

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def begin(self) -> None:  # pragma: no cover - shape parity
        return None

    def close(self) -> None:  # pragma: no cover - shape parity
        return None


@pytest.fixture
def fake_db() -> _FakeDB:
    return _FakeDB()


@pytest.fixture
def client(fake_db: _FakeDB, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    @contextmanager
    def _session_cm():
        yield fake_db

    # The handler uses `with SessionLocal() as db:`; replace the bound
    # name in app.auth_and_rls with our context manager factory.
    monkeypatch.setattr(auth_module, "SessionLocal", _session_cm)

    app = FastAPI()
    app.include_router(clinic_auth_router)
    return TestClient(app, raise_server_exceptions=False)


def _login_body(**overrides) -> Dict[str, Any]:
    base = {
        "clinic_slug": "test-vet",
        "email": "user@example.com",
        "password": "correct-horse-battery-staple",
    }
    base.update(overrides)
    return base


def _argon2_hash(password: str) -> str:
    """Build a stored-hash string that matches the verifier in
    `app.auth_and_rls._verify_password`."""
    from argon2 import PasswordHasher

    return "argon2:" + PasswordHasher().hash(password)


# ---------------------------------------------------------------------
# 1. Unknown clinic slug → 401 invalid_credentials
# ---------------------------------------------------------------------

def test_unknown_clinic_slug_returns_invalid_credentials(
    fake_db: _FakeDB, client: TestClient
) -> None:
    # Both the slug-lookup table and the SECURITY DEFINER fallback return
    # nothing → resolver raises "invalid_credentials".
    fake_db.slug_lookup_row = None
    fake_db.resolver_fn_row = {"clinic_id": None}

    resp = client.post("/v1/clinic/auth/login", json=_login_body())
    assert resp.status_code == 401
    # Mounting only the clinic_auth_router (not the full app) means the
    # request_id-augmenting exception handler from app/main.py is not
    # registered, so we only assert the detail string here.
    assert resp.json()["detail"] == "invalid_credentials"


# ---------------------------------------------------------------------
# 2. Clinic exists, email not registered → 401 invalid_credentials
# ---------------------------------------------------------------------

def test_unknown_email_returns_invalid_credentials(
    fake_db: _FakeDB, client: TestClient
) -> None:
    fake_db.slug_lookup_row = {"clinic_id": CLINIC_UUID}
    fake_db.user_row = None  # no clinic_users row for this email

    resp = client.post("/v1/clinic/auth/login", json=_login_body())
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid_credentials"


# ---------------------------------------------------------------------
# 3. Clinic exists, email exists, password mismatch → 401 invalid_credentials
# ---------------------------------------------------------------------

def test_wrong_password_returns_invalid_credentials(
    fake_db: _FakeDB, client: TestClient
) -> None:
    fake_db.slug_lookup_row = {"clinic_id": CLINIC_UUID}
    fake_db.user_row = {
        "user_id": USER_UUID,
        "role": "staff",
        "password_hash": _argon2_hash("actual-password"),
        "active_status": True,
    }

    resp = client.post(
        "/v1/clinic/auth/login",
        json=_login_body(password="wrong-password"),
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid_credentials"


# ---------------------------------------------------------------------
# 4. Inactive / disabled user → 401 invalid_credentials
#    (No separate "account disabled" leakage.)
# ---------------------------------------------------------------------

def test_inactive_user_returns_invalid_credentials(
    fake_db: _FakeDB, client: TestClient
) -> None:
    fake_db.slug_lookup_row = {"clinic_id": CLINIC_UUID}
    fake_db.user_row = {
        "user_id": USER_UUID,
        "role": "staff",
        # Correct hash for the password sent, so the failure can ONLY be
        # the active_status=False branch — proves we don't leak a
        # different string for "account disabled".
        "password_hash": _argon2_hash("correct-horse-battery-staple"),
        "active_status": False,
    }

    resp = client.post("/v1/clinic/auth/login", json=_login_body())
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid_credentials"


# ---------------------------------------------------------------------
# 5. Negative regression: no legacy "invalid credentials" string remains
# ---------------------------------------------------------------------

def test_no_login_path_returns_legacy_space_form(
    fake_db: _FakeDB, client: TestClient
) -> None:
    """Smoke check: every documented invalid-login path returns the
    snake_case form and never the legacy space form. Pinning this in a
    test guards against accidental reintroduction."""
    cases = [
        # Unknown slug
        ({"slug_lookup_row": None, "resolver_fn_row": {"clinic_id": None}, "user_row": None}, _login_body()),
        # Unknown email
        (
            {"slug_lookup_row": {"clinic_id": CLINIC_UUID}, "user_row": None},
            _login_body(),
        ),
        # Wrong password
        (
            {
                "slug_lookup_row": {"clinic_id": CLINIC_UUID},
                "user_row": {
                    "user_id": USER_UUID,
                    "role": "staff",
                    "password_hash": _argon2_hash("actual"),
                    "active_status": True,
                },
            },
            _login_body(password="wrong-password-but-long-enough"),
        ),
        # Inactive user
        (
            {
                "slug_lookup_row": {"clinic_id": CLINIC_UUID},
                "user_row": {
                    "user_id": USER_UUID,
                    "role": "staff",
                    "password_hash": _argon2_hash("correct-horse-battery-staple"),
                    "active_status": False,
                },
            },
            _login_body(),
        ),
    ]

    for fake_state, body in cases:
        for key, value in fake_state.items():
            setattr(fake_db, key, value)
        resp = client.post("/v1/clinic/auth/login", json=body)
        assert resp.status_code == 401
        detail = resp.json()["detail"]
        assert detail == "invalid_credentials"
        assert detail != "invalid credentials"
