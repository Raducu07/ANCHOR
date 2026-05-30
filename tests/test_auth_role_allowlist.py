"""M6.10.4 — Auth-layer role allowlist regression tests.

These tests exercise app.auth_and_rls._normalize_role directly to prove
that the JWT-side role gate accepts every role string the published
clinic-admin gate relies on.

Why this matters:
  The Assistant policy endpoints (PATCH /v1/assistant/policy and
  GET /v1/assistant/policy/history) gate on
  _POLICY_ADMIN_ROLES = {"admin", "owner", "practice_manager"}.
  But before any route handler runs, require_clinic_user calls
  _normalize_role, which raises 403 `forbidden_role` if the JWT's
  role is not in ROLE_ALLOWLIST. If `practice_manager` is missing from
  the default allowlist, the frontend admin/owner/practice_manager
  promise is silently non-functional in any environment that hasn't
  explicitly set ANCHOR_ROLE_ALLOWLIST.

  The assistant-policy test suite stubs require_clinic_user and sets
  request.state.role directly, so it cannot detect this gap. These
  tests close that blind spot at the auth-layer level.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.auth_and_rls import (
    DEFAULT_ROLE_ALLOWLIST,
    ROLE_ALLOWLIST,
    _normalize_role,
)


@pytest.mark.parametrize(
    "role",
    ["admin", "owner", "practice_manager", "staff", "reader", "readonly"],
)
def test_default_allowlist_accepts_documented_roles(role: str) -> None:
    """Every role the published gates rely on must be accepted by the
    default allowlist — no env override required."""
    assert role in DEFAULT_ROLE_ALLOWLIST
    assert _normalize_role(role) == role


def test_practice_manager_is_in_default_allowlist() -> None:
    """Explicit regression for the M6.10.4 finding: practice_manager
    was previously absent from DEFAULT_ROLE_ALLOWLIST, which would
    cause _normalize_role to 403 every practice_manager request before
    the Assistant policy route's _POLICY_ADMIN_ROLES gate could allow
    it."""
    assert "practice_manager" in DEFAULT_ROLE_ALLOWLIST
    # ROLE_ALLOWLIST is derived from DEFAULT_ROLE_ALLOWLIST when no env
    # override is set; in the test runtime that should hold.
    if not _env_role_override_in_effect():
        assert "practice_manager" in ROLE_ALLOWLIST


def test_normalize_role_strips_and_lowercases() -> None:
    assert _normalize_role(" Admin ") == "admin"
    assert _normalize_role("OWNER") == "owner"
    assert _normalize_role("Practice_Manager") == "practice_manager"


def test_normalize_role_rejects_unknown_role() -> None:
    with pytest.raises(HTTPException) as exc:
        _normalize_role("super_user")
    assert exc.value.status_code == 403
    assert exc.value.detail == "forbidden_role"


def test_normalize_role_rejects_empty_role() -> None:
    with pytest.raises(HTTPException) as exc:
        _normalize_role("")
    assert exc.value.status_code == 401
    assert exc.value.detail == "invalid_token_claims_missing_role"


def test_normalize_role_rejects_clinical_decision_shaped_role() -> None:
    """Defence in depth: ensure roles that imply clinical-decision
    authority cannot sneak through the default allowlist."""
    for forbidden in ("clinician_autonomous", "diagnostic_ai", "prescriber_bot"):
        with pytest.raises(HTTPException) as exc:
            _normalize_role(forbidden)
        assert exc.value.status_code == 403


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _env_role_override_in_effect() -> bool:
    """Return True if ANCHOR_ROLE_ALLOWLIST was set at module import
    time, in which case ROLE_ALLOWLIST may legitimately differ from
    DEFAULT_ROLE_ALLOWLIST."""
    import os
    return bool((os.getenv("ANCHOR_ROLE_ALLOWLIST", "") or "").strip())
