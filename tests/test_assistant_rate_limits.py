"""
2A-D.1 backend security hardening — Patch 2 endpoint-level limiter tests.

Covers, end-to-end through the FastAPI handler:
  M-3  GET /v1/assistant/runs/{run_id}/receipt returns 429 after the
       per-clinic-user `receipt` budget is exhausted.
  M-3  GET /v1/assistant/receipts/{identifier} returns 429 after the
       per-clinic-user `receipt` budget is exhausted.
  M-4  POST /v1/assistant/runs returns 429 after the per-clinic-user
       `assistant_submit` budget is exhausted.
  M-5  POST /v1/portal/assist returns 429 after the per-clinic-user
       `assistant_submit` budget is exhausted.

These tests install an isolated, deterministic FixedWindowRateLimiter with
tight budgets, exercise the limiter through the real handlers, and assert
the 429 boundary. They do not touch Postgres, do not call Anthropic, and
do not enable live generation.
"""
from __future__ import annotations

import os
import sys
import uuid as _uuid
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Make the limiter build path deterministic (must be set BEFORE importing
# app.rate_limit / app modules that depend on it at import time).
os.environ.setdefault("RATE_LIMIT_ENABLED", "1")
os.environ.setdefault("RATE_LIMIT_SECRET", "test-secret-patch2")

from app import rate_limit as rl  # noqa: E402

from tests._assistant_test_helpers import (  # noqa: E402
    TEST_CLINIC_ID,
    TEST_USER_ID,
    auth_headers,
    build_app,
)


# ---------------------------------------------------------------------
# Shared limiter fixture: deterministic, tight, isolated per test.
# ---------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolated_limiter(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(
        rl, "LIMITER", rl.FixedWindowRateLimiter(secret="test-secret-patch2")
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
            "admin": rl.RateLimitRule(window_s=60, limit=2),
            "admin_bootstrap": rl.RateLimitRule(window_s=60, limit=2),
        },
    )
    rl._reset_rate_limit_state_for_tests()
    yield
    rl._reset_rate_limit_state_for_tests()


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _receipt_row_min(*, receipt_id: str, run_id: str) -> Dict[str, Any]:
    """Minimal receipt row that satisfies portal_assistant._row_to_receipt
    for the success path. Mirrors the shape used in the existing receipt
    lookup tests, but only the fields actually read."""
    from datetime import datetime, timezone

    when = datetime(2026, 5, 24, 10, 0, 0, tzinfo=timezone.utc)
    return {
        "id": _uuid.UUID(receipt_id),
        "clinic_id": _uuid.UUID(TEST_CLINIC_ID),
        "assistant_run_id": _uuid.UUID(run_id),
        "run_status_snapshot": "generation_succeeded",
        "review_status_snapshot": "reviewed_approved",
        "review_decision_snapshot": "approved_for_use",
        "output_sha256_snapshot": "a" * 64,
        "safety_flags_snapshot": [],
        "refusal_reason_codes_snapshot": [],
        "pii_detected_snapshot": False,
        "pii_types_snapshot": [],
        "contract_version_snapshot": "assistant_contract_v1",
        "workflow_origin_snapshot": "anchor_assistant",
        "mode_snapshot": "client_communication",
        "model_provider_snapshot": "anthropic",
        "model_name_snapshot": "claude-sonnet-4-test",
        "governance_event_id_snapshot": None,
        "reviewed_at_snapshot": when,
        "reviewed_by_user_id_snapshot": _uuid.UUID(TEST_USER_ID),
        "policy_version_snapshot": 1,
        "policy_label_snapshot": "default",
        "policy_validation_profile_snapshot": "standard",
        "policy_generation_enabled_snapshot": True,
        "policy_client_communication_enabled_snapshot": True,
        "policy_require_human_review_snapshot": True,
        "policy_allow_receipts_after_review_snapshot": True,
        "policy_daily_run_limit_per_clinic_snapshot": 100,
        "policy_monthly_run_limit_per_clinic_snapshot": 1000,
        "created_at": when,
    }


def _trace_row_min(*, run_id: str, receipt_id: Optional[str]) -> Dict[str, Any]:
    from datetime import datetime, timezone

    when = datetime(2026, 5, 24, 10, 0, 0, tzinfo=timezone.utc)
    return {
        "run_id": _uuid.UUID(run_id),
        "clinic_id": _uuid.UUID(TEST_CLINIC_ID),
        "clinic_user_id": _uuid.UUID(TEST_USER_ID),
        "mode": "client_communication",
        "contract_version": "assistant_contract_v1",
        "workflow_origin": "anchor_assistant",
        "input_sha256": "b" * 64,
        "output_sha256": "a" * 64,
        "input_field_keys": ["clinician_confirmed_facts", "communication_goal"],
        "pii_detected": False,
        "pii_types": [],
        "safety_flags": [],
        "refusal_reason_codes": [],
        "review_status": "reviewed_approved",
        "run_status": "generation_succeeded",
        "receipt_id": _uuid.UUID(receipt_id) if receipt_id else None,
        "governance_event_id": None,
        "model_provider": "anthropic",
        "model_name": "claude-sonnet-4-test",
        "review_decision": "approved_for_use",
        "reviewed_at": when,
        "reviewed_by_user_id": _uuid.UUID(TEST_USER_ID),
        "created_at": when,
        "updated_at": when,
    }


def _hit_until_429(callable_fn) -> int:
    ok = 0
    for _ in range(20):
        resp = callable_fn()
        if resp.status_code == 429:
            assert "Retry-After" in resp.headers
            return ok
        ok += 1
    raise AssertionError(
        f"Expected 429 within 20 calls, got only {ok} non-429 responses"
    )


# ---------------------------------------------------------------------
# M-3: Receipt lookup — per-run endpoint
# ---------------------------------------------------------------------

def test_receipt_per_run_endpoint_429_after_budget() -> None:
    rid = str(_uuid.uuid4())
    recv_id = str(_uuid.uuid4())

    app, db = build_app()
    db.select_receipt_row = _receipt_row_min(receipt_id=recv_id, run_id=rid)
    db.select_detail_row = _trace_row_min(run_id=rid, receipt_id=recv_id)

    # raise_server_exceptions=False so any in-budget downstream failure
    # surfaces as a 500 response (which our helper counts as "not 429")
    # rather than propagating as a Python exception. The rate-limit gate
    # runs BEFORE the DB lookup so the 429 boundary is what we assert on.
    client = TestClient(app, raise_server_exceptions=False)

    def _call():
        return client.get(
            f"/v1/assistant/runs/{rid}/receipt",
            headers=auth_headers(),
        )

    ok = _hit_until_429(_call)
    # Tight budget is 2 — first two calls land (200 or 500 — limiter ran),
    # third must 429.
    assert ok == 2


# ---------------------------------------------------------------------
# M-3: Receipt lookup — identifier-keyed endpoint
# ---------------------------------------------------------------------

def test_receipt_identifier_endpoint_429_after_budget() -> None:
    rid = str(_uuid.uuid4())
    recv_id = str(_uuid.uuid4())

    app, db = build_app()
    db.select_receipt_row = _receipt_row_min(receipt_id=recv_id, run_id=rid)
    db.select_detail_row = _trace_row_min(run_id=rid, receipt_id=recv_id)

    client = TestClient(app, raise_server_exceptions=False)

    def _call():
        return client.get(
            f"/v1/assistant/receipts/{recv_id}",
            headers=auth_headers(),
        )

    ok = _hit_until_429(_call)
    assert ok == 2


# ---------------------------------------------------------------------
# M-4: POST /v1/assistant/runs — assistant_submit budget
# ---------------------------------------------------------------------

def test_assistant_run_create_429_after_budget() -> None:
    """The rate-limit check runs before mode validation, so a request body
    that would otherwise fail downstream still consumes the bucket. We
    assert that after the budget is exhausted the response code is 429
    rather than the downstream failure code."""
    app, _db = build_app()

    client = TestClient(app, raise_server_exceptions=False)

    # A deliberately-malformed payload: mode is wrong but mode validation
    # runs AFTER the rate-limit check. We only care that, once the budget
    # is exhausted, the boundary is 429 rather than 400 / 422.
    body = {
        "mode": "unsupported_mode_for_test",
        "input": {"clinician_confirmed_facts": "x", "communication_goal": "y"},
    }

    def _call():
        return client.post(
            "/v1/assistant/runs",
            headers=auth_headers(),
            json=body,
        )

    # The first two calls land (and may 4xx downstream), the third 429s.
    saw_429 = False
    for _ in range(5):
        resp = _call()
        if resp.status_code == 429:
            assert "Retry-After" in resp.headers
            saw_429 = True
            break
    assert saw_429, "Expected 429 from assistant_submit budget exhaustion"


# ---------------------------------------------------------------------
# M-5: POST /v1/portal/assist — assistant_submit budget
# ---------------------------------------------------------------------

def test_portal_assist_429_after_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """The rate-limit check runs right after the clinic-context check and
    before RLS-context set / governance evaluation. We mount only the
    portal_assist router with overridden auth + get_db so no real DB or
    Anthropic call is reached. Production-off live-generation gate stays
    in force (we never set ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED)."""
    # Ensure the live-generation gate is OFF for this test (doctrine).
    monkeypatch.delenv("ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED", raising=False)

    from app.auth_and_rls import require_clinic_user
    from app.db import get_db
    from app.portal_assist import router as assist_router

    app = FastAPI()
    app.include_router(assist_router)

    class _MiniDB:
        def execute(self, *a, **kw):
            class _R:
                def fetchone(self_inner):
                    return None

                def mappings(self_inner):
                    return self_inner

                def first(self_inner):
                    return None

                def all(self_inner):
                    return []

            return _R()

        def commit(self):
            return None

        def rollback(self):
            return None

        def begin(self):
            return None

    def _fake_db_dep(request: Request):
        yield _MiniDB()

    def _fake_require_clinic_user(request: Request) -> Dict[str, str]:
        request.state.clinic_id = TEST_CLINIC_ID
        request.state.clinic_user_id = TEST_USER_ID
        request.state.role = "staff"
        return {
            "clinic_id": TEST_CLINIC_ID,
            "clinic_user_id": TEST_USER_ID,
            "role": "staff",
        }

    app.dependency_overrides[get_db] = _fake_db_dep
    app.dependency_overrides[require_clinic_user] = _fake_require_clinic_user

    client = TestClient(app, raise_server_exceptions=False)

    body = {
        "mode": "client_comm",
        "text": "test prompt for governance evaluation only",
    }

    def _call():
        return client.post(
            "/v1/portal/assist",
            headers=auth_headers(),
            json=body,
        )

    saw_429 = False
    for _ in range(5):
        resp = _call()
        if resp.status_code == 429:
            assert "Retry-After" in resp.headers
            saw_429 = True
            break
    assert saw_429, "Expected 429 from assistant_submit budget exhaustion"
