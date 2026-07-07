"""M5.8 - Billing and Activation Foundations tests (sandbox-only).

Coverage:
  * state defaults when no row exists (internal_demo / not_ready /
    stripe disabled)
  * PUT is admin-only; staff get 403
  * gated activation states (active_limited / active_verified) are
    REFUSED by the API with 403, as is any unknown value
  * plan validation (404 on unknown plan)
  * stripe_mode is never settable through the API (extra field ignored
    by the model; stored mode untouched)
  * webhook skeleton: disabled by default (503), refuses in prod even
    when the flag is on (503), sandbox mode logs event type only and
    never processes or stores
  * schema: clinic_billing_state has RLS + FORCE with USING/WITH CHECK;
    no payment-instrument columns; plan seed publishes no price
  * every state response carries the sandbox note

Uses an in-memory FakeDB. No live Postgres needed.
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("DATABASE_URL", "postgresql://x:y@localhost:5432/z")
os.environ.setdefault("RATE_LIMIT_ENABLED", "0")
os.environ.setdefault("ANCHOR_JWT_SECRET", "test")

CLINIC_A = "11111111-1111-4111-8111-111111111111"
ADMIN_USER = "22222222-2222-4222-8222-222222222222"
STAFF_USER = "44444444-4444-4444-8444-444444444444"

_NOW = datetime(2026, 7, 5, 12, 0, 0, tzinfo=timezone.utc)

SCHEMA_SQL = (
    REPO_ROOT / "migrations" / "20260705_03_billing_foundations_schema.sql"
).read_text(encoding="utf-8")


def _non_comment(sql: str) -> str:
    return "\n".join(
        line for line in sql.splitlines() if not line.strip().startswith("--")
    )


class _Result:
    def __init__(
        self,
        row: Optional[Dict[str, Any]] = None,
        rows: Optional[List[Dict[str, Any]]] = None,
    ):
        self._row = row
        self._rows = rows

    def mappings(self) -> "_Result":
        return self

    def first(self) -> Optional[Dict[str, Any]]:
        return self._row

    def all(self) -> List[Dict[str, Any]]:
        return list(self._rows or [])


class BillingFakeDB:
    def __init__(self) -> None:
        self.state_row: Optional[Dict[str, Any]] = None
        self.plans: List[Dict[str, Any]] = [
            {
                "plan_slug": "internal_demo",
                "version": "1.0.0",
                "title": "Internal Demo",
                "summary": "Internal demonstration use.",
                "monthly_price_pence": None,
                "currency": "GBP",
                "display_order": 1,
            },
            {
                "plan_slug": "pilot",
                "version": "1.0.0",
                "title": "Pilot",
                "summary": "Future pilot structure.",
                "monthly_price_pence": None,
                "currency": "GBP",
                "display_order": 2,
            },
        ]
        self.upserts: List[Dict[str, Any]] = []
        self.audit_inserts: List[Dict[str, Any]] = []

    def execute(self, clause: Any, params: Optional[Dict[str, Any]] = None):
        sql = str(getattr(clause, "text", clause))
        p = dict(params or {})

        if "INSERT INTO admin_audit_events" in sql:
            self.audit_inserts.append(p)
            return _Result()
        if "FROM clinic_billing_state" in sql:
            return _Result(row=self.state_row)
        if "SELECT 1 AS one FROM billing_plans" in sql:
            known = {pl["plan_slug"] for pl in self.plans}
            return _Result(
                row={"one": 1} if p.get("plan_slug") in known else None
            )
        if "FROM billing_plans" in sql:
            return _Result(rows=self.plans)
        if "INSERT INTO clinic_billing_state" in sql:
            self.upserts.append(p)
            return _Result(
                row={
                    "plan_slug": p["plan_slug"],
                    "activation_status": p["activation_status"],
                    "billing_readiness": p["billing_readiness"],
                    "stripe_mode": "disabled",
                    "updated_at": _NOW,
                }
            )
        raise AssertionError(f"unexpected SQL: {sql}")

    def commit(self) -> None:
        pass


def _build_app(*, authenticated: bool = True, role: str = "admin") -> tuple:
    from app.auth_and_rls import require_clinic_user
    from app.billing_foundations import router, webhook_router
    from app.db import get_db

    app = FastAPI()
    app.include_router(router)
    app.include_router(webhook_router)
    fake = BillingFakeDB()

    def _fake_db_dep(request: Request):
        yield fake
        fake.commit()

    app.dependency_overrides[get_db] = _fake_db_dep

    if authenticated:
        user_id = ADMIN_USER if role == "admin" else STAFF_USER

        def _fake_auth(request: Request) -> Dict[str, str]:
            request.state.clinic_id = CLINIC_A
            request.state.clinic_user_id = user_id
            request.state.role = role
            return {
                "clinic_id": CLINIC_A,
                "clinic_user_id": user_id,
                "role": role,
            }

        app.dependency_overrides[require_clinic_user] = _fake_auth

    return app, fake


# ---------------------------------------------------------------------
# State
# ---------------------------------------------------------------------

def test_state_defaults_when_no_row() -> None:
    app, _ = _build_app()
    resp = TestClient(app).get("/v1/portal/billing/state")
    assert resp.status_code == 200
    body = resp.json()
    assert body["activation_status"] == "internal_demo"
    assert body["billing_readiness"] == "not_ready"
    assert body["stripe_mode"] == "disabled"
    assert len(body["plans"]) == 2
    assert all(p["monthly_price_pence"] is None for p in body["plans"])
    assert body["sandbox_note"].startswith("Billing foundations are sandbox-only")


def test_put_admin_only() -> None:
    app, _ = _build_app(role="staff")
    resp = TestClient(app).put(
        "/v1/portal/billing/state", json={"activation_status": "pilot_candidate"}
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "forbidden_not_admin"


@pytest.mark.parametrize(
    "gated", ["active_limited", "active_verified", "live", "nonsense"]
)
def test_gated_activation_states_refused(gated: str) -> None:
    app, fake = _build_app()
    resp = TestClient(app).put(
        "/v1/portal/billing/state", json={"activation_status": gated}
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "activation_gated_requires_founder_and_gates"
    assert fake.upserts == []


def test_put_pilot_candidate_upserts() -> None:
    app, fake = _build_app()
    resp = TestClient(app).put(
        "/v1/portal/billing/state",
        json={
            "activation_status": "pilot_candidate",
            "plan_slug": "pilot",
            "billing_readiness": "sandbox_only",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["activation_status"] == "pilot_candidate"
    assert body["stripe_mode"] == "disabled"
    assert len(fake.upserts) == 1
    assert fake.upserts[0]["clinic_id"] == CLINIC_A
    # stripe_mode is not part of the insert - it cannot be set via API.
    assert "stripe_mode" not in fake.upserts[0]


def test_put_writes_metadata_only_audit_event() -> None:
    """Pre-merge FIX 2 (5 July audit): billing-state updates write an
    append-only admin_audit_events row, M6.10 precedent."""
    import json as _json

    app, fake = _build_app()
    resp = TestClient(app).put(
        "/v1/portal/billing/state",
        json={"activation_status": "pilot_candidate", "plan_slug": "pilot"},
    )
    assert resp.status_code == 200
    assert len(fake.audit_inserts) == 1
    audit = fake.audit_inserts[0]
    assert audit["clinic_id"] == CLINIC_A
    assert audit["admin_user_id"] == ADMIN_USER
    assert audit["action"] == "billing_state_updated"
    meta = _json.loads(audit["meta"])
    assert meta["activation_status"] == "pilot_candidate"
    assert meta["previous_activation_status"] == "internal_demo"
    # Metadata-only: no secret-shaped keys can exist in this module.
    blob = _json.dumps(meta).lower()
    for forbidden in ("card", "secret", "token", "iban", "stripe_key"):
        assert forbidden not in blob


def test_refused_put_writes_no_audit_event() -> None:
    app, fake = _build_app()
    resp = TestClient(app).put(
        "/v1/portal/billing/state", json={"activation_status": "active_verified"}
    )
    assert resp.status_code == 403
    assert fake.audit_inserts == []


def test_put_unknown_plan_404() -> None:
    app, fake = _build_app()
    resp = TestClient(app).put(
        "/v1/portal/billing/state",
        json={"activation_status": "internal_demo", "plan_slug": "enterprise"},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "plan_not_found"
    assert fake.upserts == []


def test_put_ignores_stripe_mode_field() -> None:
    app, fake = _build_app()
    resp = TestClient(app).put(
        "/v1/portal/billing/state",
        json={"activation_status": "internal_demo", "stripe_mode": "live"},
    )
    # Unknown field is ignored by the request model; stored mode stays
    # schema-defaulted and the response reports 'disabled'.
    assert resp.status_code == 200
    assert resp.json()["stripe_mode"] == "disabled"
    assert "stripe_mode" not in (fake.upserts[0] if fake.upserts else {})


# ---------------------------------------------------------------------
# Webhook skeleton
# ---------------------------------------------------------------------

def test_webhook_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANCHOR_BILLING_WEBHOOK_ENABLED", raising=False)
    monkeypatch.setenv("APP_ENV", "dev")
    app, _ = _build_app()
    resp = TestClient(app).post(
        "/v1/billing/webhook/stripe", json={"type": "x"}
    )
    assert resp.status_code == 503
    assert resp.json()["detail"] == "billing_webhook_disabled"


def test_webhook_refuses_in_prod_even_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANCHOR_BILLING_WEBHOOK_ENABLED", "1")
    app, _ = _build_app()
    resp = TestClient(app).post(
        "/v1/billing/webhook/stripe", json={"type": "x"}
    )
    assert resp.status_code == 503


def test_webhook_sandbox_receives_without_processing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.setenv("ANCHOR_BILLING_WEBHOOK_ENABLED", "1")
    app, fake = _build_app()
    resp = TestClient(app).post(
        "/v1/billing/webhook/stripe",
        json={"type": "invoice.created", "data": {"object": {"secret": "x"}}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"received": True, "mode": "sandbox", "processed": False}
    # Nothing touched the DB.
    assert fake.upserts == []


# ---------------------------------------------------------------------
# Schema doctrine
# ---------------------------------------------------------------------

def test_clinic_billing_state_rls_and_force() -> None:
    assert (
        "ALTER TABLE public.clinic_billing_state ENABLE ROW LEVEL SECURITY"
        in SCHEMA_SQL
    )
    assert (
        "ALTER TABLE public.clinic_billing_state FORCE ROW LEVEL SECURITY"
        in SCHEMA_SQL
    )
    block = re.search(
        r"CREATE POLICY rls_clinic_billing_state_tenant.*?\$policy\$",
        SCHEMA_SQL,
        flags=re.DOTALL,
    )
    assert block
    assert "USING (clinic_id = app_current_clinic_id())" in block.group(0)
    assert "WITH CHECK (clinic_id = app_current_clinic_id())" in block.group(0)


def test_schema_has_no_payment_instrument_columns() -> None:
    body = _non_comment(SCHEMA_SQL).lower()
    for forbidden in ("card", "pan", "iban", "account_number", "sort_code",
                      "cvv", "payment_method", "customer_secret"):
        assert forbidden not in body, f"payment column marker: {forbidden}"


def test_schema_cannot_store_live_stripe_mode() -> None:
    ddl = _non_comment(SCHEMA_SQL)
    assert "CHECK (stripe_mode IN ('disabled', 'test'))" in ddl
    assert "'live'" not in ddl


def test_plan_seed_publishes_no_price() -> None:
    inserts = re.findall(
        r"INSERT INTO public\.billing_plans.*?ON CONFLICT",
        SCHEMA_SQL,
        flags=re.DOTALL,
    )
    assert len(inserts) == 2
    for ins in inserts:
        assert "NULL, 'GBP'" in ins


def test_router_mounted_in_main_app() -> None:
    from app.main import app as main_app

    paths = {getattr(r, "path", None) for r in main_app.routes}
    assert "/v1/portal/billing/state" in paths
    assert "/v1/billing/webhook/stripe" in paths
