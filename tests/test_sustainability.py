"""M6-S - Sustainability Governance Module tests (metadata-only).

Coverage:
  * config: defaults when unset, admin-only PUT, upsert echo
  * evidence streams: create/list/void for energy readings, waste
    events, footprint estimates; void is admin-only and 404s when
    already voided; period validation
  * rolling 12-month endpoint passthrough
  * report generation: totals from the rolling view, versioning,
    SHA-256 payload hash, supersession of the prior report
  * trust summary aggregates (honest zeros)
  * schema doctrine: all five tables RLS ENABLED + FORCED with
    USING/WITH CHECK; clinic-controlled supplier_label only (no
    supplier_display_name); rolling view aggregates each stream
    separately before joining; no clinical-content columns
  * responses carry the sustainability note (not-an-audit wording)

Uses an in-memory FakeDB. No live Postgres needed.
"""
from __future__ import annotations

import os
import re
import sys
import uuid as _uuid
from datetime import date, datetime, timezone
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
    REPO_ROOT / "migrations" / "20260705_04_sustainability_schema.sql"
).read_text(encoding="utf-8")


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


class SustainabilityFakeDB:
    def __init__(self) -> None:
        self.config_row: Optional[Dict[str, Any]] = None
        self.config_upserts: List[Dict[str, Any]] = []
        self.inserts: List[Dict[str, Any]] = []
        self.voids: List[Dict[str, Any]] = []
        self.void_result_found = True
        self.energy_rows: List[Dict[str, Any]] = []
        self.waste_rows: List[Dict[str, Any]] = []
        self.footprint_rows: List[Dict[str, Any]] = []
        self.rolling_rows: List[Dict[str, Any]] = []
        self.report_rows: List[Dict[str, Any]] = []
        self.report_inserts: List[Dict[str, Any]] = []
        self.supersede_updates: List[Dict[str, Any]] = []
        self.next_version = 1
        self.counts: Dict[str, int] = {}
        self.audit_inserts: List[Dict[str, Any]] = []

    def execute(self, clause: Any, params: Optional[Dict[str, Any]] = None):
        sql = str(getattr(clause, "text", clause))
        p = dict(params or {})

        if "INSERT INTO admin_audit_events" in sql:
            self.audit_inserts.append(p)
            return _Result()
        if "INSERT INTO sustainability_config" in sql:
            self.config_upserts.append(p)
            return _Result(
                row={
                    "reporting_enabled": p["reporting_enabled"],
                    "baseline_year": p["baseline_year"],
                    "electricity_factor_g_co2e_per_kwh": p["electricity_factor"],
                    "gas_factor_g_co2e_per_kwh": p["gas_factor"],
                    "waste_factor_g_co2e_per_kg": p["waste_factor"],
                    "factor_source_text": p["factor_source_text"],
                    "updated_at": _NOW,
                }
            )
        if "SELECT reporting_enabled FROM sustainability_config" in sql:
            return _Result(row=self.config_row)
        if "FROM sustainability_config" in sql:
            return _Result(row=self.config_row)

        if "COUNT(*)::int AS c" in sql:
            for marker, count in self.counts.items():
                if marker in sql:
                    return _Result(row={"c": count})
            return _Result(row={"c": 0})

        if "INSERT INTO sustainability_energy_readings" in sql:
            self.inserts.append(p)
            return _Result(row={"reading_id": _uuid.uuid4(), "created_at": _NOW})
        if "UPDATE sustainability_energy_readings" in sql:
            self.voids.append(p)
            return _Result(
                row={"reading_id": p["row_id"]} if self.void_result_found else None
            )
        if "SELECT reading_id, energy_type" in sql:
            return _Result(rows=self.energy_rows)

        if "INSERT INTO sustainability_waste_events" in sql:
            self.inserts.append(p)
            return _Result(
                row={"waste_event_id": _uuid.uuid4(), "created_at": _NOW}
            )
        if "UPDATE sustainability_waste_events" in sql:
            self.voids.append(p)
            return _Result(
                row={"waste_event_id": p["row_id"]}
                if self.void_result_found
                else None
            )
        if "SELECT waste_event_id, waste_stream" in sql:
            return _Result(rows=self.waste_rows)

        if "INSERT INTO sustainability_workflow_footprint_estimates" in sql:
            self.inserts.append(p)
            return _Result(row={"estimate_id": _uuid.uuid4(), "created_at": _NOW})
        if "UPDATE sustainability_workflow_footprint_estimates" in sql:
            self.voids.append(p)
            return _Result(
                row={"estimate_id": p["row_id"]}
                if self.void_result_found
                else None
            )
        if "SELECT estimate_id, workflow_label" in sql:
            return _Result(rows=self.footprint_rows)

        if "FROM v_sustainability_rolling_12m" in sql:
            return _Result(rows=self.rolling_rows)
        if "COALESCE(MAX(report_version)" in sql:
            return _Result(row={"v": self.next_version})
        if "INSERT INTO sustainability_reports" in sql:
            self.report_inserts.append(p)
            return _Result(
                row={
                    "report_id": _uuid.uuid4(),
                    "report_version": p["version"],
                    "period_start": p["period_start"],
                    "period_end": p["period_end"],
                    "energy_kwh_total": p["energy_total"],
                    "waste_kg_total": p["waste_total"],
                    "estimated_kg_co2e_total": p["co2e_total"],
                    "report_hash": p["report_hash"],
                    "superseded_at": None,
                    "generated_at": _NOW,
                }
            )
        if "UPDATE sustainability_reports" in sql:
            self.supersede_updates.append(p)
            return _Result()
        if "SELECT MAX(generated_at)" in sql:
            return _Result(row={"latest": None})
        if "SELECT report_id, report_version" in sql:
            return _Result(rows=self.report_rows)

        raise AssertionError(f"unexpected SQL: {sql}")

    def commit(self) -> None:
        pass


def _build_app(*, authenticated: bool = True, role: str = "admin") -> tuple:
    from app.auth_and_rls import require_clinic_user
    from app.db import get_db
    from app.sustainability import router

    app = FastAPI()
    app.include_router(router)
    fake = SustainabilityFakeDB()

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
# Config
# ---------------------------------------------------------------------

def test_config_defaults_when_unset() -> None:
    app, _ = _build_app()
    resp = TestClient(app).get("/v1/portal/sustainability/config")
    assert resp.status_code == 200
    body = resp.json()
    assert body["reporting_enabled"] is False
    assert body["sustainability_note"].startswith("Metadata-only")


def test_config_put_admin_only() -> None:
    app, _ = _build_app(role="staff")
    resp = TestClient(app).put(
        "/v1/portal/sustainability/config", json={"reporting_enabled": True}
    )
    assert resp.status_code == 403


def test_config_put_upserts() -> None:
    app, fake = _build_app()
    resp = TestClient(app).put(
        "/v1/portal/sustainability/config",
        json={
            "reporting_enabled": True,
            "baseline_year": 2025,
            "electricity_factor_g_co2e_per_kwh": 207.0,
            "factor_source_text": "DEFRA 2025 conversion factors",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["reporting_enabled"] is True
    assert body["baseline_year"] == 2025
    assert fake.config_upserts[0]["clinic_id"] == CLINIC_A


def test_config_put_writes_audit_event_without_free_text() -> None:
    """Pre-merge FIX 2 (5 July audit): config updates write an
    append-only admin_audit_events row; the free-text
    factor_source_text content never appears in the audit meta."""
    import json as _json

    app, fake = _build_app()
    resp = TestClient(app).put(
        "/v1/portal/sustainability/config",
        json={
            "reporting_enabled": True,
            "baseline_year": 2025,
            "electricity_factor_g_co2e_per_kwh": 207.0,
            "factor_source_text": "DEFRA 2025 conversion factors",
        },
    )
    assert resp.status_code == 200
    assert len(fake.audit_inserts) == 1
    audit = fake.audit_inserts[0]
    assert audit["action"] == "sustainability_config_updated"
    assert audit["clinic_id"] == CLINIC_A
    meta = _json.loads(audit["meta"])
    assert meta["reporting_enabled"] is True
    assert meta["electricity_factor_set"] is True
    assert meta["gas_factor_set"] is False
    assert meta["factor_source_text_set"] is True
    assert "DEFRA" not in audit["meta"]

    # Refused (staff) updates write nothing.
    app_staff, fake_staff = _build_app(role="staff")
    TestClient(app_staff).put(
        "/v1/portal/sustainability/config", json={"reporting_enabled": True}
    )
    assert fake_staff.audit_inserts == []


# ---------------------------------------------------------------------
# Evidence streams
# ---------------------------------------------------------------------

def test_energy_create_and_list() -> None:
    app, fake = _build_app(role="staff")
    resp = TestClient(app).post(
        "/v1/portal/sustainability/energy-readings",
        json={
            "energy_type": "electricity",
            "period_start": "2026-06-01",
            "period_end": "2026-06-30",
            "consumption_kwh": 1250.5,
            "supplier_label": "Main supplier",
        },
    )
    assert resp.status_code == 200
    assert fake.inserts[0]["clinic_id"] == CLINIC_A
    assert fake.inserts[0]["consumption_kwh"] == 1250.5

    fake.energy_rows = [
        {
            "reading_id": _uuid.uuid4(),
            "energy_type": "electricity",
            "period_start": date(2026, 6, 1),
            "period_end": date(2026, 6, 30),
            "consumption_kwh": 1250.5,
            "supplier_label": "Main supplier",
            "is_voided": False,
            "created_at": _NOW,
        }
    ]
    resp = TestClient(app).get("/v1/portal/sustainability/energy-readings")
    assert resp.status_code == 200
    assert resp.json()["readings"][0]["consumption_kwh"] == 1250.5


def test_energy_invalid_period_rejected() -> None:
    app, fake = _build_app()
    resp = TestClient(app).post(
        "/v1/portal/sustainability/energy-readings",
        json={
            "energy_type": "gas",
            "period_start": "2026-06-30",
            "period_end": "2026-06-01",
            "consumption_kwh": 10,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "invalid_period"
    assert fake.inserts == []


def test_void_admin_only_and_not_found() -> None:
    rid = str(_uuid.uuid4())
    app_staff, _ = _build_app(role="staff")
    resp = TestClient(app_staff).post(
        f"/v1/portal/sustainability/energy-readings/{rid}/void",
        json={"void_reason": "entered against wrong month"},
    )
    assert resp.status_code == 403

    app_admin, fake = _build_app()
    resp = TestClient(app_admin).post(
        f"/v1/portal/sustainability/energy-readings/{rid}/void",
        json={"void_reason": "entered against wrong month"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"voided": True}

    fake.void_result_found = False
    resp = TestClient(app_admin).post(
        f"/v1/portal/sustainability/energy-readings/{rid}/void",
        json={"void_reason": "entered against wrong month"},
    )
    assert resp.status_code == 404


def test_waste_stream_vocabulary_enforced() -> None:
    app, fake = _build_app()
    resp = TestClient(app).post(
        "/v1/portal/sustainability/waste-events",
        json={
            "waste_stream": "radioactive",
            "occurred_on": "2026-06-15",
            "weight_kg": 3,
        },
    )
    assert resp.status_code == 422
    assert fake.inserts == []


def test_footprint_create() -> None:
    app, fake = _build_app(role="staff")
    resp = TestClient(app).post(
        "/v1/portal/sustainability/footprint-estimates",
        json={
            "workflow_label": "Anaesthetic gas usage",
            "period_start": "2026-06-01",
            "period_end": "2026-06-30",
            "estimated_kg_co2e": 42.5,
            "factor_source_text": "Practice estimate, DEFRA factor",
        },
    )
    assert resp.status_code == 200
    assert fake.inserts[0]["estimated_kg_co2e"] == 42.5


# ---------------------------------------------------------------------
# Rolling view + reports
# ---------------------------------------------------------------------

def _rolling(month: date, e: float, w: float, f: float) -> Dict[str, Any]:
    return {
        "month": month,
        "energy_kwh": e,
        "waste_kg": w,
        "estimated_kg_co2e": f,
    }


def test_rolling_12m_passthrough() -> None:
    app, fake = _build_app(role="staff")
    fake.rolling_rows = [
        _rolling(date(2026, 5, 1), 100.0, 20.0, 5.0),
        _rolling(date(2026, 6, 1), 110.0, 22.0, 6.0),
    ]
    resp = TestClient(app).get("/v1/portal/sustainability/rolling-12m")
    assert resp.status_code == 200
    months = resp.json()["months"]
    assert len(months) == 2
    assert months[1]["energy_kwh"] == 110.0


def test_report_generation_totals_hash_and_supersession() -> None:
    app, fake = _build_app()
    fake.rolling_rows = [
        _rolling(date(2026, 5, 1), 100.0, 20.0, 5.0),
        _rolling(date(2026, 6, 1), 110.0, 22.0, 6.0),
    ]
    fake.next_version = 3
    resp = TestClient(app).post("/v1/portal/sustainability/reports")
    assert resp.status_code == 200
    body = resp.json()
    assert body["report_version"] == 3
    assert body["energy_kwh_total"] == 210.0
    assert body["waste_kg_total"] == 42.0
    assert body["estimated_kg_co2e_total"] == 11.0
    assert len(body["report_hash"]) == 64
    assert body["period_start"] == "2026-05-01"
    assert body["period_end"] == "2026-06-01"
    # Prior reports were superseded by the new one.
    assert len(fake.supersede_updates) == 1
    assert fake.supersede_updates[0]["clinic_id"] == CLINIC_A


def test_report_generation_admin_only() -> None:
    app, _ = _build_app(role="staff")
    resp = TestClient(app).post("/v1/portal/sustainability/reports")
    assert resp.status_code == 403


def test_trust_summary_honest_zeros() -> None:
    app, fake = _build_app(role="staff")
    fake.counts = {
        "sustainability_energy_readings": 4,
        "sustainability_waste_events": 2,
        "sustainability_workflow_footprint_estimates": 1,
        "sustainability_reports": 0,
    }
    resp = TestClient(app).get("/v1/portal/sustainability/trust-summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["reporting_enabled"] is False
    assert body["energy_reading_count"] == 4
    assert body["waste_event_count"] == 2
    assert body["footprint_estimate_count"] == 1
    assert body["report_count"] == 0
    assert body["latest_report_generated_at"] is None


# ---------------------------------------------------------------------
# Schema doctrine
# ---------------------------------------------------------------------

_TENANT_TABLES = (
    "sustainability_config",
    "sustainability_energy_readings",
    "sustainability_waste_events",
    "sustainability_workflow_footprint_estimates",
    "sustainability_reports",
)


def test_all_tables_enable_and_force_rls() -> None:
    for table in _TENANT_TABLES:
        assert (
            f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY"
            in SCHEMA_SQL
        ), f"{table} missing ENABLE RLS"
        assert (
            f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY"
            in SCHEMA_SQL
        ), f"{table} missing FORCE RLS"


def test_all_policies_have_using_and_with_check() -> None:
    policies = re.findall(
        r"CREATE POLICY (rls_sustainability_\w+)\s.*?\$policy\$",
        SCHEMA_SQL,
        flags=re.DOTALL,
    )
    assert len(policies) == 5
    for block in re.findall(
        r"CREATE POLICY rls_sustainability_\w+.*?\$policy\$",
        SCHEMA_SQL,
        flags=re.DOTALL,
    ):
        assert "USING (clinic_id = app_current_clinic_id())" in block
        assert "WITH CHECK (clinic_id = app_current_clinic_id())" in block


def test_supplier_label_not_display_name() -> None:
    ddl = "\n".join(
        line
        for line in SCHEMA_SQL.splitlines()
        if not line.strip().startswith("--")
    )
    assert "supplier_label" in ddl
    assert "supplier_display_name" not in ddl


def test_rolling_view_aggregates_streams_separately() -> None:
    view = SCHEMA_SQL[SCHEMA_SQL.index("v_sustainability_rolling_12m"):]
    # Three per-stream aggregations exist before any join.
    assert view.index("energy AS (") < view.index("FULL OUTER JOIN")
    assert view.index("waste AS (") < view.index("FULL OUTER JOIN")
    assert view.index("footprint AS (") < view.index("FULL OUTER JOIN")
    assert view.count("FULL OUTER JOIN") == 2
    assert view.count("SUM(") == 3


def test_no_clinical_content_columns() -> None:
    body = "\n".join(
        line
        for line in SCHEMA_SQL.splitlines()
        if not line.strip().startswith("--")
    ).lower()
    for forbidden in (
        "patient", "species", "owner_name", "diagnosis", "case_notes",
        "transcript", "prompt", "draft",
    ):
        assert forbidden not in body, f"clinical marker in schema: {forbidden}"


def test_router_mounted_in_main_app() -> None:
    from app.main import app as main_app

    paths = {getattr(r, "path", None) for r in main_app.routes}
    assert "/v1/portal/sustainability/config" in paths
    assert "/v1/portal/sustainability/rolling-12m" in paths
    assert "/v1/portal/sustainability/reports" in paths
    assert "/v1/portal/sustainability/trust-summary" in paths
