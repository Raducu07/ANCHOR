# app/sustainability.py
#
# M6-S - Sustainability Governance & Evidence Module (code-wise
# completion, gated). Authorised by the 2026-07-05 founder
# code-completion decision record. Schema corrections from Roadmap v2.6
# Section 8 were re-checked and applied in
# migrations/20260705_04_sustainability_schema.sql.
#
# Doctrine:
#   * Metadata-only: quantities (kWh, kg, kg CO2e), dates, and
#     clinic-controlled labels. No clinical content, no client data.
#   * Receipt-style evidence: reports are immutable rows with a SHA-256
#     payload hash and void-free supersession (superseded_at /
#     superseded_by_report_id). Evidence rows are corrected by
#     void-with-reason, never edited or deleted.
#   * Tenant-scoped via the existing request-scoped context; every
#     table is RLS ENABLED + FORCED.
#   * reporting_enabled defaults to false; nothing here processes real
#     clinic operational data until a founder decision activates it.
#   * Not an accredited carbon audit and not a compliance
#     certification; responses carry SUSTAINABILITY_NOTE saying so.

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/v1/portal/sustainability",
    tags=["Sustainability"],
    dependencies=[Depends(require_clinic_user)],
)

_SUSTAINABILITY_ADMIN_ROLES = {"admin", "owner", "practice_manager"}

SUSTAINABILITY_NOTE = (
    "Metadata-only sustainability governance evidence: quantities, "
    "dates, and clinic-controlled labels. Not an accredited carbon "
    "audit and not a compliance certification."
)


def _ctx(request: Request) -> Dict[str, str]:
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    role = getattr(request.state, "role", "") or ""
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")
    return {
        "clinic_id": str(clinic_id),
        "clinic_user_id": str(clinic_user_id),
        "role": str(role),
    }


def _require_admin(role: str) -> None:
    if role not in _SUSTAINABILITY_ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="forbidden_not_admin")


def _as_uuid(value: Any, *, field: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except Exception:
        raise HTTPException(status_code=400, detail=f"invalid_{field}")


def _num(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, Decimal):
        return float(value)
    return float(value)


# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------

class SustainabilityConfig(BaseModel):
    reporting_enabled: bool = False
    baseline_year: Optional[int] = Field(default=None, ge=2000, le=2100)
    electricity_factor_g_co2e_per_kwh: Optional[float] = Field(default=None, ge=0)
    gas_factor_g_co2e_per_kwh: Optional[float] = Field(default=None, ge=0)
    waste_factor_g_co2e_per_kg: Optional[float] = Field(default=None, ge=0)
    factor_source_text: Optional[str] = Field(default=None, max_length=500)


class SustainabilityConfigResponse(SustainabilityConfig):
    updated_at: Optional[datetime] = None
    sustainability_note: str


class EnergyReadingCreate(BaseModel):
    energy_type: str = Field(..., pattern="^(electricity|gas|other)$")
    period_start: date
    period_end: date
    consumption_kwh: float = Field(..., ge=0)
    supplier_label: Optional[str] = Field(default=None, max_length=200)


class WasteEventCreate(BaseModel):
    waste_stream: str = Field(
        ..., pattern="^(clinical|offensive|domestic|recycling|other)$"
    )
    occurred_on: date
    weight_kg: float = Field(..., ge=0)
    supplier_label: Optional[str] = Field(default=None, max_length=200)


class FootprintEstimateCreate(BaseModel):
    workflow_label: str = Field(..., min_length=1, max_length=200)
    period_start: date
    period_end: date
    estimated_kg_co2e: float = Field(..., ge=0)
    factor_source_text: Optional[str] = Field(default=None, max_length=500)


class VoidRequest(BaseModel):
    void_reason: str = Field(..., min_length=3, max_length=500)


class RollingMonth(BaseModel):
    month: date
    energy_kwh: Optional[float] = None
    waste_kg: Optional[float] = None
    estimated_kg_co2e: Optional[float] = None


class RollingResponse(BaseModel):
    months: List[RollingMonth]
    sustainability_note: str


class SustainabilityReport(BaseModel):
    report_id: str
    report_version: int
    period_start: date
    period_end: date
    energy_kwh_total: float
    waste_kg_total: float
    estimated_kg_co2e_total: float
    report_hash: str
    superseded_at: Optional[datetime] = None
    generated_at: datetime


class ReportListResponse(BaseModel):
    reports: List[SustainabilityReport]
    sustainability_note: str


class TrustSummaryResponse(BaseModel):
    reporting_enabled: bool
    energy_reading_count: int
    waste_event_count: int
    footprint_estimate_count: int
    report_count: int
    latest_report_generated_at: Optional[datetime] = None
    sustainability_note: str


# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------

_CONFIG_COLS = (
    "reporting_enabled, baseline_year, electricity_factor_g_co2e_per_kwh, "
    "gas_factor_g_co2e_per_kwh, waste_factor_g_co2e_per_kg, "
    "factor_source_text, updated_at"
)


def _config_response(row: Optional[Dict[str, Any]]) -> SustainabilityConfigResponse:
    if not row:
        return SustainabilityConfigResponse(
            sustainability_note=SUSTAINABILITY_NOTE
        )
    return SustainabilityConfigResponse(
        reporting_enabled=bool(row["reporting_enabled"]),
        baseline_year=row.get("baseline_year"),
        electricity_factor_g_co2e_per_kwh=_num(
            row.get("electricity_factor_g_co2e_per_kwh")
        ),
        gas_factor_g_co2e_per_kwh=_num(row.get("gas_factor_g_co2e_per_kwh")),
        waste_factor_g_co2e_per_kg=_num(row.get("waste_factor_g_co2e_per_kg")),
        factor_source_text=row.get("factor_source_text"),
        updated_at=row.get("updated_at"),
        sustainability_note=SUSTAINABILITY_NOTE,
    )


@router.get("/config", response_model=SustainabilityConfigResponse)
def get_config(
    request: Request, db: Session = Depends(get_db)
) -> SustainabilityConfigResponse:
    ctx = _ctx(request)
    row = db.execute(
        text(
            f"SELECT {_CONFIG_COLS} FROM sustainability_config "
            "WHERE clinic_id = CAST(:clinic_id AS uuid) LIMIT 1"
        ),
        {"clinic_id": ctx["clinic_id"]},
    ).mappings().first()
    return _config_response(dict(row) if row else None)


@router.put("/config", response_model=SustainabilityConfigResponse)
def put_config(
    payload: SustainabilityConfig,
    request: Request,
    db: Session = Depends(get_db),
) -> SustainabilityConfigResponse:
    ctx = _ctx(request)
    _require_admin(ctx["role"])
    row = db.execute(
        text(
            f"""
            INSERT INTO sustainability_config (
                clinic_id, reporting_enabled, baseline_year,
                electricity_factor_g_co2e_per_kwh,
                gas_factor_g_co2e_per_kwh, waste_factor_g_co2e_per_kg,
                factor_source_text, updated_by_user_id
            )
            VALUES (
                CAST(:clinic_id AS uuid), :reporting_enabled,
                :baseline_year, :electricity_factor,
                :gas_factor, :waste_factor,
                :factor_source_text, CAST(:updated_by AS uuid)
            )
            ON CONFLICT (clinic_id) DO UPDATE
            SET reporting_enabled = EXCLUDED.reporting_enabled,
                baseline_year = EXCLUDED.baseline_year,
                electricity_factor_g_co2e_per_kwh
                    = EXCLUDED.electricity_factor_g_co2e_per_kwh,
                gas_factor_g_co2e_per_kwh = EXCLUDED.gas_factor_g_co2e_per_kwh,
                waste_factor_g_co2e_per_kg = EXCLUDED.waste_factor_g_co2e_per_kg,
                factor_source_text = EXCLUDED.factor_source_text,
                updated_by_user_id = EXCLUDED.updated_by_user_id,
                updated_at = now()
            RETURNING {_CONFIG_COLS}
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "reporting_enabled": payload.reporting_enabled,
            "baseline_year": payload.baseline_year,
            "electricity_factor": payload.electricity_factor_g_co2e_per_kwh,
            "gas_factor": payload.gas_factor_g_co2e_per_kwh,
            "waste_factor": payload.waste_factor_g_co2e_per_kg,
            "factor_source_text": payload.factor_source_text,
            "updated_by": ctx["clinic_user_id"],
        },
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=500, detail="config_upsert_failed")
    return _config_response(dict(row))


# ---------------------------------------------------------------------
# Evidence streams (create / list / void)
# ---------------------------------------------------------------------

def _void_row(
    db: Session,
    *,
    table: str,
    id_col: str,
    row_id: str,
    void_reason: str,
    actor: str,
) -> None:
    result = db.execute(
        text(
            f"""
            UPDATE {table}
            SET is_voided = true,
                void_reason = :void_reason,
                voided_at = now(),
                voided_by_user_id = CAST(:actor AS uuid)
            WHERE {id_col} = CAST(:row_id AS uuid)
              AND is_voided = false
            RETURNING {id_col}
            """
        ),
        {"void_reason": void_reason, "actor": actor, "row_id": row_id},
    ).mappings().first()
    if not result:
        raise HTTPException(
            status_code=404, detail="row_not_found_or_already_voided"
        )


@router.post("/energy-readings")
def create_energy_reading(
    payload: EnergyReadingCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    ctx = _ctx(request)
    if payload.period_end < payload.period_start:
        raise HTTPException(status_code=400, detail="invalid_period")
    row = db.execute(
        text(
            """
            INSERT INTO sustainability_energy_readings (
                clinic_id, recorded_by_user_id, energy_type,
                period_start, period_end, consumption_kwh, supplier_label
            )
            VALUES (
                CAST(:clinic_id AS uuid), CAST(:actor AS uuid), :energy_type,
                :period_start, :period_end, :consumption_kwh, :supplier_label
            )
            RETURNING reading_id, created_at
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "actor": ctx["clinic_user_id"],
            "energy_type": payload.energy_type,
            "period_start": payload.period_start,
            "period_end": payload.period_end,
            "consumption_kwh": payload.consumption_kwh,
            "supplier_label": payload.supplier_label,
        },
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=500, detail="insert_failed")
    return {
        "reading_id": str(row["reading_id"]),
        "created_at": row["created_at"],
        "sustainability_note": SUSTAINABILITY_NOTE,
    }


@router.get("/energy-readings")
def list_energy_readings(
    request: Request, db: Session = Depends(get_db)
) -> Dict[str, Any]:
    ctx = _ctx(request)
    rows = db.execute(
        text(
            """
            SELECT reading_id, energy_type, period_start, period_end,
                   consumption_kwh, supplier_label, is_voided, created_at
            FROM sustainability_energy_readings
            WHERE clinic_id = CAST(:clinic_id AS uuid)
            ORDER BY period_start DESC, created_at DESC
            LIMIT 500
            """
        ),
        {"clinic_id": ctx["clinic_id"]},
    ).mappings().all()
    return {
        "readings": [
            {**dict(r), "reading_id": str(r["reading_id"]),
             "consumption_kwh": _num(r["consumption_kwh"])}
            for r in rows
        ],
        "sustainability_note": SUSTAINABILITY_NOTE,
    }


@router.post("/energy-readings/{reading_id}/void")
def void_energy_reading(
    reading_id: str,
    payload: VoidRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    ctx = _ctx(request)
    _require_admin(ctx["role"])
    _void_row(
        db,
        table="sustainability_energy_readings",
        id_col="reading_id",
        row_id=_as_uuid(reading_id, field="reading_id"),
        void_reason=payload.void_reason,
        actor=ctx["clinic_user_id"],
    )
    return {"voided": True}


@router.post("/waste-events")
def create_waste_event(
    payload: WasteEventCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    ctx = _ctx(request)
    row = db.execute(
        text(
            """
            INSERT INTO sustainability_waste_events (
                clinic_id, recorded_by_user_id, waste_stream,
                occurred_on, weight_kg, supplier_label
            )
            VALUES (
                CAST(:clinic_id AS uuid), CAST(:actor AS uuid), :waste_stream,
                :occurred_on, :weight_kg, :supplier_label
            )
            RETURNING waste_event_id, created_at
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "actor": ctx["clinic_user_id"],
            "waste_stream": payload.waste_stream,
            "occurred_on": payload.occurred_on,
            "weight_kg": payload.weight_kg,
            "supplier_label": payload.supplier_label,
        },
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=500, detail="insert_failed")
    return {
        "waste_event_id": str(row["waste_event_id"]),
        "created_at": row["created_at"],
        "sustainability_note": SUSTAINABILITY_NOTE,
    }


@router.get("/waste-events")
def list_waste_events(
    request: Request, db: Session = Depends(get_db)
) -> Dict[str, Any]:
    ctx = _ctx(request)
    rows = db.execute(
        text(
            """
            SELECT waste_event_id, waste_stream, occurred_on, weight_kg,
                   supplier_label, is_voided, created_at
            FROM sustainability_waste_events
            WHERE clinic_id = CAST(:clinic_id AS uuid)
            ORDER BY occurred_on DESC, created_at DESC
            LIMIT 500
            """
        ),
        {"clinic_id": ctx["clinic_id"]},
    ).mappings().all()
    return {
        "waste_events": [
            {**dict(r), "waste_event_id": str(r["waste_event_id"]),
             "weight_kg": _num(r["weight_kg"])}
            for r in rows
        ],
        "sustainability_note": SUSTAINABILITY_NOTE,
    }


@router.post("/waste-events/{waste_event_id}/void")
def void_waste_event(
    waste_event_id: str,
    payload: VoidRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    ctx = _ctx(request)
    _require_admin(ctx["role"])
    _void_row(
        db,
        table="sustainability_waste_events",
        id_col="waste_event_id",
        row_id=_as_uuid(waste_event_id, field="waste_event_id"),
        void_reason=payload.void_reason,
        actor=ctx["clinic_user_id"],
    )
    return {"voided": True}


@router.post("/footprint-estimates")
def create_footprint_estimate(
    payload: FootprintEstimateCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    ctx = _ctx(request)
    if payload.period_end < payload.period_start:
        raise HTTPException(status_code=400, detail="invalid_period")
    row = db.execute(
        text(
            """
            INSERT INTO sustainability_workflow_footprint_estimates (
                clinic_id, recorded_by_user_id, workflow_label,
                period_start, period_end, estimated_kg_co2e,
                factor_source_text
            )
            VALUES (
                CAST(:clinic_id AS uuid), CAST(:actor AS uuid),
                :workflow_label, :period_start, :period_end,
                :estimated_kg_co2e, :factor_source_text
            )
            RETURNING estimate_id, created_at
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "actor": ctx["clinic_user_id"],
            "workflow_label": payload.workflow_label,
            "period_start": payload.period_start,
            "period_end": payload.period_end,
            "estimated_kg_co2e": payload.estimated_kg_co2e,
            "factor_source_text": payload.factor_source_text,
        },
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=500, detail="insert_failed")
    return {
        "estimate_id": str(row["estimate_id"]),
        "created_at": row["created_at"],
        "sustainability_note": SUSTAINABILITY_NOTE,
    }


@router.get("/footprint-estimates")
def list_footprint_estimates(
    request: Request, db: Session = Depends(get_db)
) -> Dict[str, Any]:
    ctx = _ctx(request)
    rows = db.execute(
        text(
            """
            SELECT estimate_id, workflow_label, period_start, period_end,
                   estimated_kg_co2e, factor_source_text, is_voided,
                   created_at
            FROM sustainability_workflow_footprint_estimates
            WHERE clinic_id = CAST(:clinic_id AS uuid)
            ORDER BY period_start DESC, created_at DESC
            LIMIT 500
            """
        ),
        {"clinic_id": ctx["clinic_id"]},
    ).mappings().all()
    return {
        "estimates": [
            {**dict(r), "estimate_id": str(r["estimate_id"]),
             "estimated_kg_co2e": _num(r["estimated_kg_co2e"])}
            for r in rows
        ],
        "sustainability_note": SUSTAINABILITY_NOTE,
    }


@router.post("/footprint-estimates/{estimate_id}/void")
def void_footprint_estimate(
    estimate_id: str,
    payload: VoidRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    ctx = _ctx(request)
    _require_admin(ctx["role"])
    _void_row(
        db,
        table="sustainability_workflow_footprint_estimates",
        id_col="estimate_id",
        row_id=_as_uuid(estimate_id, field="estimate_id"),
        void_reason=payload.void_reason,
        actor=ctx["clinic_user_id"],
    )
    return {"voided": True}


# ---------------------------------------------------------------------
# Rolling 12-month view
# ---------------------------------------------------------------------

def _rolling_rows(db: Session, clinic_id: str) -> List[Dict[str, Any]]:
    rows = db.execute(
        text(
            """
            SELECT month, energy_kwh, waste_kg, estimated_kg_co2e
            FROM v_sustainability_rolling_12m
            WHERE clinic_id = CAST(:clinic_id AS uuid)
            ORDER BY month
            """
        ),
        {"clinic_id": clinic_id},
    ).mappings().all()
    return [dict(r) for r in rows]


@router.get("/rolling-12m", response_model=RollingResponse)
def rolling_12m(
    request: Request, db: Session = Depends(get_db)
) -> RollingResponse:
    ctx = _ctx(request)
    months = [
        RollingMonth(
            month=r["month"],
            energy_kwh=_num(r.get("energy_kwh")),
            waste_kg=_num(r.get("waste_kg")),
            estimated_kg_co2e=_num(r.get("estimated_kg_co2e")),
        )
        for r in _rolling_rows(db, ctx["clinic_id"])
    ]
    return RollingResponse(
        months=months, sustainability_note=SUSTAINABILITY_NOTE
    )


# ---------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------

def _report_from_row(r: Dict[str, Any]) -> SustainabilityReport:
    return SustainabilityReport(
        report_id=str(r["report_id"]),
        report_version=int(r["report_version"]),
        period_start=r["period_start"],
        period_end=r["period_end"],
        energy_kwh_total=_num(r["energy_kwh_total"]) or 0.0,
        waste_kg_total=_num(r["waste_kg_total"]) or 0.0,
        estimated_kg_co2e_total=_num(r["estimated_kg_co2e_total"]) or 0.0,
        report_hash=str(r["report_hash"]),
        superseded_at=r.get("superseded_at"),
        generated_at=r["generated_at"],
    )


@router.post("/reports", response_model=SustainabilityReport)
def generate_report(
    request: Request, db: Session = Depends(get_db)
) -> SustainabilityReport:
    ctx = _ctx(request)
    _require_admin(ctx["role"])

    months = _rolling_rows(db, ctx["clinic_id"])
    payload_months = [
        {
            "month": str(r["month"]),
            "energy_kwh": _num(r.get("energy_kwh")),
            "waste_kg": _num(r.get("waste_kg")),
            "estimated_kg_co2e": _num(r.get("estimated_kg_co2e")),
        }
        for r in months
    ]
    payload = {"basis": "rolling_12m", "months": payload_months}
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    report_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

    energy_total = sum((m["energy_kwh"] or 0.0) for m in payload_months)
    waste_total = sum((m["waste_kg"] or 0.0) for m in payload_months)
    co2e_total = sum((m["estimated_kg_co2e"] or 0.0) for m in payload_months)

    month_values = [r["month"] for r in months]
    period_start = min(month_values) if month_values else date.today()
    period_end = max(month_values) if month_values else date.today()

    version_row = db.execute(
        text(
            "SELECT COALESCE(MAX(report_version), 0) + 1 AS v "
            "FROM sustainability_reports "
            "WHERE clinic_id = CAST(:clinic_id AS uuid)"
        ),
        {"clinic_id": ctx["clinic_id"]},
    ).mappings().first()
    next_version = int(version_row["v"]) if version_row else 1

    inserted = db.execute(
        text(
            """
            INSERT INTO sustainability_reports (
                clinic_id, generated_by_user_id, report_version,
                period_start, period_end, energy_kwh_total,
                waste_kg_total, estimated_kg_co2e_total,
                report_payload, report_hash
            )
            VALUES (
                CAST(:clinic_id AS uuid), CAST(:actor AS uuid), :version,
                :period_start, :period_end, :energy_total,
                :waste_total, :co2e_total,
                CAST(:payload AS jsonb), :report_hash
            )
            RETURNING report_id, report_version, period_start, period_end,
                      energy_kwh_total, waste_kg_total,
                      estimated_kg_co2e_total, report_hash, superseded_at,
                      generated_at
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "actor": ctx["clinic_user_id"],
            "version": next_version,
            "period_start": period_start,
            "period_end": period_end,
            "energy_total": energy_total,
            "waste_total": waste_total,
            "co2e_total": co2e_total,
            "payload": payload_json,
            "report_hash": report_hash,
        },
    ).mappings().first()
    if not inserted:
        raise HTTPException(status_code=500, detail="report_insert_failed")

    # Supersede any prior un-superseded report (amendment discipline:
    # prior rows are never edited beyond the supersession stamp).
    db.execute(
        text(
            """
            UPDATE sustainability_reports
            SET superseded_at = now(),
                superseded_by_report_id = CAST(:new_id AS uuid)
            WHERE clinic_id = CAST(:clinic_id AS uuid)
              AND report_id <> CAST(:new_id AS uuid)
              AND superseded_at IS NULL
            """
        ),
        {
            "clinic_id": ctx["clinic_id"],
            "new_id": str(inserted["report_id"]),
        },
    )

    return _report_from_row(dict(inserted))


@router.get("/reports", response_model=ReportListResponse)
def list_reports(
    request: Request, db: Session = Depends(get_db)
) -> ReportListResponse:
    ctx = _ctx(request)
    rows = db.execute(
        text(
            """
            SELECT report_id, report_version, period_start, period_end,
                   energy_kwh_total, waste_kg_total,
                   estimated_kg_co2e_total, report_hash, superseded_at,
                   generated_at
            FROM sustainability_reports
            WHERE clinic_id = CAST(:clinic_id AS uuid)
            ORDER BY report_version DESC
            LIMIT 100
            """
        ),
        {"clinic_id": ctx["clinic_id"]},
    ).mappings().all()
    return ReportListResponse(
        reports=[_report_from_row(dict(r)) for r in rows],
        sustainability_note=SUSTAINABILITY_NOTE,
    )


# ---------------------------------------------------------------------
# Trust evidence summary (metadata-only)
# ---------------------------------------------------------------------

def _safe_count(db: Session, sql: str, params: Dict[str, Any], label: str) -> int:
    try:
        row = db.execute(text(sql), params).mappings().first()
    except Exception:
        logger.exception("sustainability trust summary query failed: %s", label)
        return 0
    if not row:
        return 0
    try:
        return int(row.get("c") or 0)
    except (TypeError, ValueError):
        return 0


@router.get("/trust-summary", response_model=TrustSummaryResponse)
def trust_summary(
    request: Request, db: Session = Depends(get_db)
) -> TrustSummaryResponse:
    ctx = _ctx(request)
    params = {"clinic_id": ctx["clinic_id"]}

    config_row = db.execute(
        text(
            "SELECT reporting_enabled FROM sustainability_config "
            "WHERE clinic_id = CAST(:clinic_id AS uuid) LIMIT 1"
        ),
        params,
    ).mappings().first()

    latest_row = db.execute(
        text(
            "SELECT MAX(generated_at) AS latest FROM sustainability_reports "
            "WHERE clinic_id = CAST(:clinic_id AS uuid)"
        ),
        params,
    ).mappings().first()

    return TrustSummaryResponse(
        reporting_enabled=bool(config_row["reporting_enabled"]) if config_row else False,
        energy_reading_count=_safe_count(
            db,
            "SELECT COUNT(*)::int AS c FROM sustainability_energy_readings "
            "WHERE clinic_id = CAST(:clinic_id AS uuid) AND is_voided = false",
            params,
            "energy",
        ),
        waste_event_count=_safe_count(
            db,
            "SELECT COUNT(*)::int AS c FROM sustainability_waste_events "
            "WHERE clinic_id = CAST(:clinic_id AS uuid) AND is_voided = false",
            params,
            "waste",
        ),
        footprint_estimate_count=_safe_count(
            db,
            "SELECT COUNT(*)::int AS c "
            "FROM sustainability_workflow_footprint_estimates "
            "WHERE clinic_id = CAST(:clinic_id AS uuid) AND is_voided = false",
            params,
            "footprint",
        ),
        report_count=_safe_count(
            db,
            "SELECT COUNT(*)::int AS c FROM sustainability_reports "
            "WHERE clinic_id = CAST(:clinic_id AS uuid)",
            params,
            "reports",
        ),
        latest_report_generated_at=(
            latest_row.get("latest") if latest_row else None
        ),
        sustainability_note=SUSTAINABILITY_NOTE,
    )
