# app/portal_export.py
import csv
import io
import uuid
from datetime import datetime
from typing import Optional, Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.auth_and_rls import require_clinic_user

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal Export"],
    dependencies=[Depends(require_clinic_user)],
)

_ALLOWED_MODES = {"clinical_note", "client_comm", "internal_summary"}


def _parse_iso8601(ts: str) -> datetime:
    s = (ts or "").strip()
    if not s:
        raise ValueError("empty timestamp")
    # tolerate '+' becoming space in querystrings
    s = s.replace(" ", "+")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


@router.get("/export.csv")
def export_governance_events_csv(
    db: Session = Depends(get_db),
    from_utc: Optional[str] = None,
    to_utc: Optional[str] = None,
    mode: Optional[str] = None,
    limit: int = 5000,
):
    """
    Metadata-only CSV export of clinic_governance_events for the current clinic (RLS enforced).
    No content. Safe for compliance/export.
    """
    limit = int(limit)
    if limit < 1:
        limit = 1
    if limit > 50000:
        limit = 50000

    params: Dict[str, Any] = {"limit": limit}

    where = ["clinic_id = app_current_clinic_id()"]

    if mode:
        m = mode.strip()
        if m not in _ALLOWED_MODES:
            raise HTTPException(status_code=400, detail="invalid mode")
        where.append("mode = :mode")
        params["mode"] = m

    if from_utc:
        try:
            dt_from = _parse_iso8601(from_utc)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid from_utc")
        where.append("created_at >= :dt_from")
        params["dt_from"] = dt_from

    if to_utc:
        try:
            dt_to = _parse_iso8601(to_utc)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid to_utc")
        where.append("created_at <= :dt_to")
        params["dt_to"] = dt_to

    where_sql = " AND ".join(where)

    sql = f"""
    SELECT
      request_id,
      clinic_id,
      user_id,
      mode,
      decision,
      risk_grade,
      reason_code,
      pii_detected,
      pii_action,
      COALESCE(pii_types, ARRAY[]::text[]) AS pii_types,
      policy_version,
      neutrality_version,
      governance_score,
      created_at
    FROM clinic_governance_events
    WHERE {where_sql}
    ORDER BY created_at DESC, request_id DESC
    LIMIT :limit
    """

    # We stream the CSV so memory stays bounded even for large limits.
    def _iter_csv():
        buf = io.StringIO()
        writer = csv.writer(buf)

        # header
        writer.writerow(
            [
                "request_id",
                "clinic_id",
                "user_id",
                "mode",
                "decision",
                "risk_grade",
                "reason_code",
                "pii_detected",
                "pii_action",
                "pii_types",
                "policy_version",
                "neutrality_version",
                "governance_score",
                "created_at_utc",
            ]
        )
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)

        rows = db.execute(text(sql), params).mappings().all()
        for r in rows:
            created = r.get("created_at")
            created_iso = created.isoformat() if hasattr(created, "isoformat") and created else ""

            pii_types = r.get("pii_types") or []
            # store as JSON-ish list string (stable + readable)
            pii_types_str = "[" + ",".join([f'"{x}"' for x in pii_types]) + "]"

            writer.writerow(
                [
                    str(r["request_id"]),
                    str(r["clinic_id"]),
                    str(r["user_id"]),
                    str(r["mode"]),
                    str(r["decision"]),
                    str(r["risk_grade"]),
                    str(r["reason_code"]),
                    bool(r["pii_detected"]),
                    str(r["pii_action"]),
                    pii_types_str,
                    int(r["policy_version"]),
                    str(r["neutrality_version"]),
                    "" if r.get("governance_score") is None else float(r["governance_score"]),
                    created_iso,
                ]
            )
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    filename = f"anchor_governance_export_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.csv"
    return StreamingResponse(
        _iter_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
