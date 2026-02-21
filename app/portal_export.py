# app/portal_export.py
import csv
import io
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, Any, Dict, Iterator, List

from fastapi import APIRouter, Depends, HTTPException, Query
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

_DEFAULT_WINDOW_HOURS = 24
_MAX_WINDOW_DAYS = 31
_MAX_ROWS = 20000


def _parse_iso8601(ts: str) -> datetime:
    """
    Accepts:
      - 2026-02-21T18:31:53+00:00
      - 2026-02-21T18:31:53Z
      - 2026-02-21T18:31:53
    Also tolerates '+' becoming ' ' in querystrings.
    Naive timestamps are treated as UTC.
    """
    s = (ts or "").strip()
    if not s:
        raise ValueError("empty timestamp")

    s = s.replace(" ", "+")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@router.get("/export.csv")
def export_governance_events_csv(
    db: Session = Depends(get_db),
    # Prefer these (nice UX): /export.csv?from=...&to=...
    from_utc: Optional[str] = Query(default=None, alias="from"),
    to_utc: Optional[str] = Query(default=None, alias="to"),
    # Back-compat if you already used from_utc/to_utc names somewhere:
    from_utc_legacy: Optional[str] = Query(default=None, alias="from_utc"),
    to_utc_legacy: Optional[str] = Query(default=None, alias="to_utc"),
    mode: Optional[str] = None,
    decision: Optional[str] = None,
    limit: int = _MAX_ROWS,
):
    """
    Metadata-only CSV export of clinic_governance_events for the current clinic (RLS enforced).
    No content. Safe for compliance/export.

    Defaults to last 24h if no from/to provided.
    Safety rails:
      - max window: 31 days
      - max rows: 20k (adjust via _MAX_ROWS)
    """
    # unify legacy params
    if from_utc is None and from_utc_legacy is not None:
        from_utc = from_utc_legacy
    if to_utc is None and to_utc_legacy is not None:
        to_utc = to_utc_legacy

    # limit guardrails
    limit = int(limit)
    if limit < 1:
        limit = 1
    if limit > _MAX_ROWS:
        limit = _MAX_ROWS

    params: Dict[str, Any] = {"limit": limit}

    where: List[str] = ["clinic_id = app_current_clinic_id()"]

    # filters
    if mode:
        m = mode.strip()
        if m != "__all__" and m not in _ALLOWED_MODES:
            raise HTTPException(status_code=400, detail="invalid mode")
        if m != "__all__":
            where.append("mode = :mode")
            params["mode"] = m

    if decision:
        d = decision.strip()
        if d != "__all__":
            where.append("decision = :decision")
            params["decision"] = d

    # time window defaults / validation
    now = datetime.now(timezone.utc)

    if from_utc is None and to_utc is None:
        dt_to = now
        dt_from = now - timedelta(hours=_DEFAULT_WINDOW_HOURS)
    else:
        if from_utc is None or to_utc is None:
            raise HTTPException(status_code=400, detail="both 'from' and 'to' must be provided together")
        try:
            dt_from = _parse_iso8601(from_utc)
            dt_to = _parse_iso8601(to_utc)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"invalid from/to: {type(e).__name__}: {e}")

        if dt_to <= dt_from:
            raise HTTPException(status_code=400, detail="'to' must be greater than 'from'")

        if (dt_to - dt_from) > timedelta(days=_MAX_WINDOW_DAYS):
            raise HTTPException(status_code=400, detail=f"window too large (max {_MAX_WINDOW_DAYS} days)")

    where.append("created_at >= :dt_from")
    where.append("created_at <  :dt_to")  # exclusive end avoids boundary duplicates
    params["dt_from"] = dt_from
    params["dt_to"] = dt_to

    where_sql = " AND ".join(where)

    sql = text(
        f"""
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
          (created_at AT TIME ZONE 'UTC') AS created_at_utc
        FROM clinic_governance_events
        WHERE {where_sql}
        ORDER BY created_at DESC, request_id DESC
        LIMIT :limit
        """
    )

    def _iter_csv() -> Iterator[bytes]:
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")

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
        yield buf.getvalue().encode("utf-8")
        buf.seek(0)
        buf.truncate(0)

        # true streaming from DB cursor
        result = db.execute(sql.execution_options(stream_results=True), params)
        while True:
            chunk = result.fetchmany(1000)
            if not chunk:
                break
            for r in chunk:
                # r is a Row; convert to mapping
                m = dict(r._mapping)

                created = m.get("created_at_utc")
                if isinstance(created, datetime):
                    created_iso = created.replace(tzinfo=timezone.utc).isoformat()
                else:
                    created_iso = str(created or "")

                pii_types_val = m.get("pii_types") or []
                pii_types_str = json.dumps(list(pii_types_val))

                writer.writerow(
                    [
                        str(m.get("request_id") or ""),
                        str(m.get("clinic_id") or ""),
                        str(m.get("user_id") or ""),
                        str(m.get("mode") or ""),
                        str(m.get("decision") or ""),
                        str(m.get("risk_grade") or ""),
                        str(m.get("reason_code") or ""),
                        bool(m.get("pii_detected")),
                        str(m.get("pii_action") or ""),
                        pii_types_str,
                        int(m.get("policy_version") or 0),
                        str(m.get("neutrality_version") or ""),
                        "" if m.get("governance_score") is None else str(m.get("governance_score")),
                        created_iso,
                    ]
                )
                yield buf.getvalue().encode("utf-8")
                buf.seek(0)
                buf.truncate(0)

    filename = f"anchor_governance_export_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.csv"
    return StreamingResponse(
        _iter_csv(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
