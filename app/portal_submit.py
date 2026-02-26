# app/portal_submit.py
import json
import logging
import re
import uuid
import hashlib
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal"],
    dependencies=[Depends(require_clinic_user)],
)

_ALLOWED_MODES = {"clinical_note", "client_comm", "internal_summary"}

_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"\b(\+?\d[\d\s().-]{7,}\d)\b")
_UK_POSTCODE_RE = re.compile(r"\b([A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2})\b", re.IGNORECASE)


# ---------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------

def detect_pii_types(text_value: str) -> List[str]:
    t = text_value or ""
    types: List[str] = []

    if _EMAIL_RE.search(t):
        types.append("email")
    if _PHONE_RE.search(t):
        types.append("phone")
    if _UK_POSTCODE_RE.search(t):
        types.append("postcode")

    seen = set()
    out: List[str] = []
    for x in types:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _sha256_hex(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()


def _canonical_json(obj: Any) -> str:
    # Stable JSON for hashing (no whitespace, sorted keys)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _set_rls_context(db: Session, *, clinic_id: uuid.UUID, clinic_user_id: uuid.UUID) -> None:
    """
    Critical: set LOCAL RLS context in the same transaction/connection.
    """
    db.execute(text("SELECT set_config('app.clinic_id', :cid, true)"), {"cid": str(clinic_id)})
    db.execute(text("SELECT set_config('app.user_id', :uid, true)"), {"uid": str(clinic_user_id)})


def _get_active_policy_version(db: Session) -> int:
    row = db.execute(
        text(
            """
            SELECT active_policy_version
            FROM clinic_policy_state
            WHERE clinic_id = app_current_clinic_id()
            LIMIT 1
            """
        )
    ).fetchone()

    if not row:
        return 1

    try:
        return int(row[0])
    except Exception:
        return 1


def _get_policy_json(db: Session, *, policy_version: int) -> Optional[Dict[str, Any]]:
    row = db.execute(
        text(
            """
            SELECT policy_json
            FROM clinic_policies
            WHERE clinic_id = app_current_clinic_id()
              AND policy_version = :pv
            LIMIT 1
            """
        ),
        {"pv": int(policy_version)},
    ).mappings().first()

    if not row:
        return None

    try:
        return dict(row["policy_json"])
    except Exception:
        return row["policy_json"]


# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------

class PortalSubmitRequest(BaseModel):
    mode: str = Field(..., description="clinical_note | client_comm | internal_summary")
    text: str = Field(..., min_length=1, max_length=20000)
    request_id: Optional[uuid.UUID] = Field(default=None)

    # R1
    ai_assisted: bool = Field(default=False)
    user_confirmed_review: bool = Field(default=True)


class OverrideRequest(BaseModel):
    override_reason: str = Field(..., min_length=3, max_length=500)


class GovernanceReceipt(BaseModel):
    request_id: uuid.UUID
    clinic_id: uuid.UUID
    clinic_user_id: uuid.UUID
    mode: str
    decision: str
    risk_grade: str
    reason_code: str
    pii_detected: bool
    pii_action: str
    pii_types: List[str]
    policy_version: int
    neutrality_version: str
    governance_score: Optional[float] = None

    # M2.7 explainability (metadata-only)
    policy_sha256: Optional[str] = None
    rules_fired: Optional[dict] = None

    # R1 fields
    ai_assisted: bool = False
    user_confirmed_review: bool = True

    # R3 override fields (effective override computed from audit, with legacy fallback)
    override_flag: bool = False
    override_reason: Optional[str] = None
    override_at_utc: Optional[str] = None

    created_at_utc: str


class PortalSubmitResponse(BaseModel):
    receipt: GovernanceReceipt


class SubmissionItem(BaseModel):
    request_id: uuid.UUID
    clinic_user_id: uuid.UUID
    mode: str
    decision: str
    risk_grade: str
    reason_code: str
    pii_detected: bool
    policy_version: int
    neutrality_version: str

    ai_assisted: Optional[bool] = None
    user_confirmed_review: Optional[bool] = None

    # R3: visible override info in list view (effective override computed from audit)
    override_flag: Optional[bool] = None
    override_reason: Optional[str] = None
    override_at_utc: Optional[str] = None

    # WHO overrode (from admin_audit_events)
    override_by_user_id: Optional[uuid.UUID] = None
    override_by_email: Optional[str] = None
    override_logged_at_utc: Optional[str] = None

    created_at_utc: str


class SubmissionsListResponse(BaseModel):
    items: List[SubmissionItem]
    next_cursor: Optional[str] = None


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _row_to_receipt(row) -> GovernanceReceipt:
    created_at = row.get("created_at")
    created_iso = created_at.isoformat() if created_at else ""

    override_at = row.get("override_at")
    override_at_iso = override_at.isoformat() if override_at else None

    return GovernanceReceipt(
        request_id=uuid.UUID(str(row["request_id"])),
        clinic_id=uuid.UUID(str(row["clinic_id"])),
        clinic_user_id=uuid.UUID(str(row["user_id"])),
        mode=row["mode"],
        decision=row["decision"],
        risk_grade=row["risk_grade"],
        reason_code=row["reason_code"],
        pii_detected=bool(row["pii_detected"]),
        pii_action=row["pii_action"],
        pii_types=list(row.get("pii_types") or []),
        policy_version=int(row["policy_version"]),
        neutrality_version=row["neutrality_version"],
        governance_score=(float(row["governance_score"]) if row.get("governance_score") is not None else None),

        policy_sha256=row.get("policy_sha256"),
        rules_fired=row.get("rules_fired"),

        ai_assisted=bool(row.get("ai_assisted") or False),
        user_confirmed_review=bool(True if row.get("user_confirmed_review") is None else row.get("user_confirmed_review")),

        override_flag=bool(row.get("override_flag") or False),
        override_reason=row.get("override_reason"),
        override_at_utc=override_at_iso,

        created_at_utc=created_iso,
    )


def _parse_cursor(cursor: str) -> Optional[dict]:
    """
    cursor format: "<created_at_iso>|<request_id>"
    """
    try:
        created_at_str, request_id_str = cursor.split("|", 1)
        _ = uuid.UUID(request_id_str)
        return {"cursor_created_at": created_at_str, "cursor_request_id": request_id_str}
    except Exception:
        return None


# ---------------------------------------------------------------------
# POST /submit
# ---------------------------------------------------------------------

@router.post("/submit", response_model=PortalSubmitResponse)
def portal_submit(payload: PortalSubmitRequest, request: Request, db: Session = Depends(get_db)):
    mode = (payload.mode or "").strip()
    if mode not in _ALLOWED_MODES:
        raise HTTPException(status_code=400, detail="invalid mode")

    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    _set_rls_context(db, clinic_id=clinic_id, clinic_user_id=clinic_user_id)

    req_id = payload.request_id or uuid.uuid4()

    pii_types = detect_pii_types(payload.text)
    pii_detected = bool(pii_types)
    pii_action = "warn" if pii_detected else "allow"

    policy_version = _get_active_policy_version(db)

    # M2.7: policy fingerprint (metadata-only)
    policy_obj = _get_policy_json(db, policy_version=policy_version)
    policy_sha256 = _sha256_hex(_canonical_json(policy_obj)) if policy_obj is not None else None

    # M2.7: explainability placeholders (wire real rule hits later)
    rules_fired = None
    event_sha256 = None

    clinic_id_s = str(clinic_id)
    clinic_user_id_s = str(clinic_user_id)
    req_id_s = str(req_id)

    gov_row = (
        db.execute(
            text(
                """
                INSERT INTO clinic_governance_events (
                  clinic_id, request_id, user_id, mode,
                  pii_detected, pii_action, pii_types,
                  decision, risk_grade, reason_code,
                  governance_score, policy_version, neutrality_version,
                  ai_assisted, user_confirmed_review,
                  policy_sha256, rules_fired, event_sha256
                )
                VALUES (
                  :clinic_id, :request_id, :user_id, :mode,
                  :pii_detected, :pii_action, :pii_types,
                  'allowed',
                  CASE WHEN :pii_detected THEN 'med' ELSE 'low' END,
                  CASE WHEN :pii_detected THEN 'pii_detected' ELSE 'ok' END,
                  NULL,
                  :policy_version,
                  'v1.1',
                  :ai_assisted,
                  :user_confirmed_review,
                  :policy_sha256,
                  CAST(:rules_fired AS jsonb),
                  :event_sha256
                )
                ON CONFLICT (clinic_id, request_id) DO NOTHING
                RETURNING *
                """
            ),
            {
                "clinic_id": clinic_id_s,
                "request_id": req_id_s,
                "user_id": clinic_user_id_s,
                "mode": mode,
                "pii_detected": pii_detected,
                "pii_action": pii_action,
                "pii_types": pii_types,
                "policy_version": policy_version,
                "ai_assisted": bool(payload.ai_assisted),
                "user_confirmed_review": bool(payload.user_confirmed_review),
                "policy_sha256": policy_sha256,
                "rules_fired": json.dumps(rules_fired) if rules_fired is not None else None,
                "event_sha256": event_sha256,
            },
        )
        .mappings()
        .first()
    )

    db.execute(
        text(
            """
            INSERT INTO ops_metrics_events (
              clinic_id, request_id, route, status_code, latency_ms,
              mode, governance_replaced, pii_warned
            )
            VALUES (
              :clinic_id, :request_id, :route, 200, 0,
              :mode, false, :pii_warned
            )
            ON CONFLICT (clinic_id, request_id) DO NOTHING
            """
        ),
        {
            "clinic_id": clinic_id_s,
            "request_id": req_id_s,
            "route": request.url.path,
            "mode": mode,
            "pii_warned": pii_detected,
        },
    )

    db.commit()

    if gov_row:
        return PortalSubmitResponse(receipt=_row_to_receipt(gov_row))

    existing = (
        db.execute(
            text(
                """
                SELECT *
                FROM clinic_governance_events
                WHERE clinic_id = :clinic_id
                  AND request_id = :request_id
                LIMIT 1
                """
            ),
            {"clinic_id": clinic_id_s, "request_id": req_id_s},
        )
        .mappings()
        .first()
    )
    if not existing:
        raise HTTPException(status_code=500, detail="idempotency failure")

    return PortalSubmitResponse(receipt=_row_to_receipt(existing))


# ---------------------------------------------------------------------
# GET /receipts/{request_id}
# - Effective override is computed from latest admin_audit_events row (append-only truth)
# - Legacy override_* fields remain as fallback only
# ---------------------------------------------------------------------

@router.get("/receipts/{request_id}", response_model=PortalSubmitResponse)
def get_receipt(request_id: uuid.UUID, request: Request, db: Session = Depends(get_db)):
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    _set_rls_context(db, clinic_id=clinic_id, clinic_user_id=clinic_user_id)

    row = (
        db.execute(
            text(
                """
                SELECT
                  g.*,
                  -- override from audit log (latest wins); fallback to legacy columns if present
                  (ae.override_logged_at IS NOT NULL OR COALESCE(g.override_flag, false)) AS override_flag,
                  COALESCE(ae.override_reason, g.override_reason) AS override_reason,
                  COALESCE(ae.override_logged_at, g.override_at) AS override_at
                FROM clinic_governance_events g
                LEFT JOIN LATERAL (
                  SELECT
                    a.created_at AS override_logged_at,
                    a.meta->>'override_reason' AS override_reason
                  FROM admin_audit_events a
                  WHERE a.clinic_id = g.clinic_id
                    AND a.action = 'override_submission'
                    AND a.target_id = g.request_id
                  ORDER BY a.created_at DESC, a.event_id DESC
                  LIMIT 1
                ) ae ON TRUE
                WHERE g.clinic_id = CAST(:clinic_id AS uuid)
                  AND g.request_id = CAST(:request_id AS uuid)
                LIMIT 1
                """
            ),
            {"clinic_id": str(clinic_id), "request_id": str(request_id)},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="receipt not found")

    return PortalSubmitResponse(receipt=_row_to_receipt(row))


# ---------------------------------------------------------------------
# POST /override/{request_id}   (R3 -> hardened)
# - Admin can override ANY submission in the clinic
# - Idempotent via DB unique index on (clinic_id, action, idempotency_key)
# - Append-only: does NOT mutate clinic_governance_events
# ---------------------------------------------------------------------

SQL_INSERT_OVERRIDE_AUDIT = text(
    """
    INSERT INTO admin_audit_events (
      clinic_id,
      admin_user_id,
      action,
      target_id,
      ip_hash,
      meta,
      idempotency_key
    )
    VALUES (
      CAST(:clinic_id AS uuid),
      CAST(:admin_user_id AS uuid),
      :action,
      CAST(:target_id AS uuid),
      :ip_hash,
      CAST(:meta AS jsonb),
      :idempotency_key
    )
    ON CONFLICT (clinic_id, action, idempotency_key)
    DO NOTHING
    RETURNING event_id;
    """
)


@router.post("/override/{request_id}", response_model=PortalSubmitResponse)
def override_submission(
    request_id: uuid.UUID,
    payload: OverrideRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    role = getattr(request.state, "role", None)

    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")
    if role != "admin":
        raise HTTPException(status_code=403, detail="forbidden")

    reason = (payload.override_reason or "").strip()
    if not reason:
        raise HTTPException(status_code=400, detail="override_reason required")

    _set_rls_context(db, clinic_id=clinic_id, clinic_user_id=clinic_user_id)

    try:
        # Ensure target exists (RLS-safe)
        original = (
            db.execute(
                text(
                    """
                    SELECT user_id::text AS original_user_id
                    FROM clinic_governance_events
                    WHERE clinic_id = CAST(:clinic_id AS uuid)
                      AND request_id = CAST(:request_id AS uuid)
                    LIMIT 1
                    """
                ),
                {"clinic_id": str(clinic_id), "request_id": str(request_id)},
            )
            .mappings()
            .first()
        )
        if not original:
            raise HTTPException(status_code=404, detail="receipt not found")

        original_user_id = original.get("original_user_id")

        # DB-enforced idempotency key (stable)
        # NOTE: includes reason; same request_id + same reason => idempotent no-op
        idem_raw = f"override_submission:{clinic_id}:{request_id}:{reason}"
        idempotency_key = _sha256_hex(idem_raw)

        # Metadata-only (no content)
        meta_payload = {
            "request_id": str(request_id),
            "original_user_id": str(original_user_id) if original_user_id else None,
            "override_reason": reason,
            "override_reason_len": len(reason),
        }

        ip_hash = getattr(request.state, "ip_hash", None)

        db.execute(
            SQL_INSERT_OVERRIDE_AUDIT,
            {
                "clinic_id": str(clinic_id),
                "admin_user_id": str(clinic_user_id),
                "action": "override_submission",
                "target_id": str(request_id),
                "ip_hash": ip_hash,
                "meta": json.dumps(meta_payload),
                "idempotency_key": idempotency_key,
            },
        ).fetchone()

        db.commit()

        # Return effective receipt (computed override via audit LATERAL join)
        return get_receipt(request_id=request_id, request=request, db=db)

    except HTTPException:
        try:
            db.rollback()
        except Exception:
            pass
        raise

    except Exception:
        try:
            db.rollback()
        except Exception:
            pass

        logger.exception(
            "portal_override_failed",
            extra={
                "route": getattr(request.url, "path", None),
                "request_id": str(request_id),
                "clinic_id": str(clinic_id),
                "clinic_user_id": str(clinic_user_id),
                "role": role,
            },
        )
        raise HTTPException(status_code=500, detail="internal_server_error")


# ---------------------------------------------------------------------
# GET /submissions  (with filtering + cursor pagination)
# - Effective override from admin_audit_events (latest per request)
# - Also returns override_by_email (joined via clinic_users)
# ---------------------------------------------------------------------

@router.get("/submissions", response_model=SubmissionsListResponse)
def list_submissions(
    request: Request,
    db: Session = Depends(get_db),
    limit: int = 20,
    cursor: Optional[str] = None,
    mode: Optional[str] = None,
    decision: Optional[str] = None,
):
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    _set_rls_context(db, clinic_id=clinic_id, clinic_user_id=clinic_user_id)

    limit = max(1, min(100, int(limit)))

    filters: List[str] = []
    params: dict = {"clinic_id": str(clinic_id), "limit": limit}

    if mode:
        mode = mode.strip()
        if mode not in _ALLOWED_MODES:
            raise HTTPException(status_code=400, detail="invalid mode filter")
        filters.append("cge.mode = :mode")
        params["mode"] = mode

    if decision:
        decision = decision.strip()
        filters.append("cge.decision = :decision")
        params["decision"] = decision

    cursor_clause = ""
    if cursor:
        parsed = _parse_cursor(cursor)
        if parsed is None:
            raise HTTPException(status_code=400, detail="invalid cursor")
        cursor_clause = """
          AND (
            cge.created_at < :cursor_created_at::timestamptz
            OR (
              cge.created_at = :cursor_created_at::timestamptz
              AND cge.request_id < :cursor_request_id::uuid
            )
          )
        """
        params.update(parsed)

    where_extra = ""
    if filters:
        where_extra = " AND " + " AND ".join(filters)

    rows = (
        db.execute(
            text(
                f"""
                SELECT
                  cge.*,

                  -- effective override fields (audit truth + legacy fallback)
                  (ae.override_logged_at IS NOT NULL OR COALESCE(cge.override_flag, false)) AS override_flag,
                  COALESCE(ae.override_reason, cge.override_reason) AS override_reason,
                  COALESCE(ae.override_logged_at, cge.override_at) AS override_at,

                  ae.override_by_user_id,
                  ae.override_by_email,
                  ae.override_logged_at
                FROM clinic_governance_events cge
                LEFT JOIN LATERAL (
                  SELECT
                    a.admin_user_id::text AS override_by_user_id,
                    cu.email AS override_by_email,
                    a.created_at AS override_logged_at,
                    a.meta->>'override_reason' AS override_reason
                  FROM admin_audit_events a
                  JOIN clinic_users cu
                    ON cu.user_id = a.admin_user_id
                   AND cu.clinic_id = a.clinic_id
                  WHERE a.clinic_id = cge.clinic_id
                    AND a.action = 'override_submission'
                    AND a.target_id = cge.request_id
                  ORDER BY a.created_at DESC, a.event_id DESC
                  LIMIT 1
                ) ae ON true
                WHERE cge.clinic_id = CAST(:clinic_id AS uuid)
                {where_extra}
                {cursor_clause}
                ORDER BY cge.created_at DESC, cge.request_id DESC
                LIMIT :limit
                """
            ),
            params,
        )
        .mappings()
        .all()
    )

    items: List[SubmissionItem] = []
    for row in rows:
        override_logged_at = row.get("override_logged_at")

        items.append(
            SubmissionItem(
                request_id=uuid.UUID(str(row["request_id"])),
                clinic_user_id=uuid.UUID(str(row["user_id"])),
                mode=row["mode"],
                decision=row["decision"],
                risk_grade=row["risk_grade"],
                reason_code=row["reason_code"],
                pii_detected=bool(row["pii_detected"]),
                policy_version=int(row["policy_version"]),
                neutrality_version=row["neutrality_version"],

                # normalize legacy nulls
                ai_assisted=bool(row.get("ai_assisted") or False),
                user_confirmed_review=bool(
                    True if row.get("user_confirmed_review") is None else row.get("user_confirmed_review")
                ),

                override_flag=bool(row.get("override_flag") or False),
                override_reason=row.get("override_reason"),
                override_at_utc=(row["override_at"].isoformat() if row.get("override_at") else None),

                override_by_user_id=(
                    uuid.UUID(row["override_by_user_id"]) if row.get("override_by_user_id") else None
                ),
                override_by_email=row.get("override_by_email"),
                override_logged_at_utc=(override_logged_at.isoformat() if override_logged_at else None),

                created_at_utc=row["created_at"].isoformat(),
            )
        )

    next_cursor = None
    if rows:
        last = rows[-1]
        next_cursor = f"{last['created_at'].isoformat()}|{last['request_id']}"

    return SubmissionsListResponse(items=items, next_cursor=next_cursor)
