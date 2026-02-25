# app/portal_submit.py
import re
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_and_rls import require_clinic_user
from app.db import get_db

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

    # stable de-dupe
    seen = set()
    out: List[str] = []
    for x in types:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _set_rls_context(db: Session, *, clinic_id: uuid.UUID, clinic_user_id: uuid.UUID) -> None:
    """
    Critical: set LOCAL RLS context in the *same transaction/connection*.
    Using set_config(..., true) makes it LOCAL to the current transaction.
    """
    db.execute(
        text("SELECT set_config('app.clinic_id', :cid, true)"),
        {"cid": str(clinic_id)},
    )
    db.execute(
        text("SELECT set_config('app.user_id', :uid, true)"),
        {"uid": str(clinic_user_id)},
    )


def _get_active_policy_version(db: Session) -> int:
    """
    Must be called AFTER _set_rls_context() so app_current_clinic_id() is non-null.
    """
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


def _iso_utc(dt) -> str:
    if not dt:
        return ""
    try:
        # if tz-aware already, keep it
        return dt.isoformat()
    except Exception:
        return str(dt)


# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------

class PortalSubmitRequest(BaseModel):
    mode: str = Field(..., description="clinical_note | client_comm | internal_summary")
    text: str = Field(..., min_length=1, max_length=20000)
    request_id: Optional[uuid.UUID] = Field(default=None)

    # -------------------------------------------------------------
    # R1: explicit declarations (user-level accountability signals)
    # -------------------------------------------------------------
    ai_assisted: bool = Field(
        default=False,
        description="User declares AI assistance was used to create/edit this text.",
    )
    user_confirmed_review: bool = Field(
        default=True,
        description="User confirms they reviewed the AI-assisted output before submission.",
    )


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
    created_at_utc: str

    # ----------------
    # R1 fields
    # ----------------
    ai_assisted: bool = False
    user_confirmed_review: bool = True

    # ----------------
    # R3 fields
    # ----------------
    override_flag: bool = False
    override_reason: Optional[str] = None
    override_at_utc: Optional[str] = None


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
    created_at_utc: str

    # expose R1/R3 summary fields in list view (optional but useful)
    ai_assisted: bool = False
    user_confirmed_review: bool = True
    override_flag: bool = False


class SubmissionsListResponse(BaseModel):
    items: List[SubmissionItem]
    next_cursor: Optional[str] = None


class OverrideRequest(BaseModel):
    override_reason: str = Field(..., min_length=2, max_length=2000)


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _row_to_receipt(row) -> GovernanceReceipt:
    created_iso = _iso_utc(row.get("created_at"))
    override_iso = _iso_utc(row.get("override_at")) if row.get("override_at") else None

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
        pii_types=list(row["pii_types"] or []),
        policy_version=int(row["policy_version"]),
        neutrality_version=row["neutrality_version"],
        governance_score=(float(row["governance_score"]) if row.get("governance_score") is not None else None),
        created_at_utc=created_iso,
        ai_assisted=bool(row.get("ai_assisted") or False),
        user_confirmed_review=bool(row.get("user_confirmed_review") if row.get("user_confirmed_review") is not None else True),
        override_flag=bool(row.get("override_flag") or False),
        override_reason=row.get("override_reason"),
        override_at_utc=override_iso,
    )


def _parse_cursor(cursor: str) -> Optional[dict]:
    """
    cursor format: "<created_at_iso>|<request_id>"
    Returns dict with cursor_created_at, cursor_request_id or None if invalid.
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

    # Ensure we're operating under tenant context for ALL queries in this request
    _set_rls_context(db, clinic_id=clinic_id, clinic_user_id=clinic_user_id)

    req_id = payload.request_id or uuid.uuid4()

    pii_types = detect_pii_types(payload.text)
    pii_detected = bool(pii_types)
    pii_action = "warn" if pii_detected else "allow"

    policy_version = _get_active_policy_version(db)

    clinic_id_s = str(clinic_id)
    clinic_user_id_s = str(clinic_user_id)
    req_id_s = str(req_id)

    # ------------------------------------------------------------
    # One important integration note (R1):
    # You already compute decision/risk_grade/reason_code/etc.
    # in this endpoint. R1 simply threads:
    #   - ai_assisted
    #   - user_confirmed_review
    # into the governance insert. Nothing else changes.
    # ------------------------------------------------------------
    ai_assisted = bool(payload.ai_assisted)
    user_confirmed_review = bool(payload.user_confirmed_review)

    # Insert governance event (idempotent)
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
                  override_flag, override_reason, override_at
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
                  :ai_assisted, :user_confirmed_review,
                  false, NULL, NULL
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
                "ai_assisted": ai_assisted,
                "user_confirmed_review": user_confirmed_review,
            },
        )
        .mappings()
        .first()
    )

    # Insert ops metrics (idempotent)
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

    # If the governance insert conflicted, fetch existing row (still under RLS)
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
                SELECT *
                FROM clinic_governance_events
                WHERE clinic_id = :clinic_id
                  AND request_id = :request_id
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
# POST /override/{request_id}   (R3)
# ---------------------------------------------------------------------

@router.post("/override/{request_id}", response_model=PortalSubmitResponse)
def override_receipt(
    request_id: uuid.UUID,
    payload: OverrideRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    R3: Override logging.
    Only the author (clinic_user_id) can override their own event.

    This does NOT change the underlying decision. It records:
      - override_flag=true
      - override_reason
      - override_at
    """
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    _set_rls_context(db, clinic_id=clinic_id, clinic_user_id=clinic_user_id)

    now = datetime.now(timezone.utc).isoformat()

    row = (
        db.execute(
            text(
                """
                UPDATE clinic_governance_events
                SET
                    override_flag = true,
                    override_reason = :override_reason,
                    override_at = :override_at::timestamptz
                WHERE clinic_id = :clinic_id
                  AND request_id = :request_id
                  AND user_id = :user_id
                RETURNING *
                """
            ),
            {
                "clinic_id": str(clinic_id),
                "request_id": str(request_id),
                "user_id": str(clinic_user_id),
                "override_reason": payload.override_reason.strip(),
                "override_at": now,
            },
        )
        .mappings()
        .first()
    )

    if not row:
        # Not found OR not owned by this user (same response to avoid leaking existence)
        raise HTTPException(status_code=404, detail="not_found_or_not_owner")

    db.commit()
    return PortalSubmitResponse(receipt=_row_to_receipt(row))


# ---------------------------------------------------------------------
# GET /submissions  (with filtering + cursor pagination)
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

    filters = []
    params = {"clinic_id": str(clinic_id), "limit": limit}

    if mode:
        mode = mode.strip()
        if mode not in _ALLOWED_MODES:
            raise HTTPException(status_code=400, detail="invalid mode filter")
        filters.append("mode = :mode")
        params["mode"] = mode

    if decision:
        decision = decision.strip()
        filters.append("decision = :decision")
        params["decision"] = decision

    cursor_clause = ""
    if cursor:
        parsed = _parse_cursor(cursor)
        if parsed is None:
            raise HTTPException(status_code=400, detail="invalid cursor")
        cursor_clause = """
            AND (
                created_at < :cursor_created_at::timestamptz
                OR (created_at = :cursor_created_at::timestamptz AND request_id < :cursor_request_id::uuid)
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
                SELECT *
                FROM clinic_governance_events
                WHERE clinic_id = :clinic_id
                {where_extra}
                {cursor_clause}
                ORDER BY created_at DESC, request_id DESC
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
                created_at_utc=row["created_at"].isoformat(),
                ai_assisted=bool(row.get("ai_assisted") or False),
                user_confirmed_review=bool(
                    row.get("user_confirmed_review") if row.get("user_confirmed_review") is not None else True
                ),
                override_flag=bool(row.get("override_flag") or False),
            )
        )

    next_cursor = None
    if rows:
        last = rows[-1]
        next_cursor = f"{last['created_at'].isoformat()}|{last['request_id']}"

    return SubmissionsListResponse(items=items, next_cursor=next_cursor)
