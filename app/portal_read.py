# app/portal_read.py
import os
import uuid
import json
import hmac
import hashlib
from datetime import datetime, timezone
from typing import List, Optional, Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.auth_and_rls import require_clinic_user, JWT_ISSUER, JWT_AUDIENCE
from app.rate_limit import enforce_authed

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal Read"],
    dependencies=[Depends(require_clinic_user)],
)

# -----------------------------
# Signing config (for export)
# -----------------------------
RECEIPT_SIGNING_SECRET = (os.getenv("ANCHOR_RECEIPT_SIGNING_SECRET", "") or "").strip()
RECEIPT_SIGNING_KID = (os.getenv("ANCHOR_RECEIPT_SIGNING_KID", "v1") or "v1").strip()


# -----------------------------
# Helpers
# -----------------------------
def _set_rls_context(db: Session, *, clinic_id: uuid.UUID, clinic_user_id: uuid.UUID) -> None:
    """
    Explicit RLS context set per request.
    Matches portal_submit.py behaviour (safe even if get_db also sets it).
    """
    db.execute(text("SELECT set_config('app.clinic_id', :cid, true)"), {"cid": str(clinic_id)})
    db.execute(text("SELECT set_config('app.user_id', :uid, true)"), {"uid": str(clinic_user_id)})


def _parse_iso8601(ts: str) -> datetime:
    s = (ts or "").strip()
    if not s:
        raise ValueError("empty timestamp")
    s = s.replace(" ", "+")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def _iso_or_empty(dt: Any) -> str:
    if dt is None:
        return ""
    try:
        return dt.isoformat()
    except Exception:
        return str(dt)


def _canonical_json_bytes(obj: Any) -> bytes:
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return s.encode("utf-8")


def _hmac_sha256_b64url(key: str, msg: bytes) -> str:
    mac = hmac.new(key.encode("utf-8"), msg, hashlib.sha256).digest()
    import base64
    return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")


def _hash_policy_json(policy_json: Any) -> str:
    """
    Hash clinic policy JSON (semantic = the whole JSON).
    Stable canonical encoding.
    """
    blob = json.dumps(policy_json or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _get_clinic_policy_json(db: Session, *, policy_version: int) -> Optional[Dict[str, Any]]:
    """
    Fetch clinic policy JSON for the given version under RLS.
    """
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


# -----------------------------
# Models
# -----------------------------
class GovernanceEventItem(BaseModel):
    request_id: uuid.UUID
    clinic_id: uuid.UUID
    clinic_user_id: uuid.UUID
    mode: str

    decision: str
    risk_grade: str
    reason_code: str

    pii_detected: bool
    pii_action: str
    pii_types: List[str] = Field(default_factory=list)

    policy_version: int
    neutrality_version: str
    governance_score: Optional[float] = None

    # Effective override (append-only truth from admin_audit_events; legacy fallback)
    override_flag: bool = False
    override_reason: Optional[str] = None
    override_at_utc: Optional[str] = None

    created_at_utc: str


class GovernanceEventsResponse(BaseModel):
    items: List[GovernanceEventItem]
    next_cursor_created_at_utc: Optional[str] = None
    next_cursor_request_id: Optional[uuid.UUID] = None


class ReceiptV1(BaseModel):
    request_id: str
    clinic_id: str
    clinic_user_id: str

    mode: str
    decision: str
    risk_grade: Optional[str] = None
    reason_code: Optional[str] = None

    pii_detected: bool = False
    pii_action: Optional[str] = None
    pii_types: List[str] = Field(default_factory=list)

    policy_version: int
    policy_hash: str
    policy_id: Optional[str] = None

    neutrality_version: Optional[str] = None
    governance_score: Optional[float] = None

    # Effective override (append-only truth)
    override_flag: bool = False
    override_reason: Optional[str] = None
    override_at_utc: Optional[str] = None

    receipt_version: str = "1.0"
    jwt_iss: str
    jwt_aud: str
    tenant_isolation: Dict[str, Any] = Field(default_factory=lambda: {"rls_forced": True})
    no_content_stored: bool = True

    created_at_utc: str


class ReceiptEnvelope(BaseModel):
    receipt: ReceiptV1


class SignedReceiptEnvelope(BaseModel):
    receipt: ReceiptV1
    signature: str
    alg: str = "HS256"
    kid: str = Field(default=RECEIPT_SIGNING_KID)
    signed_at_utc: str
    payload_hash: str


# -----------------------------
# SQL
# -----------------------------
_SQL_LIST_EVENTS = """
SELECT
  g.request_id,
  g.clinic_id,
  g.user_id AS clinic_user_id,
  g.mode,
  g.decision,
  g.risk_grade,
  g.reason_code,
  g.pii_detected,
  g.pii_action,
  COALESCE(g.pii_types, ARRAY[]::text[]) AS pii_types,
  g.policy_version,
  g.neutrality_version,
  g.governance_score,

  -- effective override fields (audit truth + legacy fallback)
  (ae.override_logged_at IS NOT NULL OR COALESCE(g.override_flag, false)) AS override_flag,
  COALESCE(ae.override_reason, g.override_reason) AS override_reason,
  COALESCE(ae.override_logged_at, g.override_at) AS override_at,

  g.created_at
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
WHERE g.clinic_id = app_current_clinic_id()
{cursor_clause}
ORDER BY g.created_at DESC, g.request_id DESC
LIMIT :limit
"""

_SQL_GET_RECEIPT = """
SELECT
  g.request_id,
  g.clinic_id,
  g.user_id AS clinic_user_id,
  g.mode,
  g.decision,
  g.risk_grade,
  g.reason_code,
  g.pii_detected,
  g.pii_action,
  COALESCE(g.pii_types, ARRAY[]::text[]) AS pii_types,
  g.policy_version,
  g.neutrality_version,
  g.governance_score,

  -- effective override fields (audit truth + legacy fallback)
  (ae.override_logged_at IS NOT NULL OR COALESCE(g.override_flag, false)) AS override_flag,
  COALESCE(ae.override_reason, g.override_reason) AS override_reason,
  COALESCE(ae.override_logged_at, g.override_at) AS override_at,

  g.created_at
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
WHERE g.clinic_id = app_current_clinic_id()
  AND g.request_id = CAST(:rid AS uuid)
LIMIT 1
"""


# -----------------------------
# Routes
# -----------------------------
@router.get("/governance-events", response_model=GovernanceEventsResponse)
def list_governance_events(
    request: Request,
    db: Session = Depends(get_db),
    limit: int = 50,
    cursor_created_at_utc: Optional[str] = None,
    cursor_request_id: Optional[uuid.UUID] = None,
) -> GovernanceEventsResponse:
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    _set_rls_context(db, clinic_id=clinic_id, clinic_user_id=clinic_user_id)

    limit = int(limit)
    if limit < 1:
        limit = 1
    if limit > 200:
        limit = 200

    cursor_clause = ""
    params: Dict[str, Any] = {"limit": limit}

    if cursor_created_at_utc:
        try:
            cursor_dt = _parse_iso8601(cursor_created_at_utc)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid cursor_created_at_utc")

        cursor_rid = cursor_request_id or uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
        cursor_clause = "AND (g.created_at, g.request_id) < (:cursor_dt, :cursor_rid)"
        params["cursor_dt"] = cursor_dt
        params["cursor_rid"] = str(cursor_rid)

    sql = _SQL_LIST_EVENTS.format(cursor_clause=cursor_clause)
    rows = db.execute(text(sql), params).mappings().all()

    items: List[GovernanceEventItem] = []
    for r in rows:
        override_at = r.get("override_at")
        items.append(
            GovernanceEventItem(
                request_id=uuid.UUID(str(r["request_id"])),
                clinic_id=uuid.UUID(str(r["clinic_id"])),
                clinic_user_id=uuid.UUID(str(r["clinic_user_id"])),
                mode=str(r["mode"]),
                decision=str(r["decision"]),
                risk_grade=str(r["risk_grade"]),
                reason_code=str(r["reason_code"]),
                pii_detected=bool(r["pii_detected"]),
                pii_action=str(r["pii_action"]),
                pii_types=list(r.get("pii_types") or []),
                policy_version=int(r["policy_version"]),
                neutrality_version=str(r["neutrality_version"]),
                governance_score=r.get("governance_score", None),

                override_flag=bool(r.get("override_flag") or False),
                override_reason=(str(r["override_reason"]) if r.get("override_reason") is not None else None),
                override_at_utc=(override_at.isoformat() if override_at is not None else None),

                created_at_utc=_iso_or_empty(r.get("created_at")),
            )
        )

    next_created = items[-1].created_at_utc if items else None
    next_rid = items[-1].request_id if items else None

    return GovernanceEventsResponse(
        items=items,
        next_cursor_created_at_utc=next_created,
        next_cursor_request_id=next_rid,
    )


@router.get("/receipt/{request_id}", response_model=ReceiptEnvelope)
def get_receipt(
    request_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> ReceiptEnvelope:
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    # -------------------------
    # Deterministic rate limiting (tenant-safe)
    # -------------------------
    enforce_authed(
        request,
        clinic_id=str(clinic_id),
        clinic_user_id=str(clinic_user_id),
        group="receipt",
    )

    _set_rls_context(db, clinic_id=clinic_id, clinic_user_id=clinic_user_id)

    row = db.execute(text(_SQL_GET_RECEIPT), {"rid": str(request_id)}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="receipt not found")

    created_at_utc = _iso_or_empty(row.get("created_at"))
    override_at = row.get("override_at")

    # policy hash from clinic policy version used by this event
    pv = int(row.get("policy_version") or 0)
    policy_json = _get_clinic_policy_json(db, policy_version=pv)
    policy_hash = _hash_policy_json(policy_json)

    # policy_id: stable, tenant-local identifier
    policy_id = f"clinic_policy:{pv}"

    receipt = ReceiptV1(
        request_id=str(row["request_id"]),
        clinic_id=str(row["clinic_id"]),
        clinic_user_id=str(row["clinic_user_id"]),
        mode=str(row["mode"]),
        decision=str(row["decision"]),
        risk_grade=(str(row["risk_grade"]) if row.get("risk_grade") is not None else None),
        reason_code=(str(row["reason_code"]) if row.get("reason_code") is not None else None),
        pii_detected=bool(row.get("pii_detected") or False),
        pii_action=(str(row["pii_action"]) if row.get("pii_action") is not None else None),
        pii_types=list(row.get("pii_types") or []),
        policy_version=pv,
        policy_hash=policy_hash,
        policy_id=policy_id,
        neutrality_version=(str(row["neutrality_version"]) if row.get("neutrality_version") is not None else None),
        governance_score=(float(row["governance_score"]) if row.get("governance_score") is not None else None),

        override_flag=bool(row.get("override_flag") or False),
        override_reason=(str(row["override_reason"]) if row.get("override_reason") is not None else None),
        override_at_utc=(override_at.isoformat() if override_at is not None else None),

        jwt_iss=str(JWT_ISSUER),
        jwt_aud=str(JWT_AUDIENCE),
        created_at_utc=created_at_utc,
    )

    return ReceiptEnvelope(receipt=receipt)


@router.get("/receipt/{request_id}/signed", response_model=SignedReceiptEnvelope)
def get_receipt_signed(
    request_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> SignedReceiptEnvelope:
    if not RECEIPT_SIGNING_SECRET:
        raise HTTPException(status_code=501, detail="receipt signing not configured")

    # Optional: no extra rate limit needed here because get_receipt() enforces it.
    env = get_receipt(request_id=request_id, request=request, db=db)
    receipt = env.receipt

    payload_obj = receipt.model_dump()
    payload_bytes = _canonical_json_bytes(payload_obj)
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    signature = _hmac_sha256_b64url(RECEIPT_SIGNING_SECRET, payload_bytes)
    signed_at_utc = datetime.now(timezone.utc).isoformat()

    return SignedReceiptEnvelope(
        receipt=receipt,
        signature=signature,
        kid=RECEIPT_SIGNING_KID,
        signed_at_utc=signed_at_utc,
        payload_hash=payload_hash,
    )


@router.get("/receipts/{request_id}", response_model=ReceiptEnvelope, deprecated=True)
def get_receipt_legacy(
    request_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
) -> ReceiptEnvelope:
    return get_receipt(request_id=request_id, request=request, db=db)
