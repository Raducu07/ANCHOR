# app/portal_bootstrap.py
import os
import hmac
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db, set_rls_context, clear_rls_context

router = APIRouter()

# ---------------------------
# Admin auth (single-token)
# Keep consistent with ops_rls_test.py for now
# ---------------------------

def require_admin(authorization: str = Header(default="")) -> None:
    token = (os.getenv("ADMIN_BEARER_TOKEN") or "").strip()
    if not token:
        raise HTTPException(status_code=500, detail="ADMIN_BEARER_TOKEN is not set")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    provided = authorization.split(" ", 1)[1].strip()
    if not hmac.compare_digest(provided, token):
        raise HTTPException(status_code=403, detail="Forbidden")


# ---------------------------
# Helpers
# ---------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _slugify(s: str) -> str:
    s = (s or "").strip().lower()
    out = []
    for ch in s:
        if ch.isalnum():
            out.append(ch)
        elif ch in (" ", "-", "_"):
            out.append("-")
    slug = "".join(out).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    if not slug:
        slug = f"clinic-{uuid.uuid4().hex[:8]}"
    return slug[:64]

def _hash_token(token_plain: str) -> str:
    # Store only hashes; never store plaintext invite tokens.
    salt = (os.getenv("INVITE_TOKEN_SALT") or "anchor-invite-salt").encode("utf-8")
    return hashlib.sha256(salt + token_plain.encode("utf-8")).hexdigest()

def json_dump(obj: Any) -> str:
    import json
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


# ---------------------------
# Request/Response models
# ---------------------------

class BootstrapClinicRequest(BaseModel):
    clinic_name: str = Field(..., min_length=2, max_length=200)
    clinic_slug: Optional[str] = Field(default=None, max_length=64)
    admin_email: str = Field(..., min_length=5, max_length=254)

    data_region: str = Field(default="UK")  # UK or EU
    retention_days_governance: int = Field(default=90, ge=1, le=3650)
    retention_days_ops: int = Field(default=30, ge=1, le=3650)
    export_enabled: bool = False

    invite_valid_days: int = Field(default=7, ge=1, le=30)
    subscription_tier: str = Field(default="starter")

class BootstrapClinicResponse(BaseModel):
    clinic_id: str
    clinic_slug: str
    policy_version: int
    invite_token: str
    expires_at: str


# ---------------------------
# Admin bootstrap endpoint
# ---------------------------

@router.post("/v1/admin/bootstrap/clinic", response_model=BootstrapClinicResponse)
def bootstrap_clinic(
    req: BootstrapClinicRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Creates:
      - clinics
      - clinic_users (system actor; inactive; required for FK)
      - clinic_privacy_profile
      - clinic_policies v1
      - clinic_policy_state -> v1
      - clinic_user_invites (admin)

    Works with FORCE RLS by setting app.clinic_id/app.user_id to the NEW clinic during inserts.
    """
    clinic_id = uuid.uuid4()

    # Deterministic system actor UUID (same value every time, OK because clinic_id scopes row visibility)
    # Unique per clinic to avoid PK collisions across clinics
    system_user_id = uuid.uuid5(uuid.NAMESPACE_DNS, f"anchor-system-bootstrap:{clinic_id}")

    slug = _slugify(req.clinic_slug or req.clinic_name)
    invite_token = secrets.token_urlsafe(24)
    token_hash = _hash_token(invite_token)
    expires_at = _now_utc() + timedelta(days=int(req.invite_valid_days))

    # Minimal default policy JSON (replace later with your real schema)
    policy_json: Dict[str, Any] = {
        "policy_version": 1,
        "mode_defaults": {
            "clinical_note": {"pii_action": "redact"},
            "client_comm": {"pii_action": "warn"},
            "internal_summary": {"pii_action": "allow"},
        },
    }

    try:
        # Set RLS context to the new clinic so WITH CHECK passes under FORCE RLS
        set_rls_context(db, clinic_id=str(clinic_id), user_id=str(system_user_id))

        # 1) clinics
        db.execute(
            text("""
                INSERT INTO clinics (clinic_id, clinic_name, clinic_slug, subscription_tier, active_status)
                VALUES (:cid, :name, :slug, :tier, true)
            """),
            {
                "cid": str(clinic_id),
                "name": req.clinic_name.strip(),
                "slug": slug,
                "tier": req.subscription_tier,
            },
        )

        # 2) system clinic user (required for FK created_by/updated_by)
        system_email = f"system+{slug}@anchor.local"
        db.execute(
            text("""
                INSERT INTO clinic_users (user_id, clinic_id, role, email, password_hash, active_status)
                VALUES (:uid, :cid, 'admin', :email, '!', false)
            """),
            {"uid": str(system_user_id), "cid": str(clinic_id), "email": system_email},
        )

        # 3) privacy profile
        db.execute(
            text("""
                INSERT INTO clinic_privacy_profile
                  (clinic_id, data_region, retention_days_governance, retention_days_ops,
                   export_enabled, updated_at)
                VALUES
                  (:cid, :region, :rg, :ro, :export_enabled, now())
            """),
            {
                "cid": str(clinic_id),
                "region": req.data_region,
                "rg": int(req.retention_days_governance),
                "ro": int(req.retention_days_ops),
                "export_enabled": bool(req.export_enabled),
            },
        )

        # 4) initial policy v1
        db.execute(
            text("""
                INSERT INTO clinic_policies (clinic_id, policy_version, policy_json, created_by)
                VALUES (:cid, 1, CAST(:pjson AS jsonb), :created_by)
            """),
            {
                "cid": str(clinic_id),
                "pjson": json_dump(policy_json),
                "created_by": str(system_user_id),
            },
        )

        # 5) active policy pointer
        db.execute(
            text("""
                INSERT INTO clinic_policy_state (clinic_id, active_policy_version, updated_by, updated_at)
                VALUES (:cid, 1, :updated_by, now())
            """),
            {"cid": str(clinic_id), "updated_by": str(system_user_id)},
        )

        # 6) admin invite (created_by is NULL until real admin exists)
        db.execute(
            text("""
                INSERT INTO clinic_user_invites
                  (invite_id, clinic_id, email, role, token_hash, expires_at, created_by, created_at)
                VALUES
                  (:iid, :cid, :email, 'admin', :th, :exp, NULL, now())
            """),
            {
                "iid": str(uuid.uuid4()),
                "cid": str(clinic_id),
                "email": req.admin_email.strip().lower(),
                "th": token_hash,
                "exp": expires_at,
            },
        )

        db.commit()

        return BootstrapClinicResponse(
            clinic_id=str(clinic_id),
            clinic_slug=slug,
            policy_version=1,
            invite_token=invite_token,
            expires_at=expires_at.isoformat(),
        )

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"bootstrap failed: {type(e).__name__}: {e}")
    finally:
        try:
            clear_rls_context(db)
        except Exception:
            pass
