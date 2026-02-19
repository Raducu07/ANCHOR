# app/auth_and_rls.py
import os
import time
import hmac
import hashlib
from typing import Optional, Dict, Any

import jwt
from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import text

from app.db import SessionLocal

router = APIRouter(prefix="/v1/clinic-auth", tags=["Clinic Auth"])

# -----------------------------
# Config
# -----------------------------
JWT_SECRET = os.getenv("ANCHOR_JWT_SECRET", "")
JWT_ISSUER = os.getenv("ANCHOR_JWT_ISSUER", "anchor")
JWT_AUDIENCE = os.getenv("ANCHOR_JWT_AUDIENCE", "anchor-portal")
JWT_TTL_SEC = int(os.getenv("ANCHOR_JWT_TTL_SEC", "86400"))  # 24h

if not JWT_SECRET:
    # Fail fast in dev; in prod Render env var must be set
    # but don't crash import-time: only raise when used
    pass

# -----------------------------
# Password verification
# -----------------------------
# If you're using argon2/bcrypt already, swap this out.
# For now: expects stored hash format "sha256:<hex>" (simple, but not ideal).
def _verify_password(password: str, stored_hash: str) -> bool:
    if not stored_hash or ":" not in stored_hash:
        return False
    scheme, digest = stored_hash.split(":", 1)
    if scheme != "sha256":
        return False
    computed = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(computed, digest)

def _make_jwt(payload: Dict[str, Any]) -> str:
    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="ANCHOR_JWT_SECRET not set")
    now = int(time.time())
    full = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + JWT_TTL_SEC,
        **payload,
    }
    return jwt.encode(full, JWT_SECRET, algorithm="HS256")

def _decode_jwt(token: str) -> Dict[str, Any]:
    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="ANCHOR_JWT_SECRET not set")
    try:
        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")

# -----------------------------
# DB helpers (RLS context)
# -----------------------------
def set_rls_context(db, clinic_id: str, user_id: str) -> None:
    # applies to current DB connection
    db.execute(text("SELECT set_config('app.clinic_id', :cid, true)"), {"cid": str(clinic_id)})
    db.execute(text("SELECT set_config('app.user_id',   :uid, true)"), {"uid": str(user_id)})

# -----------------------------
# Schemas
# -----------------------------
class ClinicLoginRequest(BaseModel):
    clinic_slug: str = Field(..., min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=200)

class ClinicLoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    clinic_id: str
    user_id: str
    role: str

# -----------------------------
# Routes
# -----------------------------
@router.post("/login", response_model=ClinicLoginResponse)
def clinic_login(req: ClinicLoginRequest) -> ClinicLoginResponse:
    """
    Auth for Portal V1 (clinic_users + clinics tables).
    Requires tables: clinics(clinic_slug), clinic_users(email, password_hash, clinic_id).
    """
    db = SessionLocal()
    try:
        # 1) Resolve clinic by slug
        clinic = db.execute(
            text("SELECT clinic_id FROM clinics WHERE clinic_slug = :slug AND active_status = true"),
            {"slug": req.clinic_slug},
        ).mappings().first()

        if not clinic:
            raise HTTPException(status_code=401, detail="invalid credentials")

        clinic_id = str(clinic["clinic_id"])

        # 2) Query user in that clinic
        user = db.execute(
            text("""
                SELECT user_id, role, password_hash, active_status
                FROM clinic_users
                WHERE clinic_id = :cid AND email = :email
                LIMIT 1
            """),
            {"cid": clinic_id, "email": str(req.email).lower()},
        ).mappings().first()

        if not user or not user["active_status"]:
            raise HTTPException(status_code=401, detail="invalid credentials")

        if not _verify_password(req.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="invalid credentials")

        user_id = str(user["user_id"])
        role = str(user["role"])

        # 3) Set RLS context for this connection (useful if you immediately fetch tenant rows post-login)
        set_rls_context(db, clinic_id=clinic_id, user_id=user_id)
        db.commit()

        # 4) Issue token
        token = _make_jwt({"clinic_id": clinic_id, "user_id": user_id, "role": role})

        return ClinicLoginResponse(
            access_token=token,
            clinic_id=clinic_id,
            user_id=user_id,
            role=role,
        )
    finally:
        db.close()

# -----------------------------
# Dependency for protected portal routes
# -----------------------------
def require_clinic_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, str]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    claims = _decode_jwt(token)

    clinic_id = str(claims.get("clinic_id") or "")
    user_id = str(claims.get("user_id") or "")
    role = str(claims.get("role") or "")
    if not clinic_id or not user_id:
        raise HTTPException(status_code=401, detail="invalid token claims")
    return {"clinic_id": clinic_id, "user_id": user_id, "role": role}
