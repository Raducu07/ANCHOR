# app/auth_and_rls.py
import os
import time
import hmac
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any

import jwt
from fastapi import APIRouter, HTTPException, Header, Request, Depends
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import SessionLocal, set_rls_context, clear_rls_context

router = APIRouter(tags=["Clinic Auth"])

# -----------------------------
# Config
# -----------------------------
JWT_SECRET = (os.getenv("ANCHOR_JWT_SECRET", "") or "").strip()
JWT_ISSUER = os.getenv("ANCHOR_JWT_ISSUER", "anchor")
JWT_AUDIENCE = os.getenv("ANCHOR_JWT_AUDIENCE", "anchor-portal")
JWT_TTL_SEC = int(os.getenv("ANCHOR_JWT_TTL_SEC", "86400"))  # 24h

INVITE_TOKEN_SALT = (os.getenv("INVITE_TOKEN_SALT", "anchor-invite-salt") or "anchor-invite-salt").encode("utf-8")


# -----------------------------
# Password hashing (Argon2 preferred)
# -----------------------------
try:
    from argon2 import PasswordHasher  # type: ignore
    from argon2.exceptions import VerifyMismatchError  # type: ignore

    _ARGON2 = PasswordHasher()
    _ARGON2_AVAILABLE = True
except Exception:
    _ARGON2 = None
    _ARGON2_AVAILABLE = False


def _hash_password(password: str) -> str:
    """
    Returns a stored password hash string.
    Format:
      - "argon2:<argon2-encoded>"   (preferred)
    """
    if not _ARGON2_AVAILABLE:
        raise HTTPException(
            status_code=500,
            detail="argon2-cffi is not installed. Add it to requirements.txt to enable secure password hashing.",
        )
    assert _ARGON2 is not None
    return "argon2:" + _ARGON2.hash(password)


def _verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies password against stored hash formats:
      - "argon2:<argon2-encoded>"
      - "sha256:<hex>" (legacy)
    """
    if not stored_hash or ":" not in stored_hash:
        return False

    scheme, digest = stored_hash.split(":", 1)

    if scheme == "argon2":
        if not _ARGON2_AVAILABLE:
            return False
        try:
            assert _ARGON2 is not None
            return bool(_ARGON2.verify(digest, password))
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    if scheme == "sha256":
        computed = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(computed, digest)

    return False


# -----------------------------
# JWT helpers
# -----------------------------
def _make_jwt(payload: Dict[str, Any]) -> str:
    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="ANCHOR_JWT_SECRET not set")

    now = int(time.time())
    full = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + int(JWT_TTL_SEC),
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
# Invite token hashing (must match portal_bootstrap.py)
# -----------------------------
def _hash_invite_token(token_plain: str) -> str:
    return hashlib.sha256(INVITE_TOKEN_SALT + token_plain.encode("utf-8")).hexdigest()


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
    clinic_user_id: str
    role: str


class InviteAcceptRequest(BaseModel):
    clinic_slug: str = Field(..., min_length=2, max_length=80)
    email: EmailStr
    invite_token: str = Field(..., min_length=10, max_length=300)
    password: str = Field(..., min_length=8, max_length=200)


class MeResponse(BaseModel):
    clinic_id: str
    clinic_user_id: str
    role: str


# -----------------------------
# Internal DB helpers
# -----------------------------
def _resolve_clinic_id_by_slug(db: Session, slug: str) -> str:
    """
    Slug lookup happens before we can set RLS context.
    Your schema includes rls_clinics_login_lookup allowing SELECT where active_status=true,
    so this should work even under FORCE RLS.
    """
    row = db.execute(
        text("""
            SELECT clinic_id
            FROM clinics
            WHERE clinic_slug = :slug AND active_status = true
            LIMIT 1
        """),
        {"slug": slug},
    ).mappings().first()

    if not row:
        raise HTTPException(status_code=401, detail="invalid credentials")

    return str(row["clinic_id"])


def _issue_login_token(clinic_id: str, clinic_user_id: str, role: str) -> ClinicLoginResponse:
    token = _make_jwt(
        {
            "clinic_id": clinic_id,
            "clinic_user_id": clinic_user_id,
            "role": role,
            "sub": clinic_user_id,
        }
    )
    return ClinicLoginResponse(
        access_token=token,
        clinic_id=clinic_id,
        clinic_user_id=clinic_user_id,
        role=role,
    )


# -----------------------------
# Routes (new canonical paths)
# -----------------------------
@router.post("/v1/clinic/auth/login", response_model=ClinicLoginResponse)
def clinic_login(req: ClinicLoginRequest) -> ClinicLoginResponse:
    """
    Clinic portal login (canonical).
    Uses:
      - clinics (slug -> clinic_id)
      - clinic_users (email/password)
    """
    db = SessionLocal()
    try:
        clinic_id = _resolve_clinic_id_by_slug(db, req.clinic_slug)

        # Must set RLS context before reading clinic_users under FORCE RLS
        temp_user = str(uuid.uuid4())
        set_rls_context(db, clinic_id=clinic_id, user_id=temp_user)

        user = db.execute(
            text("""
                SELECT user_id, role, password_hash, active_status
                FROM clinic_users
                WHERE clinic_id = :cid AND lower(email) = :email
                LIMIT 1
            """),
            {"cid": clinic_id, "email": str(req.email).lower()},
        ).mappings().first()

        if not user or not bool(user["active_status"]):
            raise HTTPException(status_code=401, detail="invalid credentials")

        stored = str(user["password_hash"] or "")
        if not _verify_password(req.password, stored):
            raise HTTPException(status_code=401, detail="invalid credentials")

        clinic_user_id = str(user["user_id"])
        role = str(user["role"])

        # Reset context to real user (good hygiene)
        set_rls_context(db, clinic_id=clinic_id, user_id=clinic_user_id)
        db.commit()

        return _issue_login_token(clinic_id, clinic_user_id, role)
    finally:
        try:
            clear_rls_context(db)
        except Exception:
            pass
        db.close()


@router.post("/v1/clinic/auth/invite/accept", response_model=ClinicLoginResponse)
def accept_invite(req: InviteAcceptRequest) -> ClinicLoginResponse:
    """
    Accept an admin/staff invite:
      - verifies token_hash + expiry + unused
      - creates clinic_users row
      - marks invite used_at
      - returns JWT (so you can login immediately)
    """
    db = SessionLocal()
    try:
        clinic_id = _resolve_clinic_id_by_slug(db, req.clinic_slug)

        # Set RLS context to this clinic so we can read/write clinic-scoped tables
        new_user_id = str(uuid.uuid4())
        set_rls_context(db, clinic_id=clinic_id, user_id=new_user_id)

        th = _hash_invite_token(req.invite_token)
        now = datetime.now(timezone.utc)

        invite = db.execute(
            text("""
                SELECT invite_id, role, expires_at, used_at, email
                FROM clinic_user_invites
                WHERE clinic_id = :cid
                  AND token_hash = :th
                LIMIT 1
            """),
            {"cid": clinic_id, "th": th},
        ).mappings().first()

        if not invite:
            raise HTTPException(status_code=401, detail="invalid invite")

        if invite["used_at"] is not None:
            raise HTTPException(status_code=401, detail="invite already used")

        exp = invite["expires_at"]
        if exp is None or (hasattr(exp, "tzinfo") and exp < now) or (not hasattr(exp, "tzinfo") and exp < now.replace(tzinfo=None)):
            raise HTTPException(status_code=401, detail="invite expired")

        invited_email = str(invite["email"] or "").lower()
        if invited_email != str(req.email).lower():
            raise HTTPException(status_code=401, detail="invalid invite")

        role = str(invite["role"])

        # Ensure email not already registered in this clinic
        exists = db.execute(
            text("""
                SELECT 1
                FROM clinic_users
                WHERE clinic_id = :cid AND lower(email) = :email
                LIMIT 1
            """),
            {"cid": clinic_id, "email": str(req.email).lower()},
        ).mappings().first()

        if exists:
            raise HTTPException(status_code=409, detail="user already exists")

        pw_hash = _hash_password(req.password)

        # Create user
        db.execute(
            text("""
                INSERT INTO clinic_users (user_id, clinic_id, role, email, password_hash, active_status, created_at)
                VALUES (:uid, :cid, :role, :email, :ph, true, now())
            """),
            {
                "uid": new_user_id,
                "cid": clinic_id,
                "role": role,
                "email": str(req.email).lower(),
                "ph": pw_hash,
            },
        )

        # Mark invite used
        db.execute(
            text("""
                UPDATE clinic_user_invites
                SET used_at = now()
                WHERE invite_id = :iid
            """),
            {"iid": str(invite["invite_id"])},
        )

        db.commit()

        # Set context to the newly created user (hygiene)
        set_rls_context(db, clinic_id=clinic_id, user_id=new_user_id)
        db.commit()

        return _issue_login_token(clinic_id, new_user_id, role)

    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"invite accept failed: {type(e).__name__}: {e}")
    finally:
        try:
            clear_rls_context(db)
        except Exception:
            pass
        db.close()


# -----------------------------
# Dependency for protected clinic routes
# Sets request.state.* so app.db.get_db() applies RLS automatically
# -----------------------------
def require_clinic_user(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, str]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")

    token = authorization.split(" ", 1)[1].strip()
    claims = _decode_jwt(token)

    clinic_id = str(claims.get("clinic_id") or "")
    clinic_user_id = str(claims.get("clinic_user_id") or "")
    role = str(claims.get("role") or "")

    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="invalid token claims")

    # This is what app.db.get_db() looks for
    request.state.clinic_id = clinic_id
    request.state.clinic_user_id = clinic_user_id

    return {"clinic_id": clinic_id, "clinic_user_id": clinic_user_id, "role": role}


@router.get("/v1/clinic/me", response_model=MeResponse)
def clinic_me(ctx: Dict[str, str] = Depends(require_clinic_user)) -> MeResponse:
    return MeResponse(
        clinic_id=str(ctx["clinic_id"]),
        clinic_user_id=str(ctx["clinic_user_id"]),
        role=str(ctx["role"]),
    )


# -----------------------------
# Backwards compatibility route
# Keeps your old /v1/clinic-auth/login working
# -----------------------------
@router.post("/v1/clinic-auth/login", response_model=ClinicLoginResponse)
def clinic_login_legacy(req: ClinicLoginRequest) -> ClinicLoginResponse:
    return clinic_login(req)
