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
from pydantic import BaseModel, Field
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

# Allow small clock skew (Render / clients)
JWT_LEEWAY_SEC = int(os.getenv("ANCHOR_JWT_LEEWAY_SEC", "30"))

# Enforce DB membership check on every protected route (recommended)
AUTH_STRICT_DB_CHECK = (os.getenv("ANCHOR_AUTH_STRICT_DB_CHECK", "1").strip() == "1")

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
# Small helpers
# -----------------------------
def _coerce_uuid(value: Any, *, field: str) -> str:
    """
    Return canonical UUID string or raise 401.
    """
    s = str(value or "").strip()
    if not s:
        raise HTTPException(status_code=401, detail=f"invalid token claims: missing {field}")
    try:
        return str(uuid.UUID(s))
    except Exception:
        raise HTTPException(status_code=401, detail=f"invalid token claims: bad {field}")


def _hash_invite_token(token_plain: str) -> str:
    return hashlib.sha256(INVITE_TOKEN_SALT + token_plain.encode("utf-8")).hexdigest()


# -----------------------------
# JWT helpers (STRICT)
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
    # HS256 only
    return jwt.encode(full, JWT_SECRET, algorithm="HS256")


def _decode_jwt(token: str) -> Dict[str, Any]:
    """
    Strict decode:
      - HS256 only (prevents alg=none)
      - requires issuer + audience
      - leeway for clock skew
    """
    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="ANCHOR_JWT_SECRET not set")

    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            leeway=JWT_LEEWAY_SEC,
            options={
                "require": ["exp", "iat", "iss", "aud"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
        if not isinstance(claims, dict):
            raise HTTPException(status_code=401, detail="invalid token")
        return claims
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")


# -----------------------------
# Schemas
# -----------------------------
class ClinicLoginRequest(BaseModel):
    clinic_slug: str = Field(..., min_length=2, max_length=80)
    email: str = Field(..., min_length=3, max_length=254)  # avoid EmailStr .local rejection
    password: str = Field(..., min_length=6, max_length=200)


class ClinicLoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    clinic_id: str
    clinic_user_id: str
    role: str


class InviteAcceptRequest(BaseModel):
    clinic_slug: str = Field(..., min_length=2, max_length=80)
    email: str = Field(..., min_length=3, max_length=254)  # avoid EmailStr .local rejection
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
    Do NOT query clinics directly here.
    Call SECURITY DEFINER function that returns clinic_id only when active.
    """
    row = db.execute(
        text("SELECT public.resolve_clinic_id_by_slug(:slug) AS clinic_id"),
        {"slug": slug},
    ).mappings().first()

    cid = str(row["clinic_id"] or "") if row else ""
    if not cid:
        raise HTTPException(status_code=401, detail="invalid credentials")

    # canonicalize
    return _coerce_uuid(cid, field="clinic_id")


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
# Routes (canonical)
# -----------------------------
@router.post("/v1/clinic/auth/login", response_model=ClinicLoginResponse)
def clinic_login(req: ClinicLoginRequest) -> ClinicLoginResponse:
    email_lc = (req.email or "").strip().lower()

    with SessionLocal() as db:
        try:
            # Ensure SET LOCAL scope behaves correctly
            db.begin()

            clinic_id = _resolve_clinic_id_by_slug(db, req.clinic_slug)

            # set temporary context so FORCE RLS won't break reads
            temp_user = str(uuid.uuid4())
            set_rls_context(db, clinic_id=clinic_id, clinic_user_id=temp_user)

            user = db.execute(
                text(
                    """
                    SELECT user_id, role, password_hash, active_status
                    FROM clinic_users
                    WHERE clinic_id = :cid AND lower(email) = :email
                    LIMIT 1
                    """
                ),
                {"cid": clinic_id, "email": email_lc},
            ).mappings().first()

            if not user or not bool(user["active_status"]):
                raise HTTPException(status_code=401, detail="invalid credentials")

            stored = str(user["password_hash"] or "")
            if not _verify_password(req.password, stored):
                raise HTTPException(status_code=401, detail="invalid credentials")

            clinic_user_id = _coerce_uuid(user["user_id"], field="clinic_user_id")
            role = str(user["role"] or "").strip()

            # reset context to real user
            set_rls_context(db, clinic_id=clinic_id, clinic_user_id=clinic_user_id, role=role)
            db.commit()

            return _issue_login_token(clinic_id, clinic_user_id, role)

        except HTTPException:
            try:
                db.rollback()
            except Exception:
                pass
            raise
        finally:
            try:
                clear_rls_context(db)
            except Exception:
                pass


@router.post("/v1/clinic/auth/invite/accept", response_model=ClinicLoginResponse)
def accept_invite(req: InviteAcceptRequest) -> ClinicLoginResponse:
    email_lc = (req.email or "").strip().lower()
    now = datetime.now(timezone.utc)

    with SessionLocal() as db:
        try:
            db.begin()

            clinic_id = _resolve_clinic_id_by_slug(db, req.clinic_slug)

            new_user_id = str(uuid.uuid4())
            set_rls_context(db, clinic_id=clinic_id, clinic_user_id=new_user_id)

            th = _hash_invite_token(req.invite_token)

            invite = db.execute(
                text(
                    """
                    SELECT invite_id, role, expires_at, used_at, email
                    FROM clinic_user_invites
                    WHERE clinic_id = :cid
                      AND token_hash = :th
                    LIMIT 1
                    """
                ),
                {"cid": clinic_id, "th": th},
            ).mappings().first()

            if not invite:
                raise HTTPException(status_code=401, detail="invalid invite")
            if invite["used_at"] is not None:
                raise HTTPException(status_code=401, detail="invite already used")

            exp = invite["expires_at"]
            if exp is None:
                raise HTTPException(status_code=401, detail="invite expired")
            if getattr(exp, "tzinfo", None) is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < now:
                raise HTTPException(status_code=401, detail="invite expired")

            invited_email = str(invite["email"] or "").strip().lower()
            if invited_email != email_lc:
                raise HTTPException(status_code=401, detail="invalid invite")

            role = str(invite["role"] or "").strip()

            exists = db.execute(
                text(
                    """
                    SELECT 1
                    FROM clinic_users
                    WHERE clinic_id = :cid AND lower(email) = :email
                    LIMIT 1
                    """
                ),
                {"cid": clinic_id, "email": email_lc},
            ).mappings().first()

            if exists:
                raise HTTPException(status_code=409, detail="user already exists")

            pw_hash = _hash_password(req.password)

            db.execute(
                text(
                    """
                    INSERT INTO clinic_users (user_id, clinic_id, role, email, password_hash, active_status, created_at)
                    VALUES (:uid, :cid, :role, :email, :ph, true, now())
                    """
                ),
                {"uid": new_user_id, "cid": clinic_id, "role": role, "email": email_lc, "ph": pw_hash},
            )

            db.execute(
                text(
                    """
                    UPDATE clinic_user_invites
                    SET used_at = now()
                    WHERE invite_id = :iid
                    """
                ),
                {"iid": str(invite["invite_id"])},
            )

            # hygiene: set context to actual new user id (and role)
            set_rls_context(db, clinic_id=clinic_id, clinic_user_id=new_user_id, role=role)

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


# -----------------------------
# Dependency for protected clinic routes
# Sets request.state.* so app.db.get_db() applies RLS automatically
# -----------------------------
def require_clinic_user(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, str]:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing bearer token")

    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="missing bearer token")

    token = (parts[1] or "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="missing bearer token")

    claims = _decode_jwt(token)

    # canonical, strict UUIDs
    clinic_id = _coerce_uuid(claims.get("clinic_id"), field="clinic_id")

    clinic_user_id = _coerce_uuid(
        claims.get("clinic_user_id")
        or claims.get("user_id")
        or claims.get("clinic_user")
        or claims.get("sub"),
        field="clinic_user_id",
    )

    role = str(claims.get("role") or "").strip()

    # Always set state (this is what get_db() consumes)
    request.state.clinic_id = clinic_id
    request.state.clinic_user_id = clinic_user_id
    request.state.role = role

    # Optional (recommended) DB membership check to prevent “orphan tokens”
    if AUTH_STRICT_DB_CHECK:
        with SessionLocal() as db:
            try:
                db.begin()

                set_rls_context(db, clinic_id=clinic_id, clinic_user_id=clinic_user_id, role=(role or None))

                row = db.execute(
                    text(
                        """
                        SELECT user_id, role, active_status
                        FROM clinic_users
                        WHERE clinic_id = :cid
                          AND user_id = :uid
                        LIMIT 1
                        """
                    ),
                    {"cid": clinic_id, "uid": clinic_user_id},
                ).mappings().first()

                if not row or not bool(row["active_status"]):
                    raise HTTPException(status_code=401, detail="invalid token")

                db_role = str(row["role"] or "").strip()
                if db_role and db_role != role:
                    request.state.role = db_role

                db.commit()
            finally:
                try:
                    clear_rls_context(db)
                except Exception:
                    pass

    return {"clinic_id": clinic_id, "clinic_user_id": clinic_user_id, "role": request.state.role}


@router.get("/v1/clinic/me", response_model=MeResponse)
def clinic_me(ctx: Dict[str, str] = Depends(require_clinic_user)) -> MeResponse:
    return MeResponse(
        clinic_id=str(ctx["clinic_id"]),
        clinic_user_id=str(ctx["clinic_user_id"]),
        role=str(ctx["role"]),
    )


# -----------------------------
# Backwards compatibility route
# -----------------------------
@router.post("/v1/clinic-auth/login", response_model=ClinicLoginResponse)
def clinic_login_legacy(req: ClinicLoginRequest) -> ClinicLoginResponse:
    return clinic_login(req)
