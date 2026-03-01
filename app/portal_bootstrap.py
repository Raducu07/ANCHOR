# app/portal_bootstrap.py
import os
import hmac
import uuid
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Set, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import db_session, set_rls_context, clear_rls_context
from app.rate_limit import enforce_admin_token
from app.rate_limit import enforce_admin_token_group

router = APIRouter()


# ============================================================
# Admin auth (unified)
# Supports:
#   - X-ANCHOR-ADMIN-TOKEN (ANCHOR_ADMIN_TOKENS / ANCHOR_ADMIN_TOKEN)
#       ANCHOR_ADMIN_TOKENS="tokA,tokB"
#       ANCHOR_ADMIN_TOKENS="tokA|2026-12-31T23:59:59Z,tokB"
#   - Authorization: Bearer (ADMIN_BEARER_TOKEN)  [back-compat]
# Notes:
#   - If X-ANCHOR-ADMIN-TOKEN is present, we authenticate via ANCHOR_* tokens.
#   - Else, we fall back to Bearer if ADMIN_BEARER_TOKEN is set.
#   - Returns AdminAuthResult (so endpoint can log method/fingerprint if desired).
# ============================================================

@dataclass(frozen=True)
class AdminAuthResult:
    method: str  # "x-header" | "bearer"
    token_fp: str


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso_z(dt_str: str) -> datetime:
    # Expect e.g. "2026-12-31T23:59:59Z"
    dt_str = (dt_str or "").strip()
    if not dt_str.endswith("Z"):
        raise ValueError("expiry must end with 'Z'")
    return datetime.fromisoformat(dt_str.replace("Z", "+00:00")).astimezone(timezone.utc)


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def _load_anchor_admin_tokens() -> Tuple[Set[str], Dict[str, Optional[datetime]]]:
    """
    Supports:
      ANCHOR_ADMIN_TOKENS="tokenA,tokenB"
      ANCHOR_ADMIN_TOKENS="tokenA|2026-12-31T23:59:59Z,tokenB"
      ANCHOR_ADMIN_TOKEN="legacySingleToken" (back-compat)
    Returns:
      (tokens_set, expiry_map[token] -> expires_at_utc_or_None)
    """
    raw = (os.getenv("ANCHOR_ADMIN_TOKENS") or "").strip()
    tokens: Set[str] = set()
    expiry: Dict[str, Optional[datetime]] = {}

    if raw:
        for part in [p.strip() for p in raw.split(",") if p.strip()]:
            if "|" in part:
                tok, exp = part.split("|", 1)
                tok = tok.strip()
                exp = exp.strip()
                if not tok:
                    continue
                try:
                    expiry[tok] = _parse_iso_z(exp)
                    tokens.add(tok)
                except Exception:
                    # ignore malformed expiry entry
                    continue
            else:
                tok = part.strip()
                if tok:
                    tokens.add(tok)
                    expiry[tok] = None

    legacy = (os.getenv("ANCHOR_ADMIN_TOKEN") or "").strip()
    if legacy and legacy not in tokens:
        tokens.add(legacy)
        expiry[legacy] = None

    return tokens, expiry


_ANCHOR_TOKENS, _ANCHOR_EXPIRY = _load_anchor_admin_tokens()


def _auth_via_x_anchor(token: Optional[str]) -> Optional[AdminAuthResult]:
    if not token:
        return None

    match = None
    for t in _ANCHOR_TOKENS:
        if hmac.compare_digest(token, t):
            match = t
            break
    if not match:
        return None

    exp = _ANCHOR_EXPIRY.get(match)
    if exp is not None and _utc_now() >= exp:
        return None

    return AdminAuthResult(method="x-header", token_fp=_token_fingerprint(match))


def _auth_via_bearer(authorization: str) -> Optional[AdminAuthResult]:
    token = (os.getenv("ADMIN_BEARER_TOKEN") or "").strip()
    if not token:
        return None
    if not authorization or not authorization.lower().startswith("bearer "):
        return None

    provided = authorization.split(" ", 1)[1].strip()
    if not hmac.compare_digest(provided, token):
        return None

    return AdminAuthResult(method="bearer", token_fp=_token_fingerprint(token))


def require_admin(
    request: Request,
    x_anchor_admin_token: Optional[str] = Header(default=None, alias="X-ANCHOR-ADMIN-TOKEN"),
    authorization: str = Header(default=""),
) -> AdminAuthResult:
    """
    Prefer X-ANCHOR-ADMIN-TOKEN (ANCHOR_ADMIN_TOKENS / ANCHOR_ADMIN_TOKEN).
    Fall back to Authorization: Bearer (ADMIN_BEARER_TOKEN) for back-compat.

    M3 hardening:
    - Deterministic rate limiting keyed by presented token (fingerprinted inside limiter).
    - Stash presented token on request.state for route-specific throttles (not logged).
    """

    # Always load fresh env-backed tokens (avoid stale cache across deploy/env tweaks)
    tokens, expiry = _load_anchor_admin_tokens()

    def auth_via_x(token: str) -> Optional[AdminAuthResult]:
        match = None
        for t in tokens:
            if hmac.compare_digest(token, t):
                match = t
                break
        if not match:
            return None
        exp = expiry.get(match)
        if exp is not None and _utc_now() >= exp:
            return None
        return AdminAuthResult(method="x-header", token_fp=_token_fingerprint(match))

    # Prefer X header if present and non-empty
    if x_anchor_admin_token:
        presented = x_anchor_admin_token.strip()

        # Stash presented token for downstream route-specific throttles (bootstrap)
        request.state.admin_token_presented = presented

        # Deterministic admin rate limiting (token fingerprinted; token never stored)
        enforce_admin_token(request, presented)

        res = auth_via_x(presented)
        if res:
            return res
        raise HTTPException(status_code=403, detail="Forbidden")

    # Otherwise try Bearer back-compat
    presented_bearer = ""
    if authorization and authorization.lower().startswith("bearer "):
        presented_bearer = authorization.split(" ", 1)[1].strip()

    if presented_bearer:
        # Stash presented token for downstream route-specific throttles (bootstrap)
        request.state.admin_token_presented = presented_bearer

        # Deterministic admin rate limiting (token fingerprinted; token never stored)
        enforce_admin_token(request, presented_bearer)

    res2 = _auth_via_bearer(authorization)
    if res2:
        return res2

    raise HTTPException(status_code=403, detail="Unauthorized")
    

# ============================================================
# Helpers
# ============================================================

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


# ============================================================
# Request/Response models
# ============================================================

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


# ============================================================
# Admin bootstrap endpoint
# ============================================================

@router.post("/v1/admin/bootstrap/clinic", response_model=BootstrapClinicResponse)
def bootstrap_clinic(
    req: BootstrapClinicRequest,
    request: Request,
    db: Session = Depends(db_session),
    admin: AdminAuthResult = Depends(require_admin),
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
    # Route-specific throttle: bootstrap is the highest-privilege action.
    presented = getattr(request.state, "admin_token_presented", None)
    if not presented:
    raise HTTPException(status_code=500, detail="admin_token_context_missing")
enforce_admin_token_group(...)
    
    clinic_id = uuid.uuid4()

    # Deterministic-ish system actor UUID per clinic (stable within this request)
    system_user_id = uuid.uuid5(uuid.NAMESPACE_DNS, f"anchor-system-bootstrap:{clinic_id}")

    slug = _slugify(req.clinic_slug or req.clinic_name)
    invite_token = secrets.token_urlsafe(24)
    token_hash = _hash_token(invite_token)
    expires_at = _utc_now() + timedelta(days=int(req.invite_valid_days))

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

        # 1b) clinic_slug_lookup (unscoped slug -> clinic_id)
        # Needed because FORCE RLS on clinics prevents slug resolution before tenant context exists.
        db.execute(
            text(
                """
                INSERT INTO public.clinic_slug_lookup (clinic_slug, clinic_id, active_status, updated_at)
                VALUES (:slug, :cid, true, now())
                ON CONFLICT (clinic_slug) DO UPDATE
                SET clinic_id = EXCLUDED.clinic_id,
                    active_status = EXCLUDED.active_status,
                    updated_at = now()
                """
            ),
            {"slug": slug, "cid": str(clinic_id)},
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

        # 6) admin invite
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
