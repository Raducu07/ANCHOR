# app/admin_auth.py
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Header, HTTPException, Request
from sqlalchemy import text

from app.db import SessionLocal


# ----------------------------
# Helpers
# ----------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _hash_with_salt(value: str, salt: str) -> str:
    # metadata hashing only (ip/ua); not a secret
    return _sha256_hex(f"{salt}:{value}")


def _get_hash_salt() -> str:
    # Used only for hashing IP/UA for audit metadata
    return (os.getenv("ANCHOR_HASH_SALT") or os.getenv("ANCHOR_LOG_SALT") or "anchor-default-salt").strip()


def _get_admin_pepper() -> str:
    # Pepper for token hashing. Rotate carefully.
    return (os.getenv("ANCHOR_ADMIN_PEPPER") or "anchor-admin-pepper-default").strip()


def _legacy_env_tokens() -> set[str]:
    """
    Backward-compatible admin tokens from env.
    Supports:
      - ANCHOR_ADMIN_TOKENS = "tok1,tok2,tok3"
      - ANCHOR_ADMIN_TOKEN  = "tok"
    """
    toks: set[str] = set()
    raw = (os.getenv("ANCHOR_ADMIN_TOKENS") or "").strip()
    if raw:
        for t in raw.split(","):
            t = t.strip()
            if t:
                toks.add(t)
    one = (os.getenv("ANCHOR_ADMIN_TOKEN") or "").strip()
    if one:
        toks.add(one)
    return toks


def _admin_mode() -> str:
    """
    Modes:
      - "hybrid" (default): accept DB tokens OR legacy env tokens
      - "db": accept DB tokens only
      - "env": accept legacy env tokens only (not recommended)
    """
    return (os.getenv("ANCHOR_ADMIN_MODE") or "hybrid").strip().lower()


def _extract_admin_token(
    x_anchor_admin_token: Optional[str],
    authorization: Optional[str],
) -> Optional[str]:
    if x_anchor_admin_token and x_anchor_admin_token.strip():
        return x_anchor_admin_token.strip()

    if authorization and authorization.strip().lower().startswith("bearer "):
        return authorization.strip()[7:].strip() or None

    return None


@dataclass(frozen=True)
class AdminContext:
    token_id: Optional[str]         # UUID string if DB token; None if legacy env token
    token_source: str               # "db" or "env"
    ip_hash: Optional[str]
    ua_hash: Optional[str]
    request_id: Optional[str]


# ----------------------------
# Audit write (best-effort)
# ----------------------------

def write_admin_audit_event(
    *,
    action: str,
    method: str,
    route: str,
    status_code: int,
    admin_token_id: Optional[str],
    request_id: Optional[str],
    ip_hash: Optional[str],
    ua_hash: Optional[str],
    meta: Optional[Dict[str, Any]] = None,
) -> None:
    meta = meta or {}
    try:
        with SessionLocal() as db:
            db.execute(
                text(
                    """
                    INSERT INTO admin_audit_events
                      (action, method, route, status_code, admin_token_id, request_id, ip_hash, ua_hash, meta)
                    VALUES
                      (:action, :method, :route, :status_code, :admin_token_id, :request_id, :ip_hash, :ua_hash, :meta::jsonb)
                    """
                ),
                {
                    "action": action,
                    "method": method,
                    "route": route,
                    "status_code": int(status_code),
                    "admin_token_id": admin_token_id,
                    "request_id": request_id,
                    "ip_hash": ip_hash,
                    "ua_hash": ua_hash,
                    "meta": meta,
                },
            )
            db.commit()
    except Exception:
        # Never break request flow due to audit logging
        return


# ----------------------------
# Token hashing / validation
# ----------------------------

def hash_admin_token(token_plaintext: str) -> str:
    pepper = _get_admin_pepper()
    return _sha256_hex(f"{pepper}:{token_plaintext}")


def generate_admin_token_plaintext() -> str:
    # 32 bytes -> ~43 chars urlsafe
    return secrets.token_urlsafe(32)


def _validate_db_token(token_plaintext: str, ip_hash: Optional[str]) -> Optional[str]:
    """
    Returns token_id (uuid string) if valid; else None.
    Enforces disabled/expiry and updates last_used_at.
    """
    token_hash = hash_admin_token(token_plaintext)
    now = _now_utc()

    with SessionLocal() as db:
        row = db.execute(
            text(
                """
                SELECT token_id, disabled_at, expires_at
                FROM admin_tokens
                WHERE token_hash = :h
                LIMIT 1
                """
            ),
            {"h": token_hash},
        ).mappings().first()

        if not row:
            return None

        if row["disabled_at"] is not None:
            return None

        if row["expires_at"] is not None and row["expires_at"] <= now:
            return None

        # Update last_used_at (best-effort)
        try:
            db.execute(
                text(
                    """
                    UPDATE admin_tokens
                    SET last_used_at = now(),
                        last_used_ip_hash = :ip_hash
                    WHERE token_id = :tid
                    """
                ),
                {"tid": str(row["token_id"]), "ip_hash": ip_hash},
            )
            db.commit()
        except Exception:
            db.rollback()

        return str(row["token_id"])


def _validate_env_token(token_plaintext: str) -> bool:
    # constant-time compare across list
    candidates = _legacy_env_tokens()
    for c in candidates:
        if hmac.compare_digest(c, token_plaintext):
            return True
    return False


# ----------------------------
# Dependency
# ----------------------------

def require_admin(
    request: Request,
    x_anchor_admin_token: Optional[str] = Header(default=None, convert_underscores=False),
    authorization: Optional[str] = Header(default=None),
) -> AdminContext:
    """
    Admin auth dependency.
    - Accepts X-ANCHOR-ADMIN-TOKEN (canonical)
    - Also accepts Authorization: Bearer <token> (optional)
    - Enforces expiry/disable for DB tokens
    - Writes audit events (success and failure best-effort)
    """
    token = _extract_admin_token(x_anchor_admin_token, authorization)

    # Hash IP/UA for metadata-only audit
    salt = _get_hash_salt()
    ip = (request.client.host if request.client else "") or ""
    ua = (request.headers.get("user-agent") or "")[:512]
    ip_hash = _hash_with_salt(ip, salt) if ip else None
    ua_hash = _hash_with_salt(ua, salt) if ua else None

    request_id = (
        request.headers.get("x-request-id")
        or request.headers.get("x-anchor-request-id")
        or request.headers.get("x-correlation-id")
    )

    mode = _admin_mode()
    path = request.url.path
    method = request.method.upper()

    if not token:
        write_admin_audit_event(
            action="admin.auth",
            method=method,
            route=path,
            status_code=401,
            admin_token_id=None,
            request_id=request_id,
            ip_hash=ip_hash,
            ua_hash=ua_hash,
            meta={"reason": "missing_token"},
        )
        raise HTTPException(status_code=401, detail="Missing admin token")

    token_id: Optional[str] = None
    source: Optional[str] = None

    if mode in ("hybrid", "db"):
        token_id = _validate_db_token(token, ip_hash=ip_hash)
        if token_id:
            source = "db"

    if not token_id and mode in ("hybrid", "env"):
        if _validate_env_token(token):
            source = "env"

    if not source:
        write_admin_audit_event(
            action="admin.auth",
            method=method,
            route=path,
            status_code=401,
            admin_token_id=None,
            request_id=request_id,
            ip_hash=ip_hash,
            ua_hash=ua_hash,
            meta={"reason": "invalid_or_expired"},
        )
        raise HTTPException(status_code=401, detail="Invalid admin token")

    # Success audit (auth)
    write_admin_audit_event(
        action="admin.auth",
        method=method,
        route=path,
        status_code=200,
        admin_token_id=token_id,
        request_id=request_id,
        ip_hash=ip_hash,
        ua_hash=ua_hash,
        meta={"token_source": source},
    )

    ctx = AdminContext(
        token_id=token_id,
        token_source=source,
        ip_hash=ip_hash,
        ua_hash=ua_hash,
        request_id=request_id,
    )
    # Stash for downstream (optional)
    request.state.admin_ctx = ctx
    return ctx
