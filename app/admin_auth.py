from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Header, HTTPException, Request
from sqlalchemy import text

from app.anchor_logging import get_hash_salt, sha256_hex
from app.db import SessionLocal
from app.rate_limit import enforce_admin_token


# ----------------------------
# Helpers
# ----------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _hash_with_salt(value: str, salt: str) -> str:
    # metadata hashing only (ip/ua); not a secret
    return sha256_hex(f"{salt}:{value}")


# Default admin-pepper fallback literal. Acceptable for local/dev/test runs;
# rejected at startup when APP_ENV=prod (see assert_admin_pepper_for_prod).
DEFAULT_ADMIN_PEPPER_LITERAL = "anchor-admin-pepper-default"


def _get_admin_pepper() -> str:
    # Pepper for token hashing. Rotate carefully.
    return (os.getenv("ANCHOR_ADMIN_PEPPER") or DEFAULT_ADMIN_PEPPER_LITERAL).strip()


def assert_admin_pepper_for_prod() -> None:
    """Fail-closed in production if ANCHOR_ADMIN_PEPPER is missing or still
    equal to the default fallback literal. No-op outside production. Called
    from the FastAPI lifespan at startup so a misconfigured prod deploy
    aborts before serving requests."""
    from app.anchor_logging import get_app_env

    if get_app_env() != "prod":
        return
    raw = (os.getenv("ANCHOR_ADMIN_PEPPER") or "").strip()
    if not raw:
        raise RuntimeError(
            "ANCHOR_ADMIN_PEPPER must be set when APP_ENV=prod; "
            "default fallback is not permitted in production."
        )
    if raw == DEFAULT_ADMIN_PEPPER_LITERAL:
        raise RuntimeError(
            "ANCHOR_ADMIN_PEPPER must not equal the default fallback literal "
            "when APP_ENV=prod."
        )


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


# 2A-D.1 Patch 4B: production-mode admin lockdown.
#
# Valid ANCHOR_ADMIN_MODE values. Kept narrow so a typo cannot silently
# resolve to a permissive default.
_ADMIN_MODE_DB = "db"
_ADMIN_MODE_HYBRID = "hybrid"
_ADMIN_MODE_ENV = "env"
_VALID_ADMIN_MODES = frozenset({_ADMIN_MODE_DB, _ADMIN_MODE_HYBRID, _ADMIN_MODE_ENV})


def _admin_mode() -> str:
    """
    Modes:
      - "hybrid": accept DB tokens OR legacy env tokens.
      - "db": accept DB tokens only (default in production).
      - "env": accept legacy env tokens only (NEVER the default; refused
        in production by assert_admin_mode_for_prod()).

    Resolution rules:
      - Non-prod: if ANCHOR_ADMIN_MODE is unset/blank, default to "hybrid"
        so existing dev/test flows that rely on env-token bootstrap keep
        working.
      - Prod: if ANCHOR_ADMIN_MODE is unset/blank, default to "db" so a
        deploy that forgets to set the variable does NOT silently fall
        into the env-token-accepting hybrid mode. An explicit
        ANCHOR_ADMIN_MODE=hybrid remains permitted as an operator
        override.
      - "env" is never selected by default. assert_admin_mode_for_prod()
        refuses it at startup in prod.
      - Unknown / typo values fall back to the env-appropriate default
        (db in prod, hybrid in non-prod). The assert helper logs and
        refuses startup in prod for an unknown explicit value too.
    """
    # Defer the import to avoid a module-level cycle with anchor_logging
    # (which is imported at the top of this file already, but
    # _admin_mode() is called inside dependencies — keeping the import
    # local here matches the pattern used by assert_admin_pepper_for_prod
    # for consistency).
    from app.anchor_logging import get_app_env

    raw = (os.getenv("ANCHOR_ADMIN_MODE") or "").strip().lower()
    is_prod = get_app_env() == "prod"

    if not raw:
        return _ADMIN_MODE_DB if is_prod else _ADMIN_MODE_HYBRID

    if raw not in _VALID_ADMIN_MODES:
        # Defensive fallback. assert_admin_mode_for_prod() will refuse
        # startup in prod for an unknown explicit value, so this branch
        # only affects non-prod runtime.
        return _ADMIN_MODE_DB if is_prod else _ADMIN_MODE_HYBRID

    return raw


def assert_admin_mode_for_prod() -> None:
    """Fail-closed in production for unsafe ANCHOR_ADMIN_MODE values.

    No-op outside production. Called from the FastAPI lifespan at startup
    so a misconfigured prod deploy aborts before serving requests.

    Refuses:
      * ANCHOR_ADMIN_MODE=env in prod — env-only admin removes DB-side
        rotation/revocation and per-token audit linkage. Bootstrap should
        use explicit "hybrid" (which still requires DB tokens to be
        provisioned alongside the env token).
      * Unknown / typo values in prod — fail loudly instead of silently
        falling back to the prod default.
    """
    from app.anchor_logging import get_app_env

    if get_app_env() != "prod":
        return

    raw = (os.getenv("ANCHOR_ADMIN_MODE") or "").strip().lower()

    # Unset / blank is fine — _admin_mode() resolves to "db" in prod.
    if not raw:
        return

    if raw == _ADMIN_MODE_ENV:
        raise RuntimeError(
            "ANCHOR_ADMIN_MODE='env' is not permitted when APP_ENV=prod; "
            "env-only admin tokens cannot be revoked or audited per-token. "
            "Use 'db' (default) or, only if an explicit bootstrap step "
            "requires it, 'hybrid'."
        )

    if raw not in _VALID_ADMIN_MODES:
        raise RuntimeError(
            f"ANCHOR_ADMIN_MODE={raw!r} is not a valid admin mode when "
            "APP_ENV=prod. Valid values are: 'db' (default), 'hybrid'."
        )


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
    token_id: Optional[str]   # UUID string if DB token; None if legacy env token
    token_source: str         # "db" or "env"
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
                    INSERT INTO platform_admin_audit_events
                      (action, method, route, status_code, admin_token_id, request_id, ip_hash, ua_hash, meta)
                    VALUES
                      (:action, :method, :route, :status_code, :admin_token_id, :request_id, :ip_hash, :ua_hash, CAST(:meta AS jsonb))
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
                    "meta": json.dumps(meta, separators=(",", ":"), ensure_ascii=False),
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
    return sha256_hex(f"{pepper}:{token_plaintext}")


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
                FROM platform_admin_tokens
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
                    UPDATE platform_admin_tokens
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
    x_anchor_admin_token: Optional[str] = Header(default=None, alias="X-ANCHOR-ADMIN-TOKEN"),
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
    salt = get_hash_salt()
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

    # Deterministic admin rate limiting (token fingerprinted; token never stored)
    enforce_admin_token(request, token)

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

    # Stash for downstream reuse (request-scoped only)
    request.state.admin_ctx = ctx
    request.state.admin_token_presented = token

    return ctx
