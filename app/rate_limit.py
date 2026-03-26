from __future__ import annotations

import hmac
import os
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from fastapi import HTTPException, Request
from starlette.status import HTTP_429_TOO_MANY_REQUESTS


# -------------------------
# Deterministic fixed-window limiter (CI-friendly)
# -------------------------

def _now_s() -> int:
    return int(time.time())


def _hmac_hex(secret: str, value: str) -> str:
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), "sha256").hexdigest()


@dataclass(frozen=True)
class RateLimitRule:
    window_s: int
    limit: int


class FixedWindowRateLimiter:
    """
    Deterministic fixed-window counter.
    In-memory (process-local). Predictable 429 for CI.
    """

    def __init__(self, *, secret: str):
        self._secret = secret
        self._lock = threading.Lock()
        # (bucket_key, window_start) -> count
        self._counts: Dict[Tuple[str, int], int] = {}

    def _window_start(self, now_s: int, window_s: int) -> int:
        return (now_s // window_s) * window_s

    def check(self, *, bucket_key: str, rule: RateLimitRule) -> Tuple[bool, int]:
        now = _now_s()
        start = self._window_start(now, rule.window_s)
        retry_after = (start + rule.window_s) - now

        with self._lock:
            k = (bucket_key, start)
            self._counts[k] = self._counts.get(k, 0) + 1
            n = self._counts[k]

            # Opportunistic cleanup (bounded):
            # drop windows older than 2 windows for this bucket_key
            old_start = start - (2 * rule.window_s)
            stale = [(bk, ws) for (bk, ws) in self._counts.keys() if bk == bucket_key and ws <= old_start]
            for dk in stale[:50]:
                self._counts.pop(dk, None)

        if n > rule.limit:
            return False, max(1, retry_after)
        return True, 0

    def hash_ip(self, ip: str) -> str:
        return _hmac_hex(self._secret, f"ip:{ip}")

    def hash_admin_token(self, token_plain: str) -> str:
        # fingerprint only, never store token
        return _hmac_hex(self._secret, f"adm:{token_plain}")

    def hash_key(self, label: str, value: str) -> str:
        # general purpose internal key hashing (ids/usernames/etc)
        return _hmac_hex(self._secret, f"{label}:{value}")


def _enabled() -> bool:
    return os.getenv("RATE_LIMIT_ENABLED", "1").strip().lower() in ("1", "true", "yes")


def build_limiter() -> Optional[FixedWindowRateLimiter]:
    if not _enabled():
        return None

    secret = (os.getenv("RATE_LIMIT_SECRET", "") or "").strip()
    if not secret:
        # Fail closed if enabled but misconfigured
        raise RuntimeError("RATE_LIMIT_SECRET is required when RATE_LIMIT_ENABLED is on")

    return FixedWindowRateLimiter(secret=secret)


def rules_from_env() -> Dict[str, RateLimitRule]:
    def _int(name: str, default: int) -> int:
        try:
            return int(os.getenv(name, str(default)).strip())
        except Exception:
            return default

    return {
        # Pre-auth
        "auth": RateLimitRule(window_s=_int("RL_AUTH_WINDOW_S", 60), limit=_int("RL_AUTH_LIMIT", 10)),
        "invite": RateLimitRule(window_s=_int("RL_INVITE_WINDOW_S", 300), limit=_int("RL_INVITE_LIMIT", 10)),
        # Authed clinic
        "receipt": RateLimitRule(window_s=_int("RL_RECEIPT_WINDOW_S", 60), limit=_int("RL_RECEIPT_LIMIT", 30)),
        "export": RateLimitRule(window_s=_int("RL_EXPORT_WINDOW_S", 300), limit=_int("RL_EXPORT_LIMIT", 5)),
        # Admin
        "admin": RateLimitRule(window_s=_int("RL_ADMIN_WINDOW_S", 60), limit=_int("RL_ADMIN_LIMIT", 60)),
        "admin_bootstrap": RateLimitRule(
            window_s=_int("RL_ADMIN_BOOTSTRAP_WINDOW_S", 3600),
            limit=_int("RL_ADMIN_BOOTSTRAP_LIMIT", 10),
        ),
    }


LIMITER = build_limiter()
RULES = rules_from_env()


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _raise_429(retry_after: int) -> None:
    raise HTTPException(
        status_code=HTTP_429_TOO_MANY_REQUESTS,
        detail="rate_limited",
        headers={"Retry-After": str(retry_after)},
    )


def enforce(
    *,
    request: Request,
    group: str,
    key_material: str,
) -> None:
    """
    Raise HTTP 429 with Retry-After if rate limited.
    Deterministic fixed-window.
    """
    if LIMITER is None:
        return

    rule = RULES.get(group)
    if not rule:
        return

    ok, retry_after = LIMITER.check(bucket_key=f"{group}:{key_material}", rule=rule)
    if not ok:
        _raise_429(retry_after)


def enforce_ip(request: Request, group: str) -> None:
    if LIMITER is None:
        return
    enforce(request=request, group=group, key_material=LIMITER.hash_ip(_ip(request)))


def enforce_admin_token(request: Request, token_plain: str) -> None:
    if LIMITER is None:
        return
    enforce(request=request, group="admin", key_material=LIMITER.hash_admin_token(token_plain))


def enforce_admin_token_group(request: Request, token_plain: str, group: str) -> None:
    """
    Admin limiter keyed by token fingerprint, but allows custom groups
    for route-specific tightening (e.g. admin_bootstrap).
    """
    if LIMITER is None:
        return
    enforce(request=request, group=group, key_material=LIMITER.hash_admin_token(token_plain))


def enforce_authed(request: Request, *, clinic_id: str, clinic_user_id: str, group: str) -> None:
    """
    Keyed by tenant + user + group.
    We hash the composite to avoid raw ids as limiter keys (internal discipline).
    """
    if LIMITER is None:
        return
    composite = f"c:{clinic_id}|u:{clinic_user_id}|g:{group}"
    enforce(request=request, group=group, key_material=LIMITER.hash_key("authed", composite))


# -------------------------
# Backward-compat shim
# -------------------------
def enforce_rate_limit(*args, **kwargs) -> Dict[str, object]:
    """
    Backward-compatible wrapper for older call sites in app.main or middleware.

    Supported legacy patterns:
      - enforce_rate_limit(request, group="auth")
      - enforce_rate_limit(request=request, group="auth")
      - enforce_rate_limit(request, key="some-key", group="auth")
      - enforce_rate_limit(group="auth", key="some-key")   # no request available
      - enforce_rate_limit(window_s=60, limit=10, key="some-key")
      - enforce_rate_limit()  -> safe no-op metadata
    Returns metadata for legacy log/middleware call sites.
    Raises HTTPException(429) when a concrete limiter check is actually applied and exceeded.
    """
    if LIMITER is None:
        return {
            "applied": False,
            "limited": False,
            "reason": "limiter_disabled",
        }

    request = kwargs.get("request")
    remaining_args = list(args)

    if request is None and remaining_args:
        first = remaining_args[0]
        # Duck-typing Request enough for this compatibility layer
        if hasattr(first, "client") and hasattr(first, "headers"):
            request = first
            remaining_args = remaining_args[1:]

    group = kwargs.get("group")
    key = kwargs.get("key") or kwargs.get("bucket_key") or kwargs.get("identifier")
    window_s = kwargs.get("window_s")
    limit = kwargs.get("limit")

    # If no request is available, do not crash generic middleware.
    # Route-specific M3 limiters remain in force elsewhere.
    if request is None:
        return {
            "applied": False,
            "limited": False,
            "reason": "no_request_supplied",
            "group": group,
            "key_present": key is not None,
        }

    # Legacy custom explicit rule path
    if window_s is not None and limit is not None:
        try:
            rule = RateLimitRule(window_s=int(window_s), limit=int(limit))
        except Exception:
            rule = RateLimitRule(window_s=60, limit=10)

        raw_material = str(key) if key is not None else _ip(request)
        key_material = LIMITER.hash_key("legacy", raw_material)
        ok, retry_after = LIMITER.check(bucket_key=f"legacy:{key_material}", rule=rule)
        if not ok:
            _raise_429(retry_after)

        return {
            "applied": True,
            "limited": False,
            "reason": "legacy_custom_rule",
            "group": "legacy",
            "retry_after": 0,
        }

    # Legacy named-group path
    if isinstance(group, str) and group in RULES:
        if key is not None:
            key_material = LIMITER.hash_key("legacy", str(key))
            rule = RULES[group]
            ok, retry_after = LIMITER.check(bucket_key=f"{group}:{key_material}", rule=rule)
            if not ok:
                _raise_429(retry_after)

            return {
                "applied": True,
                "limited": False,
                "reason": "legacy_group_key",
                "group": group,
                "retry_after": 0,
            }

        enforce_ip(request, group)
        return {
            "applied": True,
            "limited": False,
            "reason": "legacy_group_ip",
            "group": group,
            "retry_after": 0,
        }

    # Safe default fallback for old generic callers
    if key is not None:
        key_material = LIMITER.hash_key("legacy", str(key))
        rule = RULES.get("auth", RateLimitRule(window_s=60, limit=10))
        ok, retry_after = LIMITER.check(bucket_key=f"auth:{key_material}", rule=rule)
        if not ok:
            _raise_429(retry_after)

        return {
            "applied": True,
            "limited": False,
            "reason": "legacy_default_key",
            "group": "auth",
            "retry_after": 0,
        }

    enforce_ip(request, "auth")
    return {
        "applied": True,
        "limited": False,
        "reason": "legacy_default_ip",
        "group": "auth",
        "retry_after": 0,
    }


def _reset_rate_limit_state_for_tests() -> None:
    if LIMITER is None:
        return
    with LIMITER._lock:
        LIMITER._counts.clear()
