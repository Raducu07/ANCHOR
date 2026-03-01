# app/rate_limit.py
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
        "auth":   RateLimitRule(window_s=_int("RL_AUTH_WINDOW_S", 60),    limit=_int("RL_AUTH_LIMIT", 10)),
        "invite": RateLimitRule(window_s=_int("RL_INVITE_WINDOW_S", 300), limit=_int("RL_INVITE_LIMIT", 10)),
        # Authed clinic
        "receipt": RateLimitRule(window_s=_int("RL_RECEIPT_WINDOW_S", 60),  limit=_int("RL_RECEIPT_LIMIT", 30)),
        "export":  RateLimitRule(window_s=_int("RL_EXPORT_WINDOW_S", 300),  limit=_int("RL_EXPORT_LIMIT", 5)),
        # Admin
        "admin":  RateLimitRule(window_s=_int("RL_ADMIN_WINDOW_S", 60),   limit=_int("RL_ADMIN_LIMIT", 60)),
    }


# Module singletons (safe, deterministic, no background threads)
LIMITER = build_limiter()
RULES = rules_from_env()


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


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
        raise HTTPException(
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            detail="rate_limited",
            headers={"Retry-After": str(retry_after)},
        )


# Convenience helpers (metadata-only, no tokens logged)
def enforce_ip(request: Request, group: str) -> None:
    if LIMITER is None:
        return
    enforce(request=request, group=group, key_material=LIMITER.hash_ip(_ip(request)))


def enforce_admin_token(request: Request, token_plain: str) -> None:
    if LIMITER is None:
        return
    enforce(request=request, group="admin", key_material=LIMITER.hash_admin_token(token_plain))


def enforce_authed(request: Request, *, clinic_id: str, clinic_user_id: str, group: str) -> None:
    """
    Keyed by tenant + user + group.
    We hash the composite to avoid raw ids as limiter keys (internal discipline).
    """
    if LIMITER is None:
        return
    composite = f"c:{clinic_id}|u:{clinic_user_id}|g:{group}"
    enforce(request=request, group=group, key_material=LIMITER.hash_key("authed", composite))
