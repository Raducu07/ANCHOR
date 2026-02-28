# app/rate_limit.py
#
# Production-ready (simple, in-memory) rate limiting for ANCHOR.
# - Sliding window per key using deque of timestamps (monotonic seconds)
# - Thread-safe via a global lock
# - Route-aware limit rules (prefix match)
# - Keyed by clinic_user_id when available; otherwise by ip_hash / ip
#
# IMPORTANT:
# - In-memory limiters reset on process restart and are per-instance (Render scale-out => per-instance).
# - That is acceptable for M3 "minimal but real" protection.
#
# Integration:
# - Call enforce_rate_limit(...) from middleware in main.py
# - On limited, raise HTTPException(429, detail=...)
#
from __future__ import annotations

import time
import threading
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, Optional, Tuple, List


# -----------------------------
# Config model
# -----------------------------
@dataclass(frozen=True)
class RateLimitRule:
    name: str
    limit: int
    window_sec: int
    # match by URL path prefix; the first match wins
    path_prefixes: Tuple[str, ...]


# -----------------------------
# Default rules (tight & focused)
# -----------------------------
DEFAULT_RULES: Tuple[RateLimitRule, ...] = (
    # Auth endpoints: brute-force protection
    RateLimitRule(
        name="auth",
        limit=10,
        window_sec=60,
        path_prefixes=("/v1/auth", "/v1/clinic/auth", "/v1/portal/auth"),
    ),
    # Export endpoints: exfil + abuse protection
    RateLimitRule(
        name="export",
        limit=10,
        window_sec=60,
        path_prefixes=("/v1/portal/export", "/v1/portal/export.csv"),
    ),
    # Admin endpoints: reduce blast radius
    RateLimitRule(
        name="admin",
        limit=30,
        window_sec=60,
        path_prefixes=("/v1/admin",),
    ),
    # Assist endpoint: normal use
    RateLimitRule(
        name="assist",
        limit=60,
        window_sec=60,
        path_prefixes=("/v1/portal/assist",),
    ),
    # Portal submit/read/receipts: general guardrail
    RateLimitRule(
        name="portal_general",
        limit=120,
        window_sec=60,
        path_prefixes=("/v1/portal",),
    ),
)


# -----------------------------
# Internal state
# -----------------------------
_LOCK = threading.Lock()

# key -> deque[timestamps]
_BUCKETS: Dict[str, Deque[float]] = {}

# Periodic cleanup (avoid unbounded memory)
_LAST_CLEANUP_AT: float = 0.0
_CLEANUP_INTERVAL_SEC: int = 30
_MAX_KEYS_SOFT_CAP: int = 50_000  # guardrail


def _pick_rule(path: str, rules: Tuple[RateLimitRule, ...]) -> Optional[RateLimitRule]:
    for r in rules:
        for pfx in r.path_prefixes:
            if path.startswith(pfx):
                return r
    return None


def _trim_old(q: Deque[float], now: float, window_sec: int) -> None:
    cutoff = now - float(window_sec)
    while q and q[0] <= cutoff:
        q.popleft()


def _cleanup_buckets(now: float) -> None:
    global _LAST_CLEANUP_AT
    if now - _LAST_CLEANUP_AT < float(_CLEANUP_INTERVAL_SEC):
        return
    _LAST_CLEANUP_AT = now

    # Soft cap: if too many keys, aggressively remove empty/old queues
    # We remove keys whose deque is empty after trimming with a generous window.
    # This is intentionally conservative (no scanning per request).
    remove_keys: List[str] = []
    for k, q in _BUCKETS.items():
        if not q:
            remove_keys.append(k)

    for k in remove_keys:
        _BUCKETS.pop(k, None)

    # If still huge, evict oldest keys (best-effort)
    if len(_BUCKETS) > _MAX_KEYS_SOFT_CAP:
        # Evict keys with the smallest most-recent timestamp (LRU-ish)
        # This is O(n) but only happens under extreme load.
        items: List[Tuple[str, float]] = []
        for k, q in _BUCKETS.items():
            last = q[-1] if q else 0.0
            items.append((k, last))
        items.sort(key=lambda x: x[1])  # oldest first
        # Drop oldest 10%
        drop = max(1, len(items) // 10)
        for i in range(drop):
            _BUCKETS.pop(items[i][0], None)


def _build_key(
    clinic_user_id: Optional[str],
    ip_hash: Optional[str],
    ip: Optional[str],
    rule_name: str,
) -> str:
    # Prefer clinic_user_id (tenant-safe and stable)
    if clinic_user_id:
        return f"cu:{clinic_user_id}:{rule_name}"

    # Else hash if provided (your middleware already HMAC-hashes IP)
    if ip_hash:
        return f"iphash:{ip_hash}:{rule_name}"

    # Fallback: raw ip (avoid if you can)
    if ip:
        return f"ip:{ip}:{rule_name}"

    # Last resort: anonymous
    return f"anon:{rule_name}"


def check_rate_limit(
    *,
    path: str,
    method: str,
    clinic_user_id: Optional[str] = None,
    ip_hash: Optional[str] = None,
    ip: Optional[str] = None,
    rules: Tuple[RateLimitRule, ...] = DEFAULT_RULES,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Returns (allowed, meta).
    meta is safe to log (no content).
    """
    # Only rate limit "mutating or costly" methods by default
    # (You can broaden later if needed.)
    m = (method or "").upper()
    if m not in ("POST", "PUT", "PATCH", "DELETE", "GET"):
        return True, {"rate_limit_applied": False}

    rule = _pick_rule(path or "", rules)
    if rule is None:
        return True, {"rate_limit_applied": False}

    now = time.monotonic()
    key = _build_key(clinic_user_id, ip_hash, ip, rule.name)

    with _LOCK:
        q = _BUCKETS.get(key)
        if q is None:
            q = deque()
            _BUCKETS[key] = q

        _trim_old(q, now, rule.window_sec)

        # If already at/over limit, deny
        if len(q) >= rule.limit:
            # Compute retry_after (seconds until oldest entry expires)
            oldest = q[0] if q else now
            retry_after = max(1, int((oldest + float(rule.window_sec)) - now))

            meta = {
                "rate_limit_applied": True,
                "rate_limited": True,
                "rule": rule.name,
                "limit": rule.limit,
                "window_sec": rule.window_sec,
                "retry_after_sec": retry_after,
                "path": path,
                "method": m,
                # key components are intentionally not returned (avoid leaking identifiers)
            }
            return False, meta

        # Allow and record
        q.append(now)

        # opportunistic cleanup
        _cleanup_buckets(now)

    meta = {
        "rate_limit_applied": True,
        "rate_limited": False,
        "rule": rule.name,
        "limit": rule.limit,
        "window_sec": rule.window_sec,
        "path": path,
        "method": m,
    }
    return True, meta


def enforce_rate_limit(
    *,
    path: str,
    method: str,
    clinic_user_id: Optional[str] = None,
    ip_hash: Optional[str] = None,
    ip: Optional[str] = None,
    rules: Tuple[RateLimitRule, ...] = DEFAULT_RULES,
) -> Dict[str, Any]:
    """
    Convenience wrapper.
    Returns meta on allow.
    Raises no exceptions (caller decides).
    """
    allowed, meta = check_rate_limit(
        path=path,
        method=method,
        clinic_user_id=clinic_user_id,
        ip_hash=ip_hash,
        ip=ip,
        rules=rules,
    )
    meta["allowed"] = bool(allowed)
    return meta


def reset_rate_limits() -> None:
    """Test helper: clears all limiter state."""
    global _LAST_CLEANUP_AT
    with _LOCK:
        _BUCKETS.clear()
        _LAST_CLEANUP_AT = 0.0
