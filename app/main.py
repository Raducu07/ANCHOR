# app/main.py
import os
import hmac
import uuid
import json
import time
import logging
import math
import traceback
import hashlib
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set
from contextlib import asynccontextmanager
from dataclasses import dataclass

from fastapi import FastAPI, HTTPException, Depends, Header, Request, Response
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
from sqlalchemy import text

from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.db import SessionLocal, db_ping
from app.migrate import run_migrations

from app.auth_and_rls import router as clinic_auth_router
from app.ops_rls_test import router as ops_rls_router
from app.portal_bootstrap import router as portal_bootstrap_router
from app.portal_submit import router as portal_submit_router
from app.portal_read import router as portal_read_router
from app.portal_export import router as portal_export_router
from app.portal_ops import router as portal_ops_router
from app.portal_ops_timeseries import router as portal_ops_timeseries_router
from app.portal_trust_state import router as portal_trust_state_router
from app.portal_error_budget import router as portal_error_budget_router
from app.portal_ops_health import router as portal_ops_health_router
from app.portal_dashboard import router as portal_dashboard_router
from app.portal_me import router as portal_me_router

from app.admin_tokens import router as admin_tokens_router
from app.admin_audit import router as admin_audit_router

from app.governance_config import (
    get_current_policy,
    list_policy_history,
    create_new_policy,
)

from app.memory_shaping import (
    propose_memory_offer,
    compute_offer_debug,
    fetch_recent_user_texts,
)

# ✅ ONE scorer module (V1.1)
from app.neutrality_v11 import score_neutrality

# ✅ Governance layer (A2/A3)
from app.governance import govern_output

from app.schemas import (
    CreateSessionResponse,
    SendMessageRequest,
    SendMessageResponse,
    MemoryItem,
    CreateMemoryRequest,
    MemoryOfferResponse,
    NeutralityScoreRequest,
    NeutralityScoreResponse,
    SessionExportResponse,
)

# ============================================================
# M3: Admin security hardening
# - Multi-token admin auth (rotation-ready)
# - Optional per-token expiry
# - Optional IP allowlist
# - In-memory rate limiting (per IP + endpoint)
# - Structured audit logs via log_event (JSON-only discipline)
# ============================================================


@dataclass(frozen=True)
class ParsedToken:
    token: str
    expires_at: Optional[datetime]  # UTC


def _parse_iso_z(dt_str: str) -> datetime:
    # Expect e.g. "2026-12-31T23:59:59Z"
    s = (dt_str or "").strip()
    if not s.endswith("Z"):
        raise ValueError("expiry must end with 'Z'")
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def _load_admin_tokens() -> Tuple[Set[str], Dict[str, ParsedToken]]:
    """
    Supports:
      ANCHOR_ADMIN_TOKENS="tokenA,tokenB"
      ANCHOR_ADMIN_TOKENS="tokenA|2026-12-31T23:59:59Z,tokenB"
    """
    raw = (os.getenv("ANCHOR_ADMIN_TOKENS", "") or "").strip()
    tokens: Set[str] = set()
    parsed: Dict[str, ParsedToken] = {}

    if raw:
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        for p in parts:
            if "|" in p:
                tok, exp = p.split("|", 1)
                tok = tok.strip()
                exp = exp.strip()
                if not tok:
                    continue
                try:
                    expires_at = _parse_iso_z(exp)
                except Exception:
                    # Ignore malformed expiry instead of breaking startup
                    continue
                tokens.add(tok)
                parsed[tok] = ParsedToken(token=tok, expires_at=expires_at)
            else:
                tok = p.strip()
                if not tok:
                    continue
                tokens.add(tok)
                parsed[tok] = ParsedToken(token=tok, expires_at=None)

    # Back-compat support for old single-token env var
    old = (os.getenv("ANCHOR_ADMIN_TOKEN") or "").strip()
    if old and old not in tokens:
        tokens.add(old)
        parsed[old] = ParsedToken(token=old, expires_at=None)

    return tokens, parsed


def _safe_int_env(name: str, default: int) -> int:
    try:
        v = (os.getenv(name, "") or "").strip()
        return int(v) if v else int(default)
    except Exception:
        return int(default)


def _safe_float_env(name: str, default: float) -> float:
    try:
        v = (os.getenv(name, "") or "").strip()
        return float(v) if v else float(default)
    except Exception:
        return float(default)


ADMIN_IPS: Set[str] = {ip.strip() for ip in (os.getenv("ADMIN_IP_ALLOWLIST", "") or "").split(",") if ip.strip()}
ADMIN_RATE_LIMIT_RPM: int = _safe_int_env("ADMIN_RATE_LIMIT_RPM", 120)  # req/min per IP+endpoint
_ADMIN_TOKENS, _ADMIN_TOKENS_PARSED = _load_admin_tokens()

# key = (client_ip_hash, endpoint_path) -> (window_start_epoch, count)
_ADMIN_RL: Dict[Tuple[str, str], Tuple[int, int]] = {}
_ADMIN_RL_LOCK = threading.Lock()
_ADMIN_RL_MAX_KEYS = _safe_int_env("ADMIN_RL_MAX_KEYS", 5000)


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _admin_audit(event: str, request: Request, level: int = logging.INFO, **fields: Any) -> None:
    """
    Structured audit via JSON log_event().
    Metadata only. Never log secrets or payloads.
    """
    try:
        client_ip = request.client.host if request.client else None
    except Exception:
        client_ip = None

    base = {
        "method": request.method,
        "path": request.url.path,
        "client_ip_hash": _hmac_sha256_hex(client_ip),
    }
    base.update(fields)

    try:
        log_event(level, event, **base)
    except Exception:
        pass


def _rate_limit_admin(request: Request) -> None:
    if ADMIN_RATE_LIMIT_RPM <= 0:
        return

    try:
        client_ip = request.client.host if request.client else "unknown"
    except Exception:
        client_ip = "unknown"

    # Store hashed IP in RL map (avoid raw IP retention even in-memory)
    ip_hash = _hmac_sha256_hex(client_ip) or "unknown"
    key = (ip_hash, request.url.path)

    now = int(time.time())
    window = now - (now % 60)

    with _ADMIN_RL_LOCK:
        window_start, count = _ADMIN_RL.get(key, (window, 0))
        if window_start != window:
            window_start, count = window, 0

        count += 1
        _ADMIN_RL[key] = (window_start, count)

        # prevent unbounded growth under scans / many IPs
        if len(_ADMIN_RL) > _ADMIN_RL_MAX_KEYS:
            cutoff = window - 120  # keep last ~2 mins
            for k, (ws, _) in list(_ADMIN_RL.items()):
                if ws < cutoff:
                    _ADMIN_RL.pop(k, None)

    if count > ADMIN_RATE_LIMIT_RPM:
        _admin_audit("admin_rate_limited", request, level=logging.WARNING, rpm=ADMIN_RATE_LIMIT_RPM, count=count)
        raise HTTPException(status_code=429, detail="Too many requests")


def _validate_admin_ip(request: Request) -> None:
    if not ADMIN_IPS:
        return
    try:
        client_ip = request.client.host if request.client else None
    except Exception:
        client_ip = None

    if not client_ip or client_ip not in ADMIN_IPS:
        _admin_audit("admin_ip_blocked", request, level=logging.WARNING, allowlist_size=len(ADMIN_IPS))
        raise HTTPException(status_code=403, detail="IP not allowed")


def _validate_admin_token(request: Request, token: Optional[str]) -> str:
    """
    Returns token fingerprint on success.
    """
    if not token:
        _admin_audit("admin_auth_failure", request, level=logging.WARNING, reason="missing_token")
        raise HTTPException(status_code=403, detail="Unauthorized")

    match = None
    for valid in _ADMIN_TOKENS:
        if hmac.compare_digest(token, valid):
            match = valid
            break

    if not match:
        _admin_audit("admin_auth_failure", request, level=logging.WARNING, reason="invalid_token")
        raise HTTPException(status_code=403, detail="Unauthorized")

    parsed = _ADMIN_TOKENS_PARSED.get(match)
    if parsed and parsed.expires_at is not None:
        if _utc_now() >= parsed.expires_at:
            _admin_audit("admin_auth_failure", request, level=logging.WARNING, reason="expired_token")
            raise HTTPException(status_code=403, detail="Unauthorized")

    return _token_fingerprint(match)


def _extract_admin_token(x_anchor_admin_token: Optional[str], authorization: Optional[str]) -> Optional[str]:
    """
    Accepts either:
      - X-ANCHOR-ADMIN-TOKEN: <token>
      - Authorization: Bearer <token>
    """
    if x_anchor_admin_token and x_anchor_admin_token.strip():
        return x_anchor_admin_token.strip()

    if authorization:
        a = authorization.strip()
        if a.lower().startswith("bearer "):
            tok = a.split(" ", 1)[1].strip()
            return tok or None

    return None


# ============================================================
# Logging — structured, safe-by-default (M2 Step 1)
# JSON-only lines, never log request bodies or secrets.
# ============================================================

logger = logging.getLogger("anchor")
logger.propagate = False  # avoid double-logging via root


def _coerce_log_level(value: str) -> int:
    v = (value or "INFO").strip()
    if v.isdigit():
        return int(v)
    lvl = getattr(logging, v.upper(), None)
    return int(lvl) if isinstance(lvl, int) else logging.INFO


def _json_dumps(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def get_app_env() -> str:
    v = (os.getenv("APP_ENV") or os.getenv("ENV") or "dev").strip().lower()
    return v or "dev"


def is_prod() -> bool:
    return get_app_env() in {"prod", "production"}


def _get_service_name() -> str:
    return (os.getenv("SERVICE_NAME") or os.getenv("APP_NAME") or "anchor").strip() or "anchor"


def _get_app_version() -> Optional[str]:
    v = (os.getenv("APP_VERSION") or os.getenv("GIT_SHA") or os.getenv("BUILD_ID") or "").strip()
    return v or None


def _truncate(s: str, n: int = 200) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n] + "…"


def _trace_enabled() -> bool:
    v1 = (os.getenv("LOG_STACKTRACE") or "").strip().lower()
    v2 = (os.getenv("LOG_STACKTRACES") or "").strip().lower()
    truthy = {"1", "true", "yes", "y", "on"}
    return (v1 in truthy) or (v2 in truthy)


_HMAC_KEY_CACHE: Optional[bytes] = None
_WARNED_HMAC_MISSING = False


def _get_log_hmac_key() -> bytes:
    """
    Returns a key for HMAC hashing.
    - In prod: strongly recommend setting LOG_HMAC_KEY.
    - If missing: non-breaking fallback, but logs a warning once.
    """
    global _HMAC_KEY_CACHE, _WARNED_HMAC_MISSING
    if _HMAC_KEY_CACHE is not None:
        return _HMAC_KEY_CACHE

    raw = (os.getenv("LOG_HMAC_KEY") or "").strip()
    if not raw:
        fallback = "dev-insecure-log-hmac-key" if not is_prod() else "missing-log-hmac-key"
        _HMAC_KEY_CACHE = fallback.encode("utf-8")
        if not _WARNED_HMAC_MISSING:
            _WARNED_HMAC_MISSING = True
            try:
                # safe: no secrets
                log_event(logging.WARNING, "log_hmac_key_missing", env=get_app_env(), service=_get_service_name())
            except Exception:
                pass
        return _HMAC_KEY_CACHE

    _HMAC_KEY_CACHE = raw.encode("utf-8")
    return _HMAC_KEY_CACHE


def _hmac_sha256_hex(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    key = _get_log_hmac_key()
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def log_event(level: int, event: str, **fields: Any) -> None:
    payload: Dict[str, Any] = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "service": _get_service_name(),
        "env": get_app_env(),
        "version": _get_app_version(),
        "event": event,
        **fields,
    }
    try:
        logger.log(level, _json_dumps(payload))
    except Exception:
        pass


if not logger.handlers:
    level = _coerce_log_level(os.getenv("LOG_LEVEL", "INFO"))
    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)

# ============================================================
# Env helpers / edge middleware
# ============================================================


def _parse_csv_env(name: str) -> List[str]:
    raw = (os.getenv(name, "") or "").strip()
    if not raw:
        return []
    parts = [p.strip() for p in raw.split(",")]
    return [p for p in parts if p]


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _ops_ts_enabled() -> bool:
    """
    Semantics:
      - default ENABLED in prod if OPS_TS_ENABLED is unset
      - default DISABLED in non-prod if unset
      - explicit OPS_TS_ENABLED=true/false always wins
    """
    raw = os.getenv("OPS_TS_ENABLED")
    if raw is None:
        return is_prod()
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _configure_edge_middlewares(app: FastAPI) -> None:
    trusted_hosts = _parse_csv_env("TRUSTED_HOSTS")
    if trusted_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)
        log_event(logging.INFO, "trusted_host_enabled", allowed_hosts=trusted_hosts)
    else:
        log_event(logging.INFO, "trusted_host_disabled")

    allow_origins = _parse_csv_env("CORS_ALLOW_ORIGINS") or []
    if allow_origins:
        allow_credentials = _env_truthy("CORS_ALLOW_CREDENTIALS", default=False)
        if allow_credentials and any(o == "*" for o in allow_origins):
            raise RuntimeError("CORS misconfig: cannot use '*' in CORS_ALLOW_ORIGINS when CORS_ALLOW_CREDENTIALS=true")

        allow_methods = _parse_csv_env("CORS_ALLOW_METHODS") or ["GET", "POST", "OPTIONS"]
        allow_headers = _parse_csv_env("CORS_ALLOW_HEADERS") or ["Authorization", "Content-Type", "X-Request-ID"]
        max_age = _safe_int_env("CORS_MAX_AGE", 600)
        max_age = max(0, min(86400, max_age))

        app.add_middleware(
            CORSMiddleware,
            allow_origins=allow_origins,
            allow_credentials=allow_credentials,
            allow_methods=allow_methods,
            allow_headers=allow_headers,
            max_age=max_age,
        )
        log_event(
            logging.INFO,
            "cors_enabled",
            allow_origins=allow_origins,
            allow_credentials=allow_credentials,
            allow_methods=allow_methods,
            allow_headers=allow_headers,
            max_age=max_age,
        )
    else:
        log_event(logging.INFO, "cors_disabled")

# ============================================================
# M2 Step 3 — Rolling HTTP metrics (in-memory)
# ============================================================


class _HttpMetricStore:
    """
    Rolling store of recent request outcomes for quick ops visibility.
    Not durable; resets on deploy. Safe-by-default: no bodies, no headers.
    """

    def __init__(self, maxlen: int = 4000):
        self._lock = threading.Lock()
        self._items = deque(maxlen=maxlen)  # (ts_ns, method, route, status, dur_ms)

    def add(self, ts_ns: int, method: str, route: str, status: int, dur_ms: int) -> None:
        with self._lock:
            self._items.append((ts_ns, method, route, int(status), int(dur_ms)))

    def snapshot(self) -> List[Tuple[int, str, str, int, int]]:
        with self._lock:
            return list(self._items)


_HTTP_METRICS = _HttpMetricStore(maxlen=_safe_int_env("HTTP_METRICS_MAXLEN", 4000))


def _percentile(values: List[int], p: float) -> int:
    if not values:
        return 0
    vs = sorted(values)
    if p <= 0:
        return int(vs[0])
    if p >= 100:
        return int(vs[-1])
    k = (len(vs) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(vs) - 1)
    if f == c:
        return int(vs[f])
    d0 = vs[f] * (c - k)
    d1 = vs[c] * (k - f)
    return int(round(d0 + d1))


def _summarize_http_metrics(
    items: List[Tuple[int, str, str, int, int]], window_sec: int, limit: int
) -> Dict[str, Any]:
    now_ns = time.time_ns()
    window_ns = max(1, int(window_sec)) * 1_000_000_000
    cut = now_ns - window_ns

    filtered = [x for x in items if x[0] >= cut]
    total = len(filtered)

    durations = [x[4] for x in filtered]
    s5xx = sum(1 for x in filtered if 500 <= x[3] <= 599)
    s4xx = sum(1 for x in filtered if 400 <= x[3] <= 499)

    by_route: Dict[str, Dict[str, Any]] = {}
    for _, method, route, status, dur_ms in filtered:
        key = f"{method} {route}"
        bucket = by_route.get(key)
        if bucket is None:
            bucket = {"count": 0, "durations": [], "5xx": 0, "4xx": 0}
            by_route[key] = bucket
        bucket["count"] += 1
        bucket["durations"].append(int(dur_ms))
        if 500 <= status <= 599:
            bucket["5xx"] += 1
        if 400 <= status <= 499:
            bucket["4xx"] += 1

    rows: List[Dict[str, Any]] = []
    for k, b in by_route.items():
        ds = b["durations"]
        rows.append(
            {
                "route": k,
                "count": int(b["count"]),
                "p50_ms": _percentile(ds, 50),
                "p95_ms": _percentile(ds, 95),
                "avg_ms": float(sum(ds) / len(ds)) if ds else 0.0,
                "rate_5xx": float(b["5xx"] / b["count"]) if b["count"] else 0.0,
                "rate_4xx": float(b["4xx"] / b["count"]) if b["count"] else 0.0,
            }
        )

    rows.sort(key=lambda r: (r["rate_5xx"], r["p95_ms"], r["count"]), reverse=True)
    rows = rows[: max(1, min(200, int(limit)))]

    return {
        "window_sec": int(window_sec),
        "events_total": int(total),
        "p50_ms": _percentile(durations, 50),
        "p95_ms": _percentile(durations, 95),
        "avg_ms": float(sum(durations) / len(durations)) if durations else 0.0,
        "rate_5xx": float(s5xx / total) if total else 0.0,
        "rate_4xx": float(s4xx / total) if total else 0.0,
        "routes": rows,
    }

# ============================================================
# M2.4b — Historical time-series worker + endpoints
# ============================================================

_TS_STOP_EVENT: Optional[threading.Event] = None
_TS_THREAD: Optional[threading.Thread] = None


def _bucket_floor(ts_ns: int, bucket_sec: int) -> int:
    bucket_ns = int(bucket_sec) * 1_000_000_000
    return int(ts_ns // bucket_ns) * bucket_ns


def _summarize_http_metrics_range(
    items: List[Tuple[int, str, str, int, int]],
    start_ns: int,
    end_ns: int,
    route: str = "__all__",
) -> Dict[str, Any]:
    filtered = [x for x in items if start_ns <= x[0] < end_ns]
    if route != "__all__":
        filtered = [x for x in filtered if f"{x[1]} {x[2]}" == route]

    total = len(filtered)
    if total <= 0:
        return {"request_count": 0, "rate_5xx": 0.0, "p95_latency_ms": 0, "avg_latency_ms": 0.0}

    durations = [int(x[4]) for x in filtered]
    s5xx = sum(1 for x in filtered if 500 <= int(x[3]) <= 599)

    return {
        "request_count": int(total),
        "rate_5xx": float(s5xx / total) if total else 0.0,
        "p95_latency_ms": int(_percentile(durations, 95)),
        "avg_latency_ms": float(sum(durations) / len(durations)) if durations else 0.0,
    }


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None:
            return float(default)
        return float(v)
    except Exception:
        return float(default)


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return int(default)
        return int(v)
    except Exception:
        return int(default)


def _as_str_list(v: Any) -> List[str]:
    """
    Accepts:
      - list[str]
      - JSON string like '["a","b"]'
      - comma-separated string "a,b"
      - None
    Returns a clean list[str].
    """
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if isinstance(x, (str, int, float)) and str(x).strip()]
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return []
        if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
            try:
                obj = json.loads(s)
                if isinstance(obj, list):
                    return [str(x).strip() for x in obj if str(x).strip()]
            except Exception:
                pass
        return [p.strip() for p in s.split(",") if p.strip()]
    return []


def _extract_policy_strictness(db) -> Dict[str, Any]:
    policy_version = "gov-v1.0"
    neutrality_version = "n-v1.1"
    min_score_allow = 75
    hard_rules_count = 0
    soft_rules_count = 0

    try:
        pol = get_current_policy(db)

        pol_dict: Dict[str, Any] = {}
        if isinstance(pol, dict):
            pol_dict = pol
        elif hasattr(pol, "model_dump"):
            try:
                dumped = pol.model_dump()
                if isinstance(dumped, dict):
                    pol_dict = dumped
            except Exception:
                pol_dict = {}
        elif hasattr(pol, "dict"):
            try:
                dumped = pol.dict()
                if isinstance(dumped, dict):
                    pol_dict = dumped
            except Exception:
                pol_dict = {}

        if isinstance(pol_dict.get("policy"), dict):
            pol_dict = pol_dict["policy"]

        pv = pol_dict.get("policy_version") if isinstance(pol_dict, dict) else None
        nv = pol_dict.get("neutrality_version") if isinstance(pol_dict, dict) else None
        msa = pol_dict.get("min_score_allow") if isinstance(pol_dict, dict) else None

        if not pv and hasattr(pol, "policy_version"):
            pv = getattr(pol, "policy_version", None)
        if not nv and hasattr(pol, "neutrality_version"):
            nv = getattr(pol, "neutrality_version", None)
        if msa is None and hasattr(pol, "min_score_allow"):
            msa = getattr(pol, "min_score_allow", None)

        if isinstance(pv, str) and pv.strip():
            policy_version = pv.strip()
        if isinstance(nv, str) and nv.strip():
            neutrality_version = nv.strip()
        try:
            min_score_allow = int(msa)
        except Exception:
            pass

        hard_raw = (
            pol_dict.get("hard_block_rules")
            or pol_dict.get("hard_block_rules_json")
            or pol_dict.get("hard_rules")
            if isinstance(pol_dict, dict)
            else None
        )
        soft_raw = (
            pol_dict.get("soft_rules")
            or pol_dict.get("soft_rules_json")
            if isinstance(pol_dict, dict)
            else None
        )

        if hard_raw is None:
            hard_raw = getattr(pol, "hard_block_rules", None) or getattr(pol, "hard_rules", None)
        if soft_raw is None:
            soft_raw = getattr(pol, "soft_rules", None)

        hard_list = _as_str_list(hard_raw)
        soft_list = _as_str_list(soft_raw)

        hard_rules_count = len(hard_list)
        soft_rules_count = len(soft_list)

    except Exception:
        pass

    strictness_score = float(min_score_allow) + (2.0 * float(hard_rules_count)) + (1.0 * float(soft_rules_count))

    return {
        "policy_version": policy_version,
        "neutrality_version": neutrality_version,
        "min_score_allow": int(min_score_allow),
        "hard_rules_count": int(hard_rules_count),
        "soft_rules_count": int(soft_rules_count),
        "strictness_score": float(strictness_score),
    }


def _compute_governance_bucket_stats(db, start_ts: datetime, end_ts: datetime, mode: str = "__all__") -> Dict[str, Any]:
    if mode == "__all__":
        row = db.execute(
            text(
                """
                SELECT
                  COUNT(*)::int AS events_total,
                  COALESCE(AVG(CASE WHEN replaced THEN 1 ELSE 0 END), 0)::float AS replaced_rate,
                  COALESCE(AVG(score), 0)::float AS avg_score
                FROM governance_events
                WHERE created_at >= :start_ts
                  AND created_at <  :end_ts
                """
            ),
            {"start_ts": start_ts, "end_ts": end_ts},
        ).fetchone()
    else:
        row = db.execute(
            text(
                """
                SELECT
                  COUNT(*)::int AS events_total,
                  COALESCE(AVG(CASE WHEN replaced THEN 1 ELSE 0 END), 0)::float AS replaced_rate,
                  COALESCE(AVG(score), 0)::float AS avg_score
                FROM governance_events
                WHERE created_at >= :start_ts
                  AND created_at <  :end_ts
                  AND mode = :mode
                """
            ),
            {"start_ts": start_ts, "end_ts": end_ts, "mode": mode},
        ).fetchone()

    if not row:
        return {"gov_events_total": 0, "gov_replaced_rate": 0.0, "gov_avg_score": 0.0}

    return {"gov_events_total": int(row[0] or 0), "gov_replaced_rate": float(row[1] or 0.0), "gov_avg_score": float(row[2] or 0.0)}


def _ensure_ops_timeseries_table(db) -> None:
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS ops_timeseries_buckets (
              id uuid PRIMARY KEY,
              bucket_start timestamptz NOT NULL,
              bucket_sec int NOT NULL,
              route text NOT NULL DEFAULT '__all__',
              mode text NOT NULL DEFAULT '__all__',

              request_count int NOT NULL DEFAULT 0,
              rate_5xx double precision NOT NULL DEFAULT 0,
              p95_latency_ms int NOT NULL DEFAULT 0,
              avg_latency_ms double precision NOT NULL DEFAULT 0,

              gov_events_total int NOT NULL DEFAULT 0,
              gov_replaced_rate double precision NOT NULL DEFAULT 0,
              gov_avg_score double precision NOT NULL DEFAULT 0,

              policy_version text,
              neutrality_version text,
              min_score_allow int,
              hard_rules_count int,
              soft_rules_count int,
              strictness_score double precision NOT NULL DEFAULT 0,

              created_at timestamptz NOT NULL DEFAULT NOW()
            );
            """
        )
    )

    # Old uniqueness (without mode) might exist in older DBs:
    db.execute(
        text(
            """
            DO $$
            BEGIN
              IF EXISTS (
                SELECT 1 FROM pg_indexes
                WHERE schemaname = 'public'
                  AND indexname = 'idx_ops_timeseries_unique'
              ) THEN
                EXECUTE 'DROP INDEX IF EXISTS idx_ops_timeseries_unique';
              END IF;
            END $$;
            """
        )
    )

    # New uniqueness
    db.execute(
        text(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_ops_timeseries_unique_mode
              ON ops_timeseries_buckets (bucket_start, bucket_sec, route, mode);
            """
        )
    )

    db.execute(text("CREATE INDEX IF NOT EXISTS idx_ops_timeseries_bucket_start ON ops_timeseries_buckets (bucket_start DESC);"))

    # Old helper index (without mode) might exist:
    db.execute(
        text(
            """
            DO $$
            BEGIN
              IF EXISTS (
                SELECT 1 FROM pg_indexes
                WHERE schemaname = 'public'
                  AND indexname = 'idx_ops_timeseries_bucket_route_sec_start'
              ) THEN
                EXECUTE 'DROP INDEX IF EXISTS idx_ops_timeseries_bucket_route_sec_start';
              END IF;
            END $$;
            """
        )
    )

    db.execute(
        text(
            """
            CREATE INDEX IF NOT EXISTS idx_ops_timeseries_bucket_route_mode_sec_start
              ON ops_timeseries_buckets (bucket_sec, route, mode, bucket_start DESC);
            """
        )
    )

    db.execute(
        text(
            """
            CREATE INDEX IF NOT EXISTS idx_ops_timeseries_bucket_mode_sec_start
              ON ops_timeseries_buckets (bucket_sec, mode, bucket_start DESC);
            """
        )
    )

    db.execute(text("CREATE INDEX IF NOT EXISTS brin_ops_timeseries_bucket_start ON ops_timeseries_buckets USING BRIN (bucket_start);"))


def _upsert_timeseries_bucket(
    db,
    *,
    bucket_start: datetime,
    bucket_sec: int,
    route: str,
    mode: str,
    http_stats: Dict[str, Any],
    gov_stats: Dict[str, Any],
    policy_stats: Dict[str, Any],
) -> None:
    db.execute(
        text(
            """
            INSERT INTO ops_timeseries_buckets (
              id, bucket_start, bucket_sec, route, mode,
              request_count, rate_5xx, p95_latency_ms, avg_latency_ms,
              gov_events_total, gov_replaced_rate, gov_avg_score,
              policy_version, neutrality_version, min_score_allow,
              hard_rules_count, soft_rules_count, strictness_score
            )
            VALUES (
              :id, :bucket_start, :bucket_sec, :route, :mode,
              :request_count, :rate_5xx, :p95_latency_ms, :avg_latency_ms,
              :gov_events_total, :gov_replaced_rate, :gov_avg_score,
              :policy_version, :neutrality_version, :min_score_allow,
              :hard_rules_count, :soft_rules_count, :strictness_score
            )
            ON CONFLICT (bucket_start, bucket_sec, route, mode)
            DO UPDATE SET
              request_count = EXCLUDED.request_count,
              rate_5xx = EXCLUDED.rate_5xx,
              p95_latency_ms = EXCLUDED.p95_latency_ms,
              avg_latency_ms = EXCLUDED.avg_latency_ms,
              gov_events_total = EXCLUDED.gov_events_total,
              gov_replaced_rate = EXCLUDED.gov_replaced_rate,
              gov_avg_score = EXCLUDED.gov_avg_score,
              policy_version = EXCLUDED.policy_version,
              neutrality_version = EXCLUDED.neutrality_version,
              min_score_allow = EXCLUDED.min_score_allow,
              hard_rules_count = EXCLUDED.hard_rules_count,
              soft_rules_count = EXCLUDED.soft_rules_count,
              strictness_score = EXCLUDED.strictness_score;
            """
        ),
        {
            "id": str(uuid.uuid4()),
            "bucket_start": bucket_start,
            "bucket_sec": int(bucket_sec),
            "route": str(route),
            "mode": str(mode or "__all__"),
            "request_count": _safe_int(http_stats.get("request_count")),
            "rate_5xx": _safe_float(http_stats.get("rate_5xx")),
            "p95_latency_ms": _safe_int(http_stats.get("p95_latency_ms")),
            "avg_latency_ms": _safe_float(http_stats.get("avg_latency_ms")),
            "gov_events_total": _safe_int(gov_stats.get("gov_events_total")),
            "gov_replaced_rate": _safe_float(gov_stats.get("gov_replaced_rate")),
            "gov_avg_score": _safe_float(gov_stats.get("gov_avg_score")),
            "policy_version": policy_stats.get("policy_version"),
            "neutrality_version": policy_stats.get("neutrality_version"),
            "min_score_allow": _safe_int(policy_stats.get("min_score_allow")),
            "hard_rules_count": _safe_int(policy_stats.get("hard_rules_count")),
            "soft_rules_count": _safe_int(policy_stats.get("soft_rules_count")),
            "strictness_score": _safe_float(policy_stats.get("strictness_score")),
        },
    )


def _pearson_corr(xs: List[float], ys: List[float]) -> Optional[float]:
    if len(xs) != len(ys) or len(xs) < 3:
        return None
    n = float(len(xs))
    mx = sum(xs) / n
    my = sum(ys) / n
    vx = sum((x - mx) ** 2 for x in xs)
    vy = sum((y - my) ** 2 for y in ys)
    if vx <= 0 or vy <= 0:
        return None
    cov = sum((xs[i] - mx) * (ys[i] - my) for i in range(len(xs)))
    return float(cov / math.sqrt(vx * vy))


def _safe_div(n: float, d: float) -> float:
    try:
        if d == 0:
            return 0.0
        return float(n) / float(d)
    except Exception:
        return 0.0


def _zero_http_stats() -> Dict[str, Any]:
    return {"request_count": 0, "rate_5xx": 0.0, "p95_latency_ms": 0, "avg_latency_ms": 0.0}


def _list_known_modes(db, max_modes: int = 10) -> List[str]:
    rows = db.execute(
        text(
            """
            SELECT DISTINCT mode
            FROM governance_events
            WHERE created_at >= (NOW() - INTERVAL '7 days')
              AND mode IS NOT NULL
            ORDER BY mode ASC
            LIMIT :lim
            """
        ),
        {"lim": int(max_modes)},
    ).fetchall()

    modes: List[str] = []
    for r in rows:
        m = (r[0] or "").strip()
        if m:
            modes.append(m)

    if "witness" not in modes:
        modes.append("witness")

    seen = set()
    out: List[str] = []
    for m in modes:
        if m not in seen:
            seen.add(m)
            out.append(m)

    return out[: max(1, min(20, int(max_modes)))]


def _compute_governance_replaced_rate(db, window_sec: int) -> Dict[str, Any]:
    try:
        ws = int(window_sec)
    except Exception:
        ws = 900

    ws = max(30, min(86400, ws))

    row = db.execute(
        text(
            """
            SELECT
              COUNT(*)::int AS events_total,
              COALESCE(AVG(CASE WHEN replaced THEN 1 ELSE 0 END), 0)::float AS replaced_rate
            FROM governance_events
            WHERE created_at >= (NOW() - (:window_sec || ' seconds')::interval)
            """
        ),
        {"window_sec": ws},
    ).fetchone()

    if not row:
        return {"governance_events_total": 0, "governance_replaced_rate": 0.0, "window_sec": ws}

    return {"governance_events_total": int(row[0] or 0), "governance_replaced_rate": float(row[1] or 0.0), "window_sec": ws}


def _compute_trust_state_from_windows(
    *,
    request_count: int,
    rate_5xx: float,
    p95_latency_ms: int,
    gov_replaced_rate: float,
    gov_events_total: int,
    max_5xx_rate: float = 0.01,
    max_p95_latency_ms: int = 1000,
    max_governance_replaced_rate: float = 0.10,
    warn_5xx_rate: float = 0.005,
    warn_p95_latency_ms: int = 800,
    warn_governance_replaced_rate: float = 0.05,
    min_request_count: int = 20,
    min_governance_events_total: int = 50,
) -> Dict[str, Any]:
    request_count = int(request_count or 0)
    rate_5xx = float(rate_5xx or 0.0)
    p95_latency_ms = int(p95_latency_ms or 0)
    gov_replaced_rate = float(gov_replaced_rate or 0.0)
    gov_events_total = int(gov_events_total or 0)

    enough_traffic = request_count >= int(min_request_count)
    enough_gov = gov_events_total >= int(min_governance_events_total)

    burn_5xx = _safe_div(rate_5xx, float(max_5xx_rate))
    burn_p95 = _safe_div(float(p95_latency_ms), float(max_p95_latency_ms))
    burn_gov = _safe_div(gov_replaced_rate, float(max_governance_replaced_rate))

    if not enough_traffic:
        return {
            "trust_state": "green",
            "reason_codes": ["insufficient_traffic"],
            "burn_rates": {"burn_5xx": burn_5xx, "burn_p95_latency": burn_p95, "burn_governance_replaced": burn_gov},
            "checks": None,
            "thresholds": {
                "max_5xx_rate": float(max_5xx_rate),
                "max_p95_latency_ms": int(max_p95_latency_ms),
                "max_governance_replaced_rate": float(max_governance_replaced_rate),
                "warn_5xx_rate": float(warn_5xx_rate),
                "warn_p95_latency_ms": int(warn_p95_latency_ms),
                "warn_governance_replaced_rate": float(warn_governance_replaced_rate),
                "min_request_count": int(min_request_count),
                "min_governance_events_total": int(min_governance_events_total),
            },
        }

    reason_codes: List[str] = []
    breach = False
    ok_5xx = True
    ok_p95 = True
    ok_gov = True

    if rate_5xx > float(max_5xx_rate):
        breach = True
        ok_5xx = False
        reason_codes.append("breach_5xx")

    if p95_latency_ms > int(max_p95_latency_ms):
        breach = True
        ok_p95 = False
        reason_codes.append("breach_p95_latency")

    if enough_gov:
        if gov_replaced_rate > float(max_governance_replaced_rate):
            breach = True
            ok_gov = False
            reason_codes.append("breach_governance_replaced")
    else:
        reason_codes.append("insufficient_governance_events")

    near = False
    if rate_5xx > float(warn_5xx_rate):
        near = True
        reason_codes.append("warn_5xx")
    if p95_latency_ms > int(warn_p95_latency_ms):
        near = True
        reason_codes.append("warn_p95_latency")
    if enough_gov and (gov_replaced_rate > float(warn_governance_replaced_rate)):
        near = True
        reason_codes.append("warn_governance_replaced")

    trust_state = "red" if breach else ("yellow" if near else "green")

    return {
        "trust_state": trust_state,
        "reason_codes": reason_codes,
        "burn_rates": {"burn_5xx": burn_5xx, "burn_p95_latency": burn_p95, "burn_governance_replaced": burn_gov},
        "checks": {"ok_5xx": ok_5xx, "ok_p95": ok_p95, "ok_governance_replaced_rate": ok_gov},
        "thresholds": {
            "max_5xx_rate": float(max_5xx_rate),
            "max_p95_latency_ms": int(max_p95_latency_ms),
            "max_governance_replaced_rate": float(max_governance_replaced_rate),
            "warn_5xx_rate": float(warn_5xx_rate),
            "warn_p95_latency_ms": int(warn_p95_latency_ms),
            "warn_governance_replaced_rate": float(warn_governance_replaced_rate),
            "min_request_count": int(min_request_count),
            "min_governance_events_total": int(min_governance_events_total),
        },
    }


def _timeseries_worker() -> None:
    interval_sec = max(10, min(300, _safe_int_env("OPS_TS_FLUSH_INTERVAL_SEC", 30)))
    bucket_sec = max(60, min(3600, _safe_int_env("OPS_TS_BUCKET_SEC", 300)))  # default 5 minutes
    lookback_buckets = max(1, min(12, _safe_int_env("OPS_TS_LOOKBACK_BUCKETS", 2)))

    stop_ev = _TS_STOP_EVENT
    if stop_ev is None:
        return

    log_event(logging.INFO, "ops.timeseries.worker_start", interval_sec=interval_sec, bucket_sec=bucket_sec)

    while not stop_ev.is_set():
        try:
            now_ns = time.time_ns()
            end_bucket_ns = _bucket_floor(now_ns, bucket_sec)  # current bucket start
            bucket_ns = bucket_sec * 1_000_000_000

            items = _HTTP_METRICS.snapshot()

            with SessionLocal() as db:
                _ensure_ops_timeseries_table(db)
                policy_stats = _extract_policy_strictness(db)

                for i in range(lookback_buckets, 0, -1):
                    b_start_ns = end_bucket_ns - (i * bucket_ns)
                    b_end_ns = b_start_ns + bucket_ns
                    b_start_dt = datetime.fromtimestamp(b_start_ns / 1_000_000_000, tz=timezone.utc)
                    b_end_dt = datetime.fromtimestamp(b_end_ns / 1_000_000_000, tz=timezone.utc)

                    http_all = _summarize_http_metrics_range(items, b_start_ns, b_end_ns, route="__all__")
                    gov_all = _compute_governance_bucket_stats(db, b_start_dt, b_end_dt, mode="__all__")

                    _upsert_timeseries_bucket(
                        db,
                        bucket_start=b_start_dt,
                        bucket_sec=bucket_sec,
                        route="__all__",
                        mode="__all__",
                        http_stats=http_all,
                        gov_stats=gov_all,
                        policy_stats=policy_stats,
                    )

                    modes = _list_known_modes(db, max_modes=max(1, min(20, _safe_int_env("OPS_TS_MAX_MODES", 10))))
                    for m in modes:
                        gov_m = _compute_governance_bucket_stats(db, b_start_dt, b_end_dt, mode=m)
                        _upsert_timeseries_bucket(
                            db,
                            bucket_start=b_start_dt,
                            bucket_sec=bucket_sec,
                            route="__all__",
                            mode=m,
                            http_stats=_zero_http_stats(),
                            gov_stats=gov_m,
                            policy_stats=policy_stats,
                        )

                db.commit()

                # ops.trust_state heartbeat
                try:
                    window_sec = max(30, min(86400, _safe_int_env("OPS_TRUST_WINDOW_SEC", 900)))
                    http_roll = _summarize_http_metrics(items, window_sec=window_sec, limit=1)

                    request_count = int(http_roll.get("events_total", 0) or 0)
                    rate_5xx = float(http_roll.get("rate_5xx", 0.0) or 0.0)
                    p95_latency_ms = int(http_roll.get("p95_ms", 0) or 0)

                    gov_roll = _compute_governance_replaced_rate(db, window_sec=window_sec)
                    gov_replaced_rate = float(gov_roll.get("governance_replaced_rate", 0.0) or 0.0)
                    gov_events_total = int(gov_roll.get("governance_events_total", 0) or 0)

                    trust = _compute_trust_state_from_windows(
                        request_count=request_count,
                        rate_5xx=rate_5xx,
                        p95_latency_ms=p95_latency_ms,
                        gov_replaced_rate=gov_replaced_rate,
                        gov_events_total=gov_events_total,
                        max_5xx_rate=_safe_float_env("OPS_TRUST_MAX_5XX_RATE", 0.01),
                        max_p95_latency_ms=_safe_int_env("OPS_TRUST_MAX_P95_MS", 1000),
                        max_governance_replaced_rate=_safe_float_env("OPS_TRUST_MAX_GOV_REPLACED", 0.10),
                        warn_5xx_rate=_safe_float_env("OPS_TRUST_WARN_5XX_RATE", 0.005),
                        warn_p95_latency_ms=_safe_int_env("OPS_TRUST_WARN_P95_MS", 800),
                        warn_governance_replaced_rate=_safe_float_env("OPS_TRUST_WARN_GOV_REPLACED", 0.05),
                        min_request_count=_safe_int_env("OPS_TRUST_MIN_REQ", 20),
                        min_governance_events_total=_safe_int_env("OPS_TRUST_MIN_GOV", 50),
                    )

                    log_event(
                        logging.INFO,
                        "ops.trust_state",
                        window_sec=window_sec,
                        request_count=request_count,
                        rate_5xx=rate_5xx,
                        p95_latency_ms=p95_latency_ms,
                        governance_replaced_rate=gov_replaced_rate,
                        governance_events_total=gov_events_total,
                        trust_state=trust.get("trust_state"),
                        reason_codes=trust.get("reason_codes"),
                        burn_rates=trust.get("burn_rates"),
                        thresholds=trust.get("thresholds"),
                        policy_strictness=policy_stats,
                    )
                except Exception as e:
                    log_event(logging.ERROR, "ops.trust_state.error", error_type=type(e).__name__, error=_truncate(str(e), 240))

        except Exception as e:
            log_event(logging.ERROR, "ops.timeseries.worker_error", error_type=type(e).__name__, error=_truncate(str(e), 240))

        stop_ev.wait(interval_sec)

    log_event(logging.INFO, "ops.timeseries.worker_stop")


def _start_timeseries_worker() -> None:
    global _TS_STOP_EVENT, _TS_THREAD
    if _TS_THREAD and _TS_THREAD.is_alive():
        return
    _TS_STOP_EVENT = threading.Event()
    _TS_THREAD = threading.Thread(target=_timeseries_worker, name="ops-timeseries", daemon=True)
    _TS_THREAD.start()


def _stop_timeseries_worker() -> None:
    global _TS_STOP_EVENT, _TS_THREAD
    if _TS_STOP_EVENT:
        _TS_STOP_EVENT.set()
    _TS_STOP_EVENT = None
    _TS_THREAD = None

# ============================================================
# Lifespan — migrations + worker start/stop wired safely
# ============================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        if not is_prod():
            try:
                from dotenv import load_dotenv  # type: ignore
                load_dotenv()
                log_event(logging.INFO, "dotenv_loaded")
            except Exception:
                log_event(logging.INFO, "dotenv_not_loaded")

        run_migrations()
        log_event(logging.INFO, "startup_migrations_ok")

        if not _ADMIN_TOKENS:
            log_event(logging.WARNING, "admin_tokens_missing", note="No admin tokens configured; all /v1/admin/* will 403")

        if _ops_ts_enabled():
            _start_timeseries_worker()
            log_event(logging.INFO, "ops.timeseries.enabled", enabled=True, default_prod=is_prod() and os.getenv("OPS_TS_ENABLED") is None)
        else:
            log_event(logging.INFO, "ops.timeseries.disabled", enabled=False, default_prod=is_prod() and os.getenv("OPS_TS_ENABLED") is None)

    except Exception as e:
        log_event(logging.ERROR, "startup_failed", error_type=type(e).__name__, error=_truncate(str(e)))
        raise

    yield

    try:
        _stop_timeseries_worker()
    except Exception:
        pass
    log_event(logging.INFO, "shutdown")

# ============================================================
# App
# ============================================================

app = FastAPI(title="ANCHOR API", lifespan=lifespan)
_configure_edge_middlewares(app)

app.include_router(clinic_auth_router)
app.include_router(portal_bootstrap_router)
app.include_router(ops_rls_router)
app.include_router(portal_submit_router)
app.include_router(portal_read_router)
app.include_router(portal_export_router)
app.include_router(portal_ops_router)
app.include_router(portal_ops_timeseries_router)
app.include_router(portal_trust_state_router)
app.include_router(portal_error_budget_router)
app.include_router(portal_ops_health_router)
app.include_router(portal_dashboard_router)
app.include_router(portal_me_router)
app.include_router(admin_tokens_router)
app.include_router(admin_audit_router)

# ============================================================
# Exception handlers
# ============================================================


def _get_request_id(request: Request) -> str:
    rid = getattr(request.state, "request_id", None)
    return str(rid) if rid else (request.headers.get("X-Request-ID") or str(uuid.uuid4()))


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    req_id = _get_request_id(request)
    headers = dict(getattr(exc, "headers", None) or {})
    headers["X-Request-ID"] = req_id
    return JSONResponse(status_code=int(exc.status_code), content={"detail": exc.detail, "request_id": req_id}, headers=headers)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    req_id = _get_request_id(request)
    return JSONResponse(status_code=422, content={"detail": exc.errors(), "request_id": req_id}, headers={"X-Request-ID": req_id})

# ============================================================
# Request logging middleware (M2 Step 1) + metrics (M2 Step 3)
# ============================================================

_SKIP_LOG_PATHS = {"/health", "/openapi.json", "/docs"}


def _host(request: Request) -> Optional[str]:
    try:
        return request.headers.get("host")
    except Exception:
        return None


def _route_template_from_scope(request: Request) -> str:
    try:
        route = request.scope.get("route")
        if route and getattr(route, "path", None):
            return str(route.path)
    except Exception:
        pass
    return request.url.path


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = req_id

    try:
        client_ip = request.client.host if request.client else None
    except Exception:
        client_ip = None

    try:
        ua = request.headers.get("user-agent")
    except Exception:
        ua = None

    start_ns = time.time_ns()
    route_tmpl = _route_template_from_scope(request)

    if request.url.path not in _SKIP_LOG_PATHS:
        log_event(
            logging.INFO,
            "http.request.start",
            request_id=req_id,
            method=request.method,
            route=route_tmpl,
            path=request.url.path,
            host=_host(request),
            client_ip_hash=_hmac_sha256_hex(client_ip),
            user_agent_hash=_hmac_sha256_hex(ua),
        )

    try:
        response: Response = await call_next(request)
        dur_ms = int((time.time_ns() - start_ns) / 1_000_000)
        response.headers["X-Request-ID"] = req_id

        _HTTP_METRICS.add(start_ns, request.method, route_tmpl, response.status_code, dur_ms)

        if request.url.path not in _SKIP_LOG_PATHS:
            log_event(
                logging.INFO,
                "http.request.end",
                request_id=req_id,
                method=request.method,
                route=route_tmpl,
                path=request.url.path,
                host=_host(request),
                client_ip_hash=_hmac_sha256_hex(client_ip),
                user_agent_hash=_hmac_sha256_hex(ua),
                status_code=response.status_code,
                duration_ms=dur_ms,
            )
        return response

    except Exception as e:
        dur_ms = int((time.time_ns() - start_ns) / 1_000_000)
        _HTTP_METRICS.add(start_ns, request.method, route_tmpl, 500, dur_ms)

        err_fields: Dict[str, Any] = {
            "request_id": req_id,
            "method": request.method,
            "route": route_tmpl,
            "path": request.url.path,
            "host": _host(request),
            "client_ip_hash": _hmac_sha256_hex(client_ip),
            "user_agent_hash": _hmac_sha256_hex(ua),
            "status_code": 500,
            "duration_ms": dur_ms,
            "error_type": type(e).__name__,
            "error": _truncate(str(e), 240),
        }
        if _trace_enabled():
            err_fields["traceback"] = traceback.format_exc()

        log_event(logging.ERROR, "error.unhandled", **err_fields)

        return JSONResponse(
            status_code=500,
            content={"detail": "internal_server_error", "request_id": req_id},
            headers={"X-Request-ID": req_id},
        )

# ============================================================
# Root/Health/Version
# ============================================================


@app.head("/")
def root_head():
    return Response(status_code=200)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/db-check")
def db_check():
    db_ping()
    return {"db": "ok"}


@app.get("/db-memories-check")
def db_memories_check():
    with SessionLocal() as db:
        try:
            db.execute(text("SELECT 1 FROM memories LIMIT 1"))
            return {"memories_table": "ok"}
        except Exception as e:
            return {"memories_table": "error", "detail": str(e)}


@app.get("/v1/version")
def version():
    return {
        "name": "ANCHOR API",
        "env": get_app_env(),
        "git_sha": os.getenv("GIT_SHA", None),
        "build": os.getenv("BUILD_ID", None),
        "now_utc": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/")
def root():
    return {"name": "ANCHOR API", "status": "live"}


class GovernancePolicyUpdateRequest(BaseModel):
    policy_version: str = Field(..., min_length=3, max_length=64)
    neutrality_version: str = Field(default="n-v1.1", min_length=3, max_length=64)
    min_score_allow: int = Field(default=75, ge=0, le=100)
    hard_block_rules: List[str] = Field(default_factory=lambda: ["jailbreak", "therapy", "promise"])
    soft_rules: List[str] = Field(default_factory=lambda: ["direct_advice", "coercion"])
    max_findings: int = Field(default=10, ge=1, le=50)


def require_admin(
    request: Request,
    x_anchor_admin_token: str | None = Header(default=None, alias="X-ANCHOR-ADMIN-TOKEN"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict:
    _rate_limit_admin(request)
    _validate_admin_ip(request)
    token = _extract_admin_token(x_anchor_admin_token, authorization)
    fp = _validate_admin_token(request, token)
    _admin_audit("admin_access", request, level=logging.INFO, token_fp=fp)
    return {"token_fp": fp}


def _ensure_user_exists(db, user_id: uuid.UUID) -> None:
    row = db.execute(text("SELECT id FROM users WHERE id = :uid"), {"uid": str(user_id)}).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")


def _ensure_session_exists(db, session_id: uuid.UUID) -> None:
    row = db.execute(text("SELECT id FROM sessions WHERE id = :sid"), {"sid": str(session_id)}).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")


def _norm_stmt(s: str) -> str:
    return " ".join((s or "").strip().split())


def _validate_memory_statement(statement: str) -> None:
    s = (statement or "").strip()
    if not s or "\n" in s or len(s) > 280:
        raise HTTPException(status_code=400, detail="Invalid memory statement")

    banned = [
        "you should",
        "try to",
        "it might help",
        "i recommend",
        "diagnos",
        "therapy",
        "therapist",
        "you need to",
        "this will help",
        "you will feel",
    ]
    low = s.lower()
    if any(b in low for b in banned):
        raise HTTPException(status_code=400, detail="Memory statement violates neutrality rules")


def _score_neutrality_safe(text_value: str, debug: bool) -> Dict[str, Any]:
    try:
        return score_neutrality(text_value, debug=debug)  # type: ignore[arg-type]
    except TypeError:
        base = score_neutrality(text_value)  # type: ignore[misc]
        if debug and isinstance(base, dict):
            base["debug"] = {"note": "scorer does not support debug=True; returned base scoring only"}
        return base


# ============================================================
# Admin auth-check + Admin ops (HTTP metrics, SLO, error budget)
# ============================================================


@app.get("/v1/admin/auth-check")
def admin_auth_check(_: None = Depends(require_admin)):
    return {"status": "ok"}


@app.get("/v1/admin/ops/http-metrics")
def ops_http_metrics(window_sec: int = 900, limit: int = 50, _: None = Depends(require_admin)):
    window_sec = max(30, min(86400, int(window_sec)))
    limit = max(1, min(200, int(limit)))
    items = _HTTP_METRICS.snapshot()
    return {"status": "ok", "now_utc": datetime.now(timezone.utc).isoformat(), "metrics": _summarize_http_metrics(items, window_sec=window_sec, limit=limit)}


@app.get("/v1/admin/ops/metrics")
def ops_metrics(window_sec: int = 900, _: None = Depends(require_admin)):
    window_sec = max(30, min(86400, int(window_sec)))
    items = _HTTP_METRICS.snapshot()
    http_summary = _summarize_http_metrics(items, window_sec=window_sec, limit=1)

    request_count = int(http_summary.get("events_total", 0) or 0)
    rate_5xx = float(http_summary.get("rate_5xx", 0.0) or 0.0)
    p95_latency_ms = int(http_summary.get("p95_ms", 0) or 0)

    with SessionLocal() as db:
        gov = _compute_governance_replaced_rate(db, window_sec=window_sec)

    return {
        "status": "ok",
        "now_utc": datetime.now(timezone.utc).isoformat(),
        "window_sec": int(window_sec),
        "request_count": request_count,
        "rate_5xx": rate_5xx,
        "p95_latency_ms": p95_latency_ms,
        "governance_replaced_rate": float(gov.get("governance_replaced_rate", 0.0) or 0.0),
        "governance_events_total": int(gov.get("governance_events_total", 0) or 0),
    }


@app.get("/v1/admin/ops/slo-check")
def ops_slo_check(
    window_sec: int = 900,
    max_5xx_rate: float = 0.01,
    max_p95_latency_ms: int = 1000,
    max_governance_replaced_rate: float = 0.10,
    min_request_count: int = 20,
    _: None = Depends(require_admin),
):
    window_sec = max(30, min(86400, int(window_sec)))
    items = _HTTP_METRICS.snapshot()
    http_summary = _summarize_http_metrics(items, window_sec=window_sec, limit=1)

    request_count = int(http_summary.get("events_total", 0) or 0)
    rate_5xx = float(http_summary.get("rate_5xx", 0.0) or 0.0)
    p95_latency_ms = int(http_summary.get("p95_ms", 0) or 0)

    with SessionLocal() as db:
        gov = _compute_governance_replaced_rate(db, window_sec=window_sec)

    gov_replaced = float(gov.get("governance_replaced_rate", 0.0) or 0.0)
    gov_total = int(gov.get("governance_events_total", 0) or 0)

    enough_traffic = request_count >= int(min_request_count)

    ok_5xx = rate_5xx <= float(max_5xx_rate)
    ok_p95 = p95_latency_ms <= int(max_p95_latency_ms)
    ok_gov = gov_replaced <= float(max_governance_replaced_rate)

    if not enough_traffic:
        return {
            "status": "ok",
            "now_utc": datetime.now(timezone.utc).isoformat(),
            "window_sec": int(window_sec),
            "slo_ok": None,
            "reason": "insufficient_traffic",
            "request_count": request_count,
            "rate_5xx": rate_5xx,
            "p95_latency_ms": p95_latency_ms,
            "governance_replaced_rate": gov_replaced,
            "governance_events_total": gov_total,
            "thresholds": {
                "max_5xx_rate": float(max_5xx_rate),
                "max_p95_latency_ms": int(max_p95_latency_ms),
                "max_governance_replaced_rate": float(max_governance_replaced_rate),
                "min_request_count": int(min_request_count),
            },
        }

    slo_ok = bool(ok_5xx and ok_p95 and ok_gov)
    return {
        "status": "ok",
        "now_utc": datetime.now(timezone.utc).isoformat(),
        "window_sec": int(window_sec),
        "slo_ok": slo_ok,
        "checks": {"ok_5xx": ok_5xx, "ok_p95": ok_p95, "ok_governance_replaced_rate": ok_gov},
        "request_count": request_count,
        "rate_5xx": rate_5xx,
        "p95_latency_ms": p95_latency_ms,
        "governance_replaced_rate": gov_replaced,
        "governance_events_total": gov_total,
        "thresholds": {
            "max_5xx_rate": float(max_5xx_rate),
            "max_p95_latency_ms": int(max_p95_latency_ms),
            "max_governance_replaced_rate": float(max_governance_replaced_rate),
            "min_request_count": int(min_request_count),
        },
    }


@app.get("/v1/admin/ops/error-budget")
def ops_error_budget(
    window_sec: int = 900,
    max_5xx_rate: float = 0.01,
    max_p95_latency_ms: int = 1000,
    max_governance_replaced_rate: float = 0.10,
    warn_5xx_rate: float = 0.005,
    warn_p95_latency_ms: int = 800,
    warn_governance_replaced_rate: float = 0.05,
    min_request_count: int = 20,
    min_governance_events_total: int = 50,
    _: None = Depends(require_admin),
):
    window_sec = max(30, min(86400, int(window_sec)))
    items = _HTTP_METRICS.snapshot()
    http_summary = _summarize_http_metrics(items, window_sec=window_sec, limit=1)

    request_count = int(http_summary.get("events_total", 0) or 0)
    rate_5xx = float(http_summary.get("rate_5xx", 0.0) or 0.0)
    p95_latency_ms = int(http_summary.get("p95_ms", 0) or 0)

    with SessionLocal() as db:
        gov = _compute_governance_replaced_rate(db, window_sec=window_sec)

    gov_replaced = float(gov.get("governance_replaced_rate", 0.0) or 0.0)
    gov_total = int(gov.get("governance_events_total", 0) or 0)

    enough_traffic = request_count >= int(min_request_count)
    enough_gov = gov_total >= int(min_governance_events_total)

    burn_5xx = _safe_div(rate_5xx, float(max_5xx_rate))
    burn_p95 = _safe_div(float(p95_latency_ms), float(max_p95_latency_ms))
    burn_gov = _safe_div(gov_replaced, float(max_governance_replaced_rate))

    if not enough_traffic:
        return {
            "status": "ok",
            "now_utc": datetime.now(timezone.utc).isoformat(),
            "window_sec": int(window_sec),
            "trust_state": "green",
            "reason_codes": ["insufficient_traffic"],
            "request_count": request_count,
            "rate_5xx": rate_5xx,
            "p95_latency_ms": p95_latency_ms,
            "governance_replaced_rate": gov_replaced,
            "governance_events_total": gov_total,
            "burn_rates": {"burn_5xx": burn_5xx, "burn_p95_latency": burn_p95, "burn_governance_replaced": burn_gov},
            "thresholds": {
                "max_5xx_rate": float(max_5xx_rate),
                "max_p95_latency_ms": int(max_p95_latency_ms),
                "max_governance_replaced_rate": float(max_governance_replaced_rate),
                "warn_5xx_rate": float(warn_5xx_rate),
                "warn_p95_latency_ms": int(warn_p95_latency_ms),
                "warn_governance_replaced_rate": float(warn_governance_replaced_rate),
                "min_request_count": int(min_request_count),
                "min_governance_events_total": int(min_governance_events_total),
            },
        }

    reason_codes: List[str] = []
    breach = False
    if rate_5xx > float(max_5xx_rate):
        breach = True
        reason_codes.append("breach_5xx")
    if p95_latency_ms > int(max_p95_latency_ms):
        breach = True
        reason_codes.append("breach_p95_latency")

    if enough_gov:
        if gov_replaced > float(max_governance_replaced_rate):
            breach = True
            reason_codes.append("breach_governance_replaced")
    else:
        reason_codes.append("insufficient_governance_events")

    near = False
    if rate_5xx > float(warn_5xx_rate):
        near = True
        reason_codes.append("warn_5xx")
    if p95_latency_ms > int(warn_p95_latency_ms):
        near = True
        reason_codes.append("warn_p95_latency")
    if enough_gov and (gov_replaced > float(warn_governance_replaced_rate)):
        near = True
        reason_codes.append("warn_governance_replaced")

    trust_state = "red" if breach else ("yellow" if near else "green")

    return {
        "status": "ok",
        "now_utc": datetime.now(timezone.utc).isoformat(),
        "window_sec": int(window_sec),
        "trust_state": trust_state,
        "reason_codes": reason_codes,
        "request_count": request_count,
        "rate_5xx": rate_5xx,
        "p95_latency_ms": p95_latency_ms,
        "governance_replaced_rate": gov_replaced,
        "governance_events_total": gov_total,
        "burn_rates": {"burn_5xx": burn_5xx, "burn_p95_latency": burn_p95, "burn_governance_replaced": burn_gov},
        "thresholds": {
            "max_5xx_rate": float(max_5xx_rate),
            "max_p95_latency_ms": int(max_p95_latency_ms),
            "max_governance_replaced_rate": float(max_governance_replaced_rate),
            "warn_5xx_rate": float(warn_5xx_rate),
            "warn_p95_latency_ms": int(warn_p95_latency_ms),
            "warn_governance_replaced_rate": float(warn_governance_replaced_rate),
            "min_request_count": int(min_request_count),
            "min_governance_events_total": int(min_governance_events_total),
        },
    }

# ============================================================
# Neutrality scoring + Governance policy endpoints (legacy API)
# ============================================================


@app.post("/v1/neutrality/score", response_model=NeutralityScoreResponse)
def neutrality_score(req: NeutralityScoreRequest):
    try:
        debug_flag = bool(getattr(req, "debug", False))
        return _score_neutrality_safe(req.text, debug_flag)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"neutrality_error: {type(e).__name__}: {e}")


@app.get("/v1/governance/policy/current")
def governance_policy_current():
    with SessionLocal() as db:
        try:
            return {"policy": get_current_policy(db)}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"policy_error: {type(e).__name__}: {e}")


@app.get("/v1/governance/policy/history")
def governance_policy_history(limit: int = 50):
    limit = max(1, min(200, int(limit)))
    with SessionLocal() as db:
        try:
            return {"history": list_policy_history(db, limit=limit)}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"policy_error: {type(e).__name__}: {e}")


@app.post("/v1/governance/policy")
def governance_policy_create(payload: GovernancePolicyUpdateRequest, request: Request, admin: dict = Depends(require_admin)):
    with SessionLocal() as db:
        try:
            created = create_new_policy(
                db,
                policy_version=payload.policy_version,
                neutrality_version=payload.neutrality_version,
                min_score_allow=int(payload.min_score_allow),
                hard_block_rules=list(payload.hard_block_rules or []),
                soft_rules=list(payload.soft_rules or []),
                max_findings=int(payload.max_findings),
            )
            created_version = None
            if isinstance(created, dict):
                created_version = created.get("policy_version") or created.get("version")
            else:
                created_version = getattr(created, "policy_version", None) or getattr(created, "version", None)

            log_event(
                logging.INFO,
                "policy_change",
                method=request.method,
                path=request.url.path,
                token_fp=admin.get("token_fp"),
                policy_version=created_version,
                neutrality_version=payload.neutrality_version,
                min_score_allow=int(payload.min_score_allow),
                hard_rules_count=len(list(payload.hard_block_rules or [])),
                soft_rules_count=len(list(payload.soft_rules or [])),
                max_findings=int(payload.max_findings),
            )
            return {"created": created}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"policy_error: {type(e).__name__}: {e}")


@app.get("/v1/governance/policy/schema")
def governance_policy_schema():
    with SessionLocal() as db:
        try:
            row = db.execute(text("SELECT updated_at FROM governance_config ORDER BY updated_at DESC LIMIT 1")).fetchone()
            return {"governance_config_table": "ok", "latest_updated_at": row[0].isoformat() if row and row[0] else None}
        except Exception as e:
            return {"governance_config_table": "error", "detail": str(e)}

# ============================================================
# Sessions + Messages (legacy API; kept for backwards compatibility)
# ============================================================


@app.post("/v1/sessions", response_model=CreateSessionResponse)
def create_session():
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()

    with SessionLocal() as db:
        db.execute(text("INSERT INTO users (id) VALUES (:id)"), {"id": str(user_id)})
        db.execute(
            text("INSERT INTO sessions (id, user_id, mode, question_used) VALUES (:sid, :uid, 'witness', false)"),
            {"sid": str(session_id), "uid": str(user_id)},
        )
        db.commit()

    return CreateSessionResponse(user_id=user_id, session_id=session_id, mode="witness")


@app.post("/v1/users/{user_id}/sessions", response_model=CreateSessionResponse)
def create_session_for_user(user_id: uuid.UUID):
    session_id = uuid.uuid4()

    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)
        db.execute(
            text("INSERT INTO sessions (id, user_id, mode, question_used) VALUES (:sid, :uid, 'witness', false)"),
            {"sid": str(session_id), "uid": str(user_id)},
        )
        db.commit()

    return CreateSessionResponse(user_id=user_id, session_id=session_id, mode="witness")


@app.post("/v1/sessions/{session_id}/messages", response_model=SendMessageResponse)
def send_message(session_id: uuid.UUID, payload: SendMessageRequest, request: Request):
    handler_start_ns = time.time_ns()

    with SessionLocal() as db:
        _ensure_session_exists(db, session_id)

        uid_row = db.execute(text("SELECT user_id FROM sessions WHERE id = :sid"), {"sid": str(session_id)}).fetchone()
        user_id = uuid.UUID(str(uid_row[0])) if uid_row and uid_row[0] else None

        db.execute(
            text("INSERT INTO messages (id, session_id, role, content) VALUES (:id, :sid, 'user', :content)"),
            {"id": str(uuid.uuid4()), "sid": str(session_id), "content": payload.content},
        )

        draft_reply = (
            "I'm here with you. I'm going to reflect back what I heard, briefly.\n\n"
            f"**What you said:** {payload.content}\n\n"
            "One question: what feels most important in this right now?"
        )

        final_reply, _decision, audit = govern_output(
            user_text=payload.content,
            assistant_text=draft_reply,
            user_id=user_id,
            session_id=session_id,
            mode="witness",
            debug=False,
        )

        try:
            req_id = _get_request_id(request)
            dur_ms = int((time.time_ns() - handler_start_ns) / 1_000_000)
            # Minimal decision summary only; do not log content
            a = audit if isinstance(audit, dict) else {}
            decision = a.get("decision") if isinstance(a.get("decision"), dict) else {}
            findings = a.get("findings") if isinstance(a.get("findings"), list) else []
            log_event(
                logging.INFO,
                "governance.decision",
                request_id=req_id,
                user_id=str(user_id) if user_id else None,
                session_id=str(session_id),
                mode="witness",
                route="/v1/sessions/{session_id}/messages",
                duration_ms=dur_ms,
                allowed=bool(decision.get("allowed", True)),
                replaced=bool(decision.get("replaced", False)),
                score=int(decision.get("score", 0) or 0),
                grade=str(decision.get("grade", "unknown") or "unknown"),
                findings_count=len(findings),
            )
        except Exception:
            pass

        db.execute(
            text("INSERT INTO messages (id, session_id, role, content) VALUES (:id, :sid, 'assistant', :content)"),
            {"id": str(uuid.uuid4()), "sid": str(session_id), "content": final_reply},
        )

        db.commit()

    return SendMessageResponse(session_id=session_id, role="assistant", content=final_reply)


@app.get("/v1/sessions/{session_id}/messages")
def list_messages(session_id: uuid.UUID):
    with SessionLocal() as db:
        _ensure_session_exists(db, session_id)
        rows = db.execute(
            text(
                """
                SELECT role, content, created_at
                FROM messages
                WHERE session_id = :sid
                ORDER BY created_at ASC,
                         CASE role WHEN 'user' THEN 0 WHEN 'assistant' THEN 1 ELSE 2 END ASC,
                         id ASC
                """
            ),
            {"sid": str(session_id)},
        ).fetchall()

    return [{"role": r[0], "content": r[1], "created_at": r[2].isoformat() if r[2] else None} for r in rows]

# ============================================================
# Memory endpoints (legacy API; kept for backwards compatibility)
# ============================================================


@app.get("/v1/users/{user_id}/evidence-check")
def evidence_check(user_id: uuid.UUID):
    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)

        sessions_count = db.execute(text("SELECT COUNT(*) FROM sessions WHERE user_id = :uid"), {"uid": str(user_id)}).fetchone()[0]
        user_msgs = db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM messages m
                JOIN sessions s ON s.id = m.session_id
                WHERE s.user_id = :uid AND m.role = 'user'
                """
            ),
            {"uid": str(user_id)},
        ).fetchone()[0]

        last_sessions = db.execute(
            text(
                """
                SELECT id, created_at
                FROM sessions
                WHERE user_id = :uid
                ORDER BY created_at DESC
                LIMIT 5
                """
            ),
            {"uid": str(user_id)},
        ).fetchall()

    return {
        "user_id": str(user_id),
        "sessions_count": int(sessions_count),
        "user_message_count": int(user_msgs),
        "last_sessions": [{"id": str(r[0]), "created_at": r[1].isoformat()} for r in last_sessions],
    }


@app.get("/v1/users/{user_id}/memory-debug")
def memory_debug(user_id: uuid.UUID, limit: int = 80):
    limit = max(1, min(500, int(limit)))
    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)
        items = fetch_recent_user_texts(db, user_id, limit=limit)

        signals = {
            "overwhelm_load": ["overwhelmed", "too much", "can't keep up", "cannot keep up", "exhausted", "burnt out", "drained", "no time", "stressed", "pressure"],
            "responsibility_conflict": ["i have to", "i must", "obligation", "obligations", "responsible", "expectations", "expects", "everyone", "depend on me", "duty"],
            "control_uncertainty": ["i don't know", "uncertain", "confused", "not sure", "what if", "worried", "anxious"],
        }

        counts = {k: 0 for k in signals}
        evidence = {k: set() for k in signals}

        for sid, txt in items:
            low = (txt or "").strip().lower()
            if not low:
                continue
            for k, needles in signals.items():
                if any(n in low for n in needles):
                    counts[k] += 1
                    evidence[k].add(str(sid))

        best_key = max(counts, key=lambda k: counts[k]) if counts else None
        best_count = counts[best_key] if best_key else 0

        return {
            "user_id": str(user_id),
            "scanned_user_messages": len(items),
            "counts": counts,
            "best_key": best_key,
            "best_count": best_count,
            "evidence_session_ids": list(evidence[best_key])[:5] if best_key else [],
            "sample_last_5_texts": [t for (_, t) in items[-5:]],
        }


@app.get("/v1/users/{user_id}/memory-offer-debug")
def memory_offer_debug(user_id: uuid.UUID):
    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)
        return compute_offer_debug(db, user_id)


@app.get("/v1/users/{user_id}/memories", response_model=List[MemoryItem])
def list_memories(user_id: uuid.UUID, active: bool = True, kind: Optional[str] = None):
    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)
        if kind:
            rows = db.execute(
                text(
                    "SELECT id, kind, statement, confidence, active, evidence_session_ids, created_at "
                    "FROM memories "
                    "WHERE user_id = :uid AND active = :active AND kind = :kind "
                    "ORDER BY created_at DESC"
                ),
                {"uid": str(user_id), "active": active, "kind": kind},
            ).fetchall()
        else:
            rows = db.execute(
                text(
                    "SELECT id, kind, statement, confidence, active, evidence_session_ids, created_at "
                    "FROM memories "
                    "WHERE user_id = :uid AND active = :active "
                    "ORDER BY created_at DESC"
                ),
                {"uid": str(user_id), "active": active},
            ).fetchall()

    result: List[MemoryItem] = []
    for r in rows:
        evidence = r[5] or []
        evidence_uuids: List[uuid.UUID] = []
        for x in evidence:
            try:
                evidence_uuids.append(uuid.UUID(str(x)))
            except Exception:
                pass

        result.append(
            MemoryItem(
                id=uuid.UUID(str(r[0])),
                kind=r[1],
                statement=r[2],
                confidence=r[3],
                active=bool(r[4]),
                evidence_session_ids=evidence_uuids,
                created_at=r[6].isoformat() if r[6] else "",
            )
        )
    return result


@app.post("/v1/users/{user_id}/memory-offer", response_model=MemoryOfferResponse)
def memory_offer(user_id: uuid.UUID):
    DEFAULT_KIND = "negative_space"
    DEFAULT_STATEMENT = "No stable pattern is evident yet from recent entries."
    DEFAULT_STATEMENT_DUP = "No new stable pattern stands out beyond what is already saved."

    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)
        offer = propose_memory_offer(db, user_id)

        if not offer:
            dup_default = db.execute(
                text(
                    """
                    SELECT 1
                    FROM memories
                    WHERE user_id = :uid
                      AND active = true
                      AND kind = :kind
                      AND statement = :statement
                    LIMIT 1
                    """
                ),
                {"uid": str(user_id), "kind": DEFAULT_KIND, "statement": DEFAULT_STATEMENT},
            ).fetchone()

            if dup_default:
                return MemoryOfferResponse(
                    offer=CreateMemoryRequest(kind=DEFAULT_KIND, statement=DEFAULT_STATEMENT_DUP, confidence="tentative", evidence_session_ids=[])
                )
            return MemoryOfferResponse(
                offer=CreateMemoryRequest(kind=DEFAULT_KIND, statement=DEFAULT_STATEMENT, confidence="tentative", evidence_session_ids=[])
            )

        offer_kind = offer["kind"]
        offer_stmt = _norm_stmt(offer["statement"])
        _validate_memory_statement(offer_stmt)

        dup = db.execute(
            text(
                """
                SELECT 1
                FROM memories
                WHERE user_id = :uid
                  AND active = true
                  AND kind = :kind
                  AND statement = :statement
                LIMIT 1
                """
            ),
            {"uid": str(user_id), "kind": offer_kind, "statement": offer_stmt},
        ).fetchone()

        if dup:
            return MemoryOfferResponse(
                offer=CreateMemoryRequest(kind=DEFAULT_KIND, statement=DEFAULT_STATEMENT_DUP, confidence="tentative", evidence_session_ids=[])
            )

        return MemoryOfferResponse(
            offer=CreateMemoryRequest(
                kind=offer_kind,
                statement=offer_stmt,
                confidence=offer["confidence"],
                evidence_session_ids=offer["evidence_session_ids"],
            )
        )


@app.post("/v1/users/{user_id}/memories", response_model=MemoryItem)
def create_memory(user_id: uuid.UUID, payload: CreateMemoryRequest):
    stmt = _norm_stmt(payload.statement)
    _validate_memory_statement(stmt)

    if payload.kind == "negative_space":
        raise HTTPException(status_code=400, detail="negative_space is an offer fallback and cannot be saved as a memory")

    kind_allowed = {"recurring_tension", "unexpressed_axis", "values_vs_emphasis", "decision_posture", "negative_space"}
    if payload.kind not in kind_allowed:
        raise HTTPException(status_code=400, detail="Invalid memory kind")

    conf_allowed = {"tentative", "emerging", "consistent"}
    if payload.confidence not in conf_allowed:
        raise HTTPException(status_code=400, detail="Invalid confidence")

    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)

        count_row = db.execute(text("SELECT COUNT(*) FROM memories WHERE user_id = :uid AND active = true"), {"uid": str(user_id)}).fetchone()
        if count_row and int(count_row[0]) >= 5:
            raise HTTPException(status_code=400, detail="Max active memories reached (5)")

        mem_id = uuid.uuid4()
        evidence_json = [str(x) for x in (payload.evidence_session_ids or [])]
        evidence_str = json.dumps(evidence_json)

        row = db.execute(
            text(
                """
                INSERT INTO memories (
                    id, user_id, kind, statement,
                    evidence_session_ids, confidence, active
                )
                VALUES (
                    :id, :uid, :kind, :statement,
                    CAST(:evidence AS jsonb),
                    :confidence, true
                )
                RETURNING id, kind, statement, confidence, active, evidence_session_ids, created_at
                """
            ),
            {"id": str(mem_id), "uid": str(user_id), "kind": payload.kind, "statement": stmt, "evidence": evidence_str, "confidence": payload.confidence},
        ).fetchone()

        db.commit()

    evidence_uuids: List[uuid.UUID] = []
    for x in (row[5] or []):
        try:
            evidence_uuids.append(uuid.UUID(str(x)))
        except Exception:
            pass

    return MemoryItem(
        id=uuid.UUID(str(row[0])),
        kind=row[1],
        statement=row[2],
        confidence=row[3],
        active=bool(row[4]),
        evidence_session_ids=evidence_uuids,
        created_at=row[6].isoformat() if row[6] else "",
    )


@app.post("/v1/users/{user_id}/memories/{memory_id}/archive")
def archive_memory(user_id: uuid.UUID, memory_id: uuid.UUID):
    with SessionLocal() as db:
        _ensure_user_exists(db, user_id)
        row = db.execute(
            text(
                """
                UPDATE memories
                SET active = false, updated_at = NOW()
                WHERE id = :mid AND user_id = :uid
                RETURNING id
                """
            ),
            {"mid": str(memory_id), "uid": str(user_id)},
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Memory not found")

        db.commit()

    return {"archived": True}

# ===========================
# RUNBOOK — Ops / Debugging
# ===========================
# Quick health:
#   GET  /health
#   GET  /db-check
#
# Admin HTTP SLO view (rolling in-memory):
#   GET  /v1/admin/ops/http-metrics?window_sec=900&limit=50
#   Header: X-ANCHOR-ADMIN-TOKEN: <token>
#   OR     Authorization: Bearer <token>
#
# Admin minimal SLO metrics + boolean check:
#   GET  /v1/admin/ops/metrics?window_sec=900
#   GET  /v1/admin/ops/slo-check?window_sec=900
#
# Admin error-budget / trust-state:
#   GET  /v1/admin/ops/error-budget?window_sec=900
#
# Recommended env:
#   LOG_HMAC_KEY=<long random>
#   TRUSTED_HOSTS="anchor-api-prod.onrender.com"
#
# Sensitive logging policy:
#   - Never log request bodies or Authorization headers.
#   - Only metadata, hashed client identity, and governance decision summary.
