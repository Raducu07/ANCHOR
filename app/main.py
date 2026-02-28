# app/main.py
import os
import hmac
import uuid
import json
import time
import logging
import hashlib
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy import text

from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.db import SessionLocal, db_ping
from app.migrate import run_migrations

from app.http_metrics import HTTP_METRICS

# ---- Portal routers (clinic-scoped) ----
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

# ---- Admin routers (admin-scoped) ----
from app.admin_tokens import router as admin_tokens_router
from app.admin_audit import router as admin_audit_router
from app.admin_ops import router as admin_ops_router

# ============================================================
# Logging — structured, safe-by-default
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


def _truncate(s: str, n: int = 240) -> str:
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
    - In prod: set LOG_HMAC_KEY.
    - If missing: non-breaking fallback, logs a warning once.
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
# Edge middleware config
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
            raise RuntimeError("CORS misconfig: cannot use '*' when CORS_ALLOW_CREDENTIALS=true")

        allow_methods = _parse_csv_env("CORS_ALLOW_METHODS") or ["GET", "POST", "OPTIONS"]
        allow_headers = _parse_csv_env("CORS_ALLOW_HEADERS") or ["Authorization", "Content-Type", "X-Request-ID"]
        try:
            max_age = int((os.getenv("CORS_MAX_AGE", "600") or "600").strip())
        except Exception:
            max_age = 600
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
# Lifespan — migrations
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
    except Exception as e:
        log_event(logging.ERROR, "startup_failed", error_type=type(e).__name__, error=_truncate(str(e)))
        raise

    yield
    log_event(logging.INFO, "shutdown")

# ============================================================
# App
# ============================================================

app = FastAPI(title="ANCHOR API", lifespan=lifespan)
_configure_edge_middlewares(app)

# Routers (single source of truth)
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
app.include_router(admin_ops_router)

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
    return JSONResponse(
        status_code=int(exc.status_code),
        content={"detail": exc.detail, "request_id": req_id},
        headers=headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    req_id = _get_request_id(request)
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "request_id": req_id},
        headers={"X-Request-ID": req_id},
    )

# ============================================================
# Request logging middleware + metrics
# ============================================================

_SKIP_LOG_PATHS = {"/health", "/openapi.json", "/docs"}


def _host(request: Request) -> Optional[str]:
    try:
        return request.headers.get("host")
    except Exception:
        return None


def _route_template_from_scope(request: Request) -> str:
    try:
        rt = request.scope.get("route")
        if rt and getattr(rt, "path", None):
            return str(rt.path)
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

    if request.url.path not in _SKIP_LOG_PATHS:
        log_event(
            logging.INFO,
            "http.request.start",
            request_id=req_id,
            method=request.method,
            route=request.url.path,
            path=request.url.path,
            host=_host(request),
            client_ip_hash=_hmac_sha256_hex(client_ip),
            user_agent_hash=_hmac_sha256_hex(ua),
        )

    try:
        response: Response = await call_next(request)
        dur_ms = int((time.time_ns() - start_ns) / 1_000_000)
        response.headers["X-Request-ID"] = req_id

        route_tmpl = _route_template_from_scope(request)
        HTTP_METRICS.add(start_ns, request.method, route_tmpl, response.status_code, dur_ms)

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
        route_tmpl = _route_template_from_scope(request)

        HTTP_METRICS.add(start_ns, request.method, route_tmpl, 500, dur_ms)

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
# Root/Health/Version + basic DB checks
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
