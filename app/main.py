# app/main.py
from __future__ import annotations

import json
import logging
import os
import time
import uuid
import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from sqlalchemy import text

from app.db import db_ping, SessionLocal
from app.migrate import run_migrations
from fastapi import HTTPException, Request, Response
from app.rate_limit import enforce_rate_limit

# Routers
from app.auth_and_rls import router as clinic_auth_router
from app.ops_rls_test import router as ops_rls_router
from app.portal_bootstrap import router as portal_bootstrap_router
from app.portal_submit import router as portal_submit_router
from app.portal_read import router as portal_read_router
from app.portal_export import router as portal_export_router
from app.portal_ops import router as portal_ops_router
from app.portal_ops_summary import router as portal_ops_summary_router
from app.portal_ops_timeseries import router as portal_ops_timeseries_router
from app.portal_trust_state import router as portal_trust_state_router
from app.portal_error_budget import router as portal_error_budget_router
from app.portal_ops_health import router as portal_ops_health_router
from app.portal_dashboard import router as portal_dashboard_router
from app.portal_me import router as portal_me_router
from app.portal_assist import router as portal_assist_router

from app.admin_tokens import router as admin_tokens_router
from app.admin_audit import router as admin_audit_router
from app.admin_ops import router as admin_ops_router


# ============================================================
# Structured JSON logging (metadata-only)
# ============================================================

logger = logging.getLogger("anchor")
logger.propagate = False


def _coerce_log_level(value: str) -> int:
    v = (value or "INFO").strip()
    if v.isdigit():
        return int(v)
    lvl = getattr(logging, v.upper(), None)
    return int(lvl) if isinstance(lvl, int) else logging.INFO


def _json_dumps(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_app_env() -> str:
    return (os.getenv("APP_ENV") or os.getenv("ENV") or "dev").strip().lower() or "dev"


def _get_service_name() -> str:
    return (os.getenv("SERVICE_NAME") or os.getenv("APP_NAME") or "anchor").strip() or "anchor"


def _get_app_version() -> Optional[str]:
    v = (os.getenv("APP_VERSION") or os.getenv("GIT_SHA") or os.getenv("BUILD_ID") or "").strip()
    return v or None


def _get_hash_salt() -> str:
    # Used for hashing IP/UA in logs. Not a secret, but should be stable.
    return (os.getenv("ANCHOR_HASH_SALT") or os.getenv("ANCHOR_LOG_SALT") or "anchor-default-salt").strip()


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _hash_with_salt(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    salt = _get_hash_salt()
    return _sha256_hex(f"{salt}:{value}")


def log_event(level: int, event: str, **fields: Any) -> None:
    payload: Dict[str, Any] = {
        "ts_utc": _utc_iso(),
        "service": _get_service_name(),
        "env": get_app_env(),
        "version": _get_app_version(),
        "event": event,
        **fields,
    }
    try:
        logger.log(level, _json_dumps(payload))
    except Exception:
        # Never fail request flow due to logging
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


def _configure_edge_middlewares(app: FastAPI) -> None:
    trusted_hosts = _parse_csv_env("TRUSTED_HOSTS")
    if trusted_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)
        log_event(logging.INFO, "trusted_host_enabled", allowed_hosts=trusted_hosts)
    else:
        log_event(logging.INFO, "trusted_host_disabled")

    allow_origins = _parse_csv_env("CORS_ALLOW_ORIGINS")
    if allow_origins:
        allow_credentials = _env_truthy("CORS_ALLOW_CREDENTIALS", default=False)
        if allow_credentials and any(o == "*" for o in allow_origins):
            raise RuntimeError("CORS misconfig: cannot use '*' in CORS_ALLOW_ORIGINS when CORS_ALLOW_CREDENTIALS=true")

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
        if get_app_env() != "prod":
            # Optional dotenv for local runs
            try:
                from dotenv import load_dotenv  # type: ignore
                load_dotenv()
                log_event(logging.INFO, "dotenv_loaded")
            except Exception:
                log_event(logging.INFO, "dotenv_not_loaded")

        run_migrations()
        log_event(logging.INFO, "startup_migrations_ok")
    except Exception as e:
        log_event(logging.ERROR, "startup_failed", error_type=type(e).__name__, error=str(e)[:240])
        raise

    yield

    log_event(logging.INFO, "shutdown")


# ============================================================
# App
# ============================================================

app = FastAPI(title="ANCHOR API", lifespan=lifespan)
_configure_edge_middlewares(app)

# Routers (clinic portal)
app.include_router(clinic_auth_router)
app.include_router(portal_bootstrap_router)
app.include_router(ops_rls_router)

app.include_router(portal_submit_router)
app.include_router(portal_read_router)
app.include_router(portal_export_router)

app.include_router(portal_ops_router)
app.include_router(portal_ops_summary_router)
app.include_router(portal_ops_timeseries_router)
app.include_router(portal_trust_state_router)
app.include_router(portal_error_budget_router)
app.include_router(portal_ops_health_router)
app.include_router(portal_dashboard_router)
app.include_router(portal_me_router)
app.include_router(portal_assist_router)

# Routers (platform admin)
app.include_router(admin_tokens_router)
app.include_router(admin_audit_router)


# ============================================================
# Exception handlers (include request_id)
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
# Request middleware — request-id + safe logs
# ============================================================

_SKIP_LOG_PATHS = {"/health", "/openapi.json", "/docs", "/redoc"}


def _host(request: Request) -> Optional[str]:
    try:
        return request.headers.get("host")
    except Exception:
        return None


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = req_id

    ip = None
    try:
        ip = request.client.host if request.client else None
    except Exception:
        ip = None

    ua = None
    try:
        ua = (request.headers.get("user-agent") or "")[:512]
    except Exception:
        ua = None

    # Hash once, store on request.state for consistent reuse
    ip_hash = _hash_with_salt(ip)
    ua_hash = _hash_with_salt(ua)
    request.state.ip_hash = ip_hash
    request.state.ua_hash = ua_hash

    start = time.time()
    path = request.url.path

    # ---------------------------
    # M3: rate limiting (metadata-only)
    # Must run BEFORE call_next()
    # ---------------------------
    clinic_user_id = getattr(request.state, "clinic_user_id", None)

    rl_meta = enforce_rate_limit(
        path=path,
        method=request.method,
        clinic_user_id=clinic_user_id,
        ip_hash=ip_hash,
        ip=None,  # avoid raw IP
    )

    # TEMP DEBUG (remove after test)
    if path == "/v1/portal/assist":
        log_event(
            logging.INFO,
            "http.rate_limit.debug",
            request_id=req_id,
            path=path,
            method=request.method,
            client_ip_hash=ip_hash,
            rule=rl_meta.get("rule"),
            rate_limit_applied=rl_meta.get("rate_limit_applied"),
            rate_limited=rl_meta.get("rate_limited"),
            limit=rl_meta.get("limit"),
            window_sec=rl_meta.get("window_sec"),
        )
    
    if rl_meta.get("rate_limited"):
        # Log metadata only (no content)
        log_event(
            logging.WARNING,
            "http.request.rate_limited",
            request_id=req_id,
            method=request.method,
            path=path,
            host=_host(request),
            client_ip_hash=ip_hash,
            user_agent_hash=ua_hash,
            clinic_id=getattr(request.state, "clinic_id", None),
            clinic_user_id=clinic_user_id,
            rule=rl_meta.get("rule"),
            limit=rl_meta.get("limit"),
            window_sec=rl_meta.get("window_sec"),
            retry_after_sec=rl_meta.get("retry_after_sec"),
        )

        retry_after = int(rl_meta.get("retry_after_sec") or 60)
        return JSONResponse(
            status_code=429,
            content={
                "detail": {
                    "error": "rate_limited",
                    "rule": rl_meta.get("rule"),
                    "retry_after_sec": retry_after,
                    "request_id": req_id,
                }
            },
            headers={"X-Request-ID": req_id, "Retry-After": str(retry_after)},
        )

    # ---------------------------
    # Normal request logging
    # ---------------------------
    if path not in _SKIP_LOG_PATHS:
        log_event(
            logging.INFO,
            "http.request.start",
            request_id=req_id,
            method=request.method,
            path=path,
            host=_host(request),
            client_ip_hash=ip_hash,
            user_agent_hash=ua_hash,
        )

    try:
        resp: Response = await call_next(request)
        dur_ms = int((time.time() - start) * 1000)
        resp.headers["X-Request-ID"] = req_id

        if path not in _SKIP_LOG_PATHS:
            log_event(
                logging.INFO,
                "http.request.end",
                request_id=req_id,
                method=request.method,
                path=path,
                host=_host(request),
                status_code=resp.status_code,
                duration_ms=dur_ms,
            )
        return resp

    except Exception as e:
        dur_ms = int((time.time() - start) * 1000)
        log_event(
            logging.ERROR,
            "http.request.unhandled_error",
            request_id=req_id,
            method=request.method,
            path=path,
            host=_host(request),
            client_ip_hash=ip_hash,
            user_agent_hash=ua_hash,
            status_code=500,
            duration_ms=dur_ms,
            error_type=type(e).__name__,
            error=str(e)[:240],
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "internal_server_error", "request_id": req_id},
            headers={"X-Request-ID": req_id},
        )


# ============================================================
# Root/Health/Version/DB checks
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
    # If you no longer have memories in the portal-era schema, feel free to remove this.
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
        "now_utc": _utc_iso(),
    }


@app.get("/")
def root():
    return {"name": "ANCHOR API", "status": "live"}
