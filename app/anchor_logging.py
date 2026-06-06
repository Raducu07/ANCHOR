from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

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


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_app_env() -> str:
    return (os.getenv("APP_ENV") or os.getenv("ENV") or "dev").strip().lower() or "dev"


def get_service_name() -> str:
    return (os.getenv("SERVICE_NAME") or os.getenv("APP_NAME") or "anchor").strip() or "anchor"


def get_app_version() -> Optional[str]:
    v = (os.getenv("APP_VERSION") or os.getenv("GIT_SHA") or os.getenv("BUILD_ID") or "").strip()
    return v or None


# Default hash-salt fallback literal. Acceptable for local/dev/test runs;
# rejected at startup when APP_ENV=prod (see assert_hash_salt_for_prod).
DEFAULT_HASH_SALT_LITERAL = "anchor-default-salt"


def get_hash_salt() -> str:
    return (
        os.getenv("ANCHOR_HASH_SALT")
        or os.getenv("ANCHOR_LOG_SALT")
        or DEFAULT_HASH_SALT_LITERAL
    ).strip()


def assert_hash_salt_for_prod() -> None:
    """Fail-closed in production if ANCHOR_HASH_SALT / ANCHOR_LOG_SALT are
    missing or still equal to the default fallback literal.

    No-op outside production. Called from the FastAPI lifespan at startup
    so a misconfigured prod deploy aborts before serving requests."""
    if get_app_env() != "prod":
        return
    raw_primary = (os.getenv("ANCHOR_HASH_SALT") or "").strip()
    raw_fallback = (os.getenv("ANCHOR_LOG_SALT") or "").strip()
    resolved = (raw_primary or raw_fallback).strip()
    if not resolved:
        raise RuntimeError(
            "ANCHOR_HASH_SALT (or ANCHOR_LOG_SALT) must be set when APP_ENV=prod; "
            "default fallback is not permitted in production."
        )
    if resolved == DEFAULT_HASH_SALT_LITERAL:
        raise RuntimeError(
            "ANCHOR_HASH_SALT must not equal the default fallback literal "
            "when APP_ENV=prod."
        )


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def hash_with_salt(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    salt = get_hash_salt()
    return sha256_hex(f"{salt}:{value}")


def log_event(level: int, event: str, **fields: Any) -> None:
    payload: Dict[str, Any] = {
        "ts_utc": utc_iso(),
        "service": get_service_name(),
        "env": get_app_env(),
        "version": get_app_version(),
        "event": event,
        **fields,
    }
    try:
        logger.log(level, _json_dumps(payload))
    except Exception:
        pass


def ensure_logging_configured() -> None:
    if logger.handlers:
        return

    level = _coerce_log_level(os.getenv("LOG_LEVEL", "INFO"))
    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)
