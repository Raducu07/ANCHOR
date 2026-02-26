# app/db.py
import os
from typing import Generator

from fastapi import HTTPException, Request
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker


# ============================================================
# Database URL (Render-friendly) + engine/session
# ============================================================

def _normalize_database_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise RuntimeError("DATABASE_URL is not set")

    # Render sometimes provides postgres://
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)

    # Prefer psycopg v3 if available
    try:
        import psycopg  # noqa: F401
        if url.startswith("postgresql://") and not url.startswith("postgresql+psycopg://"):
            url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    except Exception:
        # psycopg v3 not installed — leave scheme unchanged
        pass

    return url


DATABASE_URL = _normalize_database_url(os.getenv("DATABASE_URL", ""))

ENGINE = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
    max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),
)

SessionLocal = sessionmaker(bind=ENGINE, autocommit=False, autoflush=False)


# ============================================================
# Health check
# ============================================================

def db_ping() -> bool:
    with ENGINE.connect() as conn:
        conn.execute(text("SELECT 1"))
    return True


# ============================================================
# RLS Context Helpers
# ============================================================

# Endpoints that must be able to open a DB session BEFORE clinic context exists.
# These handlers are responsible for setting SET LOCAL app.clinic_id/app.user_id themselves.
NO_CLINIC_CONTEXT_PATHS = {
    "/v1/admin/bootstrap/clinic",
    "/v1/clinic/auth/login",
    "/v1/clinic/auth/invite/accept",
}


def set_rls_context(db: Session, *, clinic_id: str, user_id: str) -> None:
    """
    Sets tenant context for FORCE RLS using:
      current_setting('app.clinic_id', true)
      current_setting('app.user_id', true)
    """
    db.execute(text("SELECT set_config('app.clinic_id', :cid, true)"), {"cid": str(clinic_id)})
    db.execute(text("SELECT set_config('app.user_id', :uid, true)"), {"uid": str(user_id)})


def clear_rls_context(db: Session) -> None:
    db.execute(text("SELECT set_config('app.clinic_id', '', true)"))
    db.execute(text("SELECT set_config('app.user_id', '', true)"))


def _apply_rls_from_request(db: Session, request: Request) -> None:
    """
    Applies RLS context using request.state values.
    IMPORTANT: Request must NOT be Optional in FastAPI dependencies.
    """
    clinic_id = getattr(request.state, "clinic_id", None)
    user_id = getattr(request.state, "clinic_user_id", None)

    if not clinic_id or not user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    set_rls_context(db, clinic_id=str(clinic_id), user_id=str(user_id))


# ============================================================
# Primary FastAPI dependency (request-scoped session + RLS)
# ============================================================

def get_db(request: Request) -> Generator[Session, None, None]:
    """
    FastAPI dependency.

    Expects request.state.clinic_id and request.state.clinic_user_id
    to be set by auth dependency (require_clinic_user).

    Special-case: some endpoints must open a DB session *without* an incoming
    clinic context (bootstrap/login/invite-accept). Those endpoints MUST set
    RLS context manually (typically using SET LOCAL) before touching tenant tables.
    """
    db = SessionLocal()
    try:
        path = ""
        try:
            path = request.url.path
        except Exception:
            path = ""

        if path in NO_CLINIC_CONTEXT_PATHS:
            # Do NOT enforce clinic context here.
            # Handler will set RLS context manually (or operate on non-tenant tables).
            yield db
            db.commit()
            return

        _apply_rls_from_request(db, request)
        yield db
        db.commit()

    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise
    finally:
        # Always clear any tenant context that might have been set during the request
        try:
            clear_rls_context(db)
        except Exception:
            pass
        db.close()


# ============================================================
# Non-request session helper (cron/admin/bootstrap)
# ============================================================

def db_session() -> Generator[Session, None, None]:
    """
    Use this for background jobs, bootstrap, or admin endpoints
    that manage RLS manually.
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
