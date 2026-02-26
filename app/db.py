# app/db.py
import os
from typing import Generator, Optional

from fastapi import HTTPException, Request
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker


# ============================================================
# Database URL (Render-friendly) + engine/session
# - Normalizes postgres:// -> postgresql://
# - Prefers psycopg v3 driver if installed
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
    pool_size=int(os.getenv("DB_POOL_SIZE", "5") or "5"),
    max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10") or "10"),
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
# RLS Context Helpers (FORCE RLS / multi-tenant)
# ============================================================

def set_rls_context(db: Session, *, clinic_id: str, user_id: str) -> None:
    """
    Sets tenant context for FORCE RLS using:
      current_setting('app.clinic_id', true)
      current_setting('app.user_id', true)

    IMPORTANT: these are session-level settings; always clear them.
    """
    db.execute(text("SELECT set_config('app.clinic_id', :cid, true)"), {"cid": str(clinic_id)})
    db.execute(text("SELECT set_config('app.user_id', :uid, true)"), {"uid": str(user_id)})


def clear_rls_context(db: Session) -> None:
    """
    Clears tenant context for the current DB session.
    Safe to call even if nothing was set.
    """
    db.execute(text("SELECT set_config('app.clinic_id', '', true)"))
    db.execute(text("SELECT set_config('app.user_id', '', true)"))


def _apply_rls_from_request(db: Session, request: Request) -> None:
    """
    Applies RLS context using request.state values set by your auth dependency.
    Expects:
      request.state.clinic_id
      request.state.clinic_user_id
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
    to be set by auth dependency (e.g., require_clinic_user).
    """
    db = SessionLocal()
    try:
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
    Use this for bootstrap, admin endpoints, and background jobs.

    RLS must be managed manually:
      - call set_rls_context(...)
      - do work
      - call clear_rls_context(...)
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
