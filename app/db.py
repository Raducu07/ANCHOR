# app/db.py
import os
from typing import Generator, Optional

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

    # Prefer psycopg v3 if installed
    try:
        import psycopg  # noqa: F401

        if url.startswith("postgresql://") and not url.startswith("postgresql+psycopg://"):
            url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    except Exception:
        # psycopg v3 not installed — leave scheme as-is
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
# RLS Context Helpers
# ============================================================

def set_rls_context(db: Session, *, clinic_id: str, user_id: str) -> None:
    """
    Sets tenant context for FORCE RLS using:
      current_setting('app.clinic_id', true)
      current_setting('app.user_id', true)
    """
    db.execute(text("SELECT set_config('app.clinic_id', :cid, true)"), {"cid": str(clinic_id)})
    db.execute(text("SELECT set_config('app.user_id', :uid, true)"), {"uid": str(user_id)})


def clear_rls_context(db: Session) -> None:
    # Clear to empty string, scoped to current transaction
    db.execute(text("SELECT set_config('app.clinic_id', '', true)"))
    db.execute(text("SELECT set_config('app.user_id', '', true)"))


def _apply_rls_from_request(db: Session, request: Request) -> None:
    """
    Applies RLS context using request.state values.

    Expects:
      request.state.clinic_id
      request.state.clinic_user_id

    These MUST be set by your auth dependency/middleware before get_db runs.
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
    Request-scoped DB session WITH automatic RLS context.

    Use this for clinic-user endpoints where tenant context must be enforced.
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
    DB session WITHOUT automatic RLS context.

    Use this for:
      - admin endpoints
      - bootstrap flows
      - background/cron jobs

    If FORCE RLS is enabled and you need to write tenant rows,
    call set_rls_context(db, clinic_id=..., user_id=...) manually.
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
