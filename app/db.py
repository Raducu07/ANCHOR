# app/db.py
import os
from typing import Generator

from fastapi import Request
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

# ============================================================
# Database URL (Render-friendly) + engine/session
# - Normalizes postgres:// -> postgresql://
# - Forces psycopg v3 driver (postgresql+psycopg://)
# ============================================================

def get_database_url() -> str:
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError("DATABASE_URL is not set")

    # Render sometimes provides postgres://
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)

    # Force SQLAlchemy to use psycopg v3 driver
    if url.startswith("postgresql://") and not url.startswith("postgresql+psycopg://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)

    return url


ENGINE = create_engine(
    get_database_url(),
    pool_pre_ping=True,
    pool_size=int(os.getenv("DB_POOL_SIZE", "5") or "5"),
    max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10") or "10"),
    pool_recycle=int(os.getenv("DB_POOL_RECYCLE_SEC", "1800") or "1800"),
)

SessionLocal = sessionmaker(
    bind=ENGINE,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


# ============================================================
# Basic connectivity check
# ============================================================

def db_ping() -> bool:
    with ENGINE.connect() as conn:
        conn.execute(text("SELECT 1"))
    return True


# ============================================================
# RLS context helpers (Portal multi-tenancy)
# Session GUCs used by your RLS policies:
#   current_setting('app.clinic_id', true)
#   current_setting('app.user_id', true)
#
# IMPORTANT:
# - Use session-level set_config(..., false) so pooled connections
#   never “revert” to a previous tenant after a transaction ends.
# ============================================================

def set_rls_context(db: Session, clinic_id: str, user_id: str) -> None:
    db.execute(
        text("SELECT set_config('app.clinic_id', :cid, false)"),
        {"cid": str(clinic_id)},
    )
    db.execute(
        text("SELECT set_config('app.user_id', :uid, false)"),
        {"uid": str(user_id)},
    )


def clear_rls_context(db: Session) -> None:
    # Clear context so pooled connections never “leak” tenant identity
    db.execute(text("SELECT set_config('app.clinic_id', '', false)"))
    db.execute(text("SELECT set_config('app.user_id',   '', false)"))


def _apply_rls_from_request(db: Session, request: Request) -> None:
    """
    If your auth middleware decodes a clinic JWT and sets:
      request.state.clinic_id
      request.state.clinic_user_id

    then apply them so all queries are RLS-scoped for this request.
    """
    clinic_id = getattr(request.state, "clinic_id", None)
    user_id = getattr(request.state, "clinic_user_id", None)

    if clinic_id and user_id:
        set_rls_context(db, clinic_id=str(clinic_id), user_id=str(user_id))


# ============================================================
# FastAPI dependency: per-request DB session (RLS-aware)
#
# IMPORTANT:
# - This does NOT auto-commit.
# - Endpoints should explicitly commit/rollback.
# ============================================================

def get_db(request: Request) -> Generator[Session, None, None]:
    db: Session = SessionLocal()
    try:
        _apply_rls_from_request(db, request)
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        try:
            clear_rls_context(db)
        except Exception:
            # Never block response teardown on cleanup failures
            pass
        db.close()
