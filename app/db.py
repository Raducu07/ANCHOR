# app/db.py
import os
from typing import Generator, Optional

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
#
# GUCs used by your RLS policies:
#   current_setting('app.clinic_id', true)
#   current_setting('app.user_id', true)
#
# IMPORTANT:
# - Use session-level set_config(..., false) so pooled connections
#   keep the correct tenant for the lifetime of the connection.
# - Always CLEAR on teardown to prevent tenant leakage via pooling.
# ============================================================

_SET_GUC_SQL = text("SELECT set_config(:k, :v, false)")

def _set_guc(db: Session, key: str, value: str) -> None:
    # value must be text; use "" as a cleared state
    db.execute(_SET_GUC_SQL, {"k": key, "v": value})


def set_rls_context(db: Session, clinic_id: Optional[str] = None, user_id: Optional[str] = None) -> None:
    """
    Apply tenant/user scoping to the CURRENT DB connection (session GUCs).
    Call this at the START of every request.
    """
    if clinic_id is not None:
        _set_guc(db, "app.clinic_id", str(clinic_id))
    if user_id is not None:
        _set_guc(db, "app.user_id", str(user_id))


def clear_rls_context(db: Session) -> None:
    """
    Clear context so pooled connections never “leak” tenant identity.
    """
    _set_guc(db, "app.clinic_id", "")
    _set_guc(db, "app.user_id", "")


def _apply_rls_from_request(db: Session, request: Optional[Request]) -> None:
    """
    If your auth middleware decodes a clinic JWT and sets:
      request.state.clinic_id
      request.state.clinic_user_id

    then apply them so all queries are RLS-scoped for this request.
    """
    if request is None:
        return

    clinic_id = getattr(request.state, "clinic_id", None)
    user_id = getattr(request.state, "clinic_user_id", None)

    # ✅ Apply clinic_id whenever present (even if user_id is missing)
    if clinic_id is not None:
        set_rls_context(db, clinic_id=str(clinic_id))

    # ✅ Apply user_id when present (optional)
    if user_id is not None:
        set_rls_context(db, user_id=str(user_id))


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
        # Forces a connection early and sets per-connection GUCs for RLS
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
