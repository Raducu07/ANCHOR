# app/db.py
import os
import uuid
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
# RLS Context Helpers (pool-safe)
# ============================================================


def reset_session_state(db: Session) -> None:
    """
    Defensive reset of any session-level state on pooled connections.
    Prefer running inside an open transaction (your get_db begins one).
    """
    db.execute(text("RESET ALL"))


def _uuid_str(value: str) -> str:
    """
    Validate UUID and return canonical string.
    """
    return str(uuid.UUID(str(value)))


def _set_local_text(db: Session, setting_name: str, value: str) -> None:
    """
    Postgres rejects bind params in SET LOCAL (e.g., $1 / :cid).
    We inject a safely-escaped literal.
    """
    v = (value or "").replace("'", "''")
    db.execute(text(f"SET LOCAL {setting_name} = '{v}'"))


def set_rls_context(
    db: Session,
    *,
    clinic_id: str,
    clinic_user_id: Optional[str] = None,
    user_id: Optional[str] = None,  # ✅ alias for old call sites
    role: Optional[str] = None,
) -> None:
    """
    Sets tenant context for FORCE RLS using transaction-scoped SET LOCAL.

    IMPORTANT:
      - GUC settings (SET LOCAL app.*) store TEXT values.
      - Do NOT append ::uuid here (can fail on some Postgres parsers for SET).
      - Cast in RLS policies where needed, e.g.:
          (current_setting('app.clinic_id', true))::uuid

    For backward-compat, we also set app.user_id = clinic_user_id.
    """
    if not clinic_user_id and user_id:
        clinic_user_id = user_id
    if not clinic_user_id:
        raise ValueError("clinic_user_id is required")

    reset_session_state(db)

    cid = _uuid_str(clinic_id)
    cuid = _uuid_str(clinic_user_id)

    # ✅ store as plain text
    _set_local_text(db, "app.clinic_id", cid)
    _set_local_text(db, "app.clinic_user_id", cuid)

    # Back-compat for older policies/codepaths that used app.user_id
    _set_local_text(db, "app.user_id", cuid)

    # Optional role dimension
    _set_local_text(db, "app.role", str(role or ""))


def clear_rls_context(db: Session) -> None:
    """
    Not strictly necessary if you always use SET LOCAL,
    but kept as a safety net for any non-transactional misuse.
    """
    try:
        db.execute(text("RESET ALL"))
    except Exception:
        pass


def _apply_rls_from_request(db: Session, request: Request) -> None:
    """
    Applies RLS context using request.state values.

    Expects:
      request.state.clinic_id
      request.state.clinic_user_id
      request.state.role (optional)

    These MUST be set by clinic auth dependency/middleware.
    """
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    role = getattr(request.state, "role", None)

    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing_clinic_context")

    set_rls_context(
        db,
        clinic_id=str(clinic_id),
        clinic_user_id=str(clinic_user_id),
        role=(str(role) if role else None),
    )


# ============================================================
# Primary FastAPI dependency (request-scoped session + RLS)
# ============================================================


def get_db(request: Request) -> Generator[Session, None, None]:
    """
    Request-scoped DB session WITH automatic RLS context.

    Critical properties:
      - opens a transaction before setting context
      - RESET ALL + SET LOCAL to prevent pooled-connection leakage
      - commit/rollback ends the SET LOCAL scope automatically
    """
    db = SessionLocal()
    try:
        # Ensure we are in a transaction before SET LOCAL
        db.begin()
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
      - platform admin endpoints
      - bootstrap flows
      - background jobs

    If FORCE RLS is enabled and you need to operate under a tenant:
      - start transaction (db.begin())
      - call set_rls_context(...)
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
