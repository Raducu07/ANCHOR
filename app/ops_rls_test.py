# app/ops_rls_test.py
from __future__ import annotations

import os
import hmac
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import SessionLocal, set_rls_context, clear_rls_context

router = APIRouter(prefix="/v1/admin/ops", tags=["admin"])


# ---------------------------
# Admin auth (self-contained)
# ---------------------------
def require_admin(authorization: str = Header(default="")) -> None:
    """
    Admin-only guard using a static bearer token.
    Expected:
      Authorization: Bearer <ADMIN_BEARER_TOKEN>

    Configure:
      ADMIN_BEARER_TOKEN in environment
    """
    token = (os.getenv("ADMIN_BEARER_TOKEN") or "").strip()
    if not token:
        raise HTTPException(status_code=500, detail="ADMIN_BEARER_TOKEN is not set")

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing_bearer_token")

    provided = authorization.split(" ", 1)[1].strip()
    if not hmac.compare_digest(provided, token):
        raise HTTPException(status_code=403, detail="forbidden")


def _try_force_rls_flag(db: Session) -> Optional[bool]:
    """
    Best-effort: checks pg_class.relforcerowsecurity for governance_events.
    Returns None if permissions do not allow inspection.
    """
    try:
        v = db.execute(
            text(
                """
                SELECT c.relforcerowsecurity
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname='public' AND c.relname='governance_events'
                """
            )
        ).scalar()
        if v is None:
            return None
        return bool(v)
    except Exception:
        return None


@router.get("/rls-self-test")
def rls_self_test(_: None = Depends(require_admin)) -> Dict[str, Any]:
    """
    Admin-only: verifies Postgres RLS tenant isolation for clinic-scoped tables.

    This endpoint must NOT depend on clinic-auth DB dependencies.
    It uses a raw SessionLocal and explicitly sets/clears app.clinic_id
    via set_rls_context/clear_rls_context.
    """

    clinic_a = uuid.uuid4()
    clinic_b = uuid.uuid4()
    user_a = uuid.uuid4()
    user_b = uuid.uuid4()

    now_utc = datetime.now(timezone.utc).isoformat()
    checks: Dict[str, Any] = {}

    with SessionLocal() as db:
        force_rls = _try_force_rls_flag(db)

        # ------------------------------------------------------------
        # Insert one governance event under clinic A context
        # ------------------------------------------------------------
        clear_rls_context(db)
        set_rls_context(db, clinic_id=str(clinic_a), user_id=str(user_a))
        db.execute(
            text(
                """
                INSERT INTO governance_events
                  (clinic_id, clinic_user_id, mode, decision, replaced, score, grade, reason, created_at)
                VALUES
                  (:clinic_id, :clinic_user_id, :mode, :decision, :replaced, :score, :grade, :reason, now())
                """
            ),
            {
                "clinic_id": str(clinic_a),
                "clinic_user_id": str(user_a),
                "mode": "witness",
                "decision": "allowed",
                "replaced": False,
                "score": 100,
                "grade": "A",
                "reason": "allowed",
            },
        )

        # ------------------------------------------------------------
        # Insert one governance event under clinic B context
        # ------------------------------------------------------------
        clear_rls_context(db)
        set_rls_context(db, clinic_id=str(clinic_b), user_id=str(user_b))
        db.execute(
            text(
                """
                INSERT INTO governance_events
                  (clinic_id, clinic_user_id, mode, decision, replaced, score, grade, reason, created_at)
                VALUES
                  (:clinic_id, :clinic_user_id, :mode, :decision, :replaced, :score, :grade, :reason, now())
                """
            ),
            {
                "clinic_id": str(clinic_b),
                "clinic_user_id": str(user_b),
                "mode": "witness",
                "decision": "allowed",
                "replaced": False,
                "score": 100,
                "grade": "A",
                "reason": "allowed",
            },
        )

        db.commit()

        # ------------------------------------------------------------
        # Verify: when context is clinic A, clinic B rows are not visible
        # ------------------------------------------------------------
        clear_rls_context(db)
        set_rls_context(db, clinic_id=str(clinic_a), user_id=str(user_a))

        a_count = db.execute(
            text("SELECT COUNT(*) FROM governance_events WHERE clinic_id = :cid"),
            {"cid": str(clinic_a)},
        ).scalar() or 0

        b_visible_from_a = db.execute(
            text("SELECT COUNT(*) FROM governance_events WHERE clinic_id = :cid"),
            {"cid": str(clinic_b)},
        ).scalar() or 0

        # Cleanup
        clear_rls_context(db)

        checks["clinic_a_count"] = int(a_count)
        checks["clinic_b_visible_from_a"] = int(b_visible_from_a)

        ok = (int(a_count) >= 1) and (int(b_visible_from_a) == 0)

    return {
        "status": "ok" if ok else "fail",
        "now_utc": now_utc,
        "forcerls": force_rls,
        "checks": checks,
    }
