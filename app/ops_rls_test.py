# app/ops_rls_test.py
from __future__ import annotations

import os
import hmac
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

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
    """
    token = (os.getenv("ADMIN_BEARER_TOKEN") or "").strip()
    if not token:
        raise HTTPException(status_code=500, detail="ADMIN_BEARER_TOKEN is not set")

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing_bearer_token")

    provided = authorization.split(" ", 1)[1].strip()
    if not hmac.compare_digest(provided, token):
        raise HTTPException(status_code=403, detail="forbidden")


# ---------------------------
# RLS self-test endpoint
# ---------------------------
@router.get("/rls-self-test")
def rls_self_test(_: None = Depends(require_admin)) -> Dict[str, Any]:
    """
    Admin-only: verifies Postgres RLS tenant isolation using clinics + clinic_users.

    IMPORTANT:
    - Does NOT rely on clinic JWT/context.
    - Explicitly sets app.clinic_id/app.user_id via set_rls_context before each operation.
    """

    clinic_a = uuid.uuid4()
    clinic_b = uuid.uuid4()
    user_a = uuid.uuid4()
    user_b = uuid.uuid4()

    slug_a = f"rls-a-{uuid.uuid4().hex[:10]}"
    slug_b = f"rls-b-{uuid.uuid4().hex[:10]}"
    email_a = f"rls_a_{uuid.uuid4().hex[:10]}@example.test"
    email_b = f"rls_b_{uuid.uuid4().hex[:10]}@example.test"

    now_utc = datetime.now(timezone.utc).isoformat()

    checks: Dict[str, Any] = {}

    with SessionLocal() as db:
        try:
            # 1) Create clinic A under clinic A context
            clear_rls_context(db)
            set_rls_context(db, clinic_id=str(clinic_a), user_id=str(user_a))
            db.execute(
                text(
                    """
                    INSERT INTO clinics (clinic_id, clinic_name, clinic_slug, subscription_tier, active_status)
                    VALUES (:cid, :name, :slug, 'starter', true)
                    """
                ),
                {"cid": str(clinic_a), "name": "RLS Clinic A", "slug": slug_a},
            )

            # 2) Create clinic B under clinic B context
            clear_rls_context(db)
            set_rls_context(db, clinic_id=str(clinic_b), user_id=str(user_b))
            db.execute(
                text(
                    """
                    INSERT INTO clinics (clinic_id, clinic_name, clinic_slug, subscription_tier, active_status)
                    VALUES (:cid, :name, :slug, 'starter', true)
                    """
                ),
                {"cid": str(clinic_b), "name": "RLS Clinic B", "slug": slug_b},
            )

            # 3) Create clinic user A (under clinic A)
            clear_rls_context(db)
            set_rls_context(db, clinic_id=str(clinic_a), user_id=str(user_a))
            db.execute(
                text(
                    """
                    INSERT INTO clinic_users (user_id, clinic_id, role, email, password_hash, active_status)
                    VALUES (:uid, :cid, 'admin', :email, 'x', true)
                    """
                ),
                {"uid": str(user_a), "cid": str(clinic_a), "email": email_a},
            )

            # 4) Create clinic user B (under clinic B)
            clear_rls_context(db)
            set_rls_context(db, clinic_id=str(clinic_b), user_id=str(user_b))
            db.execute(
                text(
                    """
                    INSERT INTO clinic_users (user_id, clinic_id, role, email, password_hash, active_status)
                    VALUES (:uid, :cid, 'admin', :email, 'x', true)
                    """
                ),
                {"uid": str(user_b), "cid": str(clinic_b), "email": email_b},
            )

            db.commit()

            # 5) Verify visibility from clinic A context
            clear_rls_context(db)
            set_rls_context(db, clinic_id=str(clinic_a), user_id=str(user_a))

            a_sees_a = (db.execute(text("SELECT COUNT(*) FROM clinics WHERE clinic_id = :cid"), {"cid": str(clinic_a)}).scalar() or 0)
            a_sees_b = (db.execute(text("SELECT COUNT(*) FROM clinics WHERE clinic_id = :cid"), {"cid": str(clinic_b)}).scalar() or 0)
            a_sees_user_a = (db.execute(text("SELECT COUNT(*) FROM clinic_users WHERE user_id = :uid"), {"uid": str(user_a)}).scalar() or 0)
            a_sees_user_b = (db.execute(text("SELECT COUNT(*) FROM clinic_users WHERE user_id = :uid"), {"uid": str(user_b)}).scalar() or 0)

            checks["a_sees_a"] = int(a_sees_a)
            checks["a_sees_b"] = int(a_sees_b)
            checks["a_sees_user_a"] = int(a_sees_user_a)
            checks["a_sees_user_b"] = int(a_sees_user_b)

            # 6) Verify visibility from clinic B context
            clear_rls_context(db)
            set_rls_context(db, clinic_id=str(clinic_b), user_id=str(user_b))

            b_sees_b = (db.execute(text("SELECT COUNT(*) FROM clinics WHERE clinic_id = :cid"), {"cid": str(clinic_b)}).scalar() or 0)
            b_sees_a = (db.execute(text("SELECT COUNT(*) FROM clinics WHERE clinic_id = :cid"), {"cid": str(clinic_a)}).scalar() or 0)
            b_sees_user_b = (db.execute(text("SELECT COUNT(*) FROM clinic_users WHERE user_id = :uid"), {"uid": str(user_b)}).scalar() or 0)
            b_sees_user_a = (db.execute(text("SELECT COUNT(*) FROM clinic_users WHERE user_id = :uid"), {"uid": str(user_a)}).scalar() or 0)

            checks["b_sees_b"] = int(b_sees_b)
            checks["b_sees_a"] = int(b_sees_a)
            checks["b_sees_user_b"] = int(b_sees_user_b)
            checks["b_sees_user_a"] = int(b_sees_user_a)

            clear_rls_context(db)

            ok = (
                checks["a_sees_a"] >= 1
                and checks["a_sees_b"] == 0
                and checks["a_sees_user_a"] >= 1
                and checks["a_sees_user_b"] == 0
                and checks["b_sees_b"] >= 1
                and checks["b_sees_a"] == 0
                and checks["b_sees_user_b"] >= 1
                and checks["b_sees_user_a"] == 0
            )

            return {
                "status": "ok" if ok else "fail",
                "now_utc": now_utc,
                "checks": checks,
                "note": "FORCE RLS is enabled; this test sets app.clinic_id/app.user_id before inserts and reads.",
            }

        finally:
            # Best-effort cleanup (admin route; safe to attempt)
            try:
                clear_rls_context(db)
                set_rls_context(db, clinic_id=str(clinic_a), user_id=str(user_a))
                db.execute(text("DELETE FROM clinic_users WHERE user_id = :uid"), {"uid": str(user_a)})
                db.execute(text("DELETE FROM clinics WHERE clinic_id = :cid"), {"cid": str(clinic_a)})
                db.commit()
            except Exception:
                db.rollback()

            try:
                clear_rls_context(db)
                set_rls_context(db, clinic_id=str(clinic_b), user_id=str(user_b))
                db.execute(text("DELETE FROM clinic_users WHERE user_id = :uid"), {"uid": str(user_b)})
                db.execute(text("DELETE FROM clinics WHERE clinic_id = :cid"), {"cid": str(clinic_b)})
                db.commit()
            except Exception:
                db.rollback()

            try:
                clear_rls_context(db)
            except Exception:
                pass
