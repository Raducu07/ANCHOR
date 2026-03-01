# app/ops_rls_test.py
from __future__ import annotations

import os
import hmac
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

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
# Debug helpers (metadata-only)
# ---------------------------
def _rls_flags(db: Session, table: str) -> Dict[str, Optional[bool]]:
    row = db.execute(
        text(
            """
            SELECT c.relrowsecurity, c.relforcerowsecurity
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname='public' AND c.relname=:t
            """
        ),
        {"t": table},
    ).fetchone()
    if not row:
        return {"relrowsecurity": None, "relforcerowsecurity": None}
    return {"relrowsecurity": bool(row[0]), "relforcerowsecurity": bool(row[1])}


def _policies(db: Session, table: str) -> List[Dict[str, Any]]:
    rows = db.execute(
        text(
            """
            SELECT policyname, permissive, roles, cmd, qual, with_check
            FROM pg_policies
            WHERE schemaname='public' AND tablename=:t
            ORDER BY policyname
            """
        ),
        {"t": table},
    ).fetchall()

    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "name": r[0],
                "permissive": r[1],
                "roles": r[2],
                "cmd": r[3],
                "using": r[4],
                "with_check": r[5],
            }
        )
    return out


def _current_setting(db: Session, key: str) -> Optional[str]:
    try:
        return db.execute(text("SELECT current_setting(:k, true)"), {"k": key}).scalar()
    except Exception:
        return None


def _role_props(db: Session) -> Dict[str, Optional[bool]]:
    """
    Metadata: do we bypass RLS / are we superuser?
    """
    try:
        row = db.execute(
            text(
                """
                SELECT rolbypassrls, rolsuper
                FROM pg_roles
                WHERE rolname = current_user
                """
            )
        ).fetchone()
        if not row:
            return {"rolbypassrls": None, "rolsuper": None}
        return {"rolbypassrls": bool(row[0]), "rolsuper": bool(row[1])}
    except Exception:
        return {"rolbypassrls": None, "rolsuper": None}


# ---------------------------
# RLS self-test endpoint
# ---------------------------
@router.get("/rls-self-test")
def rls_self_test(_: None = Depends(require_admin)) -> Dict[str, Any]:
    """
    Admin-only: verifies Postgres RLS tenant isolation using clinics + clinic_users.

    This endpoint returns debug metadata to diagnose:
      - DB role bypassing RLS
      - RLS enabled/forced flags per table
      - active policies + their predicates
      - whether your app.* GUCs are being set as expected
      - session row_security
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
        # ---------------------------
        # Debug snapshot (metadata only)
        # ---------------------------
        debug: Dict[str, Any] = {}

        # who am I?
        try:
            debug["current_user"] = db.execute(text("SELECT current_user")).scalar()
            debug["session_user"] = db.execute(text("SELECT session_user")).scalar()
            debug["current_role"] = db.execute(text("SELECT current_role")).scalar()
        except Exception:
            debug["current_user"] = None
            debug["session_user"] = None
            debug["current_role"] = None

        # role properties
        debug.update(_role_props(db))

        # session settings of interest
        debug["row_security"] = _current_setting(db, "row_security")
        debug["transaction_isolation"] = _current_setting(db, "transaction_isolation")
        debug["search_path"] = _current_setting(db, "search_path")

        # RLS flags + policies
        debug["rls_governance_events"] = _rls_flags(db, "governance_events")
        debug["rls_ops_metrics_events"] = _rls_flags(db, "ops_metrics_events")
        debug["rls_clinic_policies"] = _rls_flags(db, "clinic_policies")
        debug["rls_clinic_policy_state"] = _rls_flags(db, "clinic_policy_state")
        debug["rls_clinic_privacy_profile"] = _rls_flags(db, "clinic_privacy_profile")
        debug["rls_admin_audit_events"] = _rls_flags(db, "admin_audit_events")
        debug["policies_clinics"] = _policies(db, "clinics")
        debug["policies_clinic_users"] = _policies(db, "clinic_users")

        # Confirm what set_rls_context actually sets (GUCs)
        try:
            clear_rls_context(db)
            set_rls_context(db, clinic_id=str(clinic_a), user_id=str(user_a))

            # primary expected keys
            debug["guc_app_clinic_id"] = _current_setting(db, "app.clinic_id")
            debug["guc_app_user_id"] = _current_setting(db, "app.user_id")

            # common alternate keys (in case policies reference different names)
            debug["guc_app_tenant_id"] = _current_setting(db, "app.tenant_id")
            debug["guc_app_clinic_uuid"] = _current_setting(db, "app.clinic_uuid")
            debug["guc_app_tenant_uuid"] = _current_setting(db, "app.tenant_uuid")
        finally:
            try:
                clear_rls_context(db)
            except Exception:
                pass

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

            a_sees_a = (
                db.execute(text("SELECT COUNT(*) FROM clinics WHERE clinic_id = :cid"), {"cid": str(clinic_a)}).scalar()
                or 0
            )
            a_sees_b = (
                db.execute(text("SELECT COUNT(*) FROM clinics WHERE clinic_id = :cid"), {"cid": str(clinic_b)}).scalar()
                or 0
            )
            a_sees_user_a = (
                db.execute(text("SELECT COUNT(*) FROM clinic_users WHERE user_id = :uid"), {"uid": str(user_a)}).scalar()
                or 0
            )
            a_sees_user_b = (
                db.execute(text("SELECT COUNT(*) FROM clinic_users WHERE user_id = :uid"), {"uid": str(user_b)}).scalar()
                or 0
            )

            checks["a_sees_a"] = int(a_sees_a)
            checks["a_sees_b"] = int(a_sees_b)
            checks["a_sees_user_a"] = int(a_sees_user_a)
            checks["a_sees_user_b"] = int(a_sees_user_b)

            # 6) Verify visibility from clinic B context
            clear_rls_context(db)
            set_rls_context(db, clinic_id=str(clinic_b), user_id=str(user_b))

            b_sees_b = (
                db.execute(text("SELECT COUNT(*) FROM clinics WHERE clinic_id = :cid"), {"cid": str(clinic_b)}).scalar()
                or 0
            )
            b_sees_a = (
                db.execute(text("SELECT COUNT(*) FROM clinics WHERE clinic_id = :cid"), {"cid": str(clinic_a)}).scalar()
                or 0
            )
            b_sees_user_b = (
                db.execute(text("SELECT COUNT(*) FROM clinic_users WHERE user_id = :uid"), {"uid": str(user_b)}).scalar()
                or 0
            )
            b_sees_user_a = (
                db.execute(text("SELECT COUNT(*) FROM clinic_users WHERE user_id = :uid"), {"uid": str(user_a)}).scalar()
                or 0
            )

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
                "debug": debug,
                "note": "Self-test sets app.* GUCs; debug shows RLS flags/policies and whether the DB role bypasses RLS.",
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
