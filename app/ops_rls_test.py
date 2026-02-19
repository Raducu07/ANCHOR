# app/ops_rls_test.py (or put directly in main.py)

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import set_rls_context, clear_rls_context, get_db
from app.auth import require_admin  # adjust to your actual admin dependency

router = APIRouter()

@router.get("/v1/admin/ops/rls-self-test")
def rls_self_test(
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Admin-only: verifies Postgres RLS tenant isolation for clinic-scoped tables.

    Assumptions:
      - You are connected as non-owner runtime role (anchor_app), so RLS applies.
      - RLS policies exist on clinic_users (and/or another clinic-scoped table).
    """

    # Use clinic_users as the canary table because it's clinic-scoped + has RLS.
    # We'll create two clinics + one user each, then verify cross-visibility is zero.
    clinic_a = uuid.uuid4()
    clinic_b = uuid.uuid4()
    user_a = uuid.uuid4()
    user_b = uuid.uuid4()

    email_a = f"rls_a_{uuid.uuid4().hex[:8]}@example.test"
    email_b = f"rls_b_{uuid.uuid4().hex[:8]}@example.test"

    try:
        # Create two clinics (must be insertable by anchor_app)
        db.execute(
            text(
                """
                INSERT INTO clinics (clinic_id, clinic_name, clinic_slug, subscription_tier, active_status)
                VALUES (:cid, :name, :slug, 'starter', true)
                """
            ),
            {"cid": str(clinic_a), "name": "RLS Clinic A", "slug": f"rls-a-{uuid.uuid4().hex[:10]}"},
        )
        db.execute(
            text(
                """
                INSERT INTO clinics (clinic_id, clinic_name, clinic_slug, subscription_tier, active_status)
                VALUES (:cid, :name, :slug, 'starter', true)
                """
            ),
            {"cid": str(clinic_b), "name": "RLS Clinic B", "slug": f"rls-b-{uuid.uuid4().hex[:10]}"},
        )
        db.commit()

        # Insert one clinic_user under each clinic by setting RLS context
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
        db.commit()
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
        clear_rls_context(db)

        # Now verify visibility:
        # As clinic A context: should see A user, not B user
        set_rls_context(db, clinic_id=str(clinic_a), user_id=str(user_a))
        a_sees_a = db.execute(
            text("SELECT count(*) FROM clinic_users WHERE email = :email"),
            {"email": email_a},
        ).scalar_one()
        a_sees_b = db.execute(
            text("SELECT count(*) FROM clinic_users WHERE email = :email"),
            {"email": email_b},
        ).scalar_one()
        clear_rls_context(db)

        # As clinic B context: should see B user, not A user
        set_rls_context(db, clinic_id=str(clinic_b), user_id=str(user_b))
        b_sees_b = db.execute(
            text("SELECT count(*) FROM clinic_users WHERE email = :email"),
            {"email": email_b},
        ).scalar_one()
        b_sees_a = db.execute(
            text("SELECT count(*) FROM clinic_users WHERE email = :email"),
            {"email": email_a},
        ).scalar_one()
        clear_rls_context(db)

        passed = (a_sees_a == 1 and a_sees_b == 0 and b_sees_b == 1 and b_sees_a == 0)

        return {
            "status": "ok",
            "passed": bool(passed),
            "now_utc": datetime.now(timezone.utc).isoformat(),
            "checks": {
                "clinic_a_sees_own_user": int(a_sees_a),
                "clinic_a_sees_other_user": int(a_sees_b),
                "clinic_b_sees_own_user": int(b_sees_b),
                "clinic_b_sees_other_user": int(b_sees_a),
            },
            "note": "If passed=false and you are still table owner, RLS is bypassed. Ensure runtime role is non-owner.",
        }

    finally:
        # Best-effort cleanup (don’t fail the endpoint if cleanup fails)
        try:
            clear_rls_context(db)
        except Exception:
            pass
        try:
            # Delete in dependency order
            db.execute(text("DELETE FROM clinic_users WHERE user_id IN (:a, :b)"), {"a": str(user_a), "b": str(user_b)})
            db.execute(text("DELETE FROM clinics WHERE clinic_id IN (:a, :b)"), {"a": str(clinic_a), "b": str(clinic_b)})
            db.commit()
        except Exception:
            db.rollback()
