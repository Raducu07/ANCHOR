# app/ops_rls_test.py
import os
import hmac
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db, set_rls_context, clear_rls_context

router = APIRouter()

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
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    provided = authorization.split(" ", 1)[1].strip()
    if not hmac.compare_digest(provided, token):
        raise HTTPException(status_code=403, detail="Forbidden")


# ---------------------------
# RLS self-test endpoint
# ---------------------------

@router.get("/v1/admin/ops/rls-self-test")
def rls_self_test(
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Admin-only: verifies Postgres RLS tenant isolation for clinic-scoped tables.

    IMPORTANT:
    - Now that you've enabled FORCE RLS, inserts MUST set app.clinic_id/app.user_id.
    - This test sets the GUC before each insert/select and clears it afterwards.
    """

    clinic_a = uuid.uuid4()
    clinic_b = uuid.uuid4()
    user_a = uuid.uuid4()
    user_b = uuid.uuid4()

    slug_a = f"rls-a-{uuid.uuid4().hex[:10]}"
    slug_b = f"rls-b-{uuid.uuid4().hex[:10]}"
    email_a = f"rls_a_{uuid.uuid4().hex[:10]}@example.test"
    email_b = f"rls_b_{uuid.uuid4().hex[:10]}@example.test"

    checks = {}
    now_utc = datetime.now(timezone.utc).isoformat()

    try:
        # ------------------------------------------------------------
        # 1) Create clinic A under clinic A context
        # ------------------------------------------------------------
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
        db.commit()
        clear_rls_context(db)

        # ------------------------------------------------------------
        # 2) Create clinic B under clinic B context
        # ------------------------------------------------------------
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
        db.commit()
        clear_rls_context(db)

        # ------------------------------------------------------------
        # 3) Insert one clinic_user under each clinic (RLS WITH CHECK)
        # ------------------------------------------------------------
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

        # ------------------------------------------------------------
        # 4) Verify cross-visibility
        # ------------------------------------------------------------
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

        checks = {
            "clinic_a_sees_own_user": int(a_sees_a),
            "clinic_a_sees_other_user": int(a_sees_b),
            "clinic_b_sees_own_user": int(b_sees_b),
            "clinic_b_sees_other_user": int(b_sees_a),
        }
        passed = (a_sees_a == 1 and a_sees_b == 0 and b_sees_b == 1 and b_sees_a == 0)

        return {
            "status": "ok",
            "passed": bool(passed),
            "now_utc": now_utc,
            "checks": checks,
            "note": "FORCE RLS is enabled; this test sets app.clinic_id/app.user_id before inserts and reads.",
        }

    except Exception as e:
        db.rollback()
        # Return readable error instead of raw 500
        raise HTTPException(status_code=500, detail=f"rls-self-test failed: {type(e).__name__}: {e}")

    finally:
        # Best-effort cleanup
        try:
            clear_rls_context(db)
        except Exception:
            pass

        try:
            # cleanup must be done under the right tenant context; delete users first
            set_rls_context(db, clinic_id=str(clinic_a), user_id=str(user_a))
            db.execute(text("DELETE FROM clinic_users WHERE user_id = :uid"), {"uid": str(user_a)})
            db.execute(text("DELETE FROM clinics WHERE clinic_id = :cid"), {"cid": str(clinic_a)})
            db.commit()
            clear_rls_context(db)

            set_rls_context(db, clinic_id=str(clinic_b), user_id=str(user_b))
            db.execute(text("DELETE FROM clinic_users WHERE user_id = :uid"), {"uid": str(user_b)})
            db.execute(text("DELETE FROM clinics WHERE clinic_id = :cid"), {"cid": str(clinic_b)})
            db.commit()
            clear_rls_context(db)
        except Exception:
            db.rollback()
            try:
                clear_rls_context(db)
            except Exception:
                pass
