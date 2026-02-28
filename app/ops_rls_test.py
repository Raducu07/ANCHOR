# app/ops_rls_test.py
from __future__ import annotations

import os
import hmac
import uuid
import json
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

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


# ---------------------------
# Helpers
# ---------------------------
def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _get_columns(db: Session, table: str) -> List[Tuple[str, str, Optional[str]]]:
    """
    Returns list of (column_name, is_nullable, column_default)
    """
    rows = db.execute(
        text(
            """
            SELECT column_name, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_schema='public' AND table_name=:t
            ORDER BY ordinal_position
            """
        ),
        {"t": table},
    ).fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


def _pick_first(existing: set, candidates: List[str]) -> Optional[str]:
    for c in candidates:
        if c in existing:
            return c
    return None


def _insert_governance_event_self_test(
    db: Session,
    table: str,
    tenant_col: str,
    user_col: Optional[str],
    clinic_id: str,
    clinic_user_id: str,
) -> None:
    cols = _get_columns(db, table)
    colset = {c[0] for c in cols}
    required = {c[0] for c in cols if (c[1] == "NO" and c[2] is None)}

    rid = str(uuid.uuid4())
    policy_sha = "0" * 64
    event_sha = _sha256_hex(f"selftest:{rid}:{clinic_id}:{clinic_user_id}")

    # Candidate values (only used if columns exist)
    candidate: Dict[str, Any] = {
        # request id / identifiers
        "request_id": rid,
        tenant_col: clinic_id,
    }

    if user_col:
        candidate[user_col] = clinic_user_id

    # Common governance metadata
    candidate.update(
        {
            "mode": "witness",
            "decision": "allowed",
            "replaced": False,
            "score": 100,
            "grade": "A",
            "reason": "allowed",
            "reason_code": "allowed",
            "policy_sha256": policy_sha,
            "event_sha256": event_sha,
            "rules_fired": json.dumps([]),
            "findings": json.dumps([]),
            "pii_action": "allow",
            "pii_types": json.dumps([]),
            "route": "__self_test__",
            "model": "__self_test__",
        }
    )

    # Keep only columns that exist
    insert_cols = [k for k in candidate.keys() if k in colset]
    params = {k: candidate[k] for k in insert_cols}

    # created_at is usually defaulted; if not, we’ll set it explicitly if it exists.
    if "created_at" in colset and "created_at" not in params:
        insert_cols.append("created_at")
        params["created_at"] = datetime.now(timezone.utc).isoformat()

    # Ensure we satisfy required columns (NOT NULL + no default)
    # Ignore common timestamp columns if present; we already handled created_at above.
    ignore = {"created_at", "updated_at"}
    missing_required = [c for c in required if c not in params and c not in ignore]
    if missing_required:
        raise HTTPException(
            status_code=500,
            detail=f"rls_self_test_schema_missing_required_columns:{','.join(sorted(missing_required))}",
        )

    # Build SQL with JSONB casts where appropriate
    def _val_sql(c: str) -> str:
        if c in ("rules_fired", "findings", "pii_types"):
            return f":{c}::jsonb"
        return f":{c}"

    sql = f"""
    INSERT INTO {table} ({", ".join(insert_cols)})
    VALUES ({", ".join(_val_sql(c) for c in insert_cols)})
    """
    db.execute(text(sql), params)


# ---------------------------
# Endpoint
# ---------------------------
@router.get("/rls-self-test")
def rls_self_test(_: None = Depends(require_admin)) -> Dict[str, Any]:
    """
    Admin-only: verifies tenant isolation on governance_events using FORCE RLS context switching.
    Does NOT depend on clinic JWT/context.
    """

    now_utc = datetime.now(timezone.utc).isoformat()
    clinic_a = str(uuid.uuid4())
    clinic_b = str(uuid.uuid4())
    user_a = str(uuid.uuid4())
    user_b = str(uuid.uuid4())

    table = "governance_events"

    with SessionLocal() as db:
        cols = _get_columns(db, table)
        colset = {c[0] for c in cols}

        # Pick tenant/user columns by common conventions
        tenant_col = _pick_first(
            colset,
            [
                "clinic_id",
                "clinic_uuid",
                "tenant_id",
                "tenant_uuid",
                "clinic",
                "tenant",
            ],
        )
        if not tenant_col:
            raise HTTPException(
                status_code=500,
                detail=f"rls_self_test_no_tenant_column_found_in_{table}",
            )

        user_col = _pick_first(
            colset,
            [
                "clinic_user_id",
                "clinic_user_uuid",
                "user_id",
                "user_uuid",
                "actor_id",
                "actor_uuid",
            ],
        )
        # user_col is optional; some schemas may omit user linkage

        # Insert under clinic A context
        clear_rls_context(db)
        set_rls_context(db, clinic_id=clinic_a, user_id=user_a)
        _insert_governance_event_self_test(db, table, tenant_col, user_col, clinic_a, user_a)

        # Insert under clinic B context
        clear_rls_context(db)
        set_rls_context(db, clinic_id=clinic_b, user_id=user_b)
        _insert_governance_event_self_test(db, table, tenant_col, user_col, clinic_b, user_b)

        db.commit()

        # Verify isolation: when context is clinic A, clinic B rows should not be visible
        clear_rls_context(db)
        set_rls_context(db, clinic_id=clinic_a, user_id=user_a)

        a_count = db.execute(
            text(f"SELECT COUNT(*) FROM {table} WHERE {tenant_col} = :cid"),
            {"cid": clinic_a},
        ).scalar() or 0

        b_visible_from_a = db.execute(
            text(f"SELECT COUNT(*) FROM {table} WHERE {tenant_col} = :cid"),
            {"cid": clinic_b},
        ).scalar() or 0

        clear_rls_context(db)

    ok = (int(a_count) >= 1) and (int(b_visible_from_a) == 0)

    return {
        "status": "ok" if ok else "fail",
        "now_utc": now_utc,
        "table": table,
        "tenant_col": tenant_col,
        "user_col": user_col,
        "clinic_a_count": int(a_count),
        "clinic_b_visible_from_a": int(b_visible_from_a),
    }
