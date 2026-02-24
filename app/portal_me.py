# app/portal_me.py
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.auth_and_rls import require_clinic_user

router = APIRouter(
    prefix="/v1/portal",
    tags=["Portal Read"],
    dependencies=[Depends(require_clinic_user)],
)


class PortalMeResponse(BaseModel):
    clinic_id: str
    clinic_user_id: str
    role: str
    clinic_name: Optional[str] = None
    clinic_slug: Optional[str] = None


@router.get("/me", response_model=PortalMeResponse)
def portal_me(request: Request, db: Session = Depends(get_db)) -> PortalMeResponse:
    """
    Minimal identity endpoint for the Portal UI.
    - Uses the same auth dependency as all portal routes.
    - Uses RLS (app_current_clinic_id()) so we never cross tenants.
    """
    clinic_id = getattr(request.state, "clinic_id", None)
    clinic_user_id = getattr(request.state, "clinic_user_id", None)
    role = getattr(request.state, "role", "") or ""

    if not clinic_id or not clinic_user_id:
        raise HTTPException(status_code=401, detail="missing clinic context")

    # RLS-safe: only reads current clinic row
    row = db.execute(
        text(
            """
            SELECT clinic_name, clinic_slug
            FROM clinics
            WHERE clinic_id = app_current_clinic_id()
            LIMIT 1
            """
        )
    ).mappings().first()

    clinic_name = str(row["clinic_name"]) if row and row.get("clinic_name") is not None else None
    clinic_slug = str(row["clinic_slug"]) if row and row.get("clinic_slug") is not None else None

    # Canonicalize UUID strings
    try:
        cid = str(uuid.UUID(str(clinic_id)))
    except Exception:
        cid = str(clinic_id)

    try:
        cuid = str(uuid.UUID(str(clinic_user_id)))
    except Exception:
        cuid = str(clinic_user_id)

    return PortalMeResponse(
        clinic_id=cid,
        clinic_user_id=cuid,
        role=str(role),
        clinic_name=clinic_name,
        clinic_slug=clinic_slug,
    )
