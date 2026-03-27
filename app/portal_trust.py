from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from app.db import SessionLocal
from app.trust_materials import TRUST_MATERIALS
from app.trust_scoring import (
    build_trust_pack_metadata,
    build_trust_posture,
    build_trust_profile,
)

# IMPORTANT:
# This import assumes your existing clinic-auth dependency is exposed here.
# If your dependency name differs, adjust this one line only.
from app.auth_and_rls import require_clinic_user


router = APIRouter(prefix="/v1/portal/trust", tags=["portal-trust"])


def _extract_clinic_id(ctx: Any) -> str:
    if ctx is None:
        raise HTTPException(status_code=500, detail="Missing clinic auth context")

    if isinstance(ctx, dict):
        clinic_id = ctx.get("clinic_id")
    else:
        clinic_id = getattr(ctx, "clinic_id", None)

    if not clinic_id:
        raise HTTPException(status_code=500, detail="Clinic auth context missing clinic_id")

    return str(clinic_id)


@router.get("/profile")
def get_trust_profile(ctx: Any = Depends(require_clinic_user)) -> Dict[str, Any]:
    clinic_id = _extract_clinic_id(ctx)
    db = SessionLocal()
    try:
        return build_trust_profile(db=db, clinic_id=clinic_id)
    finally:
        db.close()


@router.get("/posture")
def get_trust_posture(ctx: Any = Depends(require_clinic_user)) -> Dict[str, Any]:
    clinic_id = _extract_clinic_id(ctx)
    db = SessionLocal()
    try:
        return build_trust_posture(db=db, clinic_id=clinic_id)
    finally:
        db.close()


@router.get("/pack")
def get_trust_pack(ctx: Any = Depends(require_clinic_user)) -> Dict[str, Any]:
    _ = _extract_clinic_id(ctx)
    return build_trust_pack_metadata()


@router.get("/materials")
def get_trust_materials(ctx: Any = Depends(require_clinic_user)) -> Dict[str, Any]:
    _ = _extract_clinic_id(ctx)
    return {"sections": TRUST_MATERIALS}
