# app/auth_and_rls.py
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import text

# import SessionLocal from app.db like you already do
from app.db import SessionLocal

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def set_rls_context(db: Session, clinic_id: str, user_id: str | None = None) -> None:
    db.execute(text("SELECT set_config('app.clinic_id', :cid, true)"), {"cid": clinic_id})
    if user_id:
        db.execute(text("SELECT set_config('app.user_id', :uid, true)"), {"uid": user_id})

def require_clinic_auth(request: Request, db: Session = Depends(get_db)):
    # your bearer token decode logic here...
    # after decode:
    set_rls_context(db, clinic_id=clinic_id, user_id=user_id)
    return claims

def require_clinic_admin(claims=Depends(require_clinic_auth)):
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Clinic admin only")
    return claims

@router.post("/v1/auth/login")
def login(...):
    ...
