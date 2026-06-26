from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..auth import (
    DUMMY_PASSWORD_HASH,
    current_user,
    hash_password,
    issue_token,
    verify_password,
)
from ..db import get_db
from ..models import User
from ..schemas import SignupRequest, SignupResponse, TokenResponse, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])

SIGNUP_ACCEPTED_RESPONSE = {
    "message": "signup request accepted",
}


@router.post(
    "/signup",
    response_model=SignupResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def signup(req: SignupRequest, db: Session = Depends(get_db)):
    user = User(
        email=req.email,
        password_hash=hash_password(req.password),
        full_name=req.full_name,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
    return SIGNUP_ACCEPTED_RESPONSE


@router.post("/login", response_model=TokenResponse)
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.scalar(select(User).where(User.email == form.username))
    password_hash = user.password_hash if user else DUMMY_PASSWORD_HASH
    password_matches = verify_password(form.password, password_hash)
    if not user or not password_matches:
        raise HTTPException(status_code=401, detail="invalid credentials")
    return TokenResponse(access_token=issue_token(user))


me_router = APIRouter(tags=["users"])


@me_router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user
