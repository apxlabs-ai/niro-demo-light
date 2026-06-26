from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import current_user, hash_password, issue_token, verify_password
from ..db import get_db
from ..models import User
from ..schemas import SignupRequest, SignupResponse, TokenResponse, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])

SIGNUP_ACCEPTED = "signup request accepted"
# Precomputed bcrypt hash used to keep missing-user login attempts on the same
# expensive verification path as existing-user wrong-password attempts.
DUMMY_PASSWORD_HASH = "$2b$12$1hutrFaBKfpP6RrwfxPCketsHelp3pkNeBl0u0GlF/LmBzAcmLoWm"


@router.post("/signup", response_model=SignupResponse, status_code=202)
def signup(req: SignupRequest, db: Session = Depends(get_db)):
    password_hash = hash_password(req.password)
    if db.scalar(select(User).where(User.email == req.email)):
        return SignupResponse(detail=SIGNUP_ACCEPTED)
    user = User(
        email=req.email,
        password_hash=password_hash,
        full_name=req.full_name,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
    return SignupResponse(detail=SIGNUP_ACCEPTED)


@router.post("/login", response_model=TokenResponse)
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.scalar(select(User).where(User.email == form.username))
    password_hash = user.password_hash if user else DUMMY_PASSWORD_HASH
    password_ok = verify_password(form.password, password_hash)
    if user is None or not password_ok:
        raise HTTPException(status_code=401, detail="invalid credentials")
    return TokenResponse(access_token=issue_token(user))


me_router = APIRouter(tags=["users"])


@me_router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user
