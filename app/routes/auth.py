from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import current_user, hash_password, issue_token, verify_password
from ..db import get_db
from ..models import User
from ..schemas import SignupRequest, TokenResponse, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])

# Precomputed bcrypt hash of a value no account uses. When the submitted email
# is unknown we still verify the password against this dummy hash so the login
# handler performs the same bcrypt work whether or not the account exists. This
# closes the timing side channel that otherwise lets an unauthenticated caller
# enumerate registered emails by measuring /auth/login response time.
_DUMMY_PASSWORD_HASH = hash_password("niro-login-timing-dummy-password")


@router.post("/signup", response_model=UserOut, status_code=201)
def signup(req: SignupRequest, db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.email == req.email)):
        raise HTTPException(status_code=409, detail="email already registered")
    user = User(
        email=req.email,
        password_hash=hash_password(req.password),
        full_name=req.full_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.scalar(select(User).where(User.email == form.username))
    # Always run bcrypt — against the real hash if the account exists, otherwise
    # against a constant dummy hash — so an unknown email costs the same wall
    # time as a known one. Without this, Python's `or` short-circuits past
    # verify_password for unknown emails, leaking account existence via timing.
    password_hash = user.password_hash if user else _DUMMY_PASSWORD_HASH
    password_ok = verify_password(form.password, password_hash)
    if not user or not password_ok:
        raise HTTPException(status_code=401, detail="invalid credentials")
    return TokenResponse(access_token=issue_token(user))


me_router = APIRouter(tags=["users"])


@me_router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user
