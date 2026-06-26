import os
import threading
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import current_user, hash_password, issue_token, verify_password
from ..db import get_db
from ..models import User
from ..schemas import SignupRequest, TokenResponse, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Login hardening
# ---------------------------------------------------------------------------
#
# In-process, per-source failed-login throttle (no extra dependency). This is
# defense-in-depth at the application layer; in front of a gateway/WAF that
# already rate-limits login it is redundant but harmless. Defaults are tunable
# via environment variables so an operator can dial the policy without a code
# change. For a multi-process / multi-instance deployment, back this with a
# shared store (e.g. Redis) keyed the same way.
LOGIN_MAX_FAILURES = int(os.environ.get("LOGIN_MAX_FAILURES", "5"))
LOGIN_WINDOW_SECONDS = float(os.environ.get("LOGIN_WINDOW_SECONDS", "60"))

# Sliding-window store: client key -> list of recent failure timestamps.
_LOGIN_FAILURES: dict[str, list[float]] = {}
_LOGIN_FAILURES_LOCK = threading.Lock()

# Constant dummy hash used to equalize the timing of the "no such user" branch
# with the "user exists, wrong password" branch. Without this, an absent account
# short-circuits before bcrypt runs and the response-time difference leaks which
# emails are registered (account enumeration). Computed once at import.
_DUMMY_PASSWORD_HASH = hash_password("dummy-password-for-constant-time-login")


def _client_key(request: Request) -> str:
    """Identify the request source for throttling (per client IP)."""
    client = request.client
    return client.host if client and client.host else "unknown"


def _recent_failures(key: str, now: float) -> int:
    """Prune expired timestamps and return the live failure count for ``key``."""
    cutoff = now - LOGIN_WINDOW_SECONDS
    with _LOGIN_FAILURES_LOCK:
        stamps = [t for t in _LOGIN_FAILURES.get(key, []) if t > cutoff]
        if stamps:
            _LOGIN_FAILURES[key] = stamps
        else:
            _LOGIN_FAILURES.pop(key, None)
        return len(stamps)


def _record_failure(key: str, now: float) -> None:
    with _LOGIN_FAILURES_LOCK:
        _LOGIN_FAILURES.setdefault(key, []).append(now)


def _clear_failures(key: str) -> None:
    with _LOGIN_FAILURES_LOCK:
        _LOGIN_FAILURES.pop(key, None)


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
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    key = _client_key(request)
    now = time.monotonic()

    # Throttle BEFORE doing any bcrypt work, so an attacker cannot keep the
    # endpoint busy guessing passwords once they have exhausted the budget.
    if _recent_failures(key, now) >= LOGIN_MAX_FAILURES:
        raise HTTPException(
            status_code=429,
            detail="too many failed login attempts; try again later",
            headers={"Retry-After": str(int(LOGIN_WINDOW_SECONDS))},
        )

    user = db.scalar(select(User).where(User.email == form.username))
    if user is not None:
        ok = verify_password(form.password, user.password_hash)
    else:
        # Run a dummy verification against a constant hash so the absent-user
        # path costs the same as the wrong-password path. This removes the
        # response-time side channel that would otherwise reveal whether an
        # email is registered.
        verify_password(form.password, _DUMMY_PASSWORD_HASH)
        ok = False

    if not ok:
        _record_failure(key, now)
        raise HTTPException(status_code=401, detail="invalid credentials")

    # Successful login clears the failure budget for this source.
    _clear_failures(key)
    return TokenResponse(access_token=issue_token(user))


me_router = APIRouter(tags=["users"])


@me_router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user
