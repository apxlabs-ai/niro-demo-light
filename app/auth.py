import os
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import Request

from .db import get_db
from .models import Role, User

SECRET_KEY = os.environ.get("HELPDESK_SECRET", "dev-secret-do-not-use-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_TTL_MINUTES = 60 * 24

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# bcrypt only ever consumes the first 72 bytes of the input and raises
# ValueError for anything longer. A multibyte password can be within a sane
# character limit yet exceed 72 bytes, so we truncate the encoded bytes to 72
# before hashing/verifying. This makes the helpers total — they can never raise
# on over-length input — so no signup request can turn into an uncaught 500.
_BCRYPT_MAX_BYTES = 72


def _bcrypt_bytes(plain: str) -> bytes:
    return plain.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(_bcrypt_bytes(plain), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_bcrypt_bytes(plain), hashed.encode("utf-8"))
    except ValueError:
        return False


def issue_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "role": user.role.value,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="user not found")
    return user


def require_agent(user: User = Depends(current_user)) -> User:
    if user.role != Role.agent:
        raise HTTPException(status_code=403, detail="agent role required")
    return user


def current_user_mtls(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """Authenticate via mTLS client certificate.

    Reads the verified peer certificate from the TLS connection and
    maps its CN to a User by email. The TLS layer (uvicorn with
    ssl-cert-reqs=CERT_REQUIRED) has already validated the cert chain
    before this dependency runs — we only need to extract identity.
    """
    # scope["ssl_object"] is set by the test _CertInjector middleware.
    # In real uvicorn it is not in the scope; extract it from the
    # asyncio transport instead via the receive callable's closure.
    # Verified against uvicorn 0.48. If mTLS cert extraction breaks after
    # an upgrade, check the uvicorn changelog for ssl_object exposure in
    # the ASGI scope.
    ssl_obj = request.scope.get("ssl_object")
    if ssl_obj is None:
        receive = getattr(request, "_receive", None)
        protocol = getattr(receive, "__self__", None)
        transport = getattr(protocol, "transport", None)
        if transport is not None:
            ssl_obj = transport.get_extra_info("ssl_object")
    if ssl_obj is None:
        raise HTTPException(status_code=401, detail="mTLS client certificate required")
    cert = ssl_obj.getpeercert()
    subject = dict(x[0] for x in cert.get("subject", []))
    cn = subject.get("commonName")
    if not cn:
        raise HTTPException(status_code=401, detail="client certificate missing CN")
    user = db.scalar(select(User).where(User.email == cn))
    if user is None:
        raise HTTPException(status_code=401, detail="no account for certificate CN")
    return user
