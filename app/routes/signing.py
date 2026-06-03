"""Payload-signature protected routes.

These endpoints exist to exercise Niro's `type: signing` credentials:

* /signed/hmac verifies HMAC-SHA256 over the raw request body.
* /signed/rsa verifies RSA-SHA256 over the raw request body.

The demo intentionally keeps canonicalization simple. Real partner APIs
often sign timestamp + newline + body or richer canonical strings; those
details belong in the credential description Niro reads.
"""
from __future__ import annotations

import base64
import hmac
import os
import time
from hashlib import sha256

from fastapi import APIRouter, Header, HTTPException, Request

router = APIRouter(prefix="/signed", tags=["signed"])

DEFAULT_RSA_PUBLIC_KEY_PATH = "niro/certs/signing-rsa.pub"
INSECURE_DEMO_HMAC_SECRET = "demo-hmac-secret"
HMAC_REPLAY_TTL_SECONDS = 300

_seen_hmac_requests: dict[str, float] = {}


def _decode_signature(value: str) -> bytes:
    """Decode base64 signatures, accepting an optional sha256= prefix."""
    raw = value.strip()
    if raw.startswith("sha256="):
        raw = raw[len("sha256=") :]
    try:
        return base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="signature is not valid base64") from exc


def _hmac_secret() -> str:
    secret = os.environ.get("HELPDESK_HMAC_SIGNING_SECRET")
    if not secret or secret == INSECURE_DEMO_HMAC_SECRET:
        raise HTTPException(
            status_code=500,
            detail="HMAC signing secret is not configured",
        )
    return secret


def _reject_replay(signature: bytes, body: bytes) -> None:
    now = time.time()
    cutoff = now - HMAC_REPLAY_TTL_SECONDS
    for key, seen_at in list(_seen_hmac_requests.items()):
        if seen_at < cutoff:
            del _seen_hmac_requests[key]

    replay_key = sha256(signature + b"\0" + body).hexdigest()
    if replay_key in _seen_hmac_requests:
        raise HTTPException(status_code=409, detail="signature replay")
    _seen_hmac_requests[replay_key] = now


@router.post("/hmac")
async def signed_hmac(
    request: Request,
    x_signature: str | None = Header(default=None, alias="X-Signature"),
):
    """Require X-Signature = base64(HMAC-SHA256(raw_body))."""
    if not x_signature:
        raise HTTPException(status_code=401, detail="missing X-Signature")
    body = await request.body()
    secret = _hmac_secret()
    expected = hmac.new(secret.encode("utf-8"), body, sha256).digest()
    supplied = _decode_signature(x_signature)
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="bad signature")
    _reject_replay(supplied, body)
    return {"ok": True, "scheme": "hmac-sha256", "bytes": len(body)}


@router.post("/rsa")
async def signed_rsa(
    request: Request,
    signature: str | None = Header(default=None, alias="Signature"),
):
    """Require Signature = base64(RSA-SHA256(raw_body))."""
    if not signature:
        raise HTTPException(status_code=401, detail="missing Signature")

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as exc:
        raise HTTPException(
            status_code=500,
            detail="cryptography package is required for RSA signature verification",
        ) from exc

    public_key_path = os.environ.get(
        "HELPDESK_RSA_SIGNING_PUBLIC_KEY", DEFAULT_RSA_PUBLIC_KEY_PATH
    )
    try:
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except OSError as exc:
        raise HTTPException(status_code=500, detail="RSA public key is not configured") from exc

    body = await request.body()
    supplied = _decode_signature(signature)
    try:
        public_key.verify(
            supplied,
            body,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise HTTPException(status_code=401, detail="bad signature") from exc
    return {"ok": True, "scheme": "rsa-sha256", "bytes": len(body)}
