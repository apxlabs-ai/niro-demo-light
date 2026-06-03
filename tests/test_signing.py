import base64
import hmac
from hashlib import sha256

from fastapi.testclient import TestClient

from app.main import app


def test_signed_hmac_accepts_valid_signature(monkeypatch):
    monkeypatch.setenv("HELPDESK_HMAC_SIGNING_SECRET", "test-hmac-secret")
    body = b'{"hello":"world"}'
    sig = base64.b64encode(
        hmac.new(b"test-hmac-secret", body, sha256).digest()
    ).decode("ascii")

    with TestClient(app) as client:
        resp = client.post("/signed/hmac", content=body, headers={"X-Signature": sig})

    assert resp.status_code == 200
    assert resp.json()["scheme"] == "hmac-sha256"


def test_signed_hmac_rejects_missing_signature():
    with TestClient(app) as client:
        resp = client.post("/signed/hmac", content=b"{}")

    assert resp.status_code == 401


def test_signed_rsa_accepts_valid_signature(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_path = tmp_path / "signing-rsa.pub"
    public_key_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setenv("HELPDESK_RSA_SIGNING_PUBLIC_KEY", str(public_key_path))

    body = b'{"hello":"world"}'
    sig = base64.b64encode(
        key.sign(body, padding.PKCS1v15(), hashes.SHA256())
    ).decode("ascii")

    with TestClient(app) as client:
        resp = client.post("/signed/rsa", content=body, headers={"Signature": sig})

    assert resp.status_code == 200
    assert resp.json()["scheme"] == "rsa-sha256"


def test_signed_rsa_rejects_missing_signature():
    with TestClient(app) as client:
        resp = client.post("/signed/rsa", content=b"{}")

    assert resp.status_code == 401
