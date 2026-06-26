#!/usr/bin/env python3
"""HTTP + mTLS healthcheck for the local Niro target.

Verifies the working-tree surface is live and that the seeded cross-customer
fixtures are in place on BOTH listeners:

  * port 8000 — plain HTTP, Bearer-token auth.
  * port 8443 — HTTPS + mTLS, client identity from the cert CN.
"""
from __future__ import annotations

import http.client
import json
import ssl
from pathlib import Path
from typing import Any
from urllib import error, parse, request

BASE_URL = "http://127.0.0.1:8000"
TLS_HOST = "127.0.0.1"
TLS_PORT = 8443
CERTS = Path(__file__).resolve().parents[1] / "certs"

USERS = {
    "agent": ("agent@helpdesk.test", "agent-pass-1234"),
    "customer_a": ("alex@customer.test", "customer-pass-1234"),
    "customer_b": ("blair@customer.test", "customer-pass-1234"),
}

# cert CN -> (cert basename, expected user email)
MTLS_CLIENTS = {
    "agent": ("client-agent", "agent@helpdesk.test"),
    "customer_a": ("client-alex", "alex@customer.test"),
    "customer_b": ("client-blair", "blair@customer.test"),
}


def _request(
    method: str,
    path: str,
    *,
    token: str | None = None,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> Any:
    req_headers = dict(headers or {})
    if token:
        req_headers["Authorization"] = f"Bearer {token}"
    req = request.Request(
        f"{BASE_URL}{path}",
        data=body,
        headers=req_headers,
        method=method,
    )
    with request.urlopen(req, timeout=5) as resp:
        data = resp.read()
        if not data:
            return None
        return json.loads(data.decode("utf-8"))


def _login(email: str, password: str) -> str:
    body = parse.urlencode({"username": email, "password": password}).encode()
    resp = _request(
        "POST",
        "/auth/login",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return resp["access_token"]


def _expect_http(status: int, method: str, path: str, *, token: str) -> None:
    try:
        _request(method, path, token=token)
    except error.HTTPError as exc:
        if exc.code == status:
            return
        raise AssertionError(f"{method} {path} returned {exc.code}, expected {status}") from exc
    raise AssertionError(f"{method} {path} unexpectedly succeeded; expected {status}")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _mtls_context(cert_basename: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(CERTS / "ca.crt"))
    if cert_basename is not None:
        ctx.load_cert_chain(
            certfile=str(CERTS / f"{cert_basename}.crt"),
            keyfile=str(CERTS / f"{cert_basename}.key"),
        )
    ctx.check_hostname = False
    return ctx


def _mtls_request(method: str, path: str, *, cert_basename: str | None) -> tuple[int, Any]:
    ctx = _mtls_context(cert_basename)
    conn = http.client.HTTPSConnection(TLS_HOST, TLS_PORT, context=ctx, timeout=5)
    try:
        conn.request(method, path)
        resp = conn.getresponse()
        raw = resp.read()
        payload = json.loads(raw.decode("utf-8")) if raw else None
        return resp.status, payload
    finally:
        conn.close()


def main() -> None:
    # --- Plain HTTP surface (port 8000) ---
    health = _request("GET", "/health")
    _require(health == {"status": "ok"}, "health endpoint did not return ok")

    tokens = {name: _login(*creds) for name, creds in USERS.items()}
    for token in tokens.values():
        _request("GET", "/me", token=token)

    alex_tickets = _request("GET", "/tickets", token=tokens["customer_a"])
    blair_tickets = _request("GET", "/tickets", token=tokens["customer_b"])
    agent_tickets = _request("GET", "/tickets", token=tokens["agent"])
    _require(alex_tickets, "customer A has no tickets")
    _require(blair_tickets, "customer B has no tickets")
    _require(
        len(agent_tickets) >= len(alex_tickets) + len(blair_tickets),
        "agent cannot see seeded tickets",
    )

    alex_ticket_id = alex_tickets[0]["id"]
    blair_ticket_id = blair_tickets[0]["id"]
    _request("GET", f"/tickets/{alex_ticket_id}/comments", token=tokens["customer_a"])
    _request("GET", f"/tickets/{blair_ticket_id}/comments", token=tokens["customer_b"])
    # Cross-owner reads must be denied — distinct owners are what makes
    # IDOR / horizontal-escalation testing meaningful.
    _expect_http(403, "GET", f"/tickets/{blair_ticket_id}", token=tokens["customer_a"])
    _expect_http(403, "GET", f"/tickets/{alex_ticket_id}", token=tokens["customer_b"])

    # --- mTLS surface (port 8443) ---
    # A request with no client cert must be rejected at the TLS layer.
    try:
        _mtls_request("GET", "/mtls/me", cert_basename=None)
        raise AssertionError("mTLS endpoint accepted a connection with no client certificate")
    except ssl.SSLError:
        pass
    except (ConnectionResetError, OSError) as exc:
        # CERT_REQUIRED rejection surfaces as a handshake/connection error.
        if isinstance(exc, AssertionError):
            raise

    for name, (cert_basename, expected_email) in MTLS_CLIENTS.items():
        status, payload = _mtls_request("GET", "/mtls/me", cert_basename=cert_basename)
        _require(status == 200, f"mTLS /mtls/me for {name} returned {status}")
        _require(
            payload and payload.get("email") == expected_email,
            f"mTLS identity mismatch for {name}: {payload}",
        )

    # Cross-owner read over mTLS must be denied (customer A reaching B's ticket).
    status, _ = _mtls_request(
        "GET", f"/mtls/tickets/{blair_ticket_id}", cert_basename="client-alex"
    )
    _require(status == 403, f"mTLS cross-owner ticket read returned {status}, expected 403")

    print("-> harness healthcheck passed (http :8000 + mTLS :8443)")


if __name__ == "__main__":
    main()
