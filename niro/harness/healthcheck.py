#!/usr/bin/env python3
"""HTTP healthcheck for the local Niro target."""
from __future__ import annotations

import json
from typing import Any
from urllib import error, parse, request

BASE_URL = "http://127.0.0.1:8000"

USERS = {
    "agent": ("agent@helpdesk.test", "agent-pass-1234"),
    "customer_a": ("alex@customer.test", "customer-pass-1234"),
    "customer_b": ("blair@customer.test", "customer-pass-1234"),
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


def main() -> None:
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
    _require(len(agent_tickets) >= len(alex_tickets) + len(blair_tickets), "agent cannot see seeded tickets")

    alex_ticket_id = alex_tickets[0]["id"]
    blair_ticket_id = blair_tickets[0]["id"]
    _request("GET", f"/tickets/{alex_ticket_id}/comments", token=tokens["customer_a"])
    _request("GET", f"/tickets/{blair_ticket_id}/comments", token=tokens["customer_b"])
    _expect_http(403, "GET", f"/tickets/{blair_ticket_id}", token=tokens["customer_a"])
    _expect_http(403, "GET", f"/tickets/{alex_ticket_id}", token=tokens["customer_b"])

    alex_searches = _request("GET", "/searches", token=tokens["customer_a"])
    blair_searches = _request("GET", "/searches", token=tokens["customer_b"])
    _require(alex_searches, "customer A has no saved search")
    _require(blair_searches, "customer B has no saved search")
    alex_search_id = alex_searches[0]["id"]
    blair_search_id = blair_searches[0]["id"]
    _request("GET", f"/searches/{alex_search_id}/run", token=tokens["customer_a"])
    _expect_http(403, "GET", f"/searches/{blair_search_id}", token=tokens["customer_a"])

    schedules = _request("GET", f"/searches/{alex_search_id}/schedule", token=tokens["customer_a"])
    _require(schedules, "customer A saved search has no schedule")
    _request("GET", f"/searches/schedules/{schedules[0]['id']}/runs", token=tokens["customer_a"])
    # This route is currently shadowed by /searches/{search_id}; the gap is
    # recorded in niro/accepted-coverage-gaps.yaml.
    _expect_http(422, "GET", "/searches/_stats", token=tokens["agent"])

    print("-> harness healthcheck passed")


if __name__ == "__main__":
    main()
