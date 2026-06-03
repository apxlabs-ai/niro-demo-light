"""Regression tests for security findings in PR #105.

Each test must FAIL on the unfixed code and PASS after the fix is applied.

TC-926AFC68 — cache key missing scope (cross-tenant cache poisoning)
TC-1720B72E — unscoped scheduled-report worker (cross-tenant data in emails)
TC-70A69AFB — schedule email not validated against caller's own address
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.models import Role, SavedSearch, ScheduledReport, ReportRun, Ticket, User
from app.search import _cache, invalidate_cache


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def two_customers(db):
    """Two customers each with one ticket, plus their bearer tokens."""
    alice = User(
        email="alice@example.com",
        full_name="Alice",
        role=Role.customer,
        password_hash=hash_password("pw"),
    )
    bob = User(
        email="bob@example.com",
        full_name="Bob",
        role=Role.customer,
        password_hash=hash_password("pw"),
    )
    db.add_all([alice, bob])
    db.commit()
    db.refresh(alice)
    db.refresh(bob)

    ticket_alice = Ticket(
        customer_id=alice.id,
        subject="alice-secret",
        description="alice confidential",
        status="open",
        priority="high",
    )
    ticket_bob = Ticket(
        customer_id=bob.id,
        subject="bob-secret",
        description="bob confidential",
        status="open",
        priority="high",
    )
    db.add_all([ticket_alice, ticket_bob])
    db.commit()
    db.refresh(ticket_alice)
    db.refresh(ticket_bob)

    token_alice = issue_token(alice)
    token_bob = issue_token(bob)
    return alice, bob, ticket_alice, ticket_bob, token_alice, token_bob


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# TC-926AFC68: cross-tenant cache poisoning
# ---------------------------------------------------------------------------

def test_cache_does_not_leak_across_tenants(client, two_customers):
    """TC-926AFC68: Alice warms the cache for {status:open}; Bob running the
    same filter must receive only his own tickets, not Alice's.

    FAILS on unfixed code (cache key has no scope → Bob gets Alice's rows).
    PASSES after the fix (scope component in cache key gives each customer
    their own cache slot).
    """
    alice, bob, ticket_alice, ticket_bob, token_alice, token_bob = two_customers

    # Flush any leftover cache state from other tests.
    invalidate_cache()

    # Alice creates and runs a saved search → warms the cache.
    r = client.post(
        "/searches",
        json={"name": "open", "filter": {"status": "open"}},
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert r.status_code == 201
    search_alice_id = r.json()["id"]

    r = client.get(
        f"/searches/{search_alice_id}/run",
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert r.status_code == 200
    alice_result_ids = {t["id"] for t in r.json()["tickets"]}
    assert ticket_alice.id in alice_result_ids
    assert ticket_bob.id not in alice_result_ids

    # Bob runs an identical filter — must NOT get Alice's ticket.
    r = client.post(
        "/searches",
        json={"name": "open", "filter": {"status": "open"}},
        headers={"Authorization": f"Bearer {token_bob}"},
    )
    assert r.status_code == 201
    search_bob_id = r.json()["id"]

    r = client.get(
        f"/searches/{search_bob_id}/run",
        headers={"Authorization": f"Bearer {token_bob}"},
    )
    assert r.status_code == 200
    bob_result_ids = {t["id"] for t in r.json()["tickets"]}
    assert ticket_bob.id in bob_result_ids, "Bob must see his own ticket"
    assert ticket_alice.id not in bob_result_ids, (
        "TC-926AFC68: Alice's ticket must NOT appear in Bob's results "
        "(cross-tenant cache leak)"
    )


# ---------------------------------------------------------------------------
# TC-1720B72E: unscoped scheduled-report worker
# ---------------------------------------------------------------------------

def test_scheduled_report_scoped_to_owner(client, two_customers, db):
    """TC-1720B72E: a scheduled report created by Bob must only include
    Bob's tickets in the initial run, not Alice's.

    FAILS on unfixed code (jobs.execute_search called without scope= →
    initial_run.result_ticket_ids_json includes Alice's ticket IDs).
    PASSES after the fix (scope=owner passed → only Bob's tickets returned).
    """
    alice, bob, ticket_alice, ticket_bob, token_alice, token_bob = two_customers

    # Bob creates a saved search with no customer_id filter.
    r = client.post(
        "/searches",
        json={"name": "all-open", "filter": {"status": "open"}},
        headers={"Authorization": f"Bearer {token_bob}"},
    )
    assert r.status_code == 201
    search_id = r.json()["id"]

    # Bob schedules a report — the initial run fires immediately.
    r = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "bob@example.com"},
        headers={"Authorization": f"Bearer {token_bob}"},
    )
    assert r.status_code == 201
    payload = r.json()
    run_ticket_ids = json.loads(payload["initial_run"]["result_ticket_ids_json"])

    assert ticket_bob.id in run_ticket_ids, "Bob's own ticket must be in the run"
    assert ticket_alice.id not in run_ticket_ids, (
        "TC-1720B72E: Alice's ticket must NOT appear in Bob's scheduled "
        "report run (cross-tenant data in worker)"
    )


# ---------------------------------------------------------------------------
# TC-70A69AFB: schedule email not validated against caller's address
# ---------------------------------------------------------------------------

def test_schedule_email_must_match_caller(client, two_customers):
    """TC-70A69AFB: scheduling a report to an arbitrary external email address
    must be rejected (403 / 422), not silently accepted.

    FAILS on unfixed code (any RFC-valid EmailStr is accepted → 201).
    PASSES after the fix (email must equal user.email → 403 for mismatches).
    """
    alice, bob, ticket_alice, ticket_bob, token_alice, token_bob = two_customers

    # Alice creates a saved search.
    r = client.post(
        "/searches",
        json={"name": "my-open", "filter": {"status": "open"}},
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert r.status_code == 201
    search_id = r.json()["id"]

    # Alice tries to route the report to an attacker address — must be rejected.
    r = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.example.com"},
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert r.status_code in (403, 422), (
        f"TC-70A69AFB: expected 403/422 when email doesn't match caller's "
        f"address, got {r.status_code}"
    )

    # Scheduling to the caller's own address must still work.
    r = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "alice@example.com"},
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert r.status_code == 201, (
        f"Scheduling to the caller's own email must succeed, got {r.status_code}"
    )
