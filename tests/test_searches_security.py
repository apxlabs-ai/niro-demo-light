"""Regression tests for security bugs found in PR #87.

Each test MUST FAIL on the unfixed code and PASS after the fix.

  BUG-1 (CRITICAL, TC-A96C695A)  — Cache key omits scope: Customer B gets
        Customer A's cached search results when they share the same filter.

  BUG-2 (CRITICAL, TC-539F9845)  — Worker calls execute_search(scope=None):
        run_scheduled_report writes cross-tenant ticket IDs to ReportRun
        and emails them out.

  BUG-3 (MEDIUM,   TC-20C0BE35)  — Run-history endpoint re-leaks the
        cross-tenant ID list written by BUG-2 via result_ticket_ids_json.

  BUG-4 (MEDIUM,   TC-AB044886)  — ScheduleReportCreate.email is unconstrained:
        any authenticated user can route scheduled emails to an arbitrary address.
"""
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.search as search_module
from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.models import Role, Ticket, User


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
    """Two customers each owning one ticket."""
    alice = User(
        email="alice@test.example",
        full_name="Alice",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    bob = User(
        email="bob@test.example",
        full_name="Bob",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    db.add_all([alice, bob])
    db.commit()
    db.refresh(alice)
    db.refresh(bob)

    ticket_alice = Ticket(
        customer_id=alice.id,
        subject="Alice secret ticket",
        description="for alice only",
        status="open",
        priority="low",
    )
    ticket_bob = Ticket(
        customer_id=bob.id,
        subject="Bob secret ticket",
        description="for bob only",
        status="open",
        priority="low",
    )
    db.add_all([ticket_alice, ticket_bob])
    db.commit()
    db.refresh(ticket_alice)
    db.refresh(ticket_bob)
    return alice, bob, ticket_alice, ticket_bob


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


def _auth(user: User) -> dict:
    return {"Authorization": f"Bearer {issue_token(user)}"}


# ---------------------------------------------------------------------------
# BUG-1: cache scope isolation (TC-A96C695A)
# ---------------------------------------------------------------------------


def test_cache_does_not_leak_across_tenants(client, db, two_customers):
    """BUG-1: Customer B must not receive Customer A's cached search results.

    FAILS on buggy code: cache key = filter hash only, so B gets a cache
    hit and receives A's rows verbatim.
    PASSES after fix: cache key includes scope/user-id.
    """
    alice, bob, ticket_alice, ticket_bob = two_customers
    search_module._cache.clear()

    # Alice creates a saved search with an empty filter and runs it, seeding cache
    resp = client.post(
        "/searches", json={"name": "all", "filter": {}, "pinned": False},
        headers=_auth(alice),
    )
    assert resp.status_code == 201
    alice_search_id = resp.json()["id"]

    resp = client.get(f"/searches/{alice_search_id}/run", headers=_auth(alice))
    assert resp.status_code == 200
    alice_ids = {t["id"] for t in resp.json()["tickets"]}
    assert ticket_alice.id in alice_ids
    assert ticket_bob.id not in alice_ids

    # Bob creates a saved search with the IDENTICAL empty filter
    resp = client.post(
        "/searches", json={"name": "all", "filter": {}, "pinned": False},
        headers=_auth(bob),
    )
    assert resp.status_code == 201
    bob_search_id = resp.json()["id"]

    # Bob's run must return only his ticket, not Alice's cached rows
    resp = client.get(f"/searches/{bob_search_id}/run", headers=_auth(bob))
    assert resp.status_code == 200
    bob_ids = {t["id"] for t in resp.json()["tickets"]}
    assert ticket_bob.id in bob_ids, "bob must see his own ticket"
    assert ticket_alice.id not in bob_ids, (
        "BUG-1: bob received alice's ticket from the shared cache "
        "(scope not included in cache key)"
    )


# ---------------------------------------------------------------------------
# BUG-2: scheduled report worker scope (TC-539F9845)
# ---------------------------------------------------------------------------


def test_scheduled_report_initial_run_scoped_to_owner(client, db, two_customers):
    """BUG-2: initial_run.result_ticket_ids_json must only contain the
    schedule owner's ticket IDs, not tickets from other tenants.

    FAILS on buggy code: run_scheduled_report passes scope=None to
    execute_search, so every tenant's tickets appear in the run record.
    PASSES after fix: scope=owner passed through.
    """
    alice, bob, ticket_alice, ticket_bob = two_customers

    resp = client.post(
        "/searches", json={"name": "all", "filter": {}, "pinned": False},
        headers=_auth(bob),
    )
    assert resp.status_code == 201
    bob_search_id = resp.json()["id"]

    resp = client.post(
        f"/searches/{bob_search_id}/schedule",
        json={"frequency": "daily", "email": "bob@test.example"},
        headers=_auth(bob),
    )
    assert resp.status_code == 201
    body = resp.json()

    initial_ids = json.loads(body["initial_run"]["result_ticket_ids_json"])
    assert ticket_bob.id in initial_ids, "bob's own ticket must be in the run"
    assert ticket_alice.id not in initial_ids, (
        "BUG-2: alice's ticket id appeared in bob's scheduled-report run "
        "(execute_search called with scope=None in run_scheduled_report)"
    )
    assert body["initial_run"]["result_count"] == 1, (
        "result_count should reflect only bob's 1 ticket"
    )


# ---------------------------------------------------------------------------
# BUG-3: run history re-leaks cross-tenant IDs (TC-20C0BE35)
# ---------------------------------------------------------------------------


def test_run_history_does_not_expose_cross_tenant_ids(client, db, two_customers):
    """BUG-3: GET /searches/schedules/{id}/runs must not expose another
    tenant's ticket IDs in result_ticket_ids_json.

    FAILS on buggy code: BUG-2 writes cross-tenant IDs at persist time;
    this endpoint returns those rows verbatim.
    PASSES once BUG-2 is fixed (persisted list is already scoped correctly).
    """
    alice, bob, ticket_alice, ticket_bob = two_customers

    resp = client.post(
        "/searches", json={"name": "all", "filter": {}, "pinned": False},
        headers=_auth(bob),
    )
    bob_search_id = resp.json()["id"]

    resp = client.post(
        f"/searches/{bob_search_id}/schedule",
        json={"frequency": "daily", "email": "bob@test.example"},
        headers=_auth(bob),
    )
    schedule_id = resp.json()["schedule"]["id"]

    resp = client.get(
        f"/searches/schedules/{schedule_id}/runs",
        headers=_auth(bob),
    )
    assert resp.status_code == 200
    runs = resp.json()
    assert len(runs) == 1
    stored_ids = json.loads(runs[0]["result_ticket_ids_json"])
    assert ticket_alice.id not in stored_ids, (
        "BUG-3: alice's ticket id persisted in bob's schedule run history"
    )


# ---------------------------------------------------------------------------
# BUG-4: unconstrained schedule email (TC-AB044886)
# ---------------------------------------------------------------------------


def test_schedule_email_must_match_owner_email(client, db, two_customers):
    """BUG-4: Creating a schedule with an email that doesn't match the
    authenticated user's account email must be rejected with 422.

    FAILS on buggy code: any syntactically-valid EmailStr is accepted (201).
    PASSES after fix: email validated against user.email.
    """
    alice, _, _, _ = two_customers

    resp = client.post(
        "/searches", json={"name": "all", "filter": {}, "pinned": False},
        headers=_auth(alice),
    )
    alice_search_id = resp.json()["id"]

    resp = client.post(
        f"/searches/{alice_search_id}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.com"},
        headers=_auth(alice),
    )
    assert resp.status_code == 422, (
        f"BUG-4: schedule with unowned email accepted (got {resp.status_code}); "
        "must be 422 unless email matches the authenticated user's address"
    )


def test_schedule_email_matching_owner_is_accepted(client, db, two_customers):
    """Sanity check for BUG-4 fix: a schedule whose email matches the
    authenticated user's own email must still be accepted."""
    alice, _, _, _ = two_customers

    resp = client.post(
        "/searches", json={"name": "all", "filter": {}, "pinned": False},
        headers=_auth(alice),
    )
    alice_search_id = resp.json()["id"]

    resp = client.post(
        f"/searches/{alice_search_id}/schedule",
        json={"frequency": "daily", "email": alice.email},
        headers=_auth(alice),
    )
    assert resp.status_code == 201, (
        f"schedule with owner's own email must be accepted (got {resp.status_code})"
    )
