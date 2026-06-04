"""Regression tests for search / scheduled-report vulnerabilities.

All tests in this file MUST FAIL on the unfixed codebase and PASS once
the corresponding fix is applied. Do not edit assertions to match buggy
behaviour — fix the production code instead.

Findings covered:
  TC-A26D0B05  Agent write bypass on saved searches (HIGH)
  TC-2EEFE250  Scheduled-report worker runs without tenant scope (CRITICAL)
  TC-A99AE320  Result cache keyed on filter only, ignoring caller scope (CRITICAL)
"""

import json
import pytest
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password
from app.db import Base, get_db
from app.main import app
from app.models import Role, SavedSearch, ScheduledReport, Ticket, User
from app.search import invalidate_cache


# ---------------------------------------------------------------------------
# Fixtures (local, isolated from the mTLS test fixtures)
# ---------------------------------------------------------------------------

@pytest.fixture()
def db():
    # StaticPool keeps a single connection so the in-memory SQLite DB is shared
    # across threads (the FastAPI worker thread and the test thread both see the
    # same tables and rows).
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
def seeded(db):
    """Two customers + one agent, each with one ticket."""
    alice = User(
        email="alice@test.example",
        full_name="Alice",
        role=Role.customer,
        password_hash=hash_password("pw"),
    )
    bob = User(
        email="bob@test.example",
        full_name="Bob",
        role=Role.customer,
        password_hash=hash_password("pw"),
    )
    agent = User(
        email="agent@test.example",
        full_name="Agent",
        role=Role.agent,
        password_hash=hash_password("pw"),
    )
    db.add_all([alice, bob, agent])
    db.commit()
    for u in (alice, bob, agent):
        db.refresh(u)

    t_alice = Ticket(
        customer_id=alice.id,
        subject="alice-secret",
        description="alice only",
        status="open",
        priority="normal",
    )
    t_bob = Ticket(
        customer_id=bob.id,
        subject="bob-secret",
        description="bob only",
        status="open",
        priority="normal",
    )
    db.add_all([t_alice, t_bob])
    db.commit()
    db.refresh(t_alice)
    db.refresh(t_bob)
    return alice, bob, agent, t_alice, t_bob


@pytest.fixture()
def client(db):
    """TestClient wired to the in-memory DB.  Bearer auth via /auth/login."""
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


def _login(client, email, password="pw") -> str:
    resp = client.post(
        "/auth/login",
        data={"username": email, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# TC-A26D0B05: Agent must not be able to mutate a customer's saved search
# ---------------------------------------------------------------------------

def test_agent_cannot_patch_customer_saved_search(client, seeded, db):
    """TC-A26D0B05: PATCH /searches/{id} as agent on a customer-owned search
    must return 403, not 200.
    """
    alice, _, agent, *_ = seeded
    tok_alice = _login(client, alice.email)
    tok_agent = _login(client, agent.email)

    # Customer creates a saved search.
    resp = client.post(
        "/searches",
        json={"name": "alice private", "filter": {"status": "open"}},
        headers=_auth(tok_alice),
    )
    assert resp.status_code == 201
    search_id = resp.json()["id"]

    # Agent tries to PATCH it.
    resp = client.patch(
        f"/searches/{search_id}",
        json={"name": "AGENT TAMPERED"},
        headers=_auth(tok_agent),
    )
    assert resp.status_code == 403, (
        f"TC-A26D0B05: expected 403 but got {resp.status_code}. "
        "Agent must not be able to rename a customer's saved search."
    )


def test_agent_cannot_delete_customer_saved_search(client, seeded, db):
    """TC-A26D0B05: DELETE /searches/{id} as agent on a customer-owned search
    must return 403, not 204.
    """
    alice, _, agent, *_ = seeded
    tok_alice = _login(client, alice.email)
    tok_agent = _login(client, agent.email)

    resp = client.post(
        "/searches",
        json={"name": "alice private 2", "filter": {}},
        headers=_auth(tok_alice),
    )
    assert resp.status_code == 201
    search_id = resp.json()["id"]

    resp = client.delete(f"/searches/{search_id}", headers=_auth(tok_agent))
    assert resp.status_code == 403, (
        f"TC-A26D0B05: expected 403 but got {resp.status_code}. "
        "Agent must not be able to delete a customer's saved search."
    )


def test_agent_cannot_create_schedule_on_customer_search(client, seeded, db):
    """TC-A26D0B05: POST /searches/{id}/schedule as agent on a customer search
    must return 403, not 201.
    """
    alice, _, agent, *_ = seeded
    tok_alice = _login(client, alice.email)
    tok_agent = _login(client, agent.email)

    resp = client.post(
        "/searches",
        json={"name": "alice private 3", "filter": {}},
        headers=_auth(tok_alice),
    )
    assert resp.status_code == 201
    search_id = resp.json()["id"]

    resp = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.com"},
        headers=_auth(tok_agent),
    )
    assert resp.status_code == 403, (
        f"TC-A26D0B05: expected 403 but got {resp.status_code}. "
        "Agent must not be able to create a schedule on a customer's saved search."
    )


# ---------------------------------------------------------------------------
# TC-2EEFE250: Scheduled-report worker must not leak cross-tenant tickets
# ---------------------------------------------------------------------------

def test_scheduled_report_worker_scoped_to_owner(db, seeded):
    """TC-2EEFE250: run_scheduled_report must only include the saved-search
    owner's tickets, not tickets from other tenants.
    """
    from app.jobs import run_scheduled_report

    alice, bob, _, t_alice, t_bob = seeded

    # Alice creates a saved search with an empty filter (matches everything
    # in an unscoped query).
    saved = SavedSearch(
        owner_id=alice.id,
        name="alice all-tickets",
        filter_json="{}",
        pinned=False,
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)

    sched = ScheduledReport(
        saved_search_id=saved.id,
        frequency="daily",
        email="alice@test.example",
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)

    run = run_scheduled_report(sched.id, db)

    result_ids = json.loads(run.result_ticket_ids_json)
    assert t_alice.id in result_ids, "Alice's own ticket must appear in the run."
    assert t_bob.id not in result_ids, (
        f"TC-2EEFE250: Bob's ticket (id={t_bob.id}) must NOT appear in Alice's "
        "scheduled report, but it was found in result_ticket_ids_json."
    )


# ---------------------------------------------------------------------------
# TC-A99AE320: Result cache must be scoped per caller, not just per filter
# ---------------------------------------------------------------------------

def test_cache_does_not_leak_across_tenants(client, seeded, db):
    """TC-A99AE320: Customer B running the same filter as Customer A must not
    receive Customer A's ticket via a stale cache hit.
    """
    invalidate_cache()  # start each test with a clean cache

    alice, bob, _, t_alice, t_bob = seeded
    tok_alice = _login(client, alice.email)
    tok_bob = _login(client, bob.email)

    # Both customers save searches with the identical filter shape.
    def _create_search(tok):
        r = client.post(
            "/searches",
            json={"name": "open tickets", "filter": {"status": "open"}},
            headers=_auth(tok),
        )
        assert r.status_code == 201
        return r.json()["id"]

    sid_alice = _create_search(tok_alice)
    sid_bob = _create_search(tok_bob)

    # Alice runs her search first — this primes the in-process cache.
    r_alice = client.get(f"/searches/{sid_alice}/run", headers=_auth(tok_alice))
    assert r_alice.status_code == 200
    alice_ids = {t["id"] for t in r_alice.json()["tickets"]}
    assert t_alice.id in alice_ids, "Alice must see her own ticket."

    # Bob runs his search immediately after (same filter → same cache key if buggy).
    r_bob = client.get(f"/searches/{sid_bob}/run", headers=_auth(tok_bob))
    assert r_bob.status_code == 200
    bob_ticket_ids = {t["id"] for t in r_bob.json()["tickets"]}

    assert t_bob.id in bob_ticket_ids, "Bob must see his own ticket."
    assert t_alice.id not in bob_ticket_ids, (
        f"TC-A99AE320: Alice's ticket (id={t_alice.id}) appeared in Bob's search "
        "result — cross-tenant cache poisoning detected."
    )
