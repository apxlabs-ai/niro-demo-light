"""Regression tests for vulnerabilities found in PR #93.

Each test is written against the UNFIXED code and must fail before the
fix is applied. After the fix, all tests must pass.

Findings covered:
  TC-414431D6 (CRITICAL): Search result cache not scoped to user —
      Customer B can receive Customer A's cached tickets.
  TC-1D6CA662 (CRITICAL): Scheduled-report worker calls execute_search
      without scope=owner — all tenants' tickets are emailed to any address.
  TC-3B9DDE81 (HIGH): Agent can PATCH / DELETE any customer's saved
      search because _load_search_for_owner() bypasses ownership for all
      agent verbs, not just reads.

TC-D24A6106 (mTLS cross-tenant read) is already covered by
  test_mtls_ticket_by_id_cross_user_returns_403 in test_mtls.py.
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
from app.models import Role, SavedSearch, Ticket, User
import app.search as search_module


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clear_search_cache():
    """Flush the in-process result cache before every test so cache state
    from one test can't bleed into the next."""
    search_module.invalidate_cache()
    yield
    search_module.invalidate_cache()


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
def users(db):
    """Seed two customers and one agent."""
    alex = User(
        email="alex@customer.example.com",
        full_name="Alex",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    blair = User(
        email="blair@customer.example.com",
        full_name="Blair",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    agent = User(
        email="agent@helpdesk.example.com",
        full_name="Agent",
        role=Role.agent,
        password_hash=hash_password("x"),
    )
    db.add_all([alex, blair, agent])
    db.commit()
    db.refresh(alex)
    db.refresh(blair)
    db.refresh(agent)
    return alex, blair, agent


@pytest.fixture()
def tickets(db, users):
    """One open ticket per customer."""
    alex, blair, _ = users
    ta = Ticket(
        customer_id=alex.id,
        subject="Alex-secret",
        description="Alex only",
        status="open",
        priority="high",
    )
    tb = Ticket(
        customer_id=blair.id,
        subject="Blair-secret",
        description="Blair only",
        status="open",
        priority="low",
    )
    db.add_all([ta, tb])
    db.commit()
    db.refresh(ta)
    db.refresh(tb)
    return ta, tb


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


def _auth(user: User) -> dict:
    """Return an Authorization header dict for the given user."""
    return {"Authorization": f"Bearer {issue_token(user)}"}


# ---------------------------------------------------------------------------
# TC-414431D6: cache key must include user scope
# ---------------------------------------------------------------------------


def test_cache_does_not_leak_across_tenants(client, db, users, tickets):
    """TC-414431D6: Customer B running a search with the same filter as
    Customer A must NOT receive Customer A's cached tickets.

    Fails on unfixed code because _cache_key() uses only filter_json,
    so the cache slot written by A's request is returned verbatim to B.
    """
    alex, blair, _ = users
    ta, tb = tickets

    # A creates and runs a search — this populates the cache keyed on
    # the filter JSON without any user component.
    resp = client.post(
        "/searches",
        json={"name": "A-open", "filter": {"status": "open"}},
        headers=_auth(alex),
    )
    assert resp.status_code == 201
    search_a_id = resp.json()["id"]

    run_a = client.get(f"/searches/{search_a_id}/run", headers=_auth(alex))
    assert run_a.status_code == 200
    a_ids = {t["id"] for t in run_a.json()["tickets"]}
    assert ta.id in a_ids, "sanity: A's own ticket must appear in A's run"
    assert tb.id not in a_ids, "sanity: B's ticket must not appear in A's run"

    # B creates a search with the identical filter — cache should NOT be shared.
    resp = client.post(
        "/searches",
        json={"name": "B-open", "filter": {"status": "open"}},
        headers=_auth(blair),
    )
    assert resp.status_code == 201
    search_b_id = resp.json()["id"]

    run_b = client.get(f"/searches/{search_b_id}/run", headers=_auth(blair))
    assert run_b.status_code == 200
    b_ids = {t["id"] for t in run_b.json()["tickets"]}

    assert ta.id not in b_ids, (
        "TC-414431D6: Customer A's ticket must NOT appear in Customer B's results. "
        "Cache key is not scoped to the requesting user."
    )
    assert tb.id in b_ids, "B's own ticket must appear in B's results"


# ---------------------------------------------------------------------------
# TC-1D6CA662: scheduled report must be scoped to the saved-search owner
# ---------------------------------------------------------------------------


def test_scheduled_report_initial_run_scoped_to_owner(client, db, users, tickets):
    """TC-1D6CA662: The initial run fired by POST /searches/{id}/schedule must
    only include tickets belonging to the saved search's owner.

    Fails on unfixed code because run_scheduled_report() calls
    execute_search(..., scope=None), which returns rows across all tenants.
    """
    alex, blair, _ = users
    ta, tb = tickets

    # Blair creates a saved search with no filter (matches all visible tickets).
    resp = client.post(
        "/searches",
        json={"name": "Blair-all", "filter": {}},
        headers=_auth(blair),
    )
    assert resp.status_code == 201
    search_id = resp.json()["id"]

    # Blair schedules a report on that search.
    resp = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": blair.email},
        headers=_auth(blair),
    )
    assert resp.status_code == 201
    body = resp.json()

    result_ids = json.loads(body["initial_run"]["result_ticket_ids_json"])
    assert ta.id not in result_ids, (
        "TC-1D6CA662: Customer A's ticket must NOT appear in Customer B's "
        "scheduled report run. Worker called execute_search without scope."
    )
    assert tb.id in result_ids, "Blair's own ticket must appear in the report run"

    initial_ids = {t["id"] for t in body["initial_results"]}
    assert ta.id not in initial_ids, (
        "TC-1D6CA662: initial_results must not include other tenants' tickets"
    )


def test_scheduled_report_email_must_match_caller(client, db, users, tickets):
    """TC-1D6CA662 (secondary): scheduling a report to an arbitrary email
    address other than the authenticated user's own must be rejected.

    Fails on unfixed code because the route accepts any EmailStr.
    """
    _, blair, _ = users

    resp = client.post(
        "/searches",
        json={"name": "Blair-all", "filter": {}},
        headers=_auth(blair),
    )
    assert resp.status_code == 201
    search_id = resp.json()["id"]

    resp = client.post(
        f"/searches/{search_id}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.com"},
        headers=_auth(blair),
    )
    assert resp.status_code == 422, (
        "TC-1D6CA662: scheduling a report to a third-party email must be rejected "
        "with 422. Currently the route accepts any EmailStr."
    )


# ---------------------------------------------------------------------------
# TC-3B9DDE81: agents must not mutate other tenants' saved searches
# ---------------------------------------------------------------------------


def test_agent_cannot_patch_customer_saved_search(client, db, users, tickets):
    """TC-3B9DDE81: An agent must receive 403 when attempting to PATCH a
    customer's saved search.

    Fails on unfixed code because _load_search_for_owner() grants agents
    unconditional access regardless of ownership.
    """
    alex, _, agent = users

    resp = client.post(
        "/searches",
        json={"name": "Alex-search", "filter": {"status": "open"}},
        headers=_auth(alex),
    )
    assert resp.status_code == 201
    search_id = resp.json()["id"]

    resp = client.patch(
        f"/searches/{search_id}",
        json={"name": "AGENT_OVERWRITTEN"},
        headers=_auth(agent),
    )
    assert resp.status_code == 403, (
        "TC-3B9DDE81: agent PATCH on another user's saved search must be 403. "
        "_load_search_for_owner() bypasses ownership for agents."
    )


def test_agent_cannot_delete_customer_saved_search(client, db, users, tickets):
    """TC-3B9DDE81: An agent must receive 403 when attempting to DELETE a
    customer's saved search.

    Fails on unfixed code for the same reason as the PATCH variant.
    """
    alex, _, agent = users

    resp = client.post(
        "/searches",
        json={"name": "Alex-search-2", "filter": {"status": "closed"}},
        headers=_auth(alex),
    )
    assert resp.status_code == 201
    search_id = resp.json()["id"]

    resp = client.delete(f"/searches/{search_id}", headers=_auth(agent))
    assert resp.status_code == 403, (
        "TC-3B9DDE81: agent DELETE on another user's saved search must be 403."
    )

    # Confirm the resource still exists for its owner.
    get_resp = client.get(f"/searches/{search_id}", headers=_auth(alex))
    assert get_resp.status_code == 200, "resource must still exist after rejected delete"


def test_agent_can_read_customer_saved_search(client, db, users, tickets):
    """TC-3B9DDE81 (positive case): agents must still be able to READ any
    customer's saved search (analytics / support use case).

    This test must PASS both before and after the fix — it confirms we
    don't over-correct and break legitimate agent read access.
    """
    alex, _, agent = users

    resp = client.post(
        "/searches",
        json={"name": "Alex-readable", "filter": {"status": "open"}},
        headers=_auth(alex),
    )
    assert resp.status_code == 201
    search_id = resp.json()["id"]

    resp = client.get(f"/searches/{search_id}", headers=_auth(agent))
    assert resp.status_code == 200, "agents must be able to read any saved search"
