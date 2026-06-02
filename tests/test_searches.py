"""Regression tests for saved-search and scheduled-report security findings.

Each test documents a specific vulnerability found by the niro pentest and
MUST fail on the unfixed code, then pass once the fix is applied.

TC-9C47BD76: customer can direct a report to an arbitrary email address.
TC-60737F35: agent can PATCH another customer's saved search (filter tampering).
TC-E1668FF5: agent can schedule a report on another customer's saved search.
TC-0B2A920F: /_stats route shadowed by /{search_id:int} → 422 instead of stats.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.models import Role, User


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
def users(db):
    """Seed customer A, customer B, and an agent."""
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
    for u in (alex, blair, agent):
        db.refresh(u)
    return alex, blair, agent


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


def _auth(user: User) -> dict:
    return {"Authorization": f"Bearer {issue_token(user)}"}


def _create_search(client, user, *, filter_body=None, name="my search"):
    payload = {"name": name, "filter": filter_body or {}}
    resp = client.post("/searches", json=payload, headers=_auth(user))
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# TC-9C47BD76 — arbitrary email recipient in scheduled reports
# ---------------------------------------------------------------------------

def test_customer_cannot_send_report_to_arbitrary_email(client, users):
    """TC-9C47BD76: scheduling a report to an address the user doesn't own
    must be rejected.

    FAILS before fix (returns 201 with attacker@evil.com as recipient).
    PASSES after fix (returns 4xx).
    """
    alex, _, _ = users
    sid = _create_search(client, alex, name="my open tickets")
    resp = client.post(
        f"/searches/{sid}/schedule",
        json={"frequency": "daily", "email": "attacker@evil.com"},
        headers=_auth(alex),
    )
    assert resp.status_code in (400, 403, 422), (
        f"TC-9C47BD76: expected 4xx for arbitrary recipient email, got {resp.status_code}: {resp.text}"
    )


def test_customer_can_send_report_to_own_email(client, users):
    """Sanity: scheduling to the user's own email must still work after fix."""
    alex, _, _ = users
    sid = _create_search(client, alex, name="self-report")
    resp = client.post(
        f"/searches/{sid}/schedule",
        json={"frequency": "daily", "email": alex.email},
        headers=_auth(alex),
    )
    assert resp.status_code == 201, (
        f"scheduling to own email must succeed, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TC-60737F35 — agent can PATCH another customer's saved search
# ---------------------------------------------------------------------------

def test_agent_cannot_patch_customer_saved_search(client, users):
    """TC-60737F35: an agent must not be able to mutate another customer's
    saved search.

    FAILS before fix (returns 200 with mutated filter_json).
    PASSES after fix (returns 403).
    """
    _, blair, agent = users
    sid = _create_search(client, blair, name="blair's search")

    resp = client.patch(
        f"/searches/{sid}",
        json={"filter": {"subject_contains": "password"}},
        headers=_auth(agent),
    )
    assert resp.status_code == 403, (
        f"TC-60737F35: agent must not PATCH customer search, got {resp.status_code}: {resp.text}"
    )


def test_agent_can_patch_own_saved_search(client, users):
    """Sanity: an agent can update a search they own."""
    _, _, agent = users
    sid = _create_search(client, agent, name="agent's search")

    resp = client.patch(
        f"/searches/{sid}",
        json={"name": "agent's renamed search"},
        headers=_auth(agent),
    )
    assert resp.status_code == 200, (
        f"agent patching own search must succeed, got {resp.status_code}: {resp.text}"
    )


def test_customer_can_patch_own_saved_search(client, users):
    """Sanity: a customer can update their own search."""
    alex, _, _ = users
    sid = _create_search(client, alex, name="alex's search")

    resp = client.patch(
        f"/searches/{sid}",
        json={"pinned": True},
        headers=_auth(alex),
    )
    assert resp.status_code == 200, (
        f"customer patching own search must succeed, got {resp.status_code}: {resp.text}"
    )


def test_customer_cannot_patch_another_customers_search(client, users):
    """Cross-customer write access must always be rejected."""
    alex, blair, _ = users
    sid = _create_search(client, blair, name="blair's search")

    resp = client.patch(
        f"/searches/{sid}",
        json={"name": "hijacked"},
        headers=_auth(alex),
    )
    assert resp.status_code == 403, (
        f"customer must not PATCH another customer's search, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TC-E1668FF5 — agent can schedule a report on another customer's saved search
# ---------------------------------------------------------------------------

def test_agent_cannot_schedule_report_on_customer_search(client, users):
    """TC-E1668FF5: an agent must not be able to wire a recurring email report
    onto another customer's saved search, directing ticket data to an external
    address.

    FAILS before fix (returns 201 with the schedule active).
    PASSES after fix (returns 403).
    """
    _, blair, agent = users
    sid = _create_search(client, blair, name="blair's private search")

    resp = client.post(
        f"/searches/{sid}/schedule",
        json={"frequency": "hourly", "email": "attacker@evil.com"},
        headers=_auth(agent),
    )
    assert resp.status_code == 403, (
        f"TC-E1668FF5: agent must not schedule report on customer search, "
        f"got {resp.status_code}: {resp.text}"
    )


def test_agent_can_schedule_report_on_own_search(client, users):
    """Sanity: an agent can schedule a report on a search they own."""
    _, _, agent = users
    sid = _create_search(client, agent, name="agent's search")

    resp = client.post(
        f"/searches/{sid}/schedule",
        json={"frequency": "daily", "email": agent.email},
        headers=_auth(agent),
    )
    assert resp.status_code == 201, (
        f"agent scheduling own search must succeed, got {resp.status_code}: {resp.text}"
    )


def test_customer_can_schedule_report_on_own_search(client, users):
    """Sanity: a customer can schedule a report on their own search
    using their own email."""
    alex, _, _ = users
    sid = _create_search(client, alex, name="alex's search")

    resp = client.post(
        f"/searches/{sid}/schedule",
        json={"frequency": "weekly", "email": alex.email},
        headers=_auth(alex),
    )
    assert resp.status_code == 201, (
        f"customer scheduling own search must succeed, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# TC-0B2A920F — /_stats route shadowed by /{search_id:int}
# ---------------------------------------------------------------------------

def test_stats_endpoint_reachable_by_agent(client, users):
    """TC-0B2A920F: GET /searches/_stats must return 200 for agents, not 422.

    FAILS before fix (FastAPI resolves '_stats' against the earlier
    /{search_id:int} parameter and returns 422).
    PASSES after fix (static route registered before the parameterized one).
    """
    _, _, agent = users
    resp = client.get("/searches/_stats", headers=_auth(agent))
    assert resp.status_code == 200, (
        f"TC-0B2A920F: /_stats must return 200 for agent, got {resp.status_code}: {resp.text}"
    )


def test_stats_endpoint_requires_agent_role(client, users):
    """/_stats must not be accessible by customers (agent role required)."""
    alex, _, _ = users
    resp = client.get("/searches/_stats", headers=_auth(alex))
    assert resp.status_code == 403, (
        f"/_stats must return 403 for customers, got {resp.status_code}: {resp.text}"
    )
