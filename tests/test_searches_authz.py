"""Authorization regression tests for the saved-search subsystem.

Invariant under test: a helpdesk AGENT has *read-only* cross-tenant
access to saved searches and schedules (for analytics), but must NOT be
able to perform a WRITE on a saved search or schedule it does not own.
Every write by an agent on a customer-owned object must return 403.

These tests reproduce three findings that share one root cause — the
ownership helpers in app/routes/searches.py exempted agents from the
ownership check on both read AND write paths:

  * agent can create a schedule (with an arbitrary delivery email) on a
    customer's saved search        -> POST /searches/{id}/schedule
  * agent can rename / re-filter / delete a customer's saved search
                                    -> PATCH/DELETE /searches/{id}
  * agent can delete a customer's schedule
                                    -> DELETE /searches/schedules/{id}

Each write test is paired with a positive control (the legitimate owner
succeeds) and with a read control (the agent's read-only cross-tenant
access still works), so a red is provably the broken invariant rather
than a broken environment.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.models import Role, SavedSearch, User


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db():
    # StaticPool keeps a single underlying connection so the whole engine
    # shares one in-memory database across the TestClient's request thread
    # and the fixture thread (otherwise each pooled connection gets its own
    # empty :memory: DB and mid-request commits land in a different one).
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
def client(db):
    """TestClient with the in-memory DB overriding the real session."""
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def actors(db):
    """Two customers and one agent.

    `owner` owns the saved search exercised by the write tests; `other`
    is a second customer used to assert tenant isolation; `agent` is the
    cross-tenant helpdesk role whose write access must be denied.
    """
    owner = User(
        email="owner@customer.example.com",
        full_name="Owner Customer",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    other = User(
        email="other@customer.example.com",
        full_name="Other Customer",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    agent = User(
        email="agent@helpdesk.example.com",
        full_name="Helpdesk Agent",
        role=Role.agent,
        password_hash=hash_password("x"),
    )
    db.add_all([owner, other, agent])
    db.commit()
    for u in (owner, other, agent):
        db.refresh(u)
    return owner, other, agent


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(user)}"}


@pytest.fixture()
def owned_search(db, actors):
    """A saved search owned by `owner`."""
    owner, _other, _agent = actors
    from app.search import serialize_filter

    saved = SavedSearch(
        owner_id=owner.id,
        name="Owner private search",
        filter_json=serialize_filter({"status": "open"}),
        pinned=False,
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    return saved


def _create_schedule(client, owner, search_id) -> int:
    """Owner creates a schedule on their own search via the API and
    returns the new schedule id."""
    resp = client.post(
        f"/searches/{search_id}/schedule",
        headers=_auth(owner),
        json={"frequency": "daily", "email": "owner@customer.example.com"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["schedule"]["id"]


# ---------------------------------------------------------------------------
# Agent READ stays allowed (read-only cross-tenant analytics) — controls
# ---------------------------------------------------------------------------

def test_agent_can_read_non_owned_search(client, actors, owned_search):
    """Read control: agent GET on a customer's search still works (200)."""
    _owner, _other, agent = actors
    resp = client.get(f"/searches/{owned_search.id}", headers=_auth(agent))
    assert resp.status_code == 200
    assert resp.json()["id"] == owned_search.id


def test_agent_can_run_non_owned_search(client, actors, owned_search):
    """Read control: agent can execute a customer's saved search (200)."""
    _owner, _other, agent = actors
    resp = client.get(f"/searches/{owned_search.id}/run", headers=_auth(agent))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# TC-8DC5976D — agent must not schedule a report on a non-owned search
# ---------------------------------------------------------------------------

def test_owner_can_schedule_on_own_search(client, actors, owned_search):
    """Positive control: the legitimate owner can schedule -> 201."""
    owner, _other, _agent = actors
    resp = client.post(
        f"/searches/{owned_search.id}/schedule",
        headers=_auth(owner),
        json={"frequency": "daily", "email": "owner@customer.example.com"},
    )
    assert resp.status_code == 201, resp.text


def test_agent_cannot_schedule_on_non_owned_search(client, actors, owned_search):
    """Invariant: agent POST schedule on a customer's search -> 403.

    The vulnerable code let an agent attach a recurring report with an
    arbitrary delivery email to any customer's saved search.
    """
    _owner, _other, agent = actors
    resp = client.post(
        f"/searches/{owned_search.id}/schedule",
        headers=_auth(agent),
        json={"frequency": "daily", "email": "attacker@evil.example.com"},
    )
    assert resp.status_code == 403, (
        f"agent scheduled a report on a non-owned search (got {resp.status_code})"
    )


# ---------------------------------------------------------------------------
# TC-1EE62B5C — agent must not rename / re-filter / delete a customer search
# ---------------------------------------------------------------------------

def test_owner_can_patch_own_search(client, actors, owned_search):
    """Positive control: owner can rename their own search -> 200."""
    owner, _other, _agent = actors
    resp = client.patch(
        f"/searches/{owned_search.id}",
        headers=_auth(owner),
        json={"name": "Renamed by owner"},
    )
    assert resp.status_code == 200, resp.text


def test_agent_cannot_rename_non_owned_search(client, actors, owned_search):
    """Invariant: agent PATCH (rename) on a customer's search -> 403."""
    _owner, _other, agent = actors
    resp = client.patch(
        f"/searches/{owned_search.id}",
        headers=_auth(agent),
        json={"name": "AGENT_MODIFIED_no_consent"},
    )
    assert resp.status_code == 403, (
        f"agent renamed a non-owned search (got {resp.status_code})"
    )


def test_agent_cannot_refilter_non_owned_search(client, actors, owned_search):
    """Invariant: agent PATCH (re-filter) on a customer's search -> 403."""
    _owner, _other, agent = actors
    resp = client.patch(
        f"/searches/{owned_search.id}",
        headers=_auth(agent),
        json={"filter": {"status": "closed"}},
    )
    assert resp.status_code == 403, (
        f"agent changed a non-owned search's filter (got {resp.status_code})"
    )


def test_agent_cannot_delete_non_owned_search(client, actors, owned_search):
    """Invariant: agent DELETE on a customer's search -> 403, and the
    object must survive (the owner can still read it)."""
    owner, _other, agent = actors
    resp = client.delete(f"/searches/{owned_search.id}", headers=_auth(agent))
    assert resp.status_code == 403, (
        f"agent deleted a non-owned search (got {resp.status_code})"
    )
    # The search must still exist for its owner.
    still_there = client.get(f"/searches/{owned_search.id}", headers=_auth(owner))
    assert still_there.status_code == 200


# ---------------------------------------------------------------------------
# TC-C5A69F83 — agent must not delete a customer's schedule
# ---------------------------------------------------------------------------

def test_owner_can_delete_own_schedule(client, actors, owned_search):
    """Positive control: owner can delete their own schedule -> 204."""
    owner, _other, _agent = actors
    sched_id = _create_schedule(client, owner, owned_search.id)
    resp = client.delete(f"/searches/schedules/{sched_id}", headers=_auth(owner))
    assert resp.status_code == 204, resp.text


def test_agent_can_read_non_owned_schedule_list(client, actors, owned_search):
    """Read control: agent can list a customer's schedules (200)."""
    owner, _other, agent = actors
    _create_schedule(client, owner, owned_search.id)
    resp = client.get(
        f"/searches/{owned_search.id}/schedule", headers=_auth(agent)
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_agent_cannot_delete_non_owned_schedule(client, actors, owned_search):
    """Invariant: agent DELETE on a customer's schedule -> 403, and the
    schedule must survive (still visible to its owner)."""
    owner, _other, agent = actors
    sched_id = _create_schedule(client, owner, owned_search.id)

    resp = client.delete(
        f"/searches/schedules/{sched_id}", headers=_auth(agent)
    )
    assert resp.status_code == 403, (
        f"agent deleted a non-owned schedule (got {resp.status_code})"
    )
    # The schedule must still exist for its owner.
    listing = client.get(
        f"/searches/{owned_search.id}/schedule", headers=_auth(owner)
    )
    assert listing.status_code == 200
    assert any(s["id"] == sched_id for s in listing.json())
