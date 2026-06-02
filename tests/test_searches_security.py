import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.models import Role, Ticket, User
from app.search import invalidate_cache


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    invalidate_cache()
    yield session
    invalidate_cache()
    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def demo_data(db):
    alex = User(
        email="alex@customer.test",
        full_name="Alex Customer",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    blair = User(
        email="blair@customer.test",
        full_name="Blair Customer",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    agent = User(
        email="agent@helpdesk.test",
        full_name="Helpdesk Agent",
        role=Role.agent,
        password_hash=hash_password("x"),
    )
    db.add_all([alex, blair, agent])
    db.commit()
    db.refresh(alex)
    db.refresh(blair)
    db.refresh(agent)

    alex_ticket = Ticket(
        customer_id=alex.id,
        subject="alex private marker",
        description="alex only",
        priority="normal",
    )
    blair_ticket = Ticket(
        customer_id=blair.id,
        subject="blair private marker",
        description="blair only",
        priority="normal",
    )
    db.add_all([alex_ticket, blair_ticket])
    db.commit()
    db.refresh(alex_ticket)
    db.refresh(blair_ticket)

    return alex, blair, agent, alex_ticket, blair_ticket


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()
    app.middleware_stack = None


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(user)}"}


def _create_search(client: TestClient, user: User, name: str, filter_: dict):
    resp = client.post(
        "/searches",
        headers=_auth(user),
        json={"name": name, "filter": filter_, "pinned": False},
    )
    assert resp.status_code == 201
    return resp.json()


def test_saved_search_cache_is_scoped_per_customer(client, demo_data):
    alex, blair, _, alex_ticket, blair_ticket = demo_data
    alex_search = _create_search(client, alex, "alex all", {})
    blair_search = _create_search(client, blair, "blair all", {})

    alex_resp = client.get(f"/searches/{alex_search['id']}/run", headers=_auth(alex))
    assert alex_resp.status_code == 200
    assert {t["id"] for t in alex_resp.json()["tickets"]} == {alex_ticket.id}

    blair_resp = client.get(f"/searches/{blair_search['id']}/run", headers=_auth(blair))
    assert blair_resp.status_code == 200
    assert {t["id"] for t in blair_resp.json()["tickets"]} == {blair_ticket.id}


def test_scheduled_report_run_is_scoped_to_saved_search_owner(client, demo_data):
    _, blair, _, _, blair_ticket = demo_data
    search = _create_search(client, blair, "blair scheduled all", {})

    resp = client.post(
        f"/searches/{search['id']}/schedule",
        headers=_auth(blair),
        json={"frequency": "daily", "email": "blair@example.com"},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["initial_run"]["result_count"] == 1
    assert json.loads(body["initial_run"]["result_ticket_ids_json"]) == [blair_ticket.id]


def test_agent_cannot_mutate_or_schedule_customer_saved_search(client, demo_data):
    alex, _, agent, _, _ = demo_data
    patch_target = _create_search(client, alex, "alex patch target", {"status": "open"})
    delete_target = _create_search(client, alex, "alex delete target", {"status": "open"})
    schedule_target = _create_search(
        client, alex, "alex schedule target", {"status": "open"}
    )

    patch_resp = client.patch(
        f"/searches/{patch_target['id']}",
        headers=_auth(agent),
        json={"name": "agent changed it", "pinned": True},
    )
    assert patch_resp.status_code == 403

    delete_resp = client.delete(
        f"/searches/{delete_target['id']}",
        headers=_auth(agent),
    )
    assert delete_resp.status_code == 403

    schedule_resp = client.post(
        f"/searches/{schedule_target['id']}/schedule",
        headers=_auth(agent),
        json={"frequency": "daily", "email": "agent@example.com"},
    )
    assert schedule_resp.status_code == 403

    persisted = client.get(f"/searches/{patch_target['id']}", headers=_auth(alex))
    assert persisted.status_code == 200
    assert persisted.json()["name"] == "alex patch target"

    assert db_get_search_exists(client, alex, delete_target["id"])


def test_agent_cannot_read_customer_schedule_or_run_history(client, demo_data):
    alex, _, agent, _, _ = demo_data
    search = _create_search(client, alex, "alex private schedule", {})
    create_resp = client.post(
        f"/searches/{search['id']}/schedule",
        headers=_auth(alex),
        json={"frequency": "daily", "email": "private-recipient@example.com"},
    )
    assert create_resp.status_code == 201
    schedule_id = create_resp.json()["schedule"]["id"]

    owner_schedules = client.get(f"/searches/{search['id']}/schedule", headers=_auth(alex))
    assert owner_schedules.status_code == 200
    assert owner_schedules.json()[0]["email"] == "private-recipient@example.com"

    agent_schedules = client.get(
        f"/searches/{search['id']}/schedule",
        headers=_auth(agent),
    )
    assert agent_schedules.status_code == 403

    owner_runs = client.get(
        f"/searches/schedules/{schedule_id}/runs",
        headers=_auth(alex),
    )
    assert owner_runs.status_code == 200
    assert owner_runs.json()[0]["scheduled_report_id"] == schedule_id

    agent_runs = client.get(
        f"/searches/schedules/{schedule_id}/runs",
        headers=_auth(agent),
    )
    assert agent_runs.status_code == 403


def db_get_search_exists(client: TestClient, user: User, search_id: int) -> bool:
    resp = client.get(f"/searches/{search_id}", headers=_auth(user))
    return resp.status_code == 200
