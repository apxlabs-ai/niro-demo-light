import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

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
def users(db):
    alex = User(
        email="alex@example.test",
        full_name="Alex",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    blair = User(
        email="blair@example.test",
        full_name="Blair",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    agent = User(
        email="agent@example.test",
        full_name="Agent",
        role=Role.agent,
        password_hash=hash_password("x"),
    )
    db.add_all([alex, blair, agent])
    db.commit()
    for user in (alex, blair, agent):
        db.refresh(user)
    return alex, blair, agent


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()
    app.middleware_stack = None


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(user)}"}


def _create_ticket(db, owner: User, marker: str) -> Ticket:
    ticket = Ticket(
        customer_id=owner.id,
        subject=f"{marker} private",
        description=f"secret {marker}",
        priority="normal",
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    invalidate_cache()
    return ticket


def _create_search(client: TestClient, user: User, marker: str) -> int:
    resp = client.post(
        "/searches",
        headers=_auth(user),
        json={
            "name": f"search-{marker}",
            "filter": {"subject_contains": marker},
            "pinned": False,
        },
    )
    assert resp.status_code == 201
    return resp.json()["id"]


def test_saved_search_cache_is_scoped_per_customer(client, db, users):
    alex, blair, _ = users
    marker = f"cache-{uuid4()}"
    leaked_ticket = _create_ticket(db, alex, marker)

    alex_search_id = _create_search(client, alex, marker)
    resp = client.get(f"/searches/{alex_search_id}/run", headers=_auth(alex))
    assert resp.status_code == 200
    assert [t["id"] for t in resp.json()["tickets"]] == [leaked_ticket.id]

    blair_search_id = _create_search(client, blair, marker)
    resp = client.get(f"/searches/{blair_search_id}/run", headers=_auth(blair))

    assert resp.status_code == 200
    assert resp.json() == {"count": 0, "tickets": []}


def test_scheduled_report_initial_run_uses_owner_scope(client, db, users):
    alex, blair, _ = users
    marker = f"schedule-{uuid4()}"
    _create_ticket(db, alex, marker)

    blair_search_id = _create_search(client, blair, marker)
    run_resp = client.get(f"/searches/{blair_search_id}/run", headers=_auth(blair))
    assert run_resp.status_code == 200
    assert run_resp.json() == {"count": 0, "tickets": []}

    resp = client.post(
        f"/searches/{blair_search_id}/schedule",
        headers=_auth(blair),
        json={"frequency": "daily", "email": "blair@example.com"},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["initial_results"] == []
    assert body["initial_run"]["result_count"] == 0
    assert json.loads(body["initial_run"]["result_ticket_ids_json"]) == []


def test_agent_cannot_mutate_customer_saved_search(client, users):
    _, blair, agent = users
    marker = f"agent-mutate-{uuid4()}"
    blair_search_id = _create_search(client, blair, marker)

    resp = client.patch(
        f"/searches/{blair_search_id}",
        headers=_auth(agent),
        json={"name": "agent-overwrite"},
    )

    assert resp.status_code == 403
    read_resp = client.get(f"/searches/{blair_search_id}", headers=_auth(blair))
    assert read_resp.status_code == 200
    assert read_resp.json()["name"] == f"search-{marker}"
