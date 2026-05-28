import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.models import ReportRun, Role, Ticket, User
from app.search import invalidate_cache


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
    invalidate_cache()


@pytest.fixture()
def users(db):
    alex = User(
        email="alex@customer.example.com",
        full_name="Alex Customer",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    blair = User(
        email="blair@customer.example.com",
        full_name="Blair Customer",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    agent = User(
        email="agent@helpdesk.example.com",
        full_name="Helpdesk Agent",
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
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(user)}"}


def _create_ticket(client: TestClient, user: User, subject: str) -> dict:
    resp = client.post(
        "/tickets",
        headers=_auth(user),
        json={
            "subject": subject,
            "description": f"description for {subject}",
            "priority": "normal",
        },
    )
    assert resp.status_code == 201
    return resp.json()


def _create_search(client: TestClient, user: User, name: str, filter_: dict) -> dict:
    resp = client.post(
        "/searches",
        headers=_auth(user),
        json={"name": name, "filter": filter_, "pinned": False},
    )
    assert resp.status_code == 201
    return resp.json()


def test_saved_search_cache_is_scoped_per_customer(client, users):
    alex, blair, _ = users
    alex_ticket = _create_ticket(client, alex, "alex cache scope marker")
    blair_ticket = _create_ticket(client, blair, "blair cache scope marker")
    alex_search = _create_search(client, alex, "alex all tickets", {})
    blair_search = _create_search(client, blair, "blair all tickets", {})

    alex_run = client.get(f"/searches/{alex_search['id']}/run", headers=_auth(alex))
    assert alex_run.status_code == 200
    assert {t["customer_id"] for t in alex_run.json()["tickets"]} == {alex.id}

    blair_run = client.get(f"/searches/{blair_search['id']}/run", headers=_auth(blair))
    assert blair_run.status_code == 200
    blair_ids = {t["id"] for t in blair_run.json()["tickets"]}

    assert blair_ticket["id"] in blair_ids
    assert alex_ticket["id"] not in blair_ids
    assert {t["customer_id"] for t in blair_run.json()["tickets"]} == {blair.id}


def test_scheduled_report_initial_run_is_scoped_to_owner(client, db, users):
    alex, blair, _ = users
    marker = "scheduled owner scope marker"
    alex_ticket = _create_ticket(client, alex, f"alex {marker}")
    blair_ticket = _create_ticket(client, blair, f"blair {marker}")
    saved = _create_search(client, alex, "alex scheduled report", {"subject_contains": marker})

    resp = client.post(
        f"/searches/{saved['id']}/schedule",
        headers=_auth(alex),
        json={"frequency": "daily", "email": "alex@example.com"},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["initial_run"]["result_count"] == 1
    assert json.loads(body["initial_run"]["result_ticket_ids_json"]) == [alex_ticket["id"]]
    assert {t["id"] for t in body["initial_results"]} == {alex_ticket["id"]}
    assert blair_ticket["id"] not in json.loads(
        db.get(ReportRun, body["initial_run"]["id"]).result_ticket_ids_json
    )


def test_agent_cannot_modify_customer_saved_search(client, users):
    alex, _, agent = users
    saved = _create_search(client, alex, "alex private search", {})

    resp = client.patch(
        f"/searches/{saved['id']}",
        headers=_auth(agent),
        json={"name": "agent modified", "pinned": True},
    )

    assert resp.status_code == 403
    owner_view = client.get(f"/searches/{saved['id']}", headers=_auth(alex))
    assert owner_view.status_code == 200
    assert owner_view.json()["name"] == "alex private search"
    assert owner_view.json()["pinned"] is False


def test_agent_cannot_schedule_customer_saved_search(client, users):
    alex, _, agent = users
    saved = _create_search(client, alex, "alex private report", {})

    resp = client.post(
        f"/searches/{saved['id']}/schedule",
        headers=_auth(agent),
        json={"frequency": "daily", "email": "agent@example.com"},
    )

    assert resp.status_code == 403
