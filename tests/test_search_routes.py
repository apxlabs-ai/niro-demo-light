import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password
from app.db import Base, get_db
from app.main import app
from app.models import Role, Ticket, User
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
def seeded_users(db):
    alex = User(
        email="alex@customer.example.com",
        full_name="Alex Customer",
        role=Role.customer,
        password_hash=hash_password("customer-pass"),
    )
    blair = User(
        email="blair@customer.example.com",
        full_name="Blair Customer",
        role=Role.customer,
        password_hash=hash_password("customer-pass"),
    )
    agent = User(
        email="agent@helpdesk.example.com",
        full_name="Helpdesk Agent",
        role=Role.agent,
        password_hash=hash_password("agent-pass"),
    )
    db.add_all([alex, blair, agent])
    db.commit()
    db.refresh(alex)
    db.refresh(blair)
    db.refresh(agent)

    db.add_all(
        [
            Ticket(
                customer_id=alex.id,
                subject="A_ticket",
                description="owned by alex",
            ),
            Ticket(
                customer_id=blair.id,
                subject="B_ticket",
                description="owned by blair",
            ),
        ]
    )
    db.commit()
    return alex, blair, agent


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


def _token(client: TestClient, username: str, password: str) -> str:
    resp = client.post(
        "/auth/login",
        data={"username": username, "password": password},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_search(client: TestClient, token: str) -> dict:
    resp = client.post(
        "/searches",
        json={
            "name": "Customer owned search",
            "filter": {"subject_contains": "A_ticket"},
            "pinned": False,
        },
        headers=_auth(token),
    )
    assert resp.status_code == 201
    return resp.json()


def test_agent_cannot_update_customer_owned_search(client, seeded_users):
    customer_token = _token(client, "alex@customer.example.com", "customer-pass")
    agent_token = _token(client, "agent@helpdesk.example.com", "agent-pass")
    saved = _create_search(client, customer_token)

    resp = client.patch(
        f"/searches/{saved['id']}",
        json={"name": "Agent changed search", "pinned": True},
        headers=_auth(agent_token),
    )

    assert resp.status_code == 403
    followup = client.get(f"/searches/{saved['id']}", headers=_auth(customer_token))
    assert followup.status_code == 200
    assert followup.json()["name"] == "Customer owned search"
    assert followup.json()["pinned"] is False


def test_agent_cannot_schedule_customer_owned_search(client, seeded_users):
    customer_token = _token(client, "alex@customer.example.com", "customer-pass")
    agent_token = _token(client, "agent@helpdesk.example.com", "agent-pass")
    saved = _create_search(client, customer_token)

    resp = client.post(
        f"/searches/{saved['id']}/schedule",
        json={"frequency": "daily", "email": "outside@example.com"},
        headers=_auth(agent_token),
    )

    assert resp.status_code == 403


def test_disable_schedule_preserves_run_history(client, seeded_users):
    customer_token = _token(client, "alex@customer.example.com", "customer-pass")
    saved = _create_search(client, customer_token)
    created = client.post(
        f"/searches/{saved['id']}/schedule",
        json={"frequency": "daily", "email": "alex@example.com"},
        headers=_auth(customer_token),
    )
    assert created.status_code == 201
    schedule_id = created.json()["schedule"]["id"]

    before = client.get(
        f"/searches/schedules/{schedule_id}/runs",
        headers=_auth(customer_token),
    )
    assert before.status_code == 200
    assert len(before.json()) == 1

    deleted = client.delete(
        f"/searches/schedules/{schedule_id}",
        headers=_auth(customer_token),
    )
    assert deleted.status_code == 204

    after = client.get(
        f"/searches/schedules/{schedule_id}/runs",
        headers=_auth(customer_token),
    )
    assert after.status_code == 200
    assert after.json()[0]["id"] == before.json()[0]["id"]
