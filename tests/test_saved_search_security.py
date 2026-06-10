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


@pytest.fixture(autouse=True)
def clear_search_cache():
    invalidate_cache()
    yield
    invalidate_cache()


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
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def demo_data(db):
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

    alex_ticket = Ticket(
        customer_id=alex.id,
        subject="shared-marker alex-private",
        description="alex only",
        status="open",
        priority="normal",
    )
    blair_ticket = Ticket(
        customer_id=blair.id,
        subject="shared-marker blair-private",
        description="blair only",
        status="open",
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


def test_agent_cannot_modify_customer_saved_search(client, demo_data):
    alex, _, agent, *_ = demo_data
    created = client.post(
        "/searches",
        headers=_auth(alex),
        json={"name": "alex search", "filter": {}, "pinned": False},
    )
    assert created.status_code == 201
    search_id = created.json()["id"]

    changed = client.patch(
        f"/searches/{search_id}",
        headers=_auth(agent),
        json={"name": "agent rewrite", "pinned": True},
    )

    assert changed.status_code == 403
    persisted = client.get(f"/searches/{search_id}", headers=_auth(alex))
    assert persisted.json()["name"] == "alex search"
    assert persisted.json()["pinned"] is False


def test_saved_search_cache_is_scoped_per_customer(client, demo_data):
    alex, blair, _, alex_ticket, blair_ticket = demo_data
    body = {
        "name": "marker search",
        "filter": {"subject_contains": "shared-marker"},
        "pinned": False,
    }
    alex_search = client.post("/searches", headers=_auth(alex), json=body).json()
    alex_run = client.get(f"/searches/{alex_search['id']}/run", headers=_auth(alex))
    assert alex_run.status_code == 200
    assert [t["id"] for t in alex_run.json()["tickets"]] == [alex_ticket.id]

    blair_search = client.post("/searches", headers=_auth(blair), json=body).json()
    blair_run = client.get(f"/searches/{blair_search['id']}/run", headers=_auth(blair))

    assert blair_run.status_code == 200
    assert [t["id"] for t in blair_run.json()["tickets"]] == [blair_ticket.id]


def test_scheduled_report_initial_run_uses_owner_scope(client, demo_data):
    alex, blair, _, _, blair_ticket = demo_data
    created = client.post(
        "/searches",
        headers=_auth(alex),
        json={
            "name": "cross tenant schedule",
            "filter": {
                "customer_id": blair.id,
                "subject_contains": blair_ticket.subject,
            },
            "pinned": False,
        },
    )
    assert created.status_code == 201
    search_id = created.json()["id"]
    scoped_run = client.get(f"/searches/{search_id}/run", headers=_auth(alex))
    assert scoped_run.json() == {"count": 0, "tickets": []}

    scheduled = client.post(
        f"/searches/{search_id}/schedule",
        headers=_auth(alex),
        json={"frequency": "daily", "email": "alex@example.com"},
    )

    assert scheduled.status_code == 201
    body = scheduled.json()
    assert body["initial_run"]["success"] is True
    assert body["initial_run"]["result_count"] == 0
    assert body["initial_results"] == []
