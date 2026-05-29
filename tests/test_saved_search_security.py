import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.models import Role, SavedSearch, ScheduledReport, Ticket, User
from app.search import invalidate_cache, serialize_filter


@pytest.fixture()
def db():
    invalidate_cache()
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
    invalidate_cache()


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def users(db):
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
    return alex, blair, agent


def auth_headers(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(user)}"}


def create_ticket(db, customer: User, subject: str) -> Ticket:
    ticket = Ticket(
        customer_id=customer.id,
        subject=subject,
        description=f"description for {subject}",
        status="open",
        priority="normal",
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return ticket


def create_saved_search(db, owner: User, name: str, filter_dict: dict) -> SavedSearch:
    saved = SavedSearch(
        owner_id=owner.id,
        name=name,
        filter_json=serialize_filter(filter_dict),
        pinned=False,
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    return saved


def test_saved_search_result_cache_is_scoped_per_customer(client, db, users):
    alex, blair, _ = users
    marker = "cache-scope-regression"
    alex_ticket = create_ticket(db, alex, f"{marker} alex private")
    blair_ticket = create_ticket(db, blair, f"{marker} blair private")
    alex_search = create_saved_search(
        db, alex, "alex search", {"subject_contains": marker}
    )
    blair_search = create_saved_search(
        db, blair, "blair search", {"subject_contains": marker}
    )

    alex_resp = client.get(
        f"/searches/{alex_search.id}/run", headers=auth_headers(alex)
    )
    assert alex_resp.status_code == 200
    assert [t["id"] for t in alex_resp.json()["tickets"]] == [alex_ticket.id]

    blair_resp = client.get(
        f"/searches/{blair_search.id}/run", headers=auth_headers(blair)
    )
    assert blair_resp.status_code == 200
    assert [t["id"] for t in blair_resp.json()["tickets"]] == [blair_ticket.id]


def test_scheduled_report_initial_run_is_scoped_to_search_owner(client, db, users):
    alex, blair, _ = users
    marker = "schedule-scope-regression"
    alex_ticket = create_ticket(db, alex, f"{marker} alex private")
    blair_ticket = create_ticket(db, blair, f"{marker} blair private")
    alex_search = create_saved_search(
        db, alex, "alex scheduled search", {"subject_contains": marker}
    )

    resp = client.post(
        f"/searches/{alex_search.id}/schedule",
        headers=auth_headers(alex),
        json={"frequency": "daily", "email": "alex-report@example.com"},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["initial_run"]["result_count"] == 1
    assert json.loads(body["initial_run"]["result_ticket_ids_json"]) == [
        alex_ticket.id
    ]
    assert [t["id"] for t in body["initial_results"]] == [alex_ticket.id]
    assert blair_ticket.id not in json.loads(
        body["initial_run"]["result_ticket_ids_json"]
    )


def test_agent_cannot_update_customer_owned_saved_search(client, db, users):
    alex, _, agent = users
    saved = create_saved_search(
        db, alex, "customer-owned", {"subject_contains": "private"}
    )

    resp = client.patch(
        f"/searches/{saved.id}",
        headers=auth_headers(agent),
        json={"name": "agent-mutated", "pinned": True},
    )

    assert resp.status_code == 403
    db.refresh(saved)
    assert saved.name == "customer-owned"
    assert saved.pinned is False


def test_agent_cannot_delete_customer_owned_schedule(client, db, users):
    alex, _, agent = users
    saved = create_saved_search(
        db, alex, "customer-owned schedule", {"subject_contains": "private"}
    )
    schedule = ScheduledReport(
        saved_search_id=saved.id,
        frequency="daily",
        email="owner@example.com",
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    resp = client.delete(
        f"/searches/schedules/{schedule.id}", headers=auth_headers(agent)
    )

    assert resp.status_code == 403
    assert db.get(ScheduledReport, schedule.id) is not None
