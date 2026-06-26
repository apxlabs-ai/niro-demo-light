import json
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session, sessionmaker

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.models import Priority, ReportRun, Role, Ticket, User
from app.search import execute_search, invalidate_cache, serialize_filter


@pytest.fixture()
def db() -> Iterator[Session]:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = SessionLocal()
    invalidate_cache()
    try:
        yield session
    finally:
        invalidate_cache()
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db: Session) -> Iterator[TestClient]:
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def actors(db: Session) -> dict[str, User]:
    users = {
        "agent": User(
            email="agent@helpdesk.test",
            full_name="Helpdesk Agent",
            role=Role.agent,
            password_hash=hash_password("agent-pass-1234"),
        ),
        "customer_a": User(
            email="alex@customer.test",
            full_name="Alex Customer",
            role=Role.customer,
            password_hash=hash_password("customer-pass-1234"),
        ),
        "customer_b": User(
            email="blair@customer.test",
            full_name="Blair Customer",
            role=Role.customer,
            password_hash=hash_password("customer-pass-1234"),
        ),
    }
    db.add_all(users.values())
    db.commit()
    for user in users.values():
        db.refresh(user)
    return users


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(user)}"}


def _ticket(
    db: Session,
    owner: User,
    marker: str,
    label: str,
    *,
    priority: Priority = Priority.normal,
) -> Ticket:
    ticket = Ticket(
        customer_id=owner.id,
        subject=f"{marker} {label}",
        description=f"private ticket for {label}",
        priority=priority,
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    invalidate_cache()
    return ticket


def _create_search(client: TestClient, owner: User, marker: str) -> int:
    response = client.post(
        "/searches",
        headers=_auth(owner),
        json={
            "name": marker,
            "filter": {"subject_contains": marker},
            "pinned": False,
        },
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def test_saved_search_cache_is_partitioned_by_caller_scope(
    db: Session, actors: dict[str, User]
):
    marker = "tc-a938621b"
    ticket_a = _ticket(db, actors["customer_a"], marker, "customer-a")
    ticket_b = _ticket(db, actors["customer_b"], marker, "customer-b")
    filter_json = serialize_filter({"subject_contains": marker})

    agent_rows = execute_search(filter_json, db, scope=actors["agent"])
    agent_ids = {row["id"] for row in agent_rows}
    assert {ticket_a.id, ticket_b.id}.issubset(agent_ids)

    customer_rows = execute_search(filter_json, db, scope=actors["customer_a"])
    customer_ids = {row["id"] for row in customer_rows}

    assert ticket_a.id in customer_ids
    assert ticket_b.id not in customer_ids


def test_schedule_creation_response_stays_tenant_scoped_after_agent_cache_prime(
    client: TestClient, db: Session, actors: dict[str, User]
):
    marker = "tc-e6f65342"
    ticket_a = _ticket(db, actors["customer_a"], marker, "customer-a")
    ticket_b = _ticket(db, actors["customer_b"], marker, "customer-b")
    search_id = _create_search(client, actors["customer_a"], marker)

    agent_run = client.get(f"/searches/{search_id}/run", headers=_auth(actors["agent"]))
    assert agent_run.status_code == 200, agent_run.text
    agent_ids = {ticket["id"] for ticket in agent_run.json()["tickets"]}
    assert {ticket_a.id, ticket_b.id}.issubset(agent_ids)

    schedule = client.post(
        f"/searches/{search_id}/schedule",
        headers=_auth(actors["customer_a"]),
        json={"frequency": "daily", "email": "alex-reports@example.com"},
    )
    assert schedule.status_code == 201, schedule.text
    initial_result_ids = {ticket["id"] for ticket in schedule.json()["initial_results"]}

    assert ticket_a.id in initial_result_ids
    assert ticket_b.id not in initial_result_ids


def test_scheduled_report_run_history_stays_tenant_scoped(
    client: TestClient, db: Session, actors: dict[str, User]
):
    marker = "tc-a0adddba"
    ticket_a = _ticket(db, actors["customer_a"], marker, "customer-a")
    ticket_b = _ticket(db, actors["customer_b"], marker, "customer-b")
    search_id = _create_search(client, actors["customer_a"], marker)

    interactive = client.get(
        f"/searches/{search_id}/run", headers=_auth(actors["customer_a"])
    )
    assert interactive.status_code == 200, interactive.text
    interactive_ids = {ticket["id"] for ticket in interactive.json()["tickets"]}
    assert ticket_a.id in interactive_ids
    assert ticket_b.id not in interactive_ids

    direct_b = client.get(f"/tickets/{ticket_b.id}", headers=_auth(actors["customer_a"]))
    assert direct_b.status_code == 403

    schedule = client.post(
        f"/searches/{search_id}/schedule",
        headers=_auth(actors["customer_a"]),
        json={"frequency": "daily", "email": "alex-reports@example.com"},
    )
    assert schedule.status_code == 201, schedule.text
    body = schedule.json()
    schedule_id = int(body["schedule"]["id"])
    initial_run_ids = set(json.loads(body["initial_run"]["result_ticket_ids_json"]))

    history = client.get(
        f"/searches/schedules/{schedule_id}/runs",
        headers=_auth(actors["customer_a"]),
    )
    assert history.status_code == 200, history.text
    history_ids = [
        set(json.loads(run["result_ticket_ids_json"])) for run in history.json()
    ]

    assert ticket_a.id in initial_run_ids
    assert ticket_b.id not in initial_run_ids
    assert all(ticket_b.id not in run_ids for run_ids in history_ids)
    assert db.query(ReportRun).count() == 1
