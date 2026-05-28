import json
import os
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.models import Role, User
from app.search import invalidate_cache


@pytest.fixture()
def client_and_users():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(
        f"sqlite:///{db_path}", connect_args={"check_same_thread": False}
    )
    TestingSessionLocal = sessionmaker(
        bind=engine, autoflush=False, expire_on_commit=False
    )
    Base.metadata.create_all(bind=engine)

    db = TestingSessionLocal()
    customer_a = User(
        email="a@example.test",
        password_hash=hash_password("password"),
        full_name="Customer A",
        role=Role.customer,
    )
    customer_b = User(
        email="b@example.test",
        password_hash=hash_password("password"),
        full_name="Customer B",
        role=Role.customer,
    )
    agent = User(
        email="agent@example.test",
        password_hash=hash_password("password"),
        full_name="Agent",
        role=Role.agent,
    )
    db.add_all([customer_a, customer_b, agent])
    db.commit()
    for user in (customer_a, customer_b, agent):
        db.refresh(user)

    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    invalidate_cache()
    try:
        with TestClient(app) as client:
            yield client, customer_a, customer_b, agent
    finally:
        app.dependency_overrides.clear()
        app.middleware_stack = None
        db.close()
        engine.dispose()
        os.unlink(db_path)
        invalidate_cache()


def _auth_headers(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(user)}"}


def _create_ticket(client: TestClient, user: User, subject: str) -> dict:
    response = client.post(
        "/tickets",
        headers=_auth_headers(user),
        json={
            "subject": subject,
            "description": f"{subject} description",
            "priority": "normal",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _create_search(
    client: TestClient, user: User, name: str, filter_body: dict
) -> dict:
    response = client.post(
        "/searches",
        headers=_auth_headers(user),
        json={"name": name, "filter": filter_body, "pinned": False},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_search_cache_is_scoped_per_customer(client_and_users):
    client, customer_a, customer_b, _ = client_and_users
    marker = "cache-scope-regression"
    ticket_a = _create_ticket(client, customer_a, f"{marker} A private")
    ticket_b = _create_ticket(client, customer_b, f"{marker} B private")
    search_a = _create_search(
        client, customer_a, "A search", {"subject_contains": marker}
    )
    search_b = _create_search(
        client, customer_b, "B search", {"subject_contains": marker}
    )

    first = client.get(
        f"/searches/{search_a['id']}/run", headers=_auth_headers(customer_a)
    )
    assert first.status_code == 200, first.text
    assert [ticket["id"] for ticket in first.json()["tickets"]] == [ticket_a["id"]]

    second = client.get(
        f"/searches/{search_b['id']}/run", headers=_auth_headers(customer_b)
    )
    assert second.status_code == 200, second.text
    assert [ticket["id"] for ticket in second.json()["tickets"]] == [ticket_b["id"]]


def test_scheduled_report_uses_saved_search_owner_scope(client_and_users):
    client, customer_a, customer_b, _ = client_and_users
    ticket_b = _create_ticket(client, customer_b, "scheduled B private")
    search_a = _create_search(client, customer_a, "Empty owner report", {})

    scheduled = client.post(
        f"/searches/{search_a['id']}/schedule",
        headers=_auth_headers(customer_a),
        json={"frequency": "daily", "email": "attacker@example.com"},
    )
    assert scheduled.status_code == 201, scheduled.text
    body = scheduled.json()

    run_ticket_ids = json.loads(body["initial_run"]["result_ticket_ids_json"])
    assert ticket_b["id"] not in run_ticket_ids
    assert all(ticket["customer_id"] == customer_a.id for ticket in body["initial_results"])
    assert body["initial_run"]["result_count"] == len(body["initial_results"])


def test_agent_cannot_mutate_customer_saved_search(client_and_users):
    client, customer_a, _, agent = client_and_users
    search = _create_search(client, customer_a, "Owner settings", {})

    response = client.patch(
        f"/searches/{search['id']}",
        headers=_auth_headers(agent),
        json={"name": "Agent edited", "pinned": True},
    )
    assert response.status_code == 403, response.text
