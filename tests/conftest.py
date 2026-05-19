import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password
from app.db import Base, get_db
from app.main import app
from app.models import Role, Status, Ticket, User


@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,  # single shared connection — tables persist across sessions
    )
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(engine)

    db = Session()
    agent = User(email="agent@test.com", password_hash=hash_password("pass"), full_name="Agent", role=Role.agent)
    cust_a = User(email="a@test.com", password_hash=hash_password("pass"), full_name="A", role=Role.customer)
    cust_b = User(email="b@test.com", password_hash=hash_password("pass"), full_name="B", role=Role.customer)
    db.add_all([agent, cust_a, cust_b])
    db.commit()

    ticket = Ticket(customer_id=cust_a.id, subject="A's ticket", description="private", status=Status.closed)
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    ticket_id = ticket.id
    db.close()

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as c:
        c._ticket_id = ticket_id
        yield c
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)


def _login(client, email: str) -> str:
    resp = client.post("/auth/login", data={"username": email, "password": "pass"})
    assert resp.status_code == 200, f"login failed: {resp.text}"
    return resp.json()["access_token"]
