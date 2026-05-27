"""Shared fixtures: in-memory SQLite DB + FastAPI TestClient."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password
from app.db import Base, get_db
from app.main import app
from app.models import Role, Ticket, User
from app.search import _cache  # for manual cache inspection

TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture()
def db_engine():
    engine = create_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture()
def db_session(db_engine):
    Session = sessionmaker(bind=db_engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture()
def client(db_session):
    """TestClient wired to the in-memory session; cache cleared each test."""
    _cache.clear()

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()
    _cache.clear()


# --- helpers ----------------------------------------------------------

def _make_user(db, email, role, password="pass"):
    u = User(email=email, full_name=email, role=role, password_hash=hash_password(password))
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def _make_ticket(db, customer: User, subject: str):
    t = Ticket(
        customer_id=customer.id,
        subject=subject,
        description=subject,
        status="open",
        priority="normal",
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def _login(client, email, password="pass"):
    r = client.post("/auth/login", data={"username": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}
