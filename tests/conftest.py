"""Shared fixtures for all tests."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.auth import hash_password
from app.db import Base, get_db
from app.main import app
from app.models import Role, User

# Shared in-memory SQLite — all connections see the same database.
TEST_DB_URL = "sqlite:///file::memory:?cache=shared&uri=true"


@pytest.fixture(scope="session")
def engine():
    e = create_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=e)
    yield e
    Base.metadata.drop_all(bind=e)


@pytest.fixture(scope="session")
def _session_factory(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture()
def db(_session_factory):
    session = _session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(engine, _session_factory):
    """TestClient wired to the shared in-memory DB."""
    def override_get_db():
        session = _session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def seed_users(db):
    """Two customers + one agent. Cleans up after itself."""
    a = User(email="a@test.com", full_name="A", role=Role.customer,
             password_hash=hash_password("pass"))
    b = User(email="b@test.com", full_name="B", role=Role.customer,
             password_hash=hash_password("pass"))
    ag = User(email="agent@test.com", full_name="Agent", role=Role.agent,
              password_hash=hash_password("pass"))
    db.add_all([a, b, ag])
    db.commit()
    db.refresh(a)
    db.refresh(b)
    db.refresh(ag)
    yield a, b, ag
    for obj in [a, b, ag]:
        db.delete(obj)
    db.commit()


def login(client, email: str, password: str = "pass") -> str:
    """Return a Bearer token for the given credentials."""
    r = client.post("/auth/login", data={"username": email, "password": password})
    assert r.status_code == 200, r.text
    return "Bearer " + r.json()["access_token"]
