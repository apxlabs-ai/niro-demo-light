"""Shared fixtures for the helpdesk test suite."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.models import Role, User
from app.auth import hash_password, issue_token
from app.main import app


@pytest.fixture()
def db():
    # StaticPool ensures all connections share the same in-memory DB.
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db):
    """TestClient wired to an isolated in-memory DB."""
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


def make_user(db, email: str, password: str, role: Role) -> User:
    u = User(
        email=email,
        password_hash=hash_password(password),
        full_name=email.split("@")[0],
        role=role,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def auth_header(user: User) -> dict:
    return {"Authorization": f"Bearer {issue_token(user)}"}
