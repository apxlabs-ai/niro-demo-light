from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import User


def _signup(client: TestClient, email: str):
    return client.post(
        "/auth/signup",
        json={
            "email": email,
            "password": "ProofPass123",
            "full_name": "Niro Proof",
        },
    )


def _observable_shape(response, submitted_email: str):
    body = response.json()
    if isinstance(body, dict):
        body = {
            key: (
                "<generated-id>"
                if key == "id" and isinstance(value, int)
                else "<submitted-email>"
                if value == submitted_email
                else value
            )
            for key, value in body.items()
        }
    return response.status_code, body


def test_signup_duplicate_and_fresh_email_are_indistinguishable():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    db = Session()
    app.dependency_overrides[get_db] = lambda: db

    try:
        with TestClient(app) as client:
            known_email = "known@example.com"
            fresh_email = "fresh@example.com"

            first = _signup(client, known_email)
            assert first.status_code == 201
            assert db.scalar(select(User).where(User.email == known_email)) is not None

            duplicate = _signup(client, known_email)
            fresh = _signup(client, fresh_email)
            assert db.scalar(select(User).where(User.email == fresh_email)) is not None

            assert _observable_shape(duplicate, known_email) == _observable_shape(
                fresh, fresh_email
            )
    finally:
        app.dependency_overrides.clear()
        app.middleware_stack = None
        db.close()
        Base.metadata.drop_all(bind=engine)
