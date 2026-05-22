import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import search as search_module
from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.models import Role, User

TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture(autouse=True)
def clear_search_cache():
    search_module.invalidate_cache()
    yield
    search_module.invalidate_cache()


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
    TestSession = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)
    session = TestSession()
    yield session
    session.close()


@pytest.fixture()
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _make_user(db_session, email: str, role: Role) -> User:
    user = User(
        email=email,
        password_hash=hash_password("testpass"),
        full_name="Test User",
        role=role,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def user_a(db_session):
    return _make_user(db_session, "a@example.com", Role.customer)


@pytest.fixture()
def user_b(db_session):
    return _make_user(db_session, "b@example.com", Role.customer)


@pytest.fixture()
def tok_a(user_a):
    return issue_token(user_a)


@pytest.fixture()
def tok_b(user_b):
    return issue_token(user_b)
