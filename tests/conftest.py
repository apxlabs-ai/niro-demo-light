import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.models import Priority, Role, SavedSearch, Status, Ticket, User
from app.search import serialize_filter


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture()
def customer_a(db_session):
    u = User(email="a@test.com", full_name="Customer A", role=Role.customer,
             password_hash=hash_password("pass"))
    db_session.add(u)
    db_session.commit()
    db_session.refresh(u)
    return u


@pytest.fixture()
def customer_b(db_session):
    u = User(email="b@test.com", full_name="Customer B", role=Role.customer,
             password_hash=hash_password("pass"))
    db_session.add(u)
    db_session.commit()
    db_session.refresh(u)
    return u


@pytest.fixture()
def agent_user(db_session):
    u = User(email="agent@test.com", full_name="Agent", role=Role.agent,
             password_hash=hash_password("pass"))
    db_session.add(u)
    db_session.commit()
    db_session.refresh(u)
    return u


@pytest.fixture()
def ticket_a(db_session, customer_a):
    t = Ticket(customer_id=customer_a.id, subject="Ticket A", description="desc",
               status=Status.open, priority=Priority.normal)
    db_session.add(t)
    db_session.commit()
    db_session.refresh(t)
    return t


@pytest.fixture()
def ticket_b(db_session, customer_b):
    t = Ticket(customer_id=customer_b.id, subject="Ticket B", description="desc",
               status=Status.open, priority=Priority.normal)
    db_session.add(t)
    db_session.commit()
    db_session.refresh(t)
    return t


@pytest.fixture()
def token_a(customer_a):
    return issue_token(customer_a)


@pytest.fixture()
def token_b(customer_b):
    return issue_token(customer_b)


@pytest.fixture()
def token_agent(agent_user):
    return issue_token(agent_user)


@pytest.fixture()
def client(db_session):
    def _override():
        yield db_session
    app.dependency_overrides[get_db] = _override
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def saved_search_a(db_session, customer_a):
    s = SavedSearch(owner_id=customer_a.id, name="A search",
                    filter_json=serialize_filter({}), pinned=False)
    db_session.add(s)
    db_session.commit()
    db_session.refresh(s)
    return s
