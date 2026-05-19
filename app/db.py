import sqlite3

from sqlalchemy import event, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DB_URL = "sqlite:///./helpdesk.db"

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})


@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, _connection_record):
    """Enable FK enforcement on every new SQLite connection.

    SQLite ships with foreign-key constraints OFF by default. Without
    this, ON DELETE SET NULL / ON DELETE CASCADE clauses in the schema
    are silently ignored, which lets orphaned rows accumulate and
    (together with ROWID reuse) enables cross-tenant data leaks via
    reused schedule IDs. The PRAGMA must be set per-connection because
    SQLite resets it on each new connection.
    """
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
