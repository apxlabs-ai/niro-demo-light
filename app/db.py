from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DB_URL = "sqlite:///./helpdesk.db"

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_or_migrate_schema():
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    if "saved_searches" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("saved_searches")}
    if "deleted_at" not in columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE saved_searches ADD COLUMN deleted_at DATETIME"))
