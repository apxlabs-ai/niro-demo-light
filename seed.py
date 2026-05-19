"""Seed a few users so manual testing has accounts ready to log in with."""
from sqlalchemy import select, text

from app.auth import hash_password
from app.db import Base, SessionLocal, engine
from app.models import Role, User

Base.metadata.create_all(bind=engine)


def _migrate_report_runs_nullable_fk() -> None:
    """Make report_runs.scheduled_report_id nullable with ON DELETE SET NULL.

    The original schema created the column as NOT NULL with no ON DELETE
    clause. Two subsequent security fixes require it to be nullable:

    * The audit-trail fix (TC-DA11383F) nulls orphaned run FKs instead of
      deleting them when a schedule is deleted.
    * The ROWID-reuse fix (TC-25AFBB16) enables PRAGMA foreign_keys=ON,
      which makes the DB enforce the FK — a NOT NULL column with no ON
      DELETE clause triggers a constraint error on schedule deletion.

    SQLite does not support ALTER COLUMN, so we recreate the table.
    create_all() is idempotent for already-correct schemas (it checks the
    column info), but we guard with a pragma inspection to avoid running
    unnecessarily.
    """
    with engine.connect() as conn:
        cols = conn.execute(text("PRAGMA table_info(report_runs)")).mappings().all()
        col = next((c for c in cols if c["name"] == "scheduled_report_id"), None)
        if col is None or col["notnull"] == 0:
            # Column already nullable (or table doesn't exist yet) — nothing to do.
            return

        conn.execute(text("PRAGMA foreign_keys=OFF"))
        conn.execute(text("""
            CREATE TABLE _report_runs_new (
                id INTEGER NOT NULL,
                scheduled_report_id INTEGER,
                ran_at DATETIME NOT NULL,
                result_count INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                success BOOLEAN NOT NULL,
                error VARCHAR,
                result_ticket_ids_json TEXT NOT NULL,
                PRIMARY KEY (id),
                FOREIGN KEY(scheduled_report_id)
                    REFERENCES scheduled_reports (id)
                    ON DELETE SET NULL
            )
        """))
        conn.execute(text("""
            INSERT INTO _report_runs_new
            SELECT id, scheduled_report_id, ran_at, result_count,
                   duration_ms, success, error, result_ticket_ids_json
            FROM report_runs
        """))
        conn.execute(text("DROP TABLE report_runs"))
        conn.execute(text("ALTER TABLE _report_runs_new RENAME TO report_runs"))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_report_runs_scheduled_report_id
            ON report_runs (scheduled_report_id)
        """))
        conn.execute(text("PRAGMA foreign_keys=ON"))
        conn.commit()


_migrate_report_runs_nullable_fk()

SEED = [
    ("agent@helpdesk.test", "Alice Agent", Role.agent, "agent-pass-1234"),
    ("alex@customer.test", "Alex Customer", Role.customer, "customer-pass-1234"),
    ("blair@customer.test", "Blair Customer", Role.customer, "customer-pass-1234"),
]


def main():
    db = SessionLocal()
    try:
        for email, name, role, password in SEED:
            if db.scalar(select(User).where(User.email == email)):
                continue
            db.add(
                User(
                    email=email,
                    full_name=name,
                    role=role,
                    password_hash=hash_password(password),
                )
            )
        db.commit()
        print("seeded")
    finally:
        db.close()


if __name__ == "__main__":
    main()
