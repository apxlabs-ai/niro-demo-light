"""Seed a few users so manual testing has accounts ready to log in with."""
from sqlalchemy import select

from app.auth import hash_password
from app.db import SessionLocal, create_or_migrate_schema
from app.models import Role, User

create_or_migrate_schema()

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
