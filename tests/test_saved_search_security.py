import json
import os
import tempfile
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password
from app.jobs import run_scheduled_report
from app.models import (
    Base,
    ReportFrequency,
    Role,
    SavedSearch,
    ScheduledReport,
    Ticket,
    User,
)
from app.search import execute_search, invalidate_cache, serialize_filter


class SavedSearchSecurityTests(unittest.TestCase):
    def setUp(self):
        invalidate_cache()
        self.mail_log = tempfile.NamedTemporaryFile(delete=False)
        self.mail_log.close()
        os.environ["HELPDESK_MAIL_LOG"] = self.mail_log.name

        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=engine)
        self.Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
        self.db = self.Session()

        self.customer_a = User(
            email="a@example.test",
            password_hash=hash_password("password-a"),
            full_name="Customer A",
            role=Role.customer,
        )
        self.customer_b = User(
            email="b@example.test",
            password_hash=hash_password("password-b"),
            full_name="Customer B",
            role=Role.customer,
        )
        self.db.add_all([self.customer_a, self.customer_b])
        self.db.commit()
        self.db.refresh(self.customer_a)
        self.db.refresh(self.customer_b)

    def tearDown(self):
        self.db.close()
        invalidate_cache()
        os.environ.pop("HELPDESK_MAIL_LOG", None)
        try:
            os.unlink(self.mail_log.name)
        except OSError:
            pass

    def _ticket(self, customer: User, subject: str) -> Ticket:
        ticket = Ticket(
            customer_id=customer.id,
            subject=subject,
            description=f"{subject} description",
        )
        self.db.add(ticket)
        self.db.commit()
        self.db.refresh(ticket)
        return ticket

    def test_search_cache_is_scoped_by_customer(self):
        marker = "shared-cache-marker"
        ticket_a = self._ticket(self.customer_a, marker)
        ticket_b = self._ticket(self.customer_b, marker)
        filter_json = serialize_filter({"subject_contains": marker})

        rows_a = execute_search(filter_json, self.db, scope=self.customer_a)
        rows_b = execute_search(filter_json, self.db, scope=self.customer_b)

        self.assertEqual([row["id"] for row in rows_a], [ticket_a.id])
        self.assertEqual([row["id"] for row in rows_b], [ticket_b.id])

    def test_scheduled_report_is_scoped_to_saved_search_owner(self):
        marker = "scheduled-scope-marker"
        ticket_a = self._ticket(self.customer_a, marker)
        self._ticket(self.customer_b, marker)

        saved = SavedSearch(
            owner_id=self.customer_a.id,
            name="Customer A schedule",
            filter_json=serialize_filter({"subject_contains": marker}),
        )
        self.db.add(saved)
        self.db.commit()
        self.db.refresh(saved)

        schedule = ScheduledReport(
            saved_search_id=saved.id,
            frequency=ReportFrequency.daily,
            email="reports@example.test",
        )
        self.db.add(schedule)
        self.db.commit()
        self.db.refresh(schedule)

        run = run_scheduled_report(schedule.id, self.db)

        self.assertTrue(run.success)
        self.assertEqual(run.result_count, 1)
        self.assertEqual(json.loads(run.result_ticket_ids_json), [ticket_a.id])


if __name__ == "__main__":
    unittest.main()
