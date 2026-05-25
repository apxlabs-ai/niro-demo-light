import json
import os
import tempfile
import unittest

from fastapi import HTTPException
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
from app.routes.searches import schedule_report, update_search
from app.schemas import SavedSearchUpdate, ScheduleReportCreate
from app.search import execute_search, invalidate_cache, serialize_filter


class SavedSearchSecurityTests(unittest.TestCase):
    def setUp(self):
        self.mail_log = tempfile.NamedTemporaryFile(delete=False)
        self.mail_log.close()
        os.environ["HELPDESK_MAIL_LOG"] = self.mail_log.name

        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(
            bind=self.engine, autoflush=False, expire_on_commit=False
        )
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
        self.agent = User(
            email="agent@example.test",
            password_hash=hash_password("password-agent"),
            full_name="Agent",
            role=Role.agent,
        )
        self.db.add_all([self.customer_a, self.customer_b, self.agent])
        self.db.commit()
        self.db.refresh(self.customer_a)
        self.db.refresh(self.customer_b)
        self.db.refresh(self.agent)
        invalidate_cache()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()
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
        ticket_a = self._ticket(self.customer_a, f"{marker} A")
        ticket_b = self._ticket(self.customer_b, f"{marker} B")
        filter_json = serialize_filter({"subject_contains": marker})

        rows_a = execute_search(filter_json, self.db, scope=self.customer_a)
        rows_b = execute_search(filter_json, self.db, scope=self.customer_b)

        self.assertEqual([ticket_a.id], [row["id"] for row in rows_a])
        self.assertEqual([ticket_b.id], [row["id"] for row in rows_b])

    def test_scheduled_report_is_scoped_to_saved_search_owner(self):
        marker = "scheduled-scope-marker"
        self._ticket(self.customer_a, f"{marker} A")
        ticket_b = self._ticket(self.customer_b, f"{marker} B")
        saved = SavedSearch(
            owner_id=self.customer_b.id,
            name="Customer B scheduler",
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
        self.assertEqual(1, run.result_count)
        self.assertEqual([ticket_b.id], json.loads(run.result_ticket_ids_json))

    def test_agent_cannot_modify_customer_saved_search(self):
        saved = SavedSearch(
            owner_id=self.customer_a.id,
            name="Customer A search",
            filter_json=serialize_filter({}),
        )
        self.db.add(saved)
        self.db.commit()
        self.db.refresh(saved)

        with self.assertRaises(HTTPException) as err:
            update_search(
                saved.id,
                SavedSearchUpdate(name="agent changed this"),
                user=self.agent,
                db=self.db,
            )

        self.assertEqual(403, err.exception.status_code)
        self.db.refresh(saved)
        self.assertEqual("Customer A search", saved.name)

    def test_agent_cannot_create_schedule_for_customer_saved_search(self):
        saved = SavedSearch(
            owner_id=self.customer_a.id,
            name="Customer A schedule target",
            filter_json=serialize_filter({}),
        )
        self.db.add(saved)
        self.db.commit()
        self.db.refresh(saved)

        with self.assertRaises(HTTPException) as err:
            schedule_report(
                saved.id,
                ScheduleReportCreate(
                    frequency=ReportFrequency.daily,
                    email="agent-controlled@example.com",
                ),
                user=self.agent,
                db=self.db,
            )

        self.assertEqual(403, err.exception.status_code)
        self.assertEqual(0, self.db.query(ScheduledReport).count())


if __name__ == "__main__":
    unittest.main()
