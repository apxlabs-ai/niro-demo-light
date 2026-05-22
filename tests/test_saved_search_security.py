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
from app.routes.searches import disable_schedule, schedule_report, update_search
from app.schemas import SavedSearchUpdate, ScheduleReportCreate
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

        self.assertEqual(err.exception.status_code, 403)
        self.db.refresh(saved)
        self.assertEqual(saved.name, "Customer A search")

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

        self.assertEqual(err.exception.status_code, 403)
        self.assertEqual(self.db.query(ScheduledReport).count(), 0)

    def test_agent_cannot_delete_customer_schedule(self):
        saved = SavedSearch(
            owner_id=self.customer_a.id,
            name="Customer A schedule",
            filter_json=serialize_filter({}),
        )
        self.db.add(saved)
        self.db.commit()
        self.db.refresh(saved)

        schedule = ScheduledReport(
            saved_search_id=saved.id,
            frequency=ReportFrequency.daily,
            email="customer@example.com",
        )
        self.db.add(schedule)
        self.db.commit()
        self.db.refresh(schedule)

        with self.assertRaises(HTTPException) as err:
            disable_schedule(schedule.id, user=self.agent, db=self.db)

        self.assertEqual(err.exception.status_code, 403)
        self.assertIsNotNone(self.db.get(ScheduledReport, schedule.id))


if __name__ == "__main__":
    unittest.main()
