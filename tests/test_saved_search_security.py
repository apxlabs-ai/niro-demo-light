import os
import tempfile
import unittest

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password
from app.models import (
    Base,
    ReportFrequency,
    ReportRun,
    Role,
    SavedSearch,
    ScheduledReport,
    Ticket,
    User,
)
from app.routes.searches import (
    delete_search,
    disable_schedule,
    get_search,
    schedule_report,
    update_search,
)
from app.schemas import SavedSearchCreate, SavedSearchUpdate, ScheduleReportCreate
from app.search import serialize_filter


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
        Base.metadata.create_all(bind=self.engine)
        Session = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)
        self.db = Session()

        self.customer = User(
            email="alex@example.com",
            password_hash=hash_password("customer-pass-1234"),
            full_name="Customer A",
            role=Role.customer,
        )
        self.agent = User(
            email="agent@example.com",
            password_hash=hash_password("agent-pass-1234"),
            full_name="Agent",
            role=Role.agent,
        )
        self.db.add_all([self.customer, self.agent])
        self.db.commit()
        self.db.refresh(self.customer)
        self.db.refresh(self.agent)

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()
        os.environ.pop("HELPDESK_MAIL_LOG", None)
        try:
            os.unlink(self.mail_log.name)
        except OSError:
            pass

    def _saved_search(self, owner: User) -> SavedSearch:
        saved = SavedSearch(
            owner_id=owner.id,
            name="security regression search",
            filter_json=serialize_filter({"subject_contains": "security-marker"}),
        )
        self.db.add(saved)
        self.db.commit()
        self.db.refresh(saved)
        return saved

    def _schedule_with_run(self, saved: SavedSearch) -> tuple[ScheduledReport, ReportRun]:
        schedule = ScheduledReport(
            saved_search_id=saved.id,
            frequency=ReportFrequency.daily,
            email=self.customer.email,
        )
        run = ReportRun(
            schedule=schedule,
            success=True,
            result_count=1,
            result_ticket_ids_json="[1]",
        )
        self.db.add_all([schedule, run])
        self.db.commit()
        self.db.refresh(schedule)
        self.db.refresh(run)
        return schedule, run

    def test_unknown_filter_fields_are_rejected(self):
        with self.assertRaises(ValidationError):
            SavedSearchCreate.model_validate(
                {
                    "name": "unknown field",
                    "filter": {"definitely_not_a_filter": "no-match"},
                    "pinned": False,
                }
            )

    def test_schedule_delete_preserves_run_history(self):
        saved = self._saved_search(self.customer)
        schedule, run = self._schedule_with_run(saved)

        disable_schedule(schedule.id, self.customer, self.db)

        self.assertFalse(self.db.get(ScheduledReport, schedule.id).enabled)
        self.assertIsNotNone(self.db.get(ReportRun, run.id))

    def test_saved_search_delete_preserves_run_history(self):
        saved = self._saved_search(self.customer)
        schedule, run = self._schedule_with_run(saved)

        delete_search(saved.id, self.customer, self.db)

        self.assertIsNotNone(self.db.get(SavedSearch, saved.id))
        self.assertFalse(self.db.get(ScheduledReport, schedule.id).enabled)
        self.assertIsNotNone(self.db.get(ReportRun, run.id))
        with self.assertRaises(HTTPException) as get_err:
            get_search(saved.id, self.customer, self.db)
        self.assertEqual(get_err.exception.status_code, 404)
        with self.assertRaises(HTTPException) as schedule_err:
            schedule_report(
                saved.id,
                ScheduleReportCreate(
                    frequency=ReportFrequency.weekly,
                    email=self.customer.email,
                ),
                self.customer,
                self.db,
            )
        self.assertEqual(schedule_err.exception.status_code, 404)

    def test_owner_can_update_saved_search_name(self):
        saved = self._saved_search(self.customer)

        updated = update_search(
            saved.id,
            SavedSearchUpdate(name="renamed by owner"),
            self.customer,
            self.db,
        )

        self.assertEqual(updated.name, "renamed by owner")

    def test_agent_cannot_delete_customer_schedule(self):
        saved = self._saved_search(self.customer)
        schedule, _ = self._schedule_with_run(saved)

        with self.assertRaises(HTTPException) as err:
            disable_schedule(schedule.id, self.agent, self.db)

        self.assertEqual(err.exception.status_code, 403)
        self.assertTrue(self.db.get(ScheduledReport, schedule.id).enabled)

    def test_schedule_email_must_match_owner_email(self):
        saved = self._saved_search(self.agent)
        self.db.add(
            Ticket(
                customer_id=self.customer.id,
                subject="security-marker",
                description="confidential",
            )
        )
        self.db.commit()

        with self.assertRaises(HTTPException) as err:
            schedule_report(
                saved.id,
                ScheduleReportCreate(
                    frequency=ReportFrequency.daily,
                    email="external.recipient@gmail.com",
                ),
                self.agent,
                self.db,
            )

        self.assertEqual(err.exception.status_code, 422)
        count = self.db.scalar(select(func.count()).select_from(ScheduledReport))
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
