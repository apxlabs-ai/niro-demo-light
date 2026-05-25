import json
import time
import unittest

from fastapi import HTTPException

from app.db import Base, SessionLocal, engine
from app.jobs import run_scheduled_report
from app.models import (
    ReportFrequency,
    SavedSearch,
    ScheduledReport,
    Ticket,
    User,
    Role,
)
from app.routes.searches import delete_search, disable_schedule, schedule_report, update_search
from app.schemas import SavedSearchUpdate, ScheduleReportCreate
from app.search import execute_search, invalidate_cache, serialize_filter


class SavedSearchSecurityTests(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(bind=engine)
        self.db = SessionLocal()
        invalidate_cache()
        self.marker = f"sec-{time.time_ns()}"

    def tearDown(self):
        self.db.close()
        invalidate_cache()

    def _user(self, role=Role.customer):
        user = User(
            email=f"{role.value}-{self.marker}-{time.time_ns()}@test.local",
            password_hash="unused",
            full_name=f"{role.value} {self.marker}",
            role=role,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def _ticket(self, owner, subject_suffix):
        ticket = Ticket(
            customer_id=owner.id,
            subject=f"{self.marker} {subject_suffix}",
            description=f"{self.marker} private body {subject_suffix}",
        )
        self.db.add(ticket)
        self.db.commit()
        self.db.refresh(ticket)
        return ticket

    def _saved_search(self, owner, filter_dict):
        saved = SavedSearch(
            owner_id=owner.id,
            name=f"search {self.marker}",
            filter_json=serialize_filter(filter_dict),
        )
        self.db.add(saved)
        self.db.commit()
        self.db.refresh(saved)
        return saved

    def test_customer_search_cache_is_scoped_by_customer(self):
        customer_a = self._user()
        customer_b = self._user()
        ticket_a = self._ticket(customer_a, "a secret")
        ticket_b = self._ticket(customer_b, "b own")
        filter_json = serialize_filter({"subject_contains": self.marker})

        rows_a = execute_search(filter_json, self.db, scope=customer_a)
        rows_b = execute_search(filter_json, self.db, scope=customer_b)

        self.assertEqual([ticket_a.id], [row["id"] for row in rows_a])
        self.assertEqual([ticket_b.id], [row["id"] for row in rows_b])

    def test_scheduled_report_uses_saved_search_owner_scope(self):
        customer_a = self._user()
        customer_b = self._user()
        self._ticket(customer_a, "a secret")
        ticket_b = self._ticket(customer_b, "b own")
        saved = self._saved_search(customer_b, {"subject_contains": self.marker})
        report = ScheduledReport(
            saved_search_id=saved.id,
            frequency=ReportFrequency.daily,
            email="recipient@example.test",
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)

        run = run_scheduled_report(report.id, self.db)

        self.assertTrue(run.success)
        self.assertEqual(1, run.result_count)
        self.assertEqual([ticket_b.id], json.loads(run.result_ticket_ids_json))

    def test_agents_cannot_mutate_customer_saved_searches(self):
        customer = self._user()
        agent = self._user(Role.agent)
        saved = self._saved_search(customer, {})

        with self.assertRaises(HTTPException) as patch_error:
            update_search(
                saved.id,
                SavedSearchUpdate(name="agent modified", pinned=True),
                user=agent,
                db=self.db,
            )
        self.assertEqual(403, patch_error.exception.status_code)

        with self.assertRaises(HTTPException) as delete_error:
            delete_search(saved.id, user=agent, db=self.db)
        self.assertEqual(403, delete_error.exception.status_code)

    def test_agents_cannot_create_customer_saved_search_schedules(self):
        customer = self._user()
        agent = self._user(Role.agent)
        saved = self._saved_search(customer, {})

        with self.assertRaises(HTTPException) as schedule_error:
            schedule_report(
                saved.id,
                ScheduleReportCreate(email="attacker@example.com"),
                user=agent,
                db=self.db,
            )
        self.assertEqual(403, schedule_error.exception.status_code)

    def test_agents_cannot_delete_customer_saved_search_schedules(self):
        customer = self._user()
        agent = self._user(Role.agent)
        saved = self._saved_search(customer, {})
        report = ScheduledReport(
            saved_search_id=saved.id,
            frequency=ReportFrequency.daily,
            email="owner@example.test",
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)

        with self.assertRaises(HTTPException) as delete_error:
            disable_schedule(report.id, user=agent, db=self.db)
        self.assertEqual(403, delete_error.exception.status_code)
