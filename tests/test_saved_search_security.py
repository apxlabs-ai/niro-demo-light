import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth import hash_password, issue_token
from app.db import get_db
from app.jobs import run_scheduled_report
from app.main import app
from app.models import (
    Base,
    ReportFrequency,
    ReportRun,
    Role,
    SavedSearch,
    ScheduledReport,
    User,
)
from app.search import cache_size, execute_search, invalidate_cache, serialize_filter


class SavedSearchSecurityTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        engine = create_engine(
            f"sqlite:///{self.db_path}",
            connect_args={"check_same_thread": False},
        )
        self.engine = engine
        TestingSessionLocal = sessionmaker(
            bind=engine, autoflush=False, expire_on_commit=False
        )
        Base.metadata.create_all(bind=engine)

        self.db = TestingSessionLocal()
        self.customer_a = User(
            email="a@example.test",
            password_hash=hash_password("password"),
            full_name="Customer A",
            role=Role.customer,
        )
        self.customer_b = User(
            email="b@example.test",
            password_hash=hash_password("password"),
            full_name="Customer B",
            role=Role.customer,
        )
        self.agent = User(
            email="agent@example.test",
            password_hash=hash_password("password"),
            full_name="Agent",
            role=Role.agent,
        )
        self.db.add_all([self.customer_a, self.customer_b, self.agent])
        self.db.commit()
        for user in (self.customer_a, self.customer_b, self.agent):
            self.db.refresh(user)

        def override_get_db():
            db = TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        invalidate_cache()
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()
        self.db.close()
        self.engine.dispose()
        os.unlink(self.db_path)
        invalidate_cache()

    def auth_headers(self, user):
        return {"Authorization": f"Bearer {issue_token(user)}"}

    def create_ticket(self, user, subject):
        res = self.client.post(
            "/tickets",
            headers=self.auth_headers(user),
            json={
                "subject": subject,
                "description": f"{subject} description",
                "priority": "normal",
            },
        )
        self.assertEqual(res.status_code, 201, res.text)
        return res.json()

    def create_search(self, user, name, filter_body):
        res = self.client.post(
            "/searches",
            headers=self.auth_headers(user),
            json={"name": name, "filter": filter_body, "pinned": False},
        )
        self.assertEqual(res.status_code, 201, res.text)
        return res.json()

    def test_search_cache_is_scoped_per_customer(self):
        prefix = "cache-scope-regression"
        ticket_a = self.create_ticket(self.customer_a, f"{prefix} A private")
        ticket_b = self.create_ticket(self.customer_b, f"{prefix} B private")
        search_a = self.create_search(
            self.customer_a, "A search", {"subject_contains": prefix}
        )
        search_b = self.create_search(
            self.customer_b, "B search", {"subject_contains": prefix}
        )

        first = self.client.get(
            f"/searches/{search_a['id']}/run", headers=self.auth_headers(self.customer_a)
        )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual([t["id"] for t in first.json()["tickets"]], [ticket_a["id"]])

        second = self.client.get(
            f"/searches/{search_b['id']}/run", headers=self.auth_headers(self.customer_b)
        )
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual([t["id"] for t in second.json()["tickets"]], [ticket_b["id"]])

    def test_me_returns_seed_style_test_domain_email(self):
        res = self.client.get("/me", headers=self.auth_headers(self.customer_a))
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()["email"], self.customer_a.email)

    def test_scheduled_report_uses_saved_search_owner_scope(self):
        ticket_b = self.create_ticket(self.customer_b, "scheduled B private")
        search_a = self.create_search(
            self.customer_a, "Cross-customer report", {"customer_id": self.customer_b.id}
        )

        on_demand = self.client.get(
            f"/searches/{search_a['id']}/run", headers=self.auth_headers(self.customer_a)
        )
        self.assertEqual(on_demand.status_code, 200, on_demand.text)
        self.assertEqual(on_demand.json()["tickets"], [])

        scheduled = self.client.post(
            f"/searches/{search_a['id']}/schedule",
            headers=self.auth_headers(self.customer_a),
            json={"frequency": "daily", "email": "attacker@example.com"},
        )
        self.assertEqual(scheduled.status_code, 201, scheduled.text)
        body = scheduled.json()
        self.assertEqual(body["initial_run"]["result_count"], 0)
        self.assertEqual(json.loads(body["initial_run"]["result_ticket_ids_json"]), [])
        self.assertNotIn(
            ticket_b["id"],
            json.loads(body["initial_run"]["result_ticket_ids_json"]),
        )

    def test_scheduled_report_initial_run_is_bounded(self):
        prefix = "scheduled bounded regression"
        for i in range(55):
            self.create_ticket(self.customer_a, f"{prefix} {i:02d}")
        search = self.create_search(
            self.customer_a,
            "Bounded scheduled report",
            {"subject_contains": prefix},
        )

        scheduled = self.client.post(
            f"/searches/{search['id']}/schedule",
            headers=self.auth_headers(self.customer_a),
            json={"frequency": "daily", "email": "owner@example.com"},
        )
        self.assertEqual(scheduled.status_code, 201, scheduled.text)
        body = scheduled.json()
        self.assertEqual(body["initial_run"]["result_count"], 50)
        self.assertEqual(
            len(json.loads(body["initial_run"]["result_ticket_ids_json"])),
            50,
        )
        self.assertEqual(len(body["initial_results"]), 50)

    def test_agent_cannot_mutate_customer_saved_search(self):
        search = self.create_search(self.customer_a, "Owner settings", {})

        res = self.client.patch(
            f"/searches/{search['id']}",
            headers=self.auth_headers(self.agent),
            json={"name": "Agent edited", "pinned": True},
        )
        self.assertEqual(res.status_code, 403, res.text)

    def test_agent_runs_customer_search_with_owner_scope(self):
        ticket_a = self.create_ticket(self.customer_a, "owner scoped A")
        ticket_b = self.create_ticket(self.customer_b, "owner scoped B")
        search = self.create_search(self.customer_a, "Owner scoped search", {})

        res = self.client.get(
            f"/searches/{search['id']}/run",
            headers=self.auth_headers(self.agent),
        )
        self.assertEqual(res.status_code, 200, res.text)
        ticket_ids = [ticket["id"] for ticket in res.json()["tickets"]]
        self.assertIn(ticket_a["id"], ticket_ids)
        self.assertNotIn(ticket_b["id"], ticket_ids)

    def test_agent_cannot_read_customer_schedule_metadata_or_runs(self):
        search = self.create_search(self.customer_a, "Private schedule", {})
        scheduled = self.client.post(
            f"/searches/{search['id']}/schedule",
            headers=self.auth_headers(self.customer_a),
            json={"frequency": "daily", "email": "owner@example.com"},
        )
        self.assertEqual(scheduled.status_code, 201, scheduled.text)
        schedule_id = scheduled.json()["schedule"]["id"]

        schedules = self.client.get(
            f"/searches/{search['id']}/schedule",
            headers=self.auth_headers(self.agent),
        )
        self.assertEqual(schedules.status_code, 403, schedules.text)

        runs = self.client.get(
            f"/searches/schedules/{schedule_id}/runs",
            headers=self.auth_headers(self.agent),
        )
        self.assertEqual(runs.status_code, 403, runs.text)

    def test_schedule_delete_preserves_run_history(self):
        search = self.create_search(self.customer_a, "Audit history", {})
        scheduled = self.client.post(
            f"/searches/{search['id']}/schedule",
            headers=self.auth_headers(self.customer_a),
            json={"frequency": "daily", "email": "owner@example.com"},
        )
        self.assertEqual(scheduled.status_code, 201, scheduled.text)
        schedule_id = scheduled.json()["schedule"]["id"]
        run_id = scheduled.json()["initial_run"]["id"]

        before_delete = self.client.get(
            f"/searches/schedules/{schedule_id}/runs",
            headers=self.auth_headers(self.customer_a),
        )
        self.assertEqual(before_delete.status_code, 200, before_delete.text)
        self.assertIn(run_id, [run["id"] for run in before_delete.json()])

        deleted = self.client.delete(
            f"/searches/schedules/{schedule_id}",
            headers=self.auth_headers(self.customer_a),
        )
        self.assertEqual(deleted.status_code, 204, deleted.text)

        after_delete = self.client.get(
            f"/searches/schedules/{schedule_id}/runs",
            headers=self.auth_headers(self.customer_a),
        )
        self.assertEqual(after_delete.status_code, 200, after_delete.text)
        self.assertIn(run_id, [run["id"] for run in after_delete.json()])

    def test_agent_cannot_schedule_customer_ticket_report_to_external_email(self):
        prefix = "agent-external-report-regression"
        self.create_ticket(self.customer_a, f"{prefix} confidential")
        search = self.create_search(
            self.agent, "Agent global search", {"subject_contains": prefix}
        )

        scheduled = self.client.post(
            f"/searches/{search['id']}/schedule",
            headers=self.auth_headers(self.agent),
            json={"frequency": "daily", "email": "attacker@example.com"},
        )
        self.assertEqual(scheduled.status_code, 403, scheduled.text)

    def test_legacy_agent_owned_schedule_is_disabled_and_not_exposed(self):
        self.create_ticket(self.customer_a, "legacy agent schedule private")
        saved = SavedSearch(
            owner_id=self.agent.id,
            name="Legacy agent report",
            filter_json=serialize_filter({"subject_contains": "legacy agent schedule"}),
            pinned=False,
        )
        self.db.add(saved)
        self.db.commit()
        self.db.refresh(saved)
        sched = ScheduledReport(
            saved_search_id=saved.id,
            frequency=ReportFrequency.daily,
            email="external.recipient@example.net",
            enabled=True,
        )
        self.db.add(sched)
        self.db.commit()
        self.db.refresh(sched)
        self.db.add(
            ReportRun(
                scheduled_report_id=sched.id,
                success=True,
                result_count=1,
                result_ticket_ids_json="[1]",
            )
        )
        self.db.commit()

        schedules = self.client.get(
            f"/searches/{saved.id}/schedule",
            headers=self.auth_headers(self.agent),
        )
        self.assertEqual(schedules.status_code, 200, schedules.text)
        self.assertEqual(schedules.json(), [])

        runs = self.client.get(
            f"/searches/schedules/{sched.id}/runs",
            headers=self.auth_headers(self.agent),
        )
        self.assertEqual(runs.status_code, 404, runs.text)

        worker_run = run_scheduled_report(sched.id, self.db)
        self.assertFalse(worker_run.success)
        self.assertEqual(worker_run.result_ticket_ids_json, "[]")
        self.db.refresh(sched)
        self.assertFalse(sched.enabled)

    def test_reserved_deleted_search_names_are_rejected(self):
        create_res = self.client.post(
            "/searches",
            headers=self.auth_headers(self.customer_a),
            json={
                "name": "__deleted__:reserved",
                "filter": {},
                "pinned": False,
            },
        )
        self.assertEqual(create_res.status_code, 422, create_res.text)

        search = self.create_search(self.customer_a, "Normal name", {})
        update_res = self.client.patch(
            f"/searches/{search['id']}",
            headers=self.auth_headers(self.customer_a),
            json={"name": "__deleted__:renamed"},
        )
        self.assertEqual(update_res.status_code, 422, update_res.text)

    def test_deleted_at_marks_search_inaccessible_without_name_prefix(self):
        saved = SavedSearch(
            owner_id=self.customer_a.id,
            name="Legacy deleted without prefix",
            filter_json=serialize_filter({}),
            pinned=False,
            deleted_at=datetime.utcnow(),
        )
        self.db.add(saved)
        self.db.commit()
        self.db.refresh(saved)

        for method, path, kwargs in (
            ("get", f"/searches/{saved.id}", {}),
            ("get", f"/searches/{saved.id}/run", {}),
            ("patch", f"/searches/{saved.id}", {"json": {"name": "mutated"}}),
            (
                "post",
                f"/searches/{saved.id}/schedule",
                {"json": {"frequency": "daily", "email": "owner@example.com"}},
            ),
        ):
            res = getattr(self.client, method)(
                path,
                headers=self.auth_headers(self.customer_a),
                **kwargs,
            )
            self.assertEqual(res.status_code, 404, res.text)

    def test_enabled_schedules_per_search_are_capped(self):
        search = self.create_search(self.customer_a, "Quota search", {})
        for i in range(5):
            res = self.client.post(
                f"/searches/{search['id']}/schedule",
                headers=self.auth_headers(self.customer_a),
                json={"frequency": "hourly", "email": f"owner{i}@example.com"},
            )
            self.assertEqual(res.status_code, 201, res.text)

        over_quota = self.client.post(
            f"/searches/{search['id']}/schedule",
            headers=self.auth_headers(self.customer_a),
            json={"frequency": "hourly", "email": "owner5@example.com"},
        )
        self.assertEqual(over_quota.status_code, 409, over_quota.text)

    def test_disabled_schedule_rows_count_toward_schedule_quota(self):
        search = self.create_search(self.customer_a, "Disabled schedule quota", {})
        for i in range(5):
            created = self.client.post(
                f"/searches/{search['id']}/schedule",
                headers=self.auth_headers(self.customer_a),
                json={"frequency": "daily", "email": f"disabled{i}@example.com"},
            )
            self.assertEqual(created.status_code, 201, created.text)
            deleted = self.client.delete(
                f"/searches/schedules/{created.json()['schedule']['id']}",
                headers=self.auth_headers(self.customer_a),
            )
            self.assertEqual(deleted.status_code, 204, deleted.text)

        over_quota = self.client.post(
            f"/searches/{search['id']}/schedule",
            headers=self.auth_headers(self.customer_a),
            json={"frequency": "daily", "email": "disabled5@example.com"},
        )
        self.assertEqual(over_quota.status_code, 409, over_quota.text)

        schedules = self.client.get(
            f"/searches/{search['id']}/schedule",
            headers=self.auth_headers(self.customer_a),
        )
        self.assertEqual(schedules.status_code, 200, schedules.text)
        self.assertEqual(len(schedules.json()), 5)

    def test_search_result_cache_has_a_hard_entry_cap(self):
        for i in range(35):
            execute_search(
                serialize_filter({"subject_contains": f"cache-cap-regression-{i}"}),
                self.db,
                scope=self.customer_a,
            )

        self.assertLessEqual(cache_size(), 32)

    def test_saved_search_delete_preserves_schedule_run_history(self):
        search = self.create_search(self.customer_a, "Search delete audit", {})
        scheduled = self.client.post(
            f"/searches/{search['id']}/schedule",
            headers=self.auth_headers(self.customer_a),
            json={"frequency": "daily", "email": "owner@example.com"},
        )
        self.assertEqual(scheduled.status_code, 201, scheduled.text)
        schedule_id = scheduled.json()["schedule"]["id"]
        run_id = scheduled.json()["initial_run"]["id"]

        deleted = self.client.delete(
            f"/searches/{search['id']}",
            headers=self.auth_headers(self.customer_a),
        )
        self.assertEqual(deleted.status_code, 204, deleted.text)

        runs = self.client.get(
            f"/searches/schedules/{schedule_id}/runs",
            headers=self.auth_headers(self.customer_a),
        )
        self.assertEqual(runs.status_code, 200, runs.text)
        self.assertIn(run_id, [run["id"] for run in runs.json()])

        get_deleted = self.client.get(
            f"/searches/{search['id']}",
            headers=self.auth_headers(self.customer_a),
        )
        self.assertEqual(get_deleted.status_code, 404, get_deleted.text)

        run_deleted = self.client.get(
            f"/searches/{search['id']}/run",
            headers=self.auth_headers(self.customer_a),
        )
        self.assertEqual(run_deleted.status_code, 404, run_deleted.text)

        patch_deleted = self.client.patch(
            f"/searches/{search['id']}",
            headers=self.auth_headers(self.customer_a),
            json={"name": "mutated after delete"},
        )
        self.assertEqual(patch_deleted.status_code, 404, patch_deleted.text)

        schedule_deleted = self.client.post(
            f"/searches/{search['id']}/schedule",
            headers=self.auth_headers(self.customer_a),
            json={"frequency": "daily", "email": "owner2@example.com"},
        )
        self.assertEqual(schedule_deleted.status_code, 404, schedule_deleted.text)

    def test_saved_searches_are_quota_limited_and_paginated(self):
        for i in range(10):
            self.create_search(self.customer_a, f"Quota {i}", {})

        over_quota = self.client.post(
            "/searches",
            headers=self.auth_headers(self.customer_a),
            json={"name": "Quota 10", "filter": {}, "pinned": False},
        )
        self.assertEqual(over_quota.status_code, 409, over_quota.text)

        first_page = self.client.get(
            "/searches?limit=1", headers=self.auth_headers(self.customer_a)
        )
        self.assertEqual(first_page.status_code, 200, first_page.text)
        self.assertEqual(len(first_page.json()), 1)

    def test_saved_search_run_results_are_paginated(self):
        for i in range(60):
            self.create_ticket(self.customer_a, f"run page ticket {i:02d}")
        search = self.create_search(self.customer_a, "Run page", {})

        default_page = self.client.get(
            f"/searches/{search['id']}/run",
            headers=self.auth_headers(self.customer_a),
        )
        self.assertEqual(default_page.status_code, 200, default_page.text)
        self.assertEqual(default_page.json()["count"], 50)
        self.assertEqual(len(default_page.json()["tickets"]), 50)

        limited_page = self.client.get(
            f"/searches/{search['id']}/run?limit=10&offset=50",
            headers=self.auth_headers(self.customer_a),
        )
        self.assertEqual(limited_page.status_code, 200, limited_page.text)
        self.assertEqual(limited_page.json()["count"], 10)
        self.assertEqual(len(limited_page.json()["tickets"]), 10)

    def test_schedule_quota_resists_parallel_creation(self):
        search = self.create_search(self.customer_a, "Parallel quota", {})

        def create_schedule(i):
            return self.client.post(
                f"/searches/{search['id']}/schedule",
                headers=self.auth_headers(self.customer_a),
                json={"frequency": "hourly", "email": f"parallel{i}@example.com"},
            ).status_code

        with ThreadPoolExecutor(max_workers=10) as pool:
            statuses = list(pool.map(create_schedule, range(10)))

        self.assertLessEqual(statuses.count(201), 5)
        schedules = self.client.get(
            f"/searches/{search['id']}/schedule",
            headers=self.auth_headers(self.customer_a),
        )
        self.assertEqual(schedules.status_code, 200, schedules.text)
        enabled = [schedule for schedule in schedules.json() if schedule["enabled"]]
        self.assertLessEqual(len(enabled), 5)

    def test_datetime_filters_compare_as_datetimes(self):
        ticket = self.create_ticket(self.customer_a, "date filter ticket")
        created_at = ticket["created_at"]
        day = created_at.split("T", 1)[0]

        before_midnight = self.create_search(
            self.customer_a,
            "Before midnight",
            {"created_before": f"{day}T00:00:00"},
        )
        before_res = self.client.get(
            f"/searches/{before_midnight['id']}/run",
            headers=self.auth_headers(self.customer_a),
        )
        self.assertEqual(before_res.status_code, 200, before_res.text)
        self.assertEqual(before_res.json()["tickets"], [])

        after_midnight = self.create_search(
            self.customer_a,
            "After midnight",
            {"created_after": f"{day}T00:00:00"},
        )
        after_res = self.client.get(
            f"/searches/{after_midnight['id']}/run",
            headers=self.auth_headers(self.customer_a),
        )
        self.assertEqual(after_res.status_code, 200, after_res.text)
        self.assertEqual([row["id"] for row in after_res.json()["tickets"]], [ticket["id"]])


if __name__ == "__main__":
    unittest.main()
