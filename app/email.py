"""Mock email backend for scheduled reports.

In production this would be a real SMTP / SendGrid / SES adapter. In
dev + demo we write each "delivery" to a JSONL log file so operators
and integration tests can inspect what would have been sent without
needing a real mail relay.

The log path is /tmp/helpdesk-mail.log unless overridden via the
HELPDESK_MAIL_LOG environment variable.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any

_logger = logging.getLogger(__name__)

DEFAULT_LOG_PATH = "/tmp/helpdesk-mail.log"


def _log_path() -> str:
    return os.environ.get("HELPDESK_MAIL_LOG", DEFAULT_LOG_PATH)


def render_report_subject(search_name: str, result_count: int) -> str:
    """Subject line for a scheduled-report email."""
    return f"[Helpdesk] {search_name} — {result_count} ticket(s)"


def render_report_body(
    search_name: str, frequency: str, tickets: list[dict[str, Any]]
) -> str:
    """Plain-text body. Includes a compact one-line-per-ticket summary
    so the recipient gets the gist without opening an attachment."""
    lines = [
        f"Saved search: {search_name}",
        f"Frequency: {frequency}",
        f"Matching tickets: {len(tickets)}",
        "",
    ]
    if not tickets:
        lines.append("(no matches)")
    else:
        for t in tickets[:50]:  # cap the body so emails stay readable
            lines.append(
                f"  #{t['id']:>5}  [{t['status']:<16}] {t['priority']:<8} "
                f"{t['subject'][:80]}"
            )
        if len(tickets) > 50:
            lines.append(f"  … and {len(tickets) - 50} more.")
    lines.append("")
    lines.append("— Helpdesk")
    return "\n".join(lines)


def send_email(*, to: str, subject: str, body: str) -> dict[str, Any]:
    """Persist one mock email to the log file. Returns the record that
    was written so callers can attach it to audit rows (ReportRun)."""
    record = {
        "to": to,
        "subject": subject,
        "body": body,
        "sent_at": datetime.utcnow().isoformat(),
    }
    try:
        with open(_log_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as e:
        _logger.warning("mail log write failed: %s", e)
    return record
