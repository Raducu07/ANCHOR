# app/assistant_usage_limits.py
#
# Backend PR 2D — per-clinic Assistant usage limits.
#
# Cost-control guardrail enforced BEFORE any assistant_runs insert and
# BEFORE any model call. Every assistant_runs row counts toward both
# windows regardless of run_status — `created`, `generation_succeeded`,
# `generation_refused`, and `generation_failed` are all "attempts".
#
# Doctrine preserved:
#   * Tenant-safe — counts only the caller's own clinic_id under existing
#     RLS/get_db session pattern. Includes clinic_id predicate explicitly
#     for performance + intent clarity, but does NOT bypass RLS.
#   * Metadata-only — the count query touches no input/output text.
#   * Defaults — invalid or missing env vars fall back to the documented
#     defaults; a deployment cannot accidentally disable the guardrail by
#     supplying a malformed value.
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

DEFAULT_DAILY_LIMIT = 50
DEFAULT_MONTHLY_LIMIT = 1000

DAILY_LIMIT_ENV = "ANCHOR_ASSISTANT_DAILY_RUN_LIMIT_PER_CLINIC"
MONTHLY_LIMIT_ENV = "ANCHOR_ASSISTANT_MONTHLY_RUN_LIMIT_PER_CLINIC"


def _read_positive_int(env_name: str, default: int) -> int:
    """Read a positive integer from the environment.

    Returns `default` for any of:
      - missing env var
      - empty / whitespace-only value
      - non-integer value
      - integer <= 0  (zero or negative would silently disable the guardrail)
    """
    raw = os.getenv(env_name, "")
    try:
        n = int(raw.strip())
    except (ValueError, AttributeError):
        return default
    if n <= 0:
        return default
    return n


def daily_run_limit() -> int:
    return _read_positive_int(DAILY_LIMIT_ENV, DEFAULT_DAILY_LIMIT)


def monthly_run_limit() -> int:
    return _read_positive_int(MONTHLY_LIMIT_ENV, DEFAULT_MONTHLY_LIMIT)


# ---------------------------------------------------------------------
# Window helpers (UTC)
# ---------------------------------------------------------------------

def utc_day_start(now: datetime) -> datetime:
    """UTC midnight at the start of `now`'s day."""
    n = now.astimezone(timezone.utc) if now.tzinfo else now.replace(tzinfo=timezone.utc)
    return n.replace(hour=0, minute=0, second=0, microsecond=0)


def utc_month_start(now: datetime) -> datetime:
    """UTC midnight on the first day of `now`'s month."""
    n = now.astimezone(timezone.utc) if now.tzinfo else now.replace(tzinfo=timezone.utc)
    return n.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


# ---------------------------------------------------------------------
# Count query
# ---------------------------------------------------------------------
#
# Intentionally NOT filtered by run_status — every assistant_runs row is
# a governed attempt for accounting purposes (PR 2D doctrine).

_COUNT_SQL = """
SELECT COUNT(*) AS c
FROM assistant_runs
WHERE clinic_id = CAST(:clinic_id AS uuid)
  AND created_at >= :window_start
"""


def _count_runs_since(
    db: Session,
    *,
    clinic_id: str,
    window_start: datetime,
) -> int:
    row = (
        db.execute(
            text(_COUNT_SQL),
            {"clinic_id": clinic_id, "window_start": window_start},
        )
        .mappings()
        .first()
    )
    if not row:
        return 0
    try:
        return int(row.get("c") or 0)
    except (TypeError, ValueError):
        return 0


def get_assistant_run_counts(
    db: Session,
    *,
    clinic_id: str,
    now: Optional[datetime] = None,
) -> Tuple[int, int]:
    """Returns (daily_count, monthly_count) for `clinic_id`. Both queries
    always execute — the caller decides which threshold matters."""
    n = now or datetime.now(timezone.utc)
    daily = _count_runs_since(db, clinic_id=clinic_id, window_start=utc_day_start(n))
    monthly = _count_runs_since(db, clinic_id=clinic_id, window_start=utc_month_start(n))
    return daily, monthly


# ---------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------

class AssistantUsageLimitExceeded(Exception):
    """Raised by enforce_assistant_run_limits() when a clinic is over a
    daily or monthly run cap. Carries the window + limit + current count
    so the route can return a controlled 429 response."""

    def __init__(self, *, window: str, limit: int, current_count: int) -> None:
        super().__init__(f"assistant {window} run limit exceeded")
        self.window = window
        self.limit = limit
        self.current_count = current_count


def enforce_assistant_run_limits(
    db: Session,
    *,
    clinic_id: str,
    now: Optional[datetime] = None,
) -> None:
    """Raise AssistantUsageLimitExceeded if `clinic_id` is at-or-above
    either the daily or monthly run cap. Daily is checked first."""
    daily_count, monthly_count = get_assistant_run_counts(
        db, clinic_id=clinic_id, now=now
    )
    d_limit = daily_run_limit()
    m_limit = monthly_run_limit()

    if daily_count >= d_limit:
        raise AssistantUsageLimitExceeded(
            window="day", limit=d_limit, current_count=daily_count
        )
    if monthly_count >= m_limit:
        raise AssistantUsageLimitExceeded(
            window="month", limit=m_limit, current_count=monthly_count
        )
