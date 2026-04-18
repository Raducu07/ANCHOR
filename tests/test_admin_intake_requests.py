from __future__ import annotations

import os
import sys
from pathlib import Path

# Make repo root importable in both local runs and CI.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Allow importing app.db without needing a live database connection.
os.environ.setdefault("DATABASE_URL", "postgresql://anchor:anchor@localhost/anchor_test")
os.environ.setdefault("RATE_LIMIT_ENABLED", "1")
os.environ.setdefault("RATE_LIMIT_SECRET", "test-secret")

from app.admin_intake import _requests_query  # noqa: E402


def test_requests_query_without_status_omits_nullable_filter() -> None:
    sql, params = _requests_query("all", None, 50)

    assert "WHERE status = :status" not in sql
    assert "WHERE (:status IS NULL OR status = :status)" not in sql
    assert params == {"limit": 50}


def test_requests_query_with_status_adds_explicit_filter() -> None:
    sql, params = _requests_query("demo", "  new  ", 25)

    assert "WHERE status = :status" in sql
    assert params == {"limit": 25, "status": "new"}
