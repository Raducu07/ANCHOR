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

from app.admin_intake import _chat_events_query  # noqa: E402


def test_chat_events_query_without_category_omits_nullable_filter() -> None:
    sql, params = _chat_events_query(None, 25)

    assert "WHERE question_category = :category" not in sql
    assert params == {"limit": 25}


def test_chat_events_query_with_category_adds_explicit_filter() -> None:
    sql, params = _chat_events_query("  pricing  ", 50)

    assert "WHERE question_category = :category" in sql
    assert params == {"limit": 50, "category": "pricing"}
