"""
2A-D.1 Patch 3 — admin public-intake prune endpoint tests.

Covers POST /v1/admin/intake/prune:
  * requires admin auth
  * dry_run=true returns counts + cutoff and issues no DELETE
  * dry_run=false without confirm is rejected
  * dry_run=false with correct confirm DELETEs only the allowlisted
    table(s) older than cutoff (per-kind and 'all')
  * kind='all' touches all three allowlisted tables in order
  * eligible row count > 50_000 cap is rejected BEFORE any DELETE
"""
from __future__ import annotations

import os
import re
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Limiter envs (admin_auth path uses enforce_admin_token; with a stubbed
# admin dep it never reaches the limiter, but we set safe defaults).
os.environ.setdefault("RATE_LIMIT_ENABLED", "0")
os.environ.setdefault("RATE_LIMIT_SECRET", "test-secret-patch3-admin")

from app import admin_intake as admin_intake_module  # noqa: E402
from app.admin_intake import router as admin_intake_router  # noqa: E402
from app.admin_auth import AdminContext, require_admin  # noqa: E402


# ---------------------------------------------------------------------
# Fake DB that records statements + per-table COUNT(*) responses
# ---------------------------------------------------------------------

_TABLE_RE = re.compile(
    r"FROM\s+(demo_requests|start_requests|public_site_chat_events)",
    re.IGNORECASE,
)
_DELETE_TABLE_RE = re.compile(
    r"DELETE\s+FROM\s+(demo_requests|start_requests|public_site_chat_events)",
    re.IGNORECASE,
)


class _FakeMapping:
    def __init__(self, data: Dict[str, Any]):
        self._data = data

    def first(self) -> Dict[str, Any]:
        return self._data


class _FakeResult:
    def __init__(self, *, row: Dict[str, Any] | None = None, rowcount: int = 0):
        self._row = row
        self.rowcount = rowcount

    def mappings(self) -> _FakeMapping:
        return _FakeMapping(self._row or {})


class _PruneFakeDB:
    """Per-test fake DB. Configure `counts_by_table` and
    `delete_rowcounts_by_table` before issuing the request."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, Dict[str, Any]]] = []
        self.committed = False
        self.rolled_back = False
        self.counts_by_table: Dict[str, int] = {}
        self.delete_rowcounts_by_table: Dict[str, int] = {}

    def _table_in(self, sql: str, regex: re.Pattern) -> str | None:
        m = regex.search(sql)
        return m.group(1).lower() if m else None

    def execute(self, statement: Any, params: Dict[str, Any] | None = None) -> _FakeResult:
        sql = str(getattr(statement, "text", statement))
        self.calls.append((sql, dict(params or {})))

        if "DELETE FROM" in sql.upper():
            t = self._table_in(sql, _DELETE_TABLE_RE)
            assert t is not None, f"DELETE without recognised table: {sql!r}"
            return _FakeResult(rowcount=int(self.delete_rowcounts_by_table.get(t, 0)))

        if "SELECT COUNT(*)" in sql.upper():
            t = self._table_in(sql, _TABLE_RE)
            assert t is not None, f"COUNT without recognised table: {sql!r}"
            return _FakeResult(row={"c": int(self.counts_by_table.get(t, 0))})

        return _FakeResult(row={})

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    # context-manager parity
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None


# ---------------------------------------------------------------------
# App + fixtures
# ---------------------------------------------------------------------

@pytest.fixture
def fake_db() -> _PruneFakeDB:
    return _PruneFakeDB()


@pytest.fixture
def app_authed(fake_db: _PruneFakeDB, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    """App with admin auth stubbed and SessionLocal() bound to fake_db.
    A fresh fake_db is bound per test so call history is per-test."""

    @contextmanager
    def _session_cm():
        yield fake_db

    monkeypatch.setattr(admin_intake_module, "SessionLocal", _session_cm)
    # Suppress admin audit DB writes (admin_intake imports
    # write_admin_audit_event from admin_auth; we no-op it).
    monkeypatch.setattr(
        admin_intake_module,
        "write_admin_audit_event",
        lambda **kwargs: None,
    )

    app = FastAPI()
    app.include_router(admin_intake_router)

    def _fake_admin() -> AdminContext:
        return AdminContext(
            token_id=None,
            token_source="env",
            ip_hash="hashed-ip",
            ua_hash="hashed-ua",
            request_id="req-test",
        )

    app.dependency_overrides[require_admin] = _fake_admin
    return app


@pytest.fixture
def app_unauthed(fake_db: _PruneFakeDB, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    """App WITHOUT the require_admin override, to verify the guard."""

    @contextmanager
    def _session_cm():
        yield fake_db

    monkeypatch.setattr(admin_intake_module, "SessionLocal", _session_cm)
    monkeypatch.setattr(
        admin_intake_module,
        "write_admin_audit_event",
        lambda **kwargs: None,
    )

    app = FastAPI()
    app.include_router(admin_intake_router)
    return app


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _post_prune(app: FastAPI, body: Dict[str, Any]):
    return TestClient(app, raise_server_exceptions=False).post(
        "/v1/admin/intake/prune", json=body
    )


# ---------------------------------------------------------------------
# 1. Auth gate
# ---------------------------------------------------------------------

def test_prune_requires_admin_auth(app_unauthed: FastAPI) -> None:
    resp = _post_prune(
        app_unauthed,
        {"kind": "demo", "older_than_days": 365, "dry_run": True},
    )
    # require_admin returns 401 when token is missing.
    assert resp.status_code == 401


# ---------------------------------------------------------------------
# 2. Dry-run returns counts + no DELETE
# ---------------------------------------------------------------------

def test_prune_dry_run_returns_counts_and_no_delete(
    app_authed: FastAPI, fake_db: _PruneFakeDB
) -> None:
    fake_db.counts_by_table = {"demo_requests": 42}

    resp = _post_prune(
        app_authed,
        {"kind": "demo", "older_than_days": 365, "dry_run": True},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["outcome"] == "dry_run"
    assert body["kind"] == "demo"
    assert body["older_than_days"] == 365
    assert body["counts"] == {"demo": 42}
    assert body["deleted"] == {}
    assert body["cap"] == 50_000
    assert "cutoff_utc" in body

    # No DELETE statement was issued.
    assert not any("DELETE FROM" in sql.upper() for sql, _ in fake_db.calls)
    assert not fake_db.committed


# ---------------------------------------------------------------------
# 3. Destructive without confirm is rejected at validation
# ---------------------------------------------------------------------

def test_prune_destructive_without_confirm_is_422(app_authed: FastAPI) -> None:
    resp = _post_prune(
        app_authed,
        {"kind": "demo", "older_than_days": 365, "dry_run": False},
    )
    assert resp.status_code == 422


def test_prune_destructive_with_wrong_confirm_is_422(app_authed: FastAPI) -> None:
    resp = _post_prune(
        app_authed,
        {
            "kind": "demo",
            "older_than_days": 365,
            "dry_run": False,
            "confirm": "yes",
        },
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------
# 4. Destructive with correct confirm DELETEs only allowlisted table
# ---------------------------------------------------------------------

def test_prune_destructive_demo_deletes_only_demo_requests(
    app_authed: FastAPI, fake_db: _PruneFakeDB
) -> None:
    fake_db.counts_by_table = {"demo_requests": 17}
    fake_db.delete_rowcounts_by_table = {"demo_requests": 17}

    resp = _post_prune(
        app_authed,
        {
            "kind": "demo",
            "older_than_days": 365,
            "dry_run": False,
            "confirm": "I-UNDERSTAND",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["outcome"] == "deleted"
    assert body["deleted"] == {"demo": 17}
    assert body["counts"] == {"demo": 17}

    deletes = [sql for sql, _ in fake_db.calls if "DELETE FROM" in sql.upper()]
    assert len(deletes) == 1
    assert "demo_requests" in deletes[0]
    # Allowlist guarantee: only the demo table is touched.
    assert "start_requests" not in deletes[0]
    assert "public_site_chat_events" not in deletes[0]
    assert fake_db.committed is True


# ---------------------------------------------------------------------
# 5. kind='all' touches all three allowlisted tables
# ---------------------------------------------------------------------

def test_prune_destructive_all_touches_three_tables(
    app_authed: FastAPI, fake_db: _PruneFakeDB
) -> None:
    fake_db.counts_by_table = {
        "demo_requests": 3,
        "start_requests": 5,
        "public_site_chat_events": 7,
    }
    fake_db.delete_rowcounts_by_table = {
        "demo_requests": 3,
        "start_requests": 5,
        "public_site_chat_events": 7,
    }

    resp = _post_prune(
        app_authed,
        {
            "kind": "all",
            "older_than_days": 90,
            "dry_run": False,
            "confirm": "I-UNDERSTAND",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deleted"] == {"demo": 3, "start": 5, "chat": 7}
    assert body["counts"] == {"demo": 3, "start": 5, "chat": 7}

    deletes = [sql for sql, _ in fake_db.calls if "DELETE FROM" in sql.upper()]
    assert len(deletes) == 3
    touched = {
        re.search(
            r"DELETE\s+FROM\s+(\w+)", sql, re.IGNORECASE
        ).group(1).lower()
        for sql in deletes
    }
    assert touched == {"demo_requests", "start_requests", "public_site_chat_events"}


# ---------------------------------------------------------------------
# 6. Hard cap >50_000 rejected BEFORE any DELETE
# ---------------------------------------------------------------------

def test_prune_destructive_above_cap_is_rejected_before_delete(
    app_authed: FastAPI, fake_db: _PruneFakeDB
) -> None:
    fake_db.counts_by_table = {
        "demo_requests": 30_000,
        "start_requests": 30_000,
        "public_site_chat_events": 0,
    }

    resp = _post_prune(
        app_authed,
        {
            "kind": "all",
            "older_than_days": 30,
            "dry_run": False,
            "confirm": "I-UNDERSTAND",
        },
    )
    assert resp.status_code == 409
    assert resp.json().get("detail") == "intake_prune_rows_exceed_cap"

    deletes = [sql for sql, _ in fake_db.calls if "DELETE FROM" in sql.upper()]
    assert deletes == []
    assert fake_db.committed is False
    assert fake_db.rolled_back is True


# ---------------------------------------------------------------------
# 7. older_than_days bounds enforced by schema
# ---------------------------------------------------------------------

def test_prune_rejects_older_than_days_zero(app_authed: FastAPI) -> None:
    resp = _post_prune(
        app_authed,
        {"kind": "demo", "older_than_days": 0, "dry_run": True},
    )
    assert resp.status_code == 422


def test_prune_rejects_older_than_days_too_large(app_authed: FastAPI) -> None:
    resp = _post_prune(
        app_authed,
        {"kind": "demo", "older_than_days": 3651, "dry_run": True},
    )
    assert resp.status_code == 422


def test_prune_rejects_unknown_kind(app_authed: FastAPI) -> None:
    resp = _post_prune(
        app_authed,
        {"kind": "bogus", "older_than_days": 30, "dry_run": True},
    )
    assert resp.status_code == 422
