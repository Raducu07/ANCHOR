"""Shared helpers for assistant endpoint tests.

We build a minimal FastAPI app that includes only the Assistant router, then
override `require_clinic_user` (to inject tenant context onto request.state)
and `get_db` (to capture the insert without needing Postgres).
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient


TEST_CLINIC_ID = "11111111-1111-4111-8111-111111111111"
TEST_USER_ID = "22222222-2222-4222-8222-222222222222"


class _FakeResult:
    def __init__(self, row: Optional[Dict[str, Any]]):
        self._row = row

    def mappings(self) -> "_FakeResult":
        return self

    def first(self) -> Optional[Dict[str, Any]]:
        return self._row

    # Some call sites use .fetchone() — keep parity.
    def fetchone(self) -> Optional[Dict[str, Any]]:
        return self._row


class FakeDB:
    """Records every execute() call. Returns a row mirroring the inserted
    params so the endpoint's RETURNING-based response path is exercised."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, Dict[str, Any]]] = []
        self.committed = False
        self.rolled_back = False

    def execute(self, statement: Any, params: Optional[Dict[str, Any]] = None) -> _FakeResult:
        sql = str(getattr(statement, "text", statement))
        self.calls.append((sql, dict(params or {})))

        if "INSERT INTO assistant_runs" in sql and params:
            # JSONB-bound params arrive as JSON strings (CAST(... AS jsonb)).
            # Postgres returns jsonb as already-decoded Python objects via
            # psycopg, so we mirror that decoding here for the fake row.
            def _decode_jsonb(value: Any) -> Any:
                if isinstance(value, str):
                    return json.loads(value)
                return value

            row = {
                "run_id": params["run_id"],
                "mode": params["mode"],
                "contract_version": params["contract_version"],
                "pii_detected": bool(params["pii_detected"]),
                "pii_types": list(_decode_jsonb(params["pii_types"])),
                "input_field_keys": list(_decode_jsonb(params["input_field_keys"])),
                "review_status": params["review_status"],
                "output_sha256": None,
                "model_provider": None,
                "model_name": None,
            }
            return _FakeResult(row)
        return _FakeResult(None)

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def begin(self) -> None:  # pragma: no cover - shape parity
        return None

    def close(self) -> None:  # pragma: no cover - shape parity
        return None

    @property
    def insert_call(self) -> Tuple[str, Dict[str, Any]]:
        for sql, params in self.calls:
            if "INSERT INTO assistant_runs" in sql:
                return sql, params
        raise AssertionError("assistant_runs INSERT was not executed")


def build_app(*, authenticated: bool = True) -> Tuple[FastAPI, FakeDB]:
    """Returns a fresh FastAPI app + the FakeDB instance bound to its get_db."""
    from app.auth_and_rls import require_clinic_user
    from app.db import get_db
    from app.portal_assistant import router as assistant_router

    app = FastAPI()
    app.include_router(assistant_router)

    fake_db = FakeDB()

    def _fake_db_dep(request: Request):
        # Mirror app.db.get_db: yield a session, commit on success.
        try:
            yield fake_db
            fake_db.commit()
        except Exception:
            fake_db.rollback()
            raise

    app.dependency_overrides[get_db] = _fake_db_dep

    if authenticated:
        def _fake_require_clinic_user(request: Request) -> Dict[str, str]:
            request.state.clinic_id = TEST_CLINIC_ID
            request.state.clinic_user_id = TEST_USER_ID
            request.state.role = "staff"
            return {
                "clinic_id": TEST_CLINIC_ID,
                "clinic_user_id": TEST_USER_ID,
                "role": "staff",
            }

        app.dependency_overrides[require_clinic_user] = _fake_require_clinic_user

    return app, fake_db


def client_for(app: FastAPI) -> TestClient:
    return TestClient(app)


def auth_headers() -> Dict[str, str]:
    # The real require_clinic_user is overridden in build_app, so the actual
    # bearer value isn't validated. We still send one for realism.
    return {"Authorization": "Bearer test-token"}
