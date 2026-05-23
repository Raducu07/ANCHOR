"""Shared helpers for assistant endpoint tests.

We build a minimal FastAPI app that includes only the Assistant router, then
override `require_clinic_user` (to inject tenant context onto request.state)
and `get_db` (to capture inserts/updates without needing Postgres).

By default we also install a deterministic stub for `_perform_generation`
so existing PR 2A tests exercise the PR 2B success path without any real
model call. Callers that need refusal / failure / config-error behaviour
pass `model_stub=` to `build_app`.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient


TEST_CLINIC_ID = "11111111-1111-4111-8111-111111111111"
TEST_USER_ID = "22222222-2222-4222-8222-222222222222"

# A canned draft used by the default success stub. It ends with the
# governance review line so prompt-conformance assertions can pass.
DEFAULT_DRAFT_TEXT = (
    "Dear owner, this is a transient test draft used only by the fake "
    "model stub.\n"
    "⚠ REVIEW REQUIRED — check against the clinical record before use. "
    "ANCHOR does not replace professional judgement."
)
DEFAULT_PROVIDER = "anthropic"
DEFAULT_MODEL = "claude-sonnet-4-test"


def default_success_stub(*, system_prompt: str, user_message: str) -> Tuple[str, str, str]:
    """The default `_perform_generation` replacement: returns a canned
    draft + provider + model. Records nothing about the prompts."""
    return DEFAULT_DRAFT_TEXT, DEFAULT_PROVIDER, DEFAULT_MODEL


class _FakeResult:
    def __init__(self, row: Optional[Dict[str, Any]]):
        self._row = row

    def mappings(self) -> "_FakeResult":
        return self

    def first(self) -> Optional[Dict[str, Any]]:
        return self._row

    def fetchone(self) -> Optional[Dict[str, Any]]:
        return self._row


def _decode_jsonb(value: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value


class FakeDB:
    """Records every execute() call. For INSERT INTO assistant_runs, returns
    a row mirroring the inserted params so the endpoint's RETURNING path is
    exercised. UPDATE statements are recorded but return no rows."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, Dict[str, Any]]] = []
        self.committed = False
        self.rolled_back = False
        # PR 2D: usage-limit count queries pop scalars from this queue in
        # order (daily query first, then monthly). Empty queue => 0.
        self.count_queue: List[int] = []

    def execute(self, statement: Any, params: Optional[Dict[str, Any]] = None) -> _FakeResult:
        sql = str(getattr(statement, "text", statement))
        self.calls.append((sql, dict(params or {})))

        # PR 2D: count query for usage limits.
        if "SELECT COUNT(*)" in sql and "assistant_runs" in sql:
            value = self.count_queue.pop(0) if self.count_queue else 0
            return _FakeResult({"c": value})

        if "INSERT INTO assistant_runs" in sql and params:
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
                "run_status": params.get("run_status", "created"),
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

    # --- inspection helpers ---

    @property
    def insert_call(self) -> Tuple[str, Dict[str, Any]]:
        for sql, params in self.calls:
            if "INSERT INTO assistant_runs" in sql:
                return sql, params
        raise AssertionError("assistant_runs INSERT was not executed")

    @property
    def update_calls(self) -> List[Tuple[str, Dict[str, Any]]]:
        return [(sql, p) for sql, p in self.calls if "UPDATE assistant_runs" in sql]

    @property
    def last_update_call(self) -> Tuple[str, Dict[str, Any]]:
        ups = self.update_calls
        if not ups:
            raise AssertionError("assistant_runs UPDATE was not executed")
        return ups[-1]

    def update_call_with_status(self, run_status: str) -> Tuple[str, Dict[str, Any]]:
        for sql, p in self.update_calls:
            if p.get("run_status") == run_status:
                return sql, p
        raise AssertionError(
            f"no UPDATE assistant_runs with run_status={run_status!r} was executed"
        )

    def has_update(self) -> bool:
        return bool(self.update_calls)

    @property
    def count_calls(self) -> List[Tuple[str, Dict[str, Any]]]:
        return [
            (sql, p)
            for sql, p in self.calls
            if "SELECT COUNT(*)" in sql and "assistant_runs" in sql
        ]


def build_app(
    *,
    authenticated: bool = True,
    model_stub: Optional[Callable[..., Tuple[str, str, str]]] = default_success_stub,
) -> Tuple[FastAPI, FakeDB]:
    """Returns a fresh FastAPI app + the FakeDB bound to its get_db.

    `model_stub` replaces `portal_assistant._perform_generation`. Pass
    `model_stub=None` to leave the real client in place (callers that need
    AssistantModelConfigError / AssistantModelCallError set a custom stub
    that raises). Pass a callable to make it return a custom draft / raise.
    """
    from app.auth_and_rls import require_clinic_user
    from app.db import get_db
    from app import portal_assistant
    from app.portal_assistant import router as assistant_router

    app = FastAPI()
    app.include_router(assistant_router)

    fake_db = FakeDB()

    def _fake_db_dep(request: Request):
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

    if model_stub is not None:
        portal_assistant._perform_generation = model_stub  # type: ignore[assignment]

    return app, fake_db


def client_for(app: FastAPI) -> TestClient:
    return TestClient(app)


def auth_headers() -> Dict[str, str]:
    return {"Authorization": "Bearer test-token"}
