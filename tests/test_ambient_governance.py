"""M6.13 - Ambient governance shell tests (extreme caution).

Coverage:
  * every endpoint returns 503 while ANCHOR_AMBIENT_GOVERNANCE_ENABLED
    is unset (disabled by default)
  * event creation: metadata-only insert; unknown fields such as
    'transcript' / 'note_text' are dropped, never persisted
  * workflow_reference_hash must be exactly a sha256 hex digest -
    arbitrary strings (i.e. content) are refused
  * source_label anti-paste guard: multi-line labels are refused
  * review gate: decision categories, rejected -> discarded, single
    review (404 on second attempt)
  * summary counts
  * schema: RLS + FORCE with USING/WITH CHECK; NO content-capable
    columns (transcript / note / audio / content / free_text)
  * normalised-event validator drops content fields and enforces the
    closed vocabulary

Uses an in-memory FakeDB. No live Postgres needed.
"""
from __future__ import annotations

import json
import os
import re
import sys
import uuid as _uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("DATABASE_URL", "postgresql://x:y@localhost:5432/z")
os.environ.setdefault("RATE_LIMIT_ENABLED", "0")
os.environ.setdefault("ANCHOR_JWT_SECRET", "test")

CLINIC_A = "11111111-1111-4111-8111-111111111111"
STAFF_USER = "44444444-4444-4444-8444-444444444444"

_NOW = datetime(2026, 7, 5, 12, 0, 0, tzinfo=timezone.utc)
_SHA = "a" * 64

SCHEMA_SQL = (
    REPO_ROOT / "migrations" / "20260705_05_ambient_governance_schema.sql"
).read_text(encoding="utf-8")


class _Result:
    def __init__(
        self,
        row: Optional[Dict[str, Any]] = None,
        rows: Optional[List[Dict[str, Any]]] = None,
    ):
        self._row = row
        self._rows = rows

    def mappings(self) -> "_Result":
        return self

    def first(self) -> Optional[Dict[str, Any]]:
        return self._row

    def all(self) -> List[Dict[str, Any]]:
        return list(self._rows or [])


def _event_row(**overrides: Any) -> Dict[str, Any]:
    row = {
        "ambient_event_id": _uuid.uuid4(),
        "source_label": "Scribe tool A",
        "event_type": "note_generated",
        "occurred_at": _NOW,
        "duration_seconds": 300,
        "workflow_reference_hash": _SHA,
        "review_status": "pending_review",
        "review_decision": None,
        "reviewed_at": None,
        "created_at": _NOW,
    }
    row.update(overrides)
    return row


class AmbientFakeDB:
    def __init__(self) -> None:
        self.inserts: List[Dict[str, Any]] = []
        self.reviews: List[Dict[str, Any]] = []
        self.review_found = True
        self.list_rows: List[Dict[str, Any]] = []
        self.summary_rows: List[Dict[str, Any]] = []
        self.audit_inserts: List[Dict[str, Any]] = []

    def execute(self, clause: Any, params: Optional[Dict[str, Any]] = None):
        sql = str(getattr(clause, "text", clause))
        p = dict(params or {})

        if "INSERT INTO admin_audit_events" in sql:
            self.audit_inserts.append(p)
            return _Result()
        if "INSERT INTO ambient_governance_events" in sql:
            self.inserts.append(p)
            return _Result(
                row=_event_row(
                    source_label=p["source_label"],
                    event_type=p["event_type"],
                    duration_seconds=p["duration_seconds"],
                    workflow_reference_hash=p["workflow_reference_hash"],
                )
            )
        if "UPDATE ambient_governance_events" in sql:
            self.reviews.append(p)
            if not self.review_found:
                return _Result(row=None)
            return _Result(
                row=_event_row(
                    review_status=p["new_status"],
                    review_decision=p["review_decision"],
                    reviewed_at=_NOW,
                )
            )
        if "GROUP BY review_status" in sql:
            return _Result(rows=self.summary_rows)
        if "FROM ambient_governance_events" in sql:
            return _Result(rows=self.list_rows)
        raise AssertionError(f"unexpected SQL: {sql}")

    def commit(self) -> None:
        pass


def _build_app(*, authenticated: bool = True) -> tuple:
    from app.ambient_governance import router
    from app.auth_and_rls import require_clinic_user
    from app.db import get_db

    app = FastAPI()
    app.include_router(router)
    fake = AmbientFakeDB()

    def _fake_db_dep(request: Request):
        yield fake
        fake.commit()

    app.dependency_overrides[get_db] = _fake_db_dep

    if authenticated:
        def _fake_auth(request: Request) -> Dict[str, str]:
            request.state.clinic_id = CLINIC_A
            request.state.clinic_user_id = STAFF_USER
            request.state.role = "staff"
            return {
                "clinic_id": CLINIC_A,
                "clinic_user_id": STAFF_USER,
                "role": "staff",
            }

        app.dependency_overrides[require_clinic_user] = _fake_auth

    return app, fake


def _payload(**overrides: Any) -> Dict[str, Any]:
    body = {
        "source_label": "Scribe tool A",
        "event_type": "note_generated",
        "occurred_at": _NOW.isoformat(),
        "duration_seconds": 300,
        "workflow_reference_hash": _SHA,
    }
    body.update(overrides)
    return body


@pytest.fixture()
def enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANCHOR_AMBIENT_GOVERNANCE_ENABLED", "1")


# ---------------------------------------------------------------------
# Disabled by default
# ---------------------------------------------------------------------

def test_everything_503_when_flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANCHOR_AMBIENT_GOVERNANCE_ENABLED", raising=False)
    app, fake = _build_app()
    client = TestClient(app)
    eid = str(_uuid.uuid4())
    assert client.post("/v1/portal/ambient/events", json=_payload()).status_code == 503
    assert client.get("/v1/portal/ambient/events").status_code == 503
    assert client.post(
        f"/v1/portal/ambient/events/{eid}/review",
        json={"review_decision": "rejected"},
    ).status_code == 503
    assert client.get("/v1/portal/ambient/summary").status_code == 503
    assert fake.inserts == [] and fake.reviews == []


# ---------------------------------------------------------------------
# Content boundary
# ---------------------------------------------------------------------

def test_transcript_fields_are_dropped(enabled: None) -> None:
    app, fake = _build_app()
    resp = TestClient(app).post(
        "/v1/portal/ambient/events",
        json=_payload(
            transcript="OWNER SAYS THE DOG HAS BEEN VOMITING...",
            note_text="Clinical note body",
            audio="base64...",
        ),
    )
    assert resp.status_code == 200
    # The extra fields never reach the insert and never echo back.
    assert len(fake.inserts) == 1
    blob = json.dumps(fake.inserts[0], default=str) + json.dumps(resp.json())
    assert "VOMITING" not in blob
    assert "transcript" not in fake.inserts[0]
    assert "note_text" not in fake.inserts[0]


def test_reference_hash_must_be_sha256(enabled: None) -> None:
    app, fake = _build_app()
    resp = TestClient(app).post(
        "/v1/portal/ambient/events",
        json=_payload(
            workflow_reference_hash="the patient presented with lethargy"
        ),
    )
    assert resp.status_code == 422
    assert fake.inserts == []


def test_multiline_source_label_refused(enabled: None) -> None:
    app, fake = _build_app()
    resp = TestClient(app).post(
        "/v1/portal/ambient/events",
        json=_payload(source_label="Scribe tool A\nConsult transcript: ..."),
    )
    assert resp.status_code == 422
    assert fake.inserts == []


def test_unknown_event_type_refused(enabled: None) -> None:
    app, fake = _build_app()
    resp = TestClient(app).post(
        "/v1/portal/ambient/events",
        json=_payload(event_type="transcript_uploaded"),
    )
    assert resp.status_code == 422
    assert fake.inserts == []


def test_validator_helper_enforces_boundary() -> None:
    from app.ambient_governance import validate_normalised_ambient_event

    event = validate_normalised_ambient_event(
        {
            "source_label": "Tool B",
            "event_type": "consult_recorded",
            "occurred_at": _NOW,
            "transcript": "should be dropped",
        }
    )
    assert not hasattr(event, "transcript")
    with pytest.raises(ValueError):
        validate_normalised_ambient_event(
            {
                "source_label": "Tool B",
                "event_type": "consult_recorded",
                "occurred_at": _NOW,
                "workflow_reference_hash": "not-a-hash",
            }
        )


# ---------------------------------------------------------------------
# Review gate
# ---------------------------------------------------------------------

def test_review_rejected_maps_to_discarded(enabled: None) -> None:
    app, fake = _build_app()
    eid = str(_uuid.uuid4())
    resp = TestClient(app).post(
        f"/v1/portal/ambient/events/{eid}/review",
        json={"review_decision": "rejected"},
    )
    assert resp.status_code == 200
    assert resp.json()["review_status"] == "discarded"
    assert fake.reviews[0]["new_status"] == "discarded"


def test_review_approved_maps_to_reviewed(enabled: None) -> None:
    app, fake = _build_app()
    eid = str(_uuid.uuid4())
    resp = TestClient(app).post(
        f"/v1/portal/ambient/events/{eid}/review",
        json={"review_decision": "approved_for_record"},
    )
    assert resp.status_code == 200
    assert resp.json()["review_status"] == "reviewed"


def test_review_writes_metadata_only_audit_event(enabled: None) -> None:
    """Pre-merge FIX 2 (5 July audit): review decisions write an
    append-only admin_audit_events row targeting the event, carrying
    only the bounded decision category and resulting status."""
    import json as _json

    app, fake = _build_app()
    eid = str(_uuid.uuid4())
    resp = TestClient(app).post(
        f"/v1/portal/ambient/events/{eid}/review",
        json={"review_decision": "amended_before_use"},
    )
    assert resp.status_code == 200
    assert len(fake.audit_inserts) == 1
    audit = fake.audit_inserts[0]
    assert audit["action"] == "ambient_event_reviewed"
    assert audit["target_id"] == eid
    assert _json.loads(audit["meta"]) == {
        "review_decision": "amended_before_use",
        "new_status": "reviewed",
    }

    # A failed review (already reviewed) writes nothing.
    fake.review_found = False
    fake.audit_inserts.clear()
    resp = TestClient(app).post(
        f"/v1/portal/ambient/events/{eid}/review",
        json={"review_decision": "rejected"},
    )
    assert resp.status_code == 404
    assert fake.audit_inserts == []


def test_review_only_once(enabled: None) -> None:
    app, fake = _build_app()
    fake.review_found = False
    eid = str(_uuid.uuid4())
    resp = TestClient(app).post(
        f"/v1/portal/ambient/events/{eid}/review",
        json={"review_decision": "rejected"},
    )
    assert resp.status_code == 404


def test_unknown_review_decision_refused(enabled: None) -> None:
    app, _ = _build_app()
    eid = str(_uuid.uuid4())
    resp = TestClient(app).post(
        f"/v1/portal/ambient/events/{eid}/review",
        json={"review_decision": "looks_fine"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------
# Listing + summary
# ---------------------------------------------------------------------

def test_list_filter_validation(enabled: None) -> None:
    app, fake = _build_app()
    fake.list_rows = [_event_row()]
    client = TestClient(app)
    assert client.get("/v1/portal/ambient/events").status_code == 200
    resp = client.get("/v1/portal/ambient/events?review_status=bogus")
    assert resp.status_code == 400


def test_summary_counts(enabled: None) -> None:
    app, fake = _build_app()
    fake.summary_rows = [
        {"review_status": "pending_review", "c": 2, "latest": _NOW},
        {"review_status": "reviewed", "c": 5, "latest": _NOW},
        {"review_status": "discarded", "c": 1, "latest": _NOW},
    ]
    resp = TestClient(app).get("/v1/portal/ambient/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["pending_review_count"] == 2
    assert body["reviewed_count"] == 5
    assert body["discarded_count"] == 1
    assert body["ambient_note"].startswith("Metadata-only")


# ---------------------------------------------------------------------
# Schema doctrine
# ---------------------------------------------------------------------

def test_schema_rls_force_using_with_check() -> None:
    assert (
        "ALTER TABLE public.ambient_governance_events ENABLE ROW LEVEL SECURITY"
        in SCHEMA_SQL
    )
    assert (
        "ALTER TABLE public.ambient_governance_events FORCE ROW LEVEL SECURITY"
        in SCHEMA_SQL
    )
    block = re.search(
        r"CREATE POLICY rls_ambient_governance_events_tenant.*?\$policy\$",
        SCHEMA_SQL,
        flags=re.DOTALL,
    )
    assert block
    assert "USING (clinic_id = app_current_clinic_id())" in block.group(0)
    assert "WITH CHECK (clinic_id = app_current_clinic_id())" in block.group(0)


def test_schema_has_no_content_capable_columns() -> None:
    ddl = "\n".join(
        line
        for line in SCHEMA_SQL.splitlines()
        if not line.strip().startswith("--")
    ).lower()
    for forbidden in (
        "transcript", "note_body", "note_text", "audio", "content",
        "free_text", "summary_text", "patient", "owner",
    ):
        assert forbidden not in ddl, f"content-capable marker: {forbidden}"


_HARDENING_SQL = (
    REPO_ROOT / "migrations" / "20260706_01_ambient_boundary_check_hardening.sql"
).read_text(encoding="utf-8")


def test_rule13_schema_hardening_constraints_present() -> None:
    """M6.13 boundary adoption rule 13 (founder decision 2026-07-06):
    the API-layer content guards are mirrored as schema-level CHECKs."""
    assert "ADD CONSTRAINT ambient_source_label_single_line" in _HARDENING_SQL
    assert "char_length(source_label) <= 200" in _HARDENING_SQL
    assert r"source_label !~ '[\n\r]'" in _HARDENING_SQL
    assert (
        "ADD CONSTRAINT ambient_reference_hash_sha256_shape" in _HARDENING_SQL
    )
    assert "workflow_reference_hash IS NULL" in _HARDENING_SQL
    assert "workflow_reference_hash ~ '^[a-f0-9]{64}$'" in _HARDENING_SQL


def test_rule13_hardening_is_a_new_migration_not_an_edit() -> None:
    """Doctrine: existing migrations are never retroactively edited. The
    hardening constraints must NOT appear in the original 20260705_05
    schema migration."""
    assert "ambient_source_label_single_line" not in SCHEMA_SQL
    assert "ambient_reference_hash_sha256_shape" not in SCHEMA_SQL


def test_router_mounted_in_main_app() -> None:
    from app.main import app as main_app

    paths = {getattr(r, "path", None) for r in main_app.routes}
    assert "/v1/portal/ambient/events" in paths
    assert "/v1/portal/ambient/summary" in paths
