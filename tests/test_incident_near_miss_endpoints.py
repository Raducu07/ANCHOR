"""Phase 2A-5.2 - Basic Incident / Near-Miss Logging endpoint tests.

Covers the five endpoints added in this slice (vocabulary + create +
list/mine/detail). Publish/review/close/void/summary remain deferred.

Doctrine guards asserted here:
  * Vocabulary endpoint exposes every CHECK-constrained enum value
    and matches the 2A-5.1 migration verbatim.
  * Create body is `extra='forbid'` and rejects any free-text /
    identifier / claim / insurance / negligence / malpractice
    extra field.
  * Linked IDs are validated clinic-scoped before insert; cross-
    clinic IDs return 404 with the stable per-link error code.
  * Self-attestation visibility: /records is admin-tier only;
    /records/mine self-scopes via request.state.clinic_user_id.
  * Detail returns 404 for non-admin non-creator (enumeration-safe).
  * Recursive sweep of every response envelope for forbidden keys.
  * Audit event is metadata-only (IDs + enums + booleans), with no
    raw text and no broken partial-index ON CONFLICT.
  * Module does not import from sibling feature modules.
"""
from __future__ import annotations

import inspect
import json
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


CLINIC_A = "11111111-1111-4111-8111-111111111111"
CLINIC_B = "33333333-3333-4333-8333-333333333333"
ADMIN_USER = "22222222-2222-4222-8222-222222222222"
STAFF_USER = "44444444-4444-4444-8444-444444444444"
OTHER_USER = "55555555-5555-4555-8555-555555555555"

# Plausible linked-target UUIDs for fake-DB seeding.
RECEIPT_A = "aaaaaaa1-0000-4000-8000-000000000001"
RECEIPT_B = "aaaaaaa1-0000-4000-8000-000000000002"
GOV_EVENT_A = "bbbbbbb1-0000-4000-8000-000000000001"
ASSIST_RUN_A = "ccccccc1-0000-4000-8000-000000000001"
POLICY_VER_A = "ddddddd1-0000-4000-8000-000000000001"


# Forbidden response keys / body keys.
#
# NB: `summary` is deliberately NOT in this set. It collides with the
# 2A-5.3 `/summary` endpoint's structural aggregate envelope key, which
# is a noun naming a metadata-only block of counts - not a free-text
# narrative field. The doctrinal guarantee that no `summary` *column*
# can exist on the record table is enforced by the 2A-5.1 schema test
# (`test_no_forbidden_column_fragment[summary]`), and the request-body
# guard is enforced by `extra="forbid"` on every create / PATCH model.
FORBIDDEN_RESPONSE_KEYS = {
    "note", "description", "narrative", "comments",
    "free_text", "raw_prompt", "raw_output", "transcript",
    "clinical_content", "client_identifier", "patient_identifier",
    "staff_identifier", "consent_text", "legal_consent",
    "legal_claim", "insurance", "negligence", "malpractice",
    "compliance_status", "competence_grade", "score", "pass_fail",
    "staff_certified", "clinical_safety_proof", "legal_approval",
    "email", "user_email", "first_name", "last_name",
}


# Fragment-assembled wording markers so this test source itself does
# not trip broader repo-level wording scans.
_FORBIDDEN_WORDING_FRAGMENTS = [
    ("EU AI Act", " compliant"),
    ("RCVS", "-certified"),
    ("RCVS", "-approved"),
    ("guarantees", " compliance"),
    ("certified", " CPD"),
    ("proof", " of competence"),
    ("clinical", " safety proof"),
    ("compliance", " guarantee"),
    ("compliance", " proof"),
    ("certified", " audit"),
    ("insurance", "-ready record"),
    ("proves", " safe AI use"),
    ("guarantees", " protection"),
    ("RCVS", "-approved reporting"),
    ("VDS", "-approved record"),
    ("adverse event", " submission"),
    ("regulator", "-approved report"),
]


# ---------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------


class _Result:
    def __init__(self, row=None, rows=None):
        self._row = row
        self._rows = rows

    def mappings(self):
        return self

    def first(self):
        return self._row

    def all(self):
        return list(self._rows or [])


class IncidentFakeDB:
    """In-memory fake interpreting incident_near_miss SQL.

    Tracks records, audit events, and the linked-target tables that
    the create-time validator probes (receipts, governance events,
    assistant runs, policy versions). The `current_clinic` field is
    set per-request via the auth override so cross-clinic UUIDs
    yield 404 paths.
    """

    def __init__(self) -> None:
        self.current_clinic: str = CLINIC_A
        self.records: List[Dict[str, Any]] = []
        self.audit_events: List[Dict[str, Any]] = []
        self.calls: List[tuple] = []
        # Seed plausible link-targets in CLINIC_A.
        self.receipts: List[Dict[str, Any]] = [
            {"id": _uuid.UUID(RECEIPT_A), "clinic_id": CLINIC_A},
            # RECEIPT_B intentionally belongs to CLINIC_B for the
            # cross-clinic 404 test.
            {"id": _uuid.UUID(RECEIPT_B), "clinic_id": CLINIC_B},
        ]
        self.governance_events: List[Dict[str, Any]] = [
            {"event_id": _uuid.UUID(GOV_EVENT_A), "clinic_id": CLINIC_A},
        ]
        self.assistant_runs: List[Dict[str, Any]] = [
            {"id": _uuid.UUID(ASSIST_RUN_A), "clinic_id": CLINIC_A},
        ]
        self.policy_versions: List[Dict[str, Any]] = [
            {
                "clinic_policy_version_id": _uuid.UUID(POLICY_VER_A),
                "clinic_id": CLINIC_A,
            },
        ]
        self.committed = False
        self.rolled_back = False

    # session-shape stubs
    def begin(self): return None
    def commit(self): self.committed = True
    def rollback(self): self.rolled_back = True
    def close(self): return None

    def _scoped_records(self) -> List[Dict[str, Any]]:
        return [r for r in self.records if r["clinic_id"] == self.current_clinic]

    def execute(self, statement, params=None):
        sql = str(getattr(statement, "text", statement))
        p = dict(params or {})
        self.calls.append((sql, p))

        # ---- linked-target existence probes ----
        if (
            "FROM assistant_run_receipts" in sql
            and "id = CAST(:link_id AS uuid)" in sql
            and "SELECT 1" in sql
        ):
            for r in self.receipts:
                if (
                    str(r["id"]) == p["link_id"]
                    and r["clinic_id"] == p["clinic_id"]
                ):
                    return _Result(row={"?column?": 1})
            return _Result(row=None)

        if (
            "FROM clinic_governance_events" in sql
            and "event_id = CAST(:link_id AS uuid)" in sql
            and "SELECT 1" in sql
        ):
            for r in self.governance_events:
                if (
                    str(r["event_id"]) == p["link_id"]
                    and r["clinic_id"] == p["clinic_id"]
                ):
                    return _Result(row={"?column?": 1})
            return _Result(row=None)

        if (
            "FROM assistant_runs " in sql
            and "id = CAST(:link_id AS uuid)" in sql
            and "SELECT 1" in sql
        ):
            for r in self.assistant_runs:
                if (
                    str(r["id"]) == p["link_id"]
                    and r["clinic_id"] == p["clinic_id"]
                ):
                    return _Result(row={"?column?": 1})
            return _Result(row=None)

        if (
            "FROM clinic_policy_versions" in sql
            and "clinic_policy_version_id = CAST(:link_id AS uuid)" in sql
            and "SELECT 1" in sql
        ):
            for r in self.policy_versions:
                if (
                    str(r["clinic_policy_version_id"]) == p["link_id"]
                    and r["clinic_id"] == p["clinic_id"]
                ):
                    return _Result(row={"?column?": 1})
            return _Result(row=None)

        # ---- INSERT incident record ----
        if "INSERT INTO ai_incident_near_miss_records" in sql:
            now = datetime.now(timezone.utc)
            row = {
                "incident_id": _uuid.uuid4(),
                "clinic_id": p["clinic_id"],
                "created_by_user_id": _uuid.UUID(p["created_by_user_id"]),
                "reviewed_by_user_id": None,
                "closed_by_user_id": None,
                "voided_by_user_id": None,
                "status": "open",
                "severity": p["severity"],
                "category": p["category"],
                "source": p["source"],
                "outcome": p["outcome"],
                "action_taken_category": p.get("action_taken_category"),
                "learning_recommended": bool(p["learning_recommended"]),
                "policy_review_recommended": bool(
                    p["policy_review_recommended"]
                ),
                "client_communication_review_recommended": bool(
                    p["client_communication_review_recommended"]
                ),
                "occurred_at": p.get("occurred_at"),
                "detected_at": p.get("detected_at"),
                "reported_at": now,
                "reviewed_at": None,
                "closed_at": None,
                "voided_at": None,
                "linked_receipt_id": (
                    _uuid.UUID(p["linked_receipt_id"])
                    if p.get("linked_receipt_id") else None
                ),
                "linked_governance_event_id": (
                    _uuid.UUID(p["linked_governance_event_id"])
                    if p.get("linked_governance_event_id") else None
                ),
                "linked_assistant_run_id": (
                    _uuid.UUID(p["linked_assistant_run_id"])
                    if p.get("linked_assistant_run_id") else None
                ),
                "linked_clinic_policy_version_id": (
                    _uuid.UUID(p["linked_clinic_policy_version_id"])
                    if p.get("linked_clinic_policy_version_id") else None
                ),
                "void_reason_category": None,
                "created_at": now,
                "updated_at": now,
            }
            self.records.append(row)
            return _Result(row=row)

        # ---- SELECT record by clinic + incident_id ----
        if (
            "FROM ai_incident_near_miss_records" in sql
            and "incident_id = CAST(:incident_id AS uuid)" in sql
        ):
            for r in self._scoped_records():
                if str(r["incident_id"]) == p["incident_id"]:
                    return _Result(row=r)
            return _Result(row=None)

        # ---- list records (clinic-scoped, possibly user-scoped) ----
        if (
            "FROM ai_incident_near_miss_records" in sql
            and "ORDER BY reported_at DESC" in sql
        ):
            rows = list(self._scoped_records())
            if "created_by_user_id = CAST(:user_id AS uuid)" in sql:
                rows = [r for r in rows
                        if str(r["created_by_user_id"]) == p["user_id"]]
            if "status = :status" in sql:
                rows = [r for r in rows if r["status"] == p["status"]]
            if "severity = :severity" in sql:
                rows = [r for r in rows if r["severity"] == p["severity"]]
            if "category = :category" in sql:
                rows = [r for r in rows if r["category"] == p["category"]]
            if "source = :source" in sql:
                rows = [r for r in rows if r["source"] == p["source"]]
            if "linked_receipt_id = CAST(:linked_receipt_id AS uuid)" in sql:
                rows = [
                    r for r in rows
                    if r.get("linked_receipt_id")
                    and str(r["linked_receipt_id"]) == p["linked_receipt_id"]
                ]
            rows = sorted(
                rows,
                key=lambda r: (r["reported_at"], r["created_at"]),
                reverse=True,
            )
            return _Result(rows=rows[: int(p.get("limit", 50))])

        # ---- UPDATE incident record (PATCH/review/close/void) ----
        if (
            "UPDATE ai_incident_near_miss_records" in sql
            and "RETURNING" in sql
        ):
            cid = p.get("clinic_id")
            iid = p.get("incident_id")
            for r in self.records:
                if (
                    r["clinic_id"] == cid
                    and str(r["incident_id"]) == iid
                ):
                    # Status guard rails matching the SQL WHERE clause:
                    # close UPDATE filters status IN open/in_review/actioned;
                    # void UPDATE filters status <> voided;
                    # review/PATCH have no extra status filter.
                    if (
                        "status = 'closed'" in sql
                        and r["status"] not in ("open", "in_review", "actioned")
                    ):
                        return _Result(row=None)
                    if (
                        "status = 'voided'" in sql
                        and r["status"] == "voided"
                    ):
                        return _Result(row=None)

                    # Apply review (transition + COALESCE actor/timestamp).
                    if "next_status" in p:
                        r["status"] = p["next_status"]
                        if r["reviewed_by_user_id"] is None:
                            r["reviewed_by_user_id"] = _uuid.UUID(p["actor"])
                        if r["reviewed_at"] is None:
                            r["reviewed_at"] = datetime.now(timezone.utc)
                    # Apply close.
                    if "status = 'closed'" in sql:
                        r["status"] = "closed"
                        if r["closed_by_user_id"] is None:
                            r["closed_by_user_id"] = _uuid.UUID(p["actor"])
                        if r["closed_at"] is None:
                            r["closed_at"] = datetime.now(timezone.utc)
                    # Apply void.
                    if "status = 'voided'" in sql:
                        r["status"] = "voided"
                        if r["void_reason_category"] is None:
                            r["void_reason_category"] = p[
                                "void_reason_category"
                            ]
                        if r["voided_by_user_id"] is None:
                            r["voided_by_user_id"] = _uuid.UUID(p["actor"])
                        if r["voided_at"] is None:
                            r["voided_at"] = datetime.now(timezone.utc)

                    # Apply PATCH field-by-field updates.
                    for col in (
                        "category", "severity", "source", "outcome",
                        "occurred_at", "detected_at",
                        "action_taken_category",
                        "learning_recommended",
                        "policy_review_recommended",
                        "client_communication_review_recommended",
                    ):
                        if col in p:
                            r[col] = p[col]

                    r["updated_at"] = datetime.now(timezone.utc)
                    return _Result(row=r)
            return _Result(row=None)

        # ---- summary aggregate ----
        if (
            "FROM ai_incident_near_miss_records r" in sql
            and "COUNT(*) FILTER" in sql
            and "records_total" in sql
        ):
            cid = p["clinic_id"]
            window_days = int(p["window_days"])
            from datetime import timedelta as _td
            window_start = (
                datetime.now(timezone.utc) - _td(days=window_days)
            )

            scoped = [r for r in self.records if r["clinic_id"] == cid]
            in_window = [
                r for r in scoped if r["reported_at"] >= window_start
            ]

            def _count(rows, **conds) -> int:
                out = 0
                for r in rows:
                    ok = True
                    for k, v in conds.items():
                        if k == "exclude_voided":
                            if v and r["status"] == "voided":
                                ok = False
                                break
                        elif k == "status_in":
                            if r["status"] not in v:
                                ok = False
                                break
                        elif k == "severity_in":
                            if r["severity"] not in v:
                                ok = False
                                break
                        elif k == "linked_receipt":
                            if v and r.get("linked_receipt_id") is None:
                                ok = False
                                break
                        elif k == "boolean_flag":
                            if not r.get(v):
                                ok = False
                                break
                        elif r.get(k) != v:
                            ok = False
                            break
                    if ok:
                        out += 1
                return out

            non_voided_any = [r for r in scoped if r["status"] != "voided"]
            last = (
                max((r["reported_at"] for r in non_voided_any), default=None)
            )
            return _Result(row={
                "records_total": len(scoped),
                "records_in_window": len(in_window),
                "open_records": _count(in_window, status="open"),
                "in_review_records": _count(in_window, status="in_review"),
                "actioned_records": _count(in_window, status="actioned"),
                "closed_records": _count(in_window, status="closed"),
                "voided_records": _count(in_window, status="voided"),
                "high_or_critical_records": _count(
                    in_window, exclude_voided=True,
                    severity_in=("high", "critical"),
                ),
                "privacy_related_records": _count(
                    in_window, exclude_voided=True,
                    category="privacy_or_identifier_risk",
                ),
                "linked_receipt_records": _count(
                    in_window, exclude_voided=True, linked_receipt=True,
                ),
                "learning_recommended_count": _count(
                    in_window, exclude_voided=True,
                    boolean_flag="learning_recommended",
                ),
                "policy_review_recommended_count": _count(
                    in_window, exclude_voided=True,
                    boolean_flag="policy_review_recommended",
                ),
                "client_communication_review_recommended_count": _count(
                    in_window, exclude_voided=True,
                    boolean_flag="client_communication_review_recommended",
                ),
                "last_reported_at": last,
            })

        # ---- admin_audit_events INSERT ----
        if "INSERT INTO admin_audit_events" in sql:
            meta = p["meta"]
            if isinstance(meta, str):
                meta = json.loads(meta)
            self.audit_events.append({
                "clinic_id": p["clinic_id"],
                "admin_user_id": p["admin_user_id"],
                "action": p["action"],
                "target_id": p["target_id"],
                "ip_hash": p.get("ip_hash"),
                "meta": meta,
                "created_at": datetime.now(timezone.utc),
            })
            return _Result(row=None)

        return _Result(row=None)


def build_app(
    *,
    authenticated: bool = True,
    clinic_id: str = CLINIC_A,
    user_id: str = STAFF_USER,
    role: str = "staff",
) -> tuple:
    from app.auth_and_rls import require_clinic_user
    from app.db import get_db
    from app.incident_near_miss import router

    app = FastAPI()
    app.include_router(router)
    fake = IncidentFakeDB()

    def _fake_db_dep(request: Request):
        fake.current_clinic = getattr(request.state, "clinic_id", clinic_id)
        yield fake
        fake.commit()

    app.dependency_overrides[get_db] = _fake_db_dep

    if authenticated:
        def _fake_auth(request: Request) -> Dict[str, str]:
            request.state.clinic_id = clinic_id
            request.state.clinic_user_id = user_id
            request.state.role = role
            request.state.ip_hash = "test_ip_hash"
            return {
                "clinic_id": clinic_id,
                "clinic_user_id": user_id,
                "role": role,
            }
        app.dependency_overrides[require_clinic_user] = _fake_auth

    return app, fake


def auth_headers() -> Dict[str, str]:
    return {"Authorization": "Bearer test-token"}


def client_for(app: FastAPI) -> TestClient:
    return TestClient(app)


def _valid_create_body(**overrides: Any) -> Dict[str, Any]:
    body = {
        "category": "misleading_output",
        "severity": "moderate",
        "source": "assistant_workspace",
        "outcome": "caught_before_use",
    }
    body.update(overrides)
    return body


def _seed_record(
    fake: IncidentFakeDB,
    *,
    clinic_id: str = CLINIC_A,
    created_by_user_id: str = STAFF_USER,
    category: str = "misleading_output",
    severity: str = "moderate",
    source: str = "assistant_workspace",
    outcome: str = "caught_before_use",
    status: str = "open",
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    row = {
        "incident_id": _uuid.uuid4(),
        "clinic_id": clinic_id,
        "created_by_user_id": _uuid.UUID(created_by_user_id),
        "reviewed_by_user_id": None,
        "closed_by_user_id": None,
        "voided_by_user_id": None,
        "status": status,
        "severity": severity,
        "category": category,
        "source": source,
        "outcome": outcome,
        "action_taken_category": None,
        "learning_recommended": False,
        "policy_review_recommended": False,
        "client_communication_review_recommended": False,
        "occurred_at": None,
        "detected_at": None,
        "reported_at": now,
        "reviewed_at": None,
        "closed_at": None,
        "voided_at": None,
        "linked_receipt_id": None,
        "linked_governance_event_id": None,
        "linked_assistant_run_id": None,
        "linked_clinic_policy_version_id": None,
        "void_reason_category": None,
        "created_at": now,
        "updated_at": now,
    }
    fake.records.append(row)
    return row


def _assert_no_forbidden_keys(payload: Any, *, where: str = "response") -> None:
    if isinstance(payload, dict):
        leaked = set(payload.keys()) & FORBIDDEN_RESPONSE_KEYS
        assert not leaked, f"forbidden keys leaked in {where}: {leaked}"
        for k, v in payload.items():
            _assert_no_forbidden_keys(v, where=f"{where}.{k}")
    elif isinstance(payload, list):
        for i, v in enumerate(payload):
            _assert_no_forbidden_keys(v, where=f"{where}[{i}]")


# ---------------------------------------------------------------------
# 1. Router shape / route count
# ---------------------------------------------------------------------


def test_router_registers_expected_endpoint_count() -> None:
    """2A-5.2 registered five endpoints; 2A-5.3 adds five lifecycle
    endpoints (PATCH + review + close + void + summary), giving ten
    total."""
    from app.incident_near_miss import router
    pairs = set()
    for r in router.routes:
        methods = getattr(r, "methods", None) or set()
        for m in methods:
            if m in ("HEAD", "OPTIONS"):
                continue
            pairs.add((m, r.path))
    assert len(pairs) == 10, sorted(pairs)


def test_router_paths_match_design() -> None:
    from app.incident_near_miss import router
    paths_with_methods = {(r.path, tuple(sorted(getattr(r, "methods", set()))))
                          for r in router.routes}
    paths = {p for p, _ in paths_with_methods}
    assert "/v1/governance/incidents/vocabulary" in paths
    assert "/v1/governance/incidents/records" in paths
    assert "/v1/governance/incidents/records/mine" in paths
    assert "/v1/governance/incidents/records/{incident_id}" in paths


def test_lifecycle_routes_registered() -> None:
    """2A-5.3 must add the four lifecycle routes + summary."""
    from app.incident_near_miss import router
    paths_methods = {
        (tuple(sorted(getattr(r, "methods", set()) - {"HEAD", "OPTIONS"})), r.path)
        for r in router.routes
    }
    assert (("PATCH",), "/v1/governance/incidents/records/{incident_id}") in paths_methods
    assert (("POST",), "/v1/governance/incidents/records/{incident_id}/review") in paths_methods
    assert (("POST",), "/v1/governance/incidents/records/{incident_id}/close") in paths_methods
    assert (("POST",), "/v1/governance/incidents/records/{incident_id}/void") in paths_methods
    assert (("GET",), "/v1/governance/incidents/summary") in paths_methods


def test_module_does_not_import_sibling_feature_modules() -> None:
    """Conflation guard. The incident module is a standalone
    governance surface."""
    src = inspect.getsource(__import__("app.incident_near_miss",
                                       fromlist=["x"]))
    forbidden_imports = (
        "from app.assistant_policy",
        "from app.governance_policy",
        "from app.client_transparency",
        "from app.self_assessment",
        "from app.learn_v1",
        "from app.portal_assistant",
    )
    for f in forbidden_imports:
        assert f not in src, f"forbidden import in module source: {f}"


def test_no_invalid_partial_index_on_conflict_in_module() -> None:
    """M6.10.1B / TD-BE regression. Assemble fragments so this
    test source itself contains no literal forbidden string."""
    from app import incident_near_miss
    fragment = (
        "ON CONFLICT (clinic_id, " + "action, " + "idempotency_key)"
    )
    assert fragment not in inspect.getsource(incident_near_miss)


# ---------------------------------------------------------------------
# 2. /vocabulary
# ---------------------------------------------------------------------


def test_vocabulary_endpoint_returns_all_expected_values() -> None:
    app, _fake = build_app(role="staff")
    resp = client_for(app).get(
        "/v1/governance/incidents/vocabulary", headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body["statuses"]) == {
        "open", "in_review", "actioned", "closed", "voided",
    }
    assert set(body["severities"]) == {"low", "moderate", "high", "critical"}
    expected_categories = {
        "misleading_output", "inaccurate_output", "unsafe_suggestion",
        "privacy_or_identifier_risk", "overconfident_output",
        "missing_human_review", "policy_boundary_issue",
        "inappropriate_client_communication", "workflow_confusion", "other",
    }
    assert set(body["categories"]) == expected_categories
    expected_sources = {
        "assistant_workspace", "external_ai_tool", "ambient_or_scribe",
        "client_communication", "internal_summary", "clinical_note_support",
        "other",
    }
    assert set(body["sources"]) == expected_sources
    expected_outcomes = {
        "caught_before_use", "corrected_before_use", "used_with_correction",
        "escalated_for_review", "client_communication_delayed",
        "clinical_team_reviewed", "other",
    }
    assert set(body["outcomes"]) == expected_outcomes
    assert set(body["action_taken_categories"]) == {
        "no_action_required", "additional_review", "staff_briefing",
        "policy_review", "process_change", "vendor_followup", "other",
    }
    assert set(body["void_reason_categories"]) == {
        "duplicate", "wrong_clinic_record", "test_data",
        "incorrect_metadata", "other",
    }
    assert "governance_note" in body
    _assert_no_forbidden_keys(body)


def test_vocabulary_matches_migration_check_constraints() -> None:
    """Drift guard: every enum value the handler exports must appear
    inside the migration's CHECK constraint text."""
    from app import incident_near_miss
    sql_path = (
        REPO_ROOT / "migrations"
        / "20260603_03_incident_near_miss_schema.sql"
    )
    sql = sql_path.read_text(encoding="utf-8")
    for name, values in (
        ("statuses", incident_near_miss.STATUS_VALUES),
        ("severities", incident_near_miss.SEVERITY_VALUES),
        ("categories", incident_near_miss.CATEGORY_VALUES),
        ("sources", incident_near_miss.SOURCE_VALUES),
        ("outcomes", incident_near_miss.OUTCOME_VALUES),
        ("action_taken_categories", incident_near_miss.ACTION_TAKEN_VALUES),
        ("void_reason_categories", incident_near_miss.VOID_REASON_VALUES),
    ):
        for v in values:
            assert f"'{v}'" in sql, (
                f"vocab value {name}={v!r} not present in migration CHECK"
            )


def test_vocabulary_governance_note_is_safe_negative_disclaimer() -> None:
    app, _fake = build_app(role="staff")
    resp = client_for(app).get(
        "/v1/governance/incidents/vocabulary", headers=auth_headers(),
    )
    note = resp.json()["governance_note"].lower()
    # Negative disclaimers present.
    assert "metadata-only" in note
    assert "not clinical records" in note
    # Positive marketing claims absent (fragment-assembled).
    for a, b in _FORBIDDEN_WORDING_FRAGMENTS:
        phrase = (a + b).lower()
        assert phrase not in note, (
            f"governance_note positive claim: {a}{b}"
        )


# ---------------------------------------------------------------------
# 3. POST /records  - create
# ---------------------------------------------------------------------


def test_create_works_for_ordinary_clinic_user() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(),
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    r = body["record"]
    assert r["status"] == "open"
    assert r["category"] == "misleading_output"
    assert r["severity"] == "moderate"
    assert r["source"] == "assistant_workspace"
    assert r["outcome"] == "caught_before_use"
    assert r["created_by_user_id"] == STAFF_USER
    # Disclosure flags.
    for flag in (
        "raw_content_included", "clinical_content_included",
        "staff_identifiers_included", "client_identifiers_included",
        "patient_identifiers_included",
    ):
        assert r[flag] is False
    _assert_no_forbidden_keys(body)


def test_create_defaults_status_to_open() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(),
        headers=auth_headers(),
    )
    assert resp.status_code == 201
    assert resp.json()["record"]["status"] == "open"


def test_create_rejects_extra_body_fields() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json={**_valid_create_body(), "summary": "should be rejected"},
        headers=auth_headers(),
    )
    assert resp.status_code == 422
    assert fake.records == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("summary", "stuff"),
        ("note", "stuff"),
        ("description", "stuff"),
        ("narrative", "stuff"),
        ("comments", "stuff"),
        ("free_text", "stuff"),
        ("clinical_content", "stuff"),
        ("client_identifier", "stuff"),
        ("patient_identifier", "stuff"),
        ("staff_identifier", "stuff"),
        ("raw_prompt", "stuff"),
        ("raw_output", "stuff"),
        ("transcript", "stuff"),
        ("consent_text", "stuff"),
        ("legal_consent", "stuff"),
        ("legal_claim", "stuff"),
        ("insurance", "stuff"),
        ("negligence", "stuff"),
        ("malpractice", "stuff"),
    ],
)
def test_create_rejects_forbidden_narrative_fields(field: str, value: str) -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json={**_valid_create_body(), field: value},
        headers=auth_headers(),
    )
    assert resp.status_code == 422
    assert fake.records == []


@pytest.mark.parametrize(
    "field,bad_value,detail",
    [
        ("category", "not_a_category", "invalid_category"),
        ("severity", "screaming", "invalid_severity"),
        ("source", "carrier_pigeon", "invalid_source"),
        ("outcome", "vanished", "invalid_outcome"),
    ],
)
def test_create_rejects_invalid_required_enum(
    field: str, bad_value: str, detail: str,
) -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(**{field: bad_value}),
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == detail
    assert fake.records == []


def test_create_rejects_invalid_action_taken_category() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(action_taken_category="just_thoughts"),
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "invalid_action_taken_category"
    assert fake.records == []


# ---- Linked-ID validation ------------------------------------------


def test_create_validates_linked_receipt_id_when_present() -> None:
    app, fake = build_app(role="staff", clinic_id=CLINIC_A)
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(linked_receipt_id=RECEIPT_A),
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["record"]["linked_receipt_id"] == RECEIPT_A


def test_create_rejects_cross_clinic_linked_receipt_id() -> None:
    app, fake = build_app(role="staff", clinic_id=CLINIC_A)
    # RECEIPT_B belongs to CLINIC_B in the seed; CLINIC_A admin
    # cannot reference it.
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(linked_receipt_id=RECEIPT_B),
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "linked_receipt_not_found"
    assert fake.records == []


def test_create_rejects_unknown_linked_receipt_id() -> None:
    app, fake = build_app(role="staff", clinic_id=CLINIC_A)
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(linked_receipt_id=str(_uuid.uuid4())),
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "linked_receipt_not_found"


def test_create_validates_linked_governance_event_id() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(linked_governance_event_id=GOV_EVENT_A),
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text


def test_create_rejects_unknown_linked_governance_event_id() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(
            linked_governance_event_id=str(_uuid.uuid4())
        ),
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "linked_governance_event_not_found"


def test_create_validates_linked_assistant_run_id() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(linked_assistant_run_id=ASSIST_RUN_A),
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text


def test_create_rejects_unknown_linked_assistant_run_id() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(
            linked_assistant_run_id=str(_uuid.uuid4())
        ),
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "linked_assistant_run_not_found"


def test_create_validates_linked_clinic_policy_version_id() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(
            linked_clinic_policy_version_id=POLICY_VER_A
        ),
        headers=auth_headers(),
    )
    assert resp.status_code == 201, resp.text


def test_create_rejects_unknown_linked_clinic_policy_version_id() -> None:
    app, fake = build_app(role="staff")
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(
            linked_clinic_policy_version_id=str(_uuid.uuid4())
        ),
        headers=auth_headers(),
    )
    assert resp.status_code == 404
    assert resp.json().get("detail") == "linked_clinic_policy_version_not_found"


# ---- Audit event ---------------------------------------------------


def test_create_writes_metadata_only_audit_event() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(),
        headers=auth_headers(),
    )
    assert resp.status_code == 201
    assert len(fake.audit_events) == 1
    ev = fake.audit_events[0]
    assert ev["action"] == "ai_incident_near_miss_record_created"
    assert ev["clinic_id"] == CLINIC_A
    assert ev["admin_user_id"] == STAFF_USER
    # No raw text in meta.
    meta_str = json.dumps(ev["meta"])
    for forbidden in ("summary", "note", "description", "narrative",
                      "transcript", "raw_prompt", "raw_output"):
        assert forbidden not in meta_str
    # Audit meta is IDs + enums + booleans + presence flags.
    assert ev["meta"]["category"] == "misleading_output"
    assert ev["meta"]["severity"] == "moderate"
    assert ev["meta"]["status"] == "open"
    _assert_no_forbidden_keys(ev["meta"], where="audit.meta")


# ---------------------------------------------------------------------
# 4. GET /records  (admin tier)
# ---------------------------------------------------------------------


@pytest.mark.parametrize("role", ["admin", "owner", "practice_manager"])
def test_admin_tier_can_list_all_records(role: str) -> None:
    app, fake = build_app(role=role, user_id=ADMIN_USER)
    _seed_record(fake, created_by_user_id=STAFF_USER)
    _seed_record(fake, created_by_user_id=OTHER_USER)
    resp = client_for(app).get(
        "/v1/governance/incidents/records", headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["records"]) == 2
    _assert_no_forbidden_keys(body)


@pytest.mark.parametrize("role", ["staff", "clinic_user", "reader"])
def test_non_admin_cannot_list_all_records(role: str) -> None:
    app, fake = build_app(role=role)
    _seed_record(fake)
    resp = client_for(app).get(
        "/v1/governance/incidents/records", headers=auth_headers(),
    )
    assert resp.status_code == 403
    assert resp.json().get("detail") == "forbidden_not_admin"


@pytest.mark.parametrize(
    "filter_name,bad_value,detail",
    [
        ("status", "screaming", "invalid_status"),
        ("severity", "huh", "invalid_severity"),
        ("category", "nope", "invalid_category"),
        ("source", "paper", "invalid_source"),
    ],
)
def test_list_rejects_invalid_filter(
    filter_name: str, bad_value: str, detail: str,
) -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).get(
        f"/v1/governance/incidents/records?{filter_name}={bad_value}",
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == detail


def test_list_filters_by_status() -> None:
    app, fake = build_app(role="admin")
    a = _seed_record(fake, status="open")
    b = _seed_record(fake, status="closed")
    resp = client_for(app).get(
        "/v1/governance/incidents/records?status=closed",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    ids = [r["incident_id"] for r in resp.json()["records"]]
    assert str(b["incident_id"]) in ids
    assert str(a["incident_id"]) not in ids


def test_list_filters_by_severity() -> None:
    app, fake = build_app(role="admin")
    _seed_record(fake, severity="low")
    high = _seed_record(fake, severity="high")
    resp = client_for(app).get(
        "/v1/governance/incidents/records?severity=high",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["records"]) == 1
    assert body["records"][0]["incident_id"] == str(high["incident_id"])
    assert body["applied_filters"]["severity"] == "high"


def test_list_filters_by_category() -> None:
    app, fake = build_app(role="admin")
    _seed_record(fake, category="misleading_output")
    target = _seed_record(fake, category="privacy_or_identifier_risk")
    resp = client_for(app).get(
        "/v1/governance/incidents/records?category=privacy_or_identifier_risk",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["records"]) == 1
    assert body["records"][0]["incident_id"] == str(target["incident_id"])


def test_list_filters_by_source() -> None:
    app, fake = build_app(role="admin")
    _seed_record(fake, source="assistant_workspace")
    target = _seed_record(fake, source="external_ai_tool")
    resp = client_for(app).get(
        "/v1/governance/incidents/records?source=external_ai_tool",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["records"]) == 1
    assert body["records"][0]["incident_id"] == str(target["incident_id"])


def test_list_respects_limit_cap() -> None:
    app, fake = build_app(role="admin")
    for _ in range(5):
        _seed_record(fake)
    resp = client_for(app).get(
        "/v1/governance/incidents/records?limit=2",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["limit"] == 2
    assert len(body["records"]) == 2


def test_list_rejects_limit_above_cap() -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).get(
        "/v1/governance/incidents/records?limit=999",
        headers=auth_headers(),
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------
# 5. GET /records/mine  (self-scope)
# ---------------------------------------------------------------------


def test_mine_returns_only_callers_records() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    own = _seed_record(fake, created_by_user_id=STAFF_USER)
    _seed_record(fake, created_by_user_id=OTHER_USER)
    resp = client_for(app).get(
        "/v1/governance/incidents/records/mine", headers=auth_headers(),
    )
    assert resp.status_code == 200
    ids = [r["incident_id"] for r in resp.json()["records"]]
    assert ids == [str(own["incident_id"])]


def test_mine_visible_to_non_admin() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    _seed_record(fake, created_by_user_id=STAFF_USER)
    resp = client_for(app).get(
        "/v1/governance/incidents/records/mine", headers=auth_headers(),
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------
# 6. GET /records/{incident_id}
# ---------------------------------------------------------------------


def test_detail_works_for_admin() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record(fake, created_by_user_id=STAFF_USER)
    resp = client_for(app).get(
        f"/v1/governance/incidents/records/{row['incident_id']}",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["record"]["incident_id"] == str(row["incident_id"])


def test_detail_works_for_creator() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    row = _seed_record(fake, created_by_user_id=STAFF_USER)
    resp = client_for(app).get(
        f"/v1/governance/incidents/records/{row['incident_id']}",
        headers=auth_headers(),
    )
    assert resp.status_code == 200


def test_detail_returns_404_for_non_admin_non_creator() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    row = _seed_record(fake, created_by_user_id=OTHER_USER)
    resp = client_for(app).get(
        f"/v1/governance/incidents/records/{row['incident_id']}",
        headers=auth_headers(),
    )
    # Enumeration-safe 404.
    assert resp.status_code == 404
    assert resp.json().get("detail") == "incident_not_found"


def test_detail_returns_404_for_cross_clinic() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER, clinic_id=CLINIC_A)
    other = _seed_record(fake, clinic_id=CLINIC_B)
    resp = client_for(app).get(
        f"/v1/governance/incidents/records/{other['incident_id']}",
        headers=auth_headers(),
    )
    assert resp.status_code == 404


def test_detail_unknown_id_404() -> None:
    app, fake = build_app(role="admin")
    resp = client_for(app).get(
        f"/v1/governance/incidents/records/{_uuid.uuid4()}",
        headers=auth_headers(),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------
# 7. Cross-cutting doctrine sweeps
# ---------------------------------------------------------------------


def test_all_response_envelopes_metadata_only() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record(fake, created_by_user_id=ADMIN_USER)
    create_resp = client_for(app).post(
        "/v1/governance/incidents/records",
        json=_valid_create_body(),
        headers=auth_headers(),
    )
    assert create_resp.status_code == 201
    _assert_no_forbidden_keys(create_resp.json(), where="create")
    for url in (
        "/v1/governance/incidents/vocabulary",
        "/v1/governance/incidents/records",
        "/v1/governance/incidents/records/mine",
        f"/v1/governance/incidents/records/{row['incident_id']}",
    ):
        r = client_for(app).get(url, headers=auth_headers())
        assert r.status_code == 200, (url, r.text)
        _assert_no_forbidden_keys(r.json(), where=url)


def test_unauthenticated_requests_return_401() -> None:
    app, _fake = build_app(authenticated=False)
    paths = [
        "/v1/governance/incidents/vocabulary",
        "/v1/governance/incidents/records",
        "/v1/governance/incidents/records/mine",
    ]
    for path in paths:
        r = TestClient(app).get(path)
        assert r.status_code == 401, path




# ---------------------------------------------------------------------
# 2A-5.3 lifecycle helpers
# ---------------------------------------------------------------------


def _seed_record_with_status(
    fake: IncidentFakeDB, *, status: str,
    created_by_user_id: str = STAFF_USER,
    clinic_id: str = CLINIC_A,
    linked_receipt: bool = False,
    severity: str = "moderate",
    category: str = "misleading_output",
    learning_recommended: bool = False,
    policy_review_recommended: bool = False,
    client_communication_review_recommended: bool = False,
    reported_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    row = _seed_record(
        fake,
        clinic_id=clinic_id,
        created_by_user_id=created_by_user_id,
        severity=severity,
        category=category,
        status=status,
    )
    if linked_receipt:
        row["linked_receipt_id"] = _uuid.UUID(RECEIPT_A)
    row["learning_recommended"] = learning_recommended
    row["policy_review_recommended"] = policy_review_recommended
    row["client_communication_review_recommended"] = (
        client_communication_review_recommended
    )
    if reported_at is not None:
        row["reported_at"] = reported_at
    return row


# ---------------------------------------------------------------------
# 8. PATCH /records/{incident_id}
# ---------------------------------------------------------------------


def test_patch_creator_can_update_own_open_record() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=STAFF_USER,
    )
    resp = client_for(app).patch(
        f"/v1/governance/incidents/records/{row['incident_id']}",
        json={"severity": "high"},
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["record"]["severity"] == "high"


@pytest.mark.parametrize("status", ["in_review", "actioned", "closed", "voided"])
def test_patch_creator_blocked_when_record_no_longer_open(status: str) -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    row = _seed_record_with_status(
        fake, status=status, created_by_user_id=STAFF_USER,
    )
    resp = client_for(app).patch(
        f"/v1/governance/incidents/records/{row['incident_id']}",
        json={"severity": "high"},
        headers=auth_headers(),
    )
    assert resp.status_code == 409
    assert resp.json().get("detail") == "incident_not_editable"


@pytest.mark.parametrize("status", ["open", "in_review", "actioned"])
def test_patch_admin_can_update_open_in_review_or_actioned(status: str) -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status=status, created_by_user_id=OTHER_USER,
    )
    resp = client_for(app).patch(
        f"/v1/governance/incidents/records/{row['incident_id']}",
        json={"severity": "low"},
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["record"]["severity"] == "low"


@pytest.mark.parametrize("status", ["closed", "voided"])
def test_patch_admin_cannot_update_closed_or_voided(status: str) -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status=status, created_by_user_id=OTHER_USER,
    )
    resp = client_for(app).patch(
        f"/v1/governance/incidents/records/{row['incident_id']}",
        json={"severity": "high"},
        headers=auth_headers(),
    )
    assert resp.status_code == 409
    assert resp.json().get("detail") == "incident_not_editable"


def test_patch_non_admin_non_creator_returns_404() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=OTHER_USER,
    )
    resp = client_for(app).patch(
        f"/v1/governance/incidents/records/{row['incident_id']}",
        json={"severity": "high"},
        headers=auth_headers(),
    )
    # Enumeration-safe 404 (same as missing/cross-clinic).
    assert resp.status_code == 404
    assert resp.json().get("detail") == "incident_not_found"


def test_patch_rejects_extra_fields() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=STAFF_USER,
    )
    resp = client_for(app).patch(
        f"/v1/governance/incidents/records/{row['incident_id']}",
        json={"severity": "high", "summary": "freeform leak"},
        headers=auth_headers(),
    )
    assert resp.status_code == 422


@pytest.mark.parametrize(
    "field,bad_value,detail",
    [
        ("category", "nope", "invalid_category"),
        ("severity", "huh", "invalid_severity"),
        ("source", "carrier_pigeon", "invalid_source"),
        ("outcome", "vanished", "invalid_outcome"),
        ("action_taken_category", "thoughts", "invalid_action_taken_category"),
    ],
)
def test_patch_rejects_invalid_enum_values(
    field: str, bad_value: str, detail: str,
) -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=STAFF_USER,
    )
    resp = client_for(app).patch(
        f"/v1/governance/incidents/records/{row['incident_id']}",
        json={field: bad_value},
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == detail


@pytest.mark.parametrize(
    "field",
    [
        "linked_receipt_id",
        "linked_governance_event_id",
        "linked_assistant_run_id",
        "linked_clinic_policy_version_id",
        "status",
        "void_reason_category",
        "created_by_user_id",
        "reviewed_by_user_id",
        "closed_by_user_id",
        "voided_by_user_id",
    ],
)
def test_patch_rejects_disallowed_columns(field: str) -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=STAFF_USER,
    )
    body: Dict[str, Any] = {field: str(_uuid.uuid4())}
    resp = client_for(app).patch(
        f"/v1/governance/incidents/records/{row['incident_id']}",
        json=body,
        headers=auth_headers(),
    )
    # `extra="forbid"` rejection at the parser layer.
    assert resp.status_code == 422


def test_patch_updates_updated_at_and_writes_audit_event() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=OTHER_USER,
    )
    before = row["updated_at"]
    resp = client_for(app).patch(
        f"/v1/governance/incidents/records/{row['incident_id']}",
        json={"severity": "critical"},
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    # updated_at was bumped (the fake's UPDATE writes now()).
    assert row["updated_at"] >= before
    updated = [
        e for e in fake.audit_events
        if e["action"] == "ai_incident_near_miss_record_updated"
    ]
    assert len(updated) == 1
    meta = updated[0]["meta"]
    assert "changed_field_names" in meta
    assert "severity" in meta["changed_field_names"]
    assert meta["severity"] == "critical"
    assert meta["actor_tier"] == "admin"
    _assert_no_forbidden_keys(meta, where="audit.meta")


def test_patch_empty_body_returns_400() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=STAFF_USER,
    )
    resp = client_for(app).patch(
        f"/v1/governance/incidents/records/{row['incident_id']}",
        json={},
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "incident_update_empty"


# ---------------------------------------------------------------------
# 9. POST /records/{incident_id}/review
# ---------------------------------------------------------------------


def test_review_requires_admin() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=STAFF_USER,
    )
    resp = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/review",
        json={},
        headers=auth_headers(),
    )
    assert resp.status_code == 403
    assert resp.json().get("detail") == "forbidden_not_admin"


@pytest.mark.parametrize(
    "src,next_status,expected",
    [
        ("open", None, "in_review"),
        ("open", "in_review", "in_review"),
        ("open", "actioned", "actioned"),
        ("in_review", None, "actioned"),
        ("in_review", "actioned", "actioned"),
        ("in_review", "in_review", "in_review"),
        ("actioned", None, "actioned"),
        ("actioned", "actioned", "actioned"),
    ],
)
def test_review_valid_transitions(
    src: str, next_status: Optional[str], expected: str,
) -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status=src, created_by_user_id=OTHER_USER,
    )
    body: Dict[str, Any] = {}
    if next_status is not None:
        body["next_status"] = next_status
    resp = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/review",
        json=body,
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["record"]["status"] == expected


@pytest.mark.parametrize("src", ["closed", "voided"])
def test_review_blocked_from_closed_or_voided(src: str) -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status=src, created_by_user_id=OTHER_USER,
    )
    resp = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/review",
        json={},
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "invalid_transition"


def test_review_invalid_next_status_400() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=OTHER_USER,
    )
    resp = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/review",
        json={"next_status": "closed"},  # closed is not a review target
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "invalid_status"


def test_review_invalid_action_taken_category_400() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=OTHER_USER,
    )
    resp = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/review",
        json={"action_taken_category": "ponder"},
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "invalid_action_taken_category"


def test_review_sets_reviewed_by_and_reviewed_at_then_preserves() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=OTHER_USER,
    )
    first = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/review",
        json={},
        headers=auth_headers(),
    )
    assert first.status_code == 200
    pv = first.json()["record"]
    assert pv["reviewed_by_user_id"] == ADMIN_USER
    first_reviewed_at = pv["reviewed_at"]
    assert first_reviewed_at is not None

    # Second review (in_review -> actioned). reviewed_at must remain
    # the original first-write-wins value.
    second = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/review",
        json={"next_status": "actioned"},
        headers=auth_headers(),
    )
    assert second.status_code == 200
    assert second.json()["record"]["reviewed_at"] == first_reviewed_at


def test_review_writes_metadata_only_audit_event() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=OTHER_USER,
    )
    client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/review",
        json={"action_taken_category": "staff_briefing",
              "learning_recommended": True},
        headers=auth_headers(),
    )
    reviewed = [
        e for e in fake.audit_events
        if e["action"] == "ai_incident_near_miss_record_reviewed"
    ]
    assert len(reviewed) == 1
    meta = reviewed[0]["meta"]
    assert meta["previous_status"] == "open"
    assert meta["status"] == "in_review"
    assert meta["action_taken_category"] == "staff_briefing"
    assert meta["learning_recommended"] is True
    _assert_no_forbidden_keys(meta, where="audit.meta")


# ---------------------------------------------------------------------
# 10. POST /records/{incident_id}/close
# ---------------------------------------------------------------------


def test_close_requires_admin() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=STAFF_USER,
    )
    resp = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/close",
        headers=auth_headers(),
    )
    assert resp.status_code == 403


@pytest.mark.parametrize("src", ["open", "in_review", "actioned"])
def test_close_from_valid_states(src: str) -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status=src, created_by_user_id=OTHER_USER,
    )
    resp = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/close",
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()["record"]
    assert body["status"] == "closed"
    assert body["closed_by_user_id"] == ADMIN_USER
    assert body["closed_at"] is not None


def test_close_idempotent_already_closed_no_duplicate_audit() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=OTHER_USER,
    )
    client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/close",
        headers=auth_headers(),
    )
    audit_before = len([
        e for e in fake.audit_events
        if e["action"] == "ai_incident_near_miss_record_closed"
    ])
    resp = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/close",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["record"]["status"] == "closed"
    audit_after = len([
        e for e in fake.audit_events
        if e["action"] == "ai_incident_near_miss_record_closed"
    ])
    assert audit_after == audit_before


def test_close_voided_rejected() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status="voided", created_by_user_id=OTHER_USER,
    )
    resp = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/close",
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "invalid_transition"


# ---------------------------------------------------------------------
# 11. POST /records/{incident_id}/void
# ---------------------------------------------------------------------


def test_void_requires_admin() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=STAFF_USER,
    )
    resp = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/void",
        json={"void_reason_category": "duplicate"},
        headers=auth_headers(),
    )
    assert resp.status_code == 403


@pytest.mark.parametrize("src", ["open", "in_review", "actioned", "closed"])
def test_void_from_any_non_voided_state(src: str) -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status=src, created_by_user_id=OTHER_USER,
    )
    resp = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/void",
        json={"void_reason_category": "duplicate"},
        headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()["record"]
    assert body["status"] == "voided"
    assert body["void_reason_category"] == "duplicate"
    assert body["voided_by_user_id"] == ADMIN_USER
    assert body["voided_at"] is not None


def test_void_invalid_reason_400() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=OTHER_USER,
    )
    resp = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/void",
        json={"void_reason_category": "vibes"},
        headers=auth_headers(),
    )
    assert resp.status_code == 400
    assert resp.json().get("detail") == "invalid_void_reason_category"


def test_void_idempotent_preserves_first_reason() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=OTHER_USER,
    )
    r1 = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/void",
        json={"void_reason_category": "duplicate"},
        headers=auth_headers(),
    )
    assert r1.status_code == 200
    audit_before = len([
        e for e in fake.audit_events
        if e["action"] == "ai_incident_near_miss_record_voided"
    ])
    r2 = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/void",
        json={"void_reason_category": "test_data"},
        headers=auth_headers(),
    )
    assert r2.status_code == 200
    # First-reason wins.
    assert r2.json()["record"]["void_reason_category"] == "duplicate"
    audit_after = len([
        e for e in fake.audit_events
        if e["action"] == "ai_incident_near_miss_record_voided"
    ])
    assert audit_after == audit_before


def test_void_does_not_delete_row() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=OTHER_USER,
    )
    count_before = len(fake.records)
    client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/void",
        json={"void_reason_category": "duplicate"},
        headers=auth_headers(),
    )
    assert len(fake.records) == count_before
    # Row still present.
    assert any(
        str(r["incident_id"]) == str(row["incident_id"])
        for r in fake.records
    )


def test_void_writes_metadata_only_audit_event() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=OTHER_USER,
    )
    client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/void",
        json={"void_reason_category": "wrong_clinic_record"},
        headers=auth_headers(),
    )
    voided = [
        e for e in fake.audit_events
        if e["action"] == "ai_incident_near_miss_record_voided"
    ]
    assert len(voided) == 1
    meta = voided[0]["meta"]
    assert meta["previous_status"] == "open"
    assert meta["status"] == "voided"
    assert meta["void_reason_category"] == "wrong_clinic_record"
    _assert_no_forbidden_keys(meta, where="audit.meta")


# ---------------------------------------------------------------------
# 12. GET /summary
# ---------------------------------------------------------------------


def test_summary_returns_expected_shape_and_disclosure_flags() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    resp = client_for(app).get(
        "/v1/governance/incidents/summary", headers=auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    s = body["summary"]
    for key in (
        "window_days", "records_total", "records_in_window",
        "open_records", "in_review_records", "actioned_records",
        "closed_records", "voided_records",
        "high_or_critical_records", "privacy_related_records",
        "linked_receipt_records",
        "learning_recommended_count", "policy_review_recommended_count",
        "client_communication_review_recommended_count",
        "last_reported_at",
    ):
        assert key in s, f"summary missing key: {key}"
    for flag in (
        "raw_content_included", "clinical_content_included",
        "staff_identifiers_included", "client_identifiers_included",
        "patient_identifiers_included",
    ):
        assert s[flag] is False
    assert "governance_note" in body
    _assert_no_forbidden_keys(body)


def test_summary_visible_to_non_admin() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    resp = client_for(app).get(
        "/v1/governance/incidents/summary", headers=auth_headers(),
    )
    assert resp.status_code == 200


def test_summary_window_days_default_30() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    resp = client_for(app).get(
        "/v1/governance/incidents/summary", headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["summary"]["window_days"] == 30


@pytest.mark.parametrize("bad", ["0", "-1", "366", "999"])
def test_summary_rejects_window_days_outside_range(bad: str) -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    resp = client_for(app).get(
        f"/v1/governance/incidents/summary?window_days={bad}",
        headers=auth_headers(),
    )
    assert resp.status_code == 422


def test_summary_status_counts_windowed() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    _seed_record_with_status(fake, status="open", created_by_user_id=STAFF_USER)
    _seed_record_with_status(fake, status="open", created_by_user_id=OTHER_USER)
    _seed_record_with_status(fake, status="closed", created_by_user_id=OTHER_USER)
    _seed_record_with_status(fake, status="voided", created_by_user_id=OTHER_USER)
    resp = client_for(app).get(
        "/v1/governance/incidents/summary", headers=auth_headers(),
    )
    assert resp.status_code == 200
    s = resp.json()["summary"]
    assert s["records_total"] == 4
    assert s["records_in_window"] == 4
    assert s["open_records"] == 2
    assert s["closed_records"] == 1
    assert s["voided_records"] == 1


def test_summary_high_or_critical_excludes_voided() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    _seed_record_with_status(fake, status="open", severity="high",
                             created_by_user_id=OTHER_USER)
    _seed_record_with_status(fake, status="voided", severity="critical",
                             created_by_user_id=OTHER_USER)
    _seed_record_with_status(fake, status="open", severity="low",
                             created_by_user_id=OTHER_USER)
    resp = client_for(app).get(
        "/v1/governance/incidents/summary", headers=auth_headers(),
    )
    assert resp.status_code == 200
    s = resp.json()["summary"]
    # Voided high-severity row excluded.
    assert s["high_or_critical_records"] == 1
    assert s["voided_records"] == 1


def test_summary_privacy_related_excludes_voided() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    _seed_record_with_status(
        fake, status="open", category="privacy_or_identifier_risk",
        created_by_user_id=OTHER_USER,
    )
    _seed_record_with_status(
        fake, status="voided", category="privacy_or_identifier_risk",
        created_by_user_id=OTHER_USER,
    )
    resp = client_for(app).get(
        "/v1/governance/incidents/summary", headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["summary"]["privacy_related_records"] == 1


def test_summary_linked_receipt_records_count() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    _seed_record_with_status(
        fake, status="open", linked_receipt=True,
        created_by_user_id=OTHER_USER,
    )
    _seed_record_with_status(
        fake, status="voided", linked_receipt=True,
        created_by_user_id=OTHER_USER,
    )
    _seed_record_with_status(
        fake, status="open", linked_receipt=False,
        created_by_user_id=OTHER_USER,
    )
    resp = client_for(app).get(
        "/v1/governance/incidents/summary", headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["summary"]["linked_receipt_records"] == 1


def test_summary_recommendation_counts() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    _seed_record_with_status(
        fake, status="open", learning_recommended=True,
        policy_review_recommended=True,
        client_communication_review_recommended=True,
        created_by_user_id=OTHER_USER,
    )
    _seed_record_with_status(
        fake, status="voided", learning_recommended=True,
        created_by_user_id=OTHER_USER,
    )
    _seed_record_with_status(
        fake, status="open", learning_recommended=False,
        created_by_user_id=OTHER_USER,
    )
    resp = client_for(app).get(
        "/v1/governance/incidents/summary", headers=auth_headers(),
    )
    assert resp.status_code == 200
    s = resp.json()["summary"]
    assert s["learning_recommended_count"] == 1  # voided excluded
    assert s["policy_review_recommended_count"] == 1
    assert s["client_communication_review_recommended_count"] == 1


def test_summary_governance_note_safe_negative_disclaimer() -> None:
    app, fake = build_app(role="staff", user_id=STAFF_USER)
    resp = client_for(app).get(
        "/v1/governance/incidents/summary", headers=auth_headers(),
    )
    note = resp.json()["governance_note"].lower()
    assert "metadata-only" in note
    assert "not a clinical record" in note
    assert "human professional review remains required" in note
    for a, b in _FORBIDDEN_WORDING_FRAGMENTS:
        phrase = (a + b).lower()
        assert phrase not in note, (
            f"governance_note positive-claim leak: {a}{b}"
        )


# ---------------------------------------------------------------------
# 13. Cross-cutting doctrine sweeps for the lifecycle surface
# ---------------------------------------------------------------------


def test_all_lifecycle_responses_metadata_only() -> None:
    app, fake = build_app(role="admin", user_id=ADMIN_USER)
    row = _seed_record_with_status(
        fake, status="open", created_by_user_id=ADMIN_USER,
    )
    patch_resp = client_for(app).patch(
        f"/v1/governance/incidents/records/{row['incident_id']}",
        json={"severity": "high"},
        headers=auth_headers(),
    )
    assert patch_resp.status_code == 200
    _assert_no_forbidden_keys(patch_resp.json(), where="patch")

    review_resp = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/review",
        json={},
        headers=auth_headers(),
    )
    assert review_resp.status_code == 200
    _assert_no_forbidden_keys(review_resp.json(), where="review")

    close_resp = client_for(app).post(
        f"/v1/governance/incidents/records/{row['incident_id']}/close",
        headers=auth_headers(),
    )
    assert close_resp.status_code == 200
    _assert_no_forbidden_keys(close_resp.json(), where="close")

    other = _seed_record_with_status(
        fake, status="open", created_by_user_id=ADMIN_USER,
    )
    void_resp = client_for(app).post(
        f"/v1/governance/incidents/records/{other['incident_id']}/void",
        json={"void_reason_category": "duplicate"},
        headers=auth_headers(),
    )
    assert void_resp.status_code == 200
    _assert_no_forbidden_keys(void_resp.json(), where="void")

    summary_resp = client_for(app).get(
        "/v1/governance/incidents/summary", headers=auth_headers(),
    )
    assert summary_resp.status_code == 200
    _assert_no_forbidden_keys(summary_resp.json(), where="summary")
