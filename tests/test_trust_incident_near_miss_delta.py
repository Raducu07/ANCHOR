"""Phase 2A-5.4 - Trust posture incident_near_miss delta tests.

Drives `_build_incident_near_miss_block` directly with an in-memory
fake DB that interprets the single aggregate SQL it issues. No live
Postgres required.

Doctrine guards:
  * No `incident_id`, `created_by_user_id`, `reviewed_by_user_id`,
    `closed_by_user_id`, `voided_by_user_id`, or `linked_*_id`
    surfaces anywhere on the block.
  * No raw / clinical / free-text / narrative keys.
  * `governance_note` is the spec-approved negative-disclaimer string.
  * Empty-state defaults: every count 0, `last_reported_at` None, all
    five disclosure flags False.
  * Aggregation rules match the `/v1/governance/incidents/summary`
    endpoint exactly (windowed status counts + voided exclusion on
    risk / recommendation aggregates + all-time `records_total`).
"""
from __future__ import annotations

import sys
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


CLINIC_A = "11111111-1111-4111-8111-111111111111"


# Fragments combined to avoid the broader wording grep matching the
# source verbatim. Used only inside test assertions.
_FORBIDDEN_FRAGMENTS = [
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


FORBIDDEN_KEYS = {
    # Per-record identifiers must NOT appear on the Trust aggregate.
    "incident_id",
    "created_by_user_id",
    "reviewed_by_user_id",
    "closed_by_user_id",
    "voided_by_user_id",
    "linked_receipt_id",
    "linked_governance_event_id",
    "linked_assistant_run_id",
    "linked_clinic_policy_version_id",
    # Per-record narrative / identifier shapes.
    "note", "description", "narrative", "comments",
    "free_text", "raw_prompt", "raw_output", "transcript",
    "clinical_content", "client_identifier", "patient_identifier",
    "staff_identifier", "consent_text", "legal_consent",
    "legal_claim", "insurance", "negligence", "malpractice",
    "compliance_status", "competence_grade", "score", "pass_fail",
    "staff_certified", "clinical_safety_proof", "legal_approval",
    "email", "user_email", "first_name", "last_name",
}


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

    def scalar(self):
        if self._row is None:
            return None
        return next(iter(self._row.values()))


class _IncidentTrustFakeDB:
    """Minimal fake satisfying `_build_incident_near_miss_block`'s
    single SQL query. Carries a list of in-memory record dicts and
    re-implements the aggregate `COUNT FILTER` semantics in Python
    so the test asserts the helper's own SQL -> result mapping, not
    the database engine."""

    def __init__(self) -> None:
        self.records: List[Dict[str, Any]] = []
        self.calls: List[tuple] = []

    def add(
        self,
        *,
        status: str = "open",
        severity: str = "moderate",
        category: str = "misleading_output",
        linked_receipt: bool = False,
        learning_recommended: bool = False,
        policy_review_recommended: bool = False,
        client_communication_review_recommended: bool = False,
        reported_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        row = {
            "status": status,
            "severity": severity,
            "category": category,
            "linked_receipt_id": (
                _uuid.uuid4() if linked_receipt else None
            ),
            "learning_recommended": learning_recommended,
            "policy_review_recommended": policy_review_recommended,
            "client_communication_review_recommended": (
                client_communication_review_recommended
            ),
            "reported_at": reported_at or datetime.now(timezone.utc),
        }
        self.records.append(row)
        return row

    def execute(self, statement, params=None):
        sql = str(getattr(statement, "text", statement))
        p = dict(params or {})
        self.calls.append((sql, p))
        if (
            "FROM public.ai_incident_near_miss_records r" in sql
            and "records_total" in sql
        ):
            window_days = int(p["window_days"])
            window_start = (
                datetime.now(timezone.utc) - timedelta(days=window_days)
            )
            scoped = self.records  # all rows belong to this clinic in the fake
            in_window = [
                r for r in scoped if r["reported_at"] >= window_start
            ]

            def _count(rows: List[Dict[str, Any]], **conds: Any) -> int:
                out = 0
                for r in rows:
                    ok = True
                    for k, v in conds.items():
                        if k == "exclude_voided":
                            if v and r["status"] == "voided":
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

            non_voided_any = [
                r for r in scoped if r["status"] != "voided"
            ]
            last = (
                max((r["reported_at"] for r in non_voided_any), default=None)
            )
            return _Result(row={
                "records_total": len(scoped),
                "records_last_30d": len(in_window),
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
        return _Result(row=None, rows=[])


def _block(fake: _IncidentTrustFakeDB) -> Dict[str, Any]:
    from app.trust_snapshot import _build_incident_near_miss_block
    return _build_incident_near_miss_block(db=fake, clinic_id=CLINIC_A)


def _assert_no_forbidden_keys(payload: Any, *, where: str = "block") -> None:
    if isinstance(payload, dict):
        leaked = set(payload.keys()) & FORBIDDEN_KEYS
        assert not leaked, f"forbidden keys leaked in {where}: {leaked}"
        for k, v in payload.items():
            _assert_no_forbidden_keys(v, where=f"{where}.{k}")
    elif isinstance(payload, list):
        for i, v in enumerate(payload):
            _assert_no_forbidden_keys(v, where=f"{where}[{i}]")


# ---------------------------------------------------------------------
# Empty state
# ---------------------------------------------------------------------


def test_empty_state_returns_all_zero_counts() -> None:
    block = _block(_IncidentTrustFakeDB())
    for key in (
        "records_total",
        "records_last_30d",
        "open_records",
        "in_review_records",
        "actioned_records",
        "closed_records",
        "voided_records",
        "high_or_critical_records",
        "privacy_related_records",
        "linked_receipt_records",
        "learning_recommended_count",
        "policy_review_recommended_count",
        "client_communication_review_recommended_count",
    ):
        assert block[key] == 0, f"empty-state {key} should be 0"
    assert block["last_reported_at"] is None
    assert block["window_days"] == 30


def test_empty_state_includes_governance_note() -> None:
    block = _block(_IncidentTrustFakeDB())
    note = block["governance_note"].lower()
    assert "metadata-only" in note
    assert "not a clinical record" in note
    assert "human professional review remains required" in note


def test_empty_state_disclosure_flags_all_false() -> None:
    block = _block(_IncidentTrustFakeDB())
    for flag in (
        "raw_content_included",
        "clinical_content_included",
        "staff_identifiers_included",
        "client_identifiers_included",
        "patient_identifiers_included",
    ):
        assert block[flag] is False


# ---------------------------------------------------------------------
# Non-empty aggregate behaviour
# ---------------------------------------------------------------------


def test_records_total_counts_all_rows_including_voided() -> None:
    fake = _IncidentTrustFakeDB()
    fake.add(status="open")
    fake.add(status="closed")
    fake.add(status="voided")
    block = _block(fake)
    assert block["records_total"] == 3


def test_records_last_30d_excludes_older_rows() -> None:
    fake = _IncidentTrustFakeDB()
    now = datetime.now(timezone.utc)
    fake.add(status="open", reported_at=now)  # in-window
    fake.add(status="open", reported_at=now - timedelta(days=45))  # out
    block = _block(fake)
    assert block["records_total"] == 2
    assert block["records_last_30d"] == 1


def test_status_counts_are_windowed() -> None:
    fake = _IncidentTrustFakeDB()
    fake.add(status="open")
    fake.add(status="open")
    fake.add(status="in_review")
    fake.add(status="actioned")
    fake.add(status="closed")
    fake.add(status="voided")
    block = _block(fake)
    assert block["open_records"] == 2
    assert block["in_review_records"] == 1
    assert block["actioned_records"] == 1
    assert block["closed_records"] == 1
    assert block["voided_records"] == 1


def test_high_or_critical_excludes_voided() -> None:
    fake = _IncidentTrustFakeDB()
    fake.add(status="open", severity="high")
    fake.add(status="open", severity="critical")
    fake.add(status="voided", severity="critical")
    fake.add(status="open", severity="low")
    block = _block(fake)
    # 2 in-window non-voided high/critical rows.
    assert block["high_or_critical_records"] == 2


def test_privacy_related_excludes_voided() -> None:
    fake = _IncidentTrustFakeDB()
    fake.add(status="open", category="privacy_or_identifier_risk")
    fake.add(status="voided", category="privacy_or_identifier_risk")
    fake.add(status="open", category="misleading_output")
    block = _block(fake)
    assert block["privacy_related_records"] == 1


def test_linked_receipt_records_excludes_voided() -> None:
    fake = _IncidentTrustFakeDB()
    fake.add(status="open", linked_receipt=True)
    fake.add(status="voided", linked_receipt=True)
    fake.add(status="open", linked_receipt=False)
    block = _block(fake)
    assert block["linked_receipt_records"] == 1


def test_recommendation_counts_exclude_voided() -> None:
    fake = _IncidentTrustFakeDB()
    fake.add(
        status="open",
        learning_recommended=True,
        policy_review_recommended=True,
        client_communication_review_recommended=True,
    )
    fake.add(status="voided", learning_recommended=True)
    fake.add(status="open", learning_recommended=False)
    block = _block(fake)
    assert block["learning_recommended_count"] == 1
    assert block["policy_review_recommended_count"] == 1
    assert block["client_communication_review_recommended_count"] == 1


def test_last_reported_at_uses_latest_non_voided() -> None:
    fake = _IncidentTrustFakeDB()
    now = datetime.now(timezone.utc)
    # An older non-voided row.
    fake.add(status="open", reported_at=now - timedelta(days=10))
    # A more recent voided row - must be ignored.
    fake.add(status="voided", reported_at=now)
    # A middle non-voided row.
    middle = now - timedelta(days=2)
    fake.add(status="closed", reported_at=middle)
    block = _block(fake)
    assert block["last_reported_at"] == middle.isoformat()


# ---------------------------------------------------------------------
# Doctrine sweeps
# ---------------------------------------------------------------------


def test_block_excludes_all_per_record_identifiers() -> None:
    fake = _IncidentTrustFakeDB()
    fake.add(status="open", linked_receipt=True)
    block = _block(fake)
    _assert_no_forbidden_keys(block)


def test_block_excludes_staff_user_identifier_keys() -> None:
    block = _block(_IncidentTrustFakeDB())
    keys = set(block.keys())
    # Sweep specifically for staff / user identifier shapes.
    for k in (
        "created_by_user_id", "reviewed_by_user_id",
        "closed_by_user_id", "voided_by_user_id",
        "user_id", "user_email", "email",
        "first_name", "last_name", "staff_email",
    ):
        assert k not in keys, f"identifier key leaked: {k}"


def test_block_excludes_raw_and_free_text_keys() -> None:
    block = _block(_IncidentTrustFakeDB())
    keys = set(block.keys())
    for k in (
        "summary", "note", "description", "narrative",
        "comments", "free_text", "raw_prompt", "raw_output",
        "transcript", "clinical_content",
    ):
        assert k not in keys, f"narrative/raw key leaked: {k}"


def test_governance_note_avoids_prohibited_claim_wording() -> None:
    note = _block(_IncidentTrustFakeDB())["governance_note"].lower()
    for a, b in _FORBIDDEN_FRAGMENTS:
        phrase = (a + b).lower()
        assert phrase not in note, (
            f"governance_note positive claim: {a}{b}"
        )


def test_governance_note_includes_negative_disclaimers() -> None:
    note = _block(_IncidentTrustFakeDB())["governance_note"].lower()
    # Spec-approved negative-disclaimer phrases.
    for phrase in (
        "not a clinical record",
        "not a legal claim",
        "not an insurance submission",
        "not a regulator report",
        "human professional review remains required",
    ):
        assert phrase in note, f"governance_note missing disclaimer: {phrase}"


# ---------------------------------------------------------------------
# Build integration
# ---------------------------------------------------------------------


def test_build_trust_snapshot_wires_incident_near_miss_block() -> None:
    """The aggregate block lands on the snapshot envelope under
    `incident_near_miss` alongside the existing aggregate blocks
    (back-compat preserved)."""
    fake = _PermissiveFakeDB()
    from app.trust_snapshot import build_trust_snapshot
    snap = build_trust_snapshot(db=fake, clinic_id=CLINIC_A)
    assert "incident_near_miss" in snap
    block = snap["incident_near_miss"]
    # Empty state surfaced from the permissive fake.
    assert block["records_total"] == 0
    assert block["records_last_30d"] == 0
    assert block["last_reported_at"] is None
    assert block["governance_note"]
    # Existing top-level blocks still present.
    for key in (
        "clinic", "governance", "privacy", "tenancy", "operations",
        "learning", "governance_policy", "self_assessment",
        "client_transparency", "limitations",
    ):
        assert key in snap, f"existing trust key removed: {key}"


class _PermissiveFakeDB:
    """Catch-all fake for `build_trust_snapshot`: every query returns
    an empty result, exercising the helpers' defensive paths."""

    def execute(self, statement, params=None):
        return _Result(row=None, rows=[])


# ---------------------------------------------------------------------
# App import / route count
# ---------------------------------------------------------------------


def test_app_route_count_unchanged_by_trust_delta() -> None:
    """Trust integration must add no HTTP endpoints. Route count
    stays at 126 after 2A-5.3 + the Patch 11D-b FastAPI 0.133.1 upgrade."""
    import os
    os.environ.setdefault("DATABASE_URL", "postgresql://x:y@localhost:5432/z")
    os.environ.setdefault("RATE_LIMIT_ENABLED", "0")
    os.environ.setdefault("ANCHOR_JWT_SECRET", "test")
    from app.main import app
    # 2A-D.2 Patch 11D-b: bumped 125 → 126 for the FastAPI 0.125 → 0.133
    # framework upgrade (one additional framework-internal route).
    assert len(app.routes) == 126
