"""Phase 2A-3.3 - Trust posture self_assessment delta tests.

Covers the metadata-only self_assessment aggregate block added to the
Trust posture snapshot. No new endpoints; we drive
`build_trust_snapshot` and `_build_self_assessment_block` directly via
an in-memory fake DB that interprets the SQL the block emits.

Doctrine guards asserted here:
  * Block reads from frozen snapshot columns only - never from
    clinic_self_assessment_answers.
  * No raw answer rows in the block payload.
  * No staff identifiers (created_by_user_id / submitted_by_user_id /
    answered_by_user_id / email / name) in the payload.
  * Missing snapshot keys default to 0; malformed snapshots fail soft.
  * `gap_count = partial + planned + no` only (yes and
    not_applicable do NOT count as gaps).
  * If the underlying query fails, the snapshot still returns a
    safe self_assessment block.
"""
from __future__ import annotations

import json
import sys
import uuid as _uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


CLINIC_A = "11111111-1111-4111-8111-111111111111"
CLINIC_B = "33333333-3333-4333-8333-333333333333"

TPL_ID = "aaaaaaaa-0000-4000-8000-000000000001"
TEMPLATE_SLUG = "rcvs_ai_governance_self_assessment"
TEMPLATE_VERSION = "1.0.0"

ANSWER_KEYS = ("yes", "partial", "planned", "no", "not_applicable")
EVIDENCE_KEYS = (
    "policy_library", "staff_attestation", "learn_cpd",
    "assistant_receipts", "trust_posture", "manual_review",
)

# Keys that must NEVER appear anywhere inside the self_assessment Trust
# block payload (recursively).
FORBIDDEN_KEYS = {
    "answer_value",
    "answers",
    "raw_answers",
    "raw_answer_rows",
    "submitted_by_user_id",
    "created_by_user_id",
    "answered_by_user_id",
    "voided_by_user_id",
    "email",
    "name",
    "first_name",
    "last_name",
    "notes",
    "free_text",
    "reflection",
    "score",
    "pass_fail",
    "competence_grade",
    "compliance_status",
    "clinical_safety_proof",
    "staff_certified",
    "legal_approval",
    "prompt_text",
}


def _utc(year: int, month: int, day: int, hour: int = 12) -> datetime:
    return datetime(year, month, day, hour, 0, 0, tzinfo=timezone.utc)


class _Result:
    def __init__(
        self,
        row: Optional[Dict[str, Any]] = None,
        rows: Optional[List[Dict[str, Any]]] = None,
        *,
        raise_exc: bool = False,
    ):
        self._row = row
        self._rows = rows
        self._raise_exc = raise_exc

    def mappings(self) -> "_Result":
        return self

    def first(self) -> Optional[Dict[str, Any]]:
        if self._raise_exc:
            raise RuntimeError("simulated query failure")
        return self._row

    def all(self) -> List[Dict[str, Any]]:
        if self._raise_exc:
            raise RuntimeError("simulated query failure")
        return list(self._rows or [])

    def scalar(self) -> Any:
        if self._row is None:
            return None
        return next(iter(self._row.values()))


class SelfAssessmentTrustFakeDB:
    """Minimal fake DB satisfying build_trust_snapshot. Trust's
    non-self-assessment queries are wrapped in _safe_row_mapping which
    tolerates empty results, so we only implement the SQL we care
    about plus a passthrough empty default.
    """

    def __init__(self) -> None:
        self.current_clinic = CLINIC_A
        # Active templates: list of dicts {template_id, slug, version, title}.
        self.templates: List[Dict[str, Any]] = []
        # Latest entry per template: dict keyed by template_id (str) ->
        # dict with frozen snapshot fields. None / missing = "none".
        self.latest_by_template: Dict[str, Dict[str, Any]] = {}
        # Question counts per template (catalogue-level).
        self.question_counts: Dict[str, int] = {}
        # If True, the SELF-ASSESSMENT join query raises.
        self.fail_self_assessment_query = False
        self.calls: List[tuple] = []

    def add_template(
        self,
        *,
        template_id: str = TPL_ID,
        slug: str = TEMPLATE_SLUG,
        version: str = TEMPLATE_VERSION,
        title: str = "RCVS-aligned AI Governance Self-Assessment",
        question_count: int = 10,
    ) -> None:
        self.templates.append({
            "template_id": _uuid.UUID(template_id),
            "template_slug": slug,
            "template_version": version,
            "title": title,
        })
        self.question_counts[str(_uuid.UUID(template_id))] = int(question_count)

    def set_latest(
        self,
        *,
        template_id: str = TPL_ID,
        clinic_id: str = CLINIC_A,
        status: str = "submitted",
        clinic_assessment_version: int = 1,
        template_version_snapshot: str = TEMPLATE_VERSION,
        submitted_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
        total_questions_snapshot: int = 10,
        answered_questions_snapshot: int = 10,
        readiness_summary_snapshot: Optional[Any] = None,
        linked_evidence_counts_snapshot: Optional[Any] = None,
    ) -> None:
        key = (str(clinic_id), str(_uuid.UUID(template_id)))
        self.latest_by_template[key] = {
            "assessment_id": _uuid.uuid4(),
            "clinic_assessment_version": clinic_assessment_version,
            "status": status,
            "template_version_snapshot": template_version_snapshot,
            "submitted_at": submitted_at or _utc(2026, 5, 30),
            "superseded_at": None,
            "updated_at": updated_at or _utc(2026, 5, 30),
            "total_questions_snapshot": total_questions_snapshot,
            "answered_questions_snapshot": answered_questions_snapshot,
            "readiness_summary_snapshot": readiness_summary_snapshot,
            "linked_evidence_counts_snapshot": linked_evidence_counts_snapshot,
        }

    # session-shape methods
    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None

    def close(self) -> None:
        return None

    def execute(self, statement: Any, params: Optional[Dict[str, Any]] = None) -> _Result:
        sql = str(getattr(statement, "text", statement))
        p = dict(params or {})
        self.calls.append((sql, p))
        clinic_id = p.get("clinic_id")

        # ---- self_assessment_templates LEFT JOIN v_clinic_latest_self_assessment ----
        if (
            "FROM public.self_assessment_templates t" in sql
            and "v_clinic_latest_self_assessment v" in sql
        ):
            if self.fail_self_assessment_query:
                return _Result(raise_exc=True)
            out: List[Dict[str, Any]] = []
            for t in self.templates:
                key = (str(clinic_id), str(t["template_id"]))
                latest = self.latest_by_template.get(key)
                base: Dict[str, Any] = {
                    "template_id": t["template_id"],
                    "template_slug": t["template_slug"],
                    "template_version": t["template_version"],
                    "title": t["title"],
                    "assessment_id": None,
                    "clinic_assessment_version": None,
                    "status": None,
                    "template_version_snapshot": None,
                    "submitted_at": None,
                    "superseded_at": None,
                    "updated_at": None,
                    "total_questions_snapshot": None,
                    "answered_questions_snapshot": None,
                    "readiness_summary_snapshot": None,
                    "linked_evidence_counts_snapshot": None,
                }
                if latest is not None:
                    base.update(latest)
                out.append(base)
            out.sort(key=lambda r: r.get("title") or "")
            return _Result(rows=out)

        # ---- catalogue question counts ----
        if (
            "FROM public.self_assessment_questions" in sql
            and "COUNT(*)" in sql
        ):
            out = [
                {"template_id": _uuid.UUID(tid), "question_count": n}
                for tid, n in self.question_counts.items()
            ]
            return _Result(rows=out)

        # All other Trust queries: empty.
        return _Result(row=None, rows=[])


def _snapshot(fake: SelfAssessmentTrustFakeDB, *, clinic_id: str = CLINIC_A) -> Dict[str, Any]:
    from app.trust_snapshot import build_trust_snapshot

    fake.current_clinic = clinic_id
    return build_trust_snapshot(db=fake, clinic_id=clinic_id)


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
# 1. No assessment -> "none" status
# ---------------------------------------------------------------------


def test_self_assessment_block_no_assessment_returns_none_status() -> None:
    fake = SelfAssessmentTrustFakeDB()
    fake.add_template(question_count=10)
    snap = _snapshot(fake)
    block = snap["self_assessment"]
    assert block["raw_answers_included"] is False
    assert block["staff_identifiers_included"] is False
    assert block["submitted_assessment_count"] == 0
    assert block["latest_submitted_at"] is None
    assert len(block["templates"]) == 1
    t = block["templates"][0]
    assert t["template_slug"] == TEMPLATE_SLUG
    assert t["assessment_status"] == "none"
    assert t["latest_submitted_at"] is None
    assert t["clinic_assessment_version"] is None
    assert t["answered_questions"] == 0
    assert t["total_questions"] == 10
    assert t["gap_count"] == 0
    for k in ANSWER_KEYS:
        assert t["readiness_summary_counts"][k] == 0
    for k in EVIDENCE_KEYS:
        assert t["linked_evidence_counts"][k] == 0
    _assert_no_forbidden_keys(block)


# ---------------------------------------------------------------------
# 2. Submitted uses frozen snapshots verbatim
# ---------------------------------------------------------------------


def test_self_assessment_block_submitted_uses_frozen_snapshots() -> None:
    fake = SelfAssessmentTrustFakeDB()
    fake.add_template(question_count=10)
    readiness = {"yes": 4, "partial": 2, "planned": 1, "no": 1, "not_applicable": 2}
    evidence = {
        "policy_library": 3, "staff_attestation": 2, "learn_cpd": 1,
        "assistant_receipts": 0, "trust_posture": 1, "manual_review": 5,
    }
    submitted = _utc(2026, 5, 30, 14)
    fake.set_latest(
        status="submitted",
        clinic_assessment_version=2,
        submitted_at=submitted,
        updated_at=submitted,
        total_questions_snapshot=10,
        answered_questions_snapshot=10,
        readiness_summary_snapshot=readiness,
        linked_evidence_counts_snapshot=evidence,
    )
    block = _snapshot(fake)["self_assessment"]
    assert block["submitted_assessment_count"] == 1
    assert block["latest_submitted_at"] == submitted.isoformat()
    t = block["templates"][0]
    assert t["assessment_status"] == "submitted"
    assert t["clinic_assessment_version"] == 2
    assert t["total_questions"] == 10
    assert t["answered_questions"] == 10
    assert t["readiness_summary_counts"] == readiness
    assert t["linked_evidence_counts"] == evidence
    _assert_no_forbidden_keys(block)


# ---------------------------------------------------------------------
# 3. gap_count = partial + planned + no
# ---------------------------------------------------------------------


def test_self_assessment_block_gap_count_counts_partial_planned_no_only() -> None:
    fake = SelfAssessmentTrustFakeDB()
    fake.add_template(question_count=10)
    readiness = {"yes": 3, "partial": 2, "planned": 1, "no": 1, "not_applicable": 3}
    fake.set_latest(
        readiness_summary_snapshot=readiness,
        linked_evidence_counts_snapshot={k: 0 for k in EVIDENCE_KEYS},
    )
    t = _snapshot(fake)["self_assessment"]["templates"][0]
    assert t["gap_count"] == 2 + 1 + 1
    # Explicitly: yes and not_applicable are NOT gaps.
    assert t["readiness_summary_counts"]["yes"] == 3
    assert t["readiness_summary_counts"]["not_applicable"] == 3


def test_gap_count_zero_when_all_yes_or_na() -> None:
    fake = SelfAssessmentTrustFakeDB()
    fake.add_template(question_count=10)
    fake.set_latest(
        readiness_summary_snapshot={
            "yes": 7, "partial": 0, "planned": 0, "no": 0, "not_applicable": 3,
        },
        linked_evidence_counts_snapshot={k: 0 for k in EVIDENCE_KEYS},
    )
    t = _snapshot(fake)["self_assessment"]["templates"][0]
    assert t["gap_count"] == 0


# ---------------------------------------------------------------------
# 4. Missing keys -> 0 defaults; malformed -> empty
# ---------------------------------------------------------------------


def test_self_assessment_block_defaults_missing_snapshot_keys_to_zero() -> None:
    fake = SelfAssessmentTrustFakeDB()
    fake.add_template(question_count=10)
    # Snapshots omit several keys; the block must default them to 0.
    fake.set_latest(
        readiness_summary_snapshot={"yes": 5},
        linked_evidence_counts_snapshot={"policy_library": 2},
    )
    t = _snapshot(fake)["self_assessment"]["templates"][0]
    assert t["readiness_summary_counts"] == {
        "yes": 5, "partial": 0, "planned": 0, "no": 0, "not_applicable": 0,
    }
    assert t["linked_evidence_counts"] == {
        "policy_library": 2, "staff_attestation": 0, "learn_cpd": 0,
        "assistant_receipts": 0, "trust_posture": 0, "manual_review": 0,
    }
    assert t["gap_count"] == 0  # only 'yes' present


def test_self_assessment_block_malformed_snapshot_fails_soft() -> None:
    fake = SelfAssessmentTrustFakeDB()
    fake.add_template(question_count=10)
    # Garbage snapshot values - block must not crash.
    fake.set_latest(
        readiness_summary_snapshot="not a dict",
        linked_evidence_counts_snapshot=12345,
    )
    t = _snapshot(fake)["self_assessment"]["templates"][0]
    assert all(t["readiness_summary_counts"][k] == 0 for k in ANSWER_KEYS)
    assert all(t["linked_evidence_counts"][k] == 0 for k in EVIDENCE_KEYS)


def test_self_assessment_block_accepts_jsonb_as_string() -> None:
    """SQLAlchemy/asyncpg may surface jsonb as either dict or JSON
    string. The block should accept both transparently."""
    fake = SelfAssessmentTrustFakeDB()
    fake.add_template(question_count=10)
    fake.set_latest(
        readiness_summary_snapshot=json.dumps({"yes": 6, "no": 1}),
        linked_evidence_counts_snapshot=json.dumps({"learn_cpd": 4}),
    )
    t = _snapshot(fake)["self_assessment"]["templates"][0]
    assert t["readiness_summary_counts"]["yes"] == 6
    assert t["readiness_summary_counts"]["no"] == 1
    assert t["linked_evidence_counts"]["learn_cpd"] == 4
    assert t["gap_count"] == 1


# ---------------------------------------------------------------------
# 5. Excludes raw answers / staff identifiers
# ---------------------------------------------------------------------


def test_self_assessment_block_excludes_raw_answers_and_staff_identifiers() -> None:
    fake = SelfAssessmentTrustFakeDB()
    fake.add_template(question_count=10)
    fake.set_latest(
        readiness_summary_snapshot={k: 2 for k in ANSWER_KEYS},
        linked_evidence_counts_snapshot={k: 1 for k in EVIDENCE_KEYS},
    )
    block = _snapshot(fake)["self_assessment"]
    assert block["raw_answers_included"] is False
    assert block["staff_identifiers_included"] is False
    _assert_no_forbidden_keys(block)
    # Belt-and-braces: walk the JSON and assert no UUID-shaped staff
    # identifier slipped into the templates list either.
    serialized = json.dumps(block, default=str)
    for forbidden_substr in (
        "submitted_by_user_id",
        "created_by_user_id",
        "answered_by_user_id",
        "answer_value",
        "prompt_text",
    ):
        assert forbidden_substr not in serialized


# ---------------------------------------------------------------------
# 6. build_trust_snapshot top-level wiring
# ---------------------------------------------------------------------


def test_build_trust_snapshot_includes_self_assessment_block() -> None:
    fake = SelfAssessmentTrustFakeDB()
    fake.add_template(question_count=10)
    snap = _snapshot(fake)
    assert "self_assessment" in snap
    # Existing top-level Trust keys must remain.
    for key in (
        "clinic", "governance", "privacy", "tenancy", "operations",
        "learning", "governance_policy", "limitations",
        "snapshot_version", "generated_at", "evidence_window",
    ):
        assert key in snap, f"existing trust key removed: {key}"


# ---------------------------------------------------------------------
# 7. Soft-fail behaviour
# ---------------------------------------------------------------------


def test_self_assessment_block_soft_fails_on_query_error() -> None:
    fake = SelfAssessmentTrustFakeDB()
    fake.add_template(question_count=10)
    fake.fail_self_assessment_query = True
    block = _snapshot(fake)["self_assessment"]
    # Block still returns a safe shape rather than raising.
    assert block["templates"] == []
    assert block["submitted_assessment_count"] == 0
    assert block["latest_submitted_at"] is None
    assert block["raw_answers_included"] is False
    assert block["staff_identifiers_included"] is False
    assert isinstance(block["governance_note"], str)


# ---------------------------------------------------------------------
# 8. Route count unchanged by this slice
# ---------------------------------------------------------------------


def test_route_count_unchanged_by_trust_delta() -> None:
    from app.main import app
    assert len(app.routes) == 101


# ---------------------------------------------------------------------
# 9. Top-level latest_submitted_at is the MAX across templates
# ---------------------------------------------------------------------


def test_top_level_latest_submitted_at_is_max_across_templates() -> None:
    fake = SelfAssessmentTrustFakeDB()
    OTHER_TPL = "aaaaaaaa-0000-4000-8000-000000000002"
    fake.add_template(template_id=TPL_ID, slug=TEMPLATE_SLUG, question_count=10)
    fake.add_template(
        template_id=OTHER_TPL, slug="other_template",
        title="Other", question_count=5,
    )
    older = _utc(2026, 5, 1)
    newer = _utc(2026, 5, 30, 18)
    fake.set_latest(
        template_id=TPL_ID, submitted_at=older,
        readiness_summary_snapshot={k: 0 for k in ANSWER_KEYS},
        linked_evidence_counts_snapshot={k: 0 for k in EVIDENCE_KEYS},
    )
    fake.set_latest(
        template_id=OTHER_TPL, submitted_at=newer,
        readiness_summary_snapshot={k: 0 for k in ANSWER_KEYS},
        linked_evidence_counts_snapshot={k: 0 for k in EVIDENCE_KEYS},
    )
    block = _snapshot(fake)["self_assessment"]
    assert block["latest_submitted_at"] == newer.isoformat()
    assert block["submitted_assessment_count"] == 2
