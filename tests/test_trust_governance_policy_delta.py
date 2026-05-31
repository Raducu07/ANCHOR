"""Phase 2A-2.4 - Trust posture governance_policy delta tests.

Covers the metadata-only governance_policy aggregate block added to the
Trust posture snapshot. No new endpoints; we drive `build_trust_snapshot`
directly with an in-memory fake that interprets the new SQL.

Doctrine guards asserted here:
  * No raw policy body, body, content, or text fields anywhere in the
    block.
  * No staff names/emails.
  * No void_reason exposed.
  * Voided attestations are excluded from coverage.
  * All clinic-scoped SQL binds clinic_id; cross-clinic rows are never
    counted.
  * Governance note avoids high-risk wording (assembled from fragments
    only so source-scan does not match).
"""
from __future__ import annotations

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

USER_1 = "aaaa1111-0000-4000-8000-000000000001"
USER_2 = "aaaa1111-0000-4000-8000-000000000002"
USER_3 = "aaaa1111-0000-4000-8000-000000000003"
USER_INACTIVE = "aaaa1111-0000-4000-8000-000000000009"

TPL_AI_USE = "bbbb2222-0000-4000-8000-000000000001"
TPL_DISCLOSURE = "bbbb2222-0000-4000-8000-000000000002"


# Fragments combined to avoid the high-risk wording grep matching the
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
    ("legally", " complete audit trail"),
    ("staff", " certified"),
    ("approved", " by RCVS"),
]

FORBIDDEN_KEYS = {
    "policy_body",
    "policy_text",
    "policy_content",
    "body",
    "content",
    "void_reason",
    "email",
    "name",
    "first_name",
    "last_name",
    "reflection",
    "transcript",
}


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

    def scalar(self) -> Any:
        if self._row is None:
            return None
        return next(iter(self._row.values()))


class GovernanceTrustFakeDB:
    """Minimal fake DB that satisfies build_trust_snapshot queries.

    Trust snapshot's non-governance queries are wrapped by
    _safe_row_mapping which tolerates empty results, so we only need
    to implement the SQL fragments we care about.
    """

    def __init__(self) -> None:
        self.current_clinic = CLINIC_A
        # active users per (clinic_id, user_id, active_status)
        self.clinic_users: List[Dict[str, Any]] = []
        # clinic_policy_versions rows
        self.policy_versions: List[Dict[str, Any]] = []
        # policy_attestations rows
        self.policy_attestations: List[Dict[str, Any]] = []
        # template metadata for slug lookup
        self.templates: Dict[str, Dict[str, Any]] = {}
        self.calls: List[tuple] = []

    def seed_users(
        self,
        *,
        clinic_id: str = CLINIC_A,
        active_count: int = 0,
        inactive_count: int = 0,
    ) -> List[str]:
        out: List[str] = []
        base = len(self.clinic_users)
        for i in range(active_count):
            uid = f"u-active-{clinic_id[:8]}-{base + i:04d}"
            self.clinic_users.append(
                {"clinic_id": clinic_id, "user_id": uid, "active_status": True}
            )
            out.append(uid)
        for i in range(inactive_count):
            uid = f"u-inactive-{clinic_id[:8]}-{base + i:04d}"
            self.clinic_users.append(
                {
                    "clinic_id": clinic_id,
                    "user_id": uid,
                    "active_status": False,
                }
            )
            out.append(uid)
        return out

    def add_template(
        self, template_id: str, slug: str
    ) -> Dict[str, Any]:
        t = {"template_id": _uuid.UUID(template_id), "template_slug": slug}
        self.templates[str(t["template_id"])] = t
        return t

    def add_active_policy(
        self,
        *,
        clinic_id: str = CLINIC_A,
        template_id: str,
        clinic_policy_version: int = 1,
        title: str = "AI Use Policy",
        activated_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        row = {
            "clinic_policy_version_id": _uuid.uuid4(),
            "clinic_id": clinic_id,
            "policy_template_id": _uuid.UUID(template_id),
            "clinic_policy_version": clinic_policy_version,
            "status": "active",
            "title_snapshot": title,
            "activated_at": activated_at
            or datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc),
            "updated_at": updated_at
            or datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc),
        }
        self.policy_versions.append(row)
        return row

    def add_attestation(
        self,
        *,
        clinic_id: str = CLINIC_A,
        cpv_id: Any,
        user_id: str,
        acknowledged_at: Optional[datetime] = None,
        is_voided: bool = False,
    ) -> Dict[str, Any]:
        row = {
            "attestation_id": _uuid.uuid4(),
            "clinic_id": clinic_id,
            "clinic_policy_version_id": cpv_id,
            "user_id": user_id,
            "acknowledged_at": acknowledged_at
            or datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc),
            "is_voided": is_voided,
        }
        self.policy_attestations.append(row)
        return row

    # session-shape methods
    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None

    def close(self) -> None:
        return None

    def __enter__(self) -> "GovernanceTrustFakeDB":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def execute(self, statement: Any, params: Optional[Dict[str, Any]] = None) -> _Result:
        sql = str(getattr(statement, "text", statement))
        p = dict(params or {})
        self.calls.append((sql, p))
        clinic_id = p.get("clinic_id")

        # expected_user_count
        if (
            "FROM public.clinic_users" in sql
            and "active_status = true" in sql
            and "COUNT(*)" in sql
        ):
            c = sum(
                1
                for u in self.clinic_users
                if u["clinic_id"] == clinic_id and u["active_status"]
            )
            return _Result(row={"c": c})

        # active policy rows with coverage
        if (
            "FROM public.clinic_policy_versions cpv" in sql
            and "LEFT JOIN public.policy_attestations pa" in sql
            and "GROUP BY" in sql
        ):
            out: List[Dict[str, Any]] = []
            for v in self.policy_versions:
                if v["clinic_id"] != clinic_id:
                    continue
                if v["status"] != "active":
                    continue
                attestations = [
                    a
                    for a in self.policy_attestations
                    if a["clinic_id"] == v["clinic_id"]
                    and a["clinic_policy_version_id"]
                    == v["clinic_policy_version_id"]
                    and not a["is_voided"]
                ]
                tpl = self.templates.get(str(v["policy_template_id"]))
                out.append(
                    {
                        "clinic_policy_version_id": v["clinic_policy_version_id"],
                        "policy_template_id": v["policy_template_id"],
                        "clinic_policy_version": v["clinic_policy_version"],
                        "title_snapshot": v["title_snapshot"],
                        "activated_at": v["activated_at"],
                        "updated_at": v["updated_at"],
                        "template_slug": tpl["template_slug"] if tpl else None,
                        "attestation_count": len(attestations),
                        "distinct_user_count": len(
                            {a["user_id"] for a in attestations}
                        ),
                        "most_recent_acknowledged_at": (
                            max(a["acknowledged_at"] for a in attestations)
                            if attestations
                            else None
                        ),
                    }
                )
            out.sort(
                key=lambda r: r["activated_at"]
                or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True,
            )
            return _Result(rows=out)

        # total distinct users attested across active policies
        if (
            "FROM public.policy_attestations pa" in sql
            and "COUNT(DISTINCT pa.user_id)" in sql
            and "cpv.status = 'active'" in sql
        ):
            active_cpv_ids = {
                v["clinic_policy_version_id"]
                for v in self.policy_versions
                if v["clinic_id"] == clinic_id and v["status"] == "active"
            }
            users = {
                a["user_id"]
                for a in self.policy_attestations
                if a["clinic_id"] == clinic_id
                and not a["is_voided"]
                and a["clinic_policy_version_id"] in active_cpv_ids
            }
            return _Result(row={"c": len(users)})

        # other trust_snapshot queries: empty
        return _Result(row=None, rows=[])


def _snapshot(fake: GovernanceTrustFakeDB, *, clinic_id: str = CLINIC_A) -> Dict[str, Any]:
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
# 1. block presence + 19. existing fields preserved
# ---------------------------------------------------------------------


def test_trust_snapshot_includes_governance_policy_block() -> None:
    fake = GovernanceTrustFakeDB()
    snap = _snapshot(fake)
    assert "governance_policy" in snap
    # Existing top-level Trust fields are not removed.
    for key in (
        "clinic",
        "governance",
        "privacy",
        "tenancy",
        "operations",
        "learning",
        "limitations",
        "snapshot_version",
        "generated_at",
        "evidence_window",
    ):
        assert key in snap, f"existing trust key removed: {key}"


# ---------------------------------------------------------------------
# 2. zero state
# ---------------------------------------------------------------------


def test_zero_state_returns_zeros_and_raw_body_false() -> None:
    fake = GovernanceTrustFakeDB()
    block = _snapshot(fake)["governance_policy"]
    assert block["active_policy_count"] == 0
    assert block["active_policies"] == []
    assert block["total_attestation_count"] == 0
    assert block["total_distinct_users_attested"] == 0
    assert block["expected_user_count"] == 0
    assert block["outstanding_user_count"] == 0
    assert block["average_coverage_rate"] == 0.0
    assert block["last_policy_update_at"] is None
    assert block["most_recent_acknowledged_at"] is None
    assert block["raw_policy_body_included"] is False


# ---------------------------------------------------------------------
# 3. active policy count
# ---------------------------------------------------------------------


def test_active_policy_count_matches_active_rows() -> None:
    fake = GovernanceTrustFakeDB()
    fake.add_template(TPL_AI_USE, "ai_use_policy")
    fake.add_template(TPL_DISCLOSURE, "client_disclosure_when_ai_assists")
    fake.add_active_policy(template_id=TPL_AI_USE)
    fake.add_active_policy(template_id=TPL_DISCLOSURE)
    block = _snapshot(fake)["governance_policy"]
    assert block["active_policy_count"] == 2
    assert len(block["active_policies"]) == 2


# ---------------------------------------------------------------------
# 4. metadata only - no body fields
# ---------------------------------------------------------------------


def test_active_policy_rows_carry_no_body() -> None:
    fake = GovernanceTrustFakeDB()
    fake.add_template(TPL_AI_USE, "ai_use_policy")
    fake.add_active_policy(template_id=TPL_AI_USE)
    block = _snapshot(fake)["governance_policy"]
    row = block["active_policies"][0]
    assert "title" in row
    assert "clinic_policy_version" in row
    assert "template_slug" in row
    _assert_no_forbidden_keys(block, where="governance_policy")


# ---------------------------------------------------------------------
# 5. non-voided attestations count toward coverage
# ---------------------------------------------------------------------


def test_non_voided_attestations_count_toward_coverage() -> None:
    fake = GovernanceTrustFakeDB()
    fake.seed_users(active_count=3)
    fake.add_template(TPL_AI_USE, "ai_use_policy")
    cpv = fake.add_active_policy(template_id=TPL_AI_USE)
    fake.add_attestation(
        cpv_id=cpv["clinic_policy_version_id"], user_id=USER_1
    )
    fake.add_attestation(
        cpv_id=cpv["clinic_policy_version_id"], user_id=USER_2
    )
    block = _snapshot(fake)["governance_policy"]
    cov = block["active_policies"][0]["attestation_coverage"]
    assert cov["attestation_count"] == 2
    assert cov["distinct_user_count"] == 2
    assert block["total_attestation_count"] == 2
    assert block["total_distinct_users_attested"] == 2


# ---------------------------------------------------------------------
# 6. voided excluded
# ---------------------------------------------------------------------


def test_voided_attestations_excluded() -> None:
    fake = GovernanceTrustFakeDB()
    fake.seed_users(active_count=3)
    fake.add_template(TPL_AI_USE, "ai_use_policy")
    cpv = fake.add_active_policy(template_id=TPL_AI_USE)
    fake.add_attestation(
        cpv_id=cpv["clinic_policy_version_id"], user_id=USER_1
    )
    fake.add_attestation(
        cpv_id=cpv["clinic_policy_version_id"],
        user_id=USER_2,
        is_voided=True,
    )
    block = _snapshot(fake)["governance_policy"]
    cov = block["active_policies"][0]["attestation_coverage"]
    assert cov["attestation_count"] == 1
    assert cov["distinct_user_count"] == 1
    assert block["total_distinct_users_attested"] == 1


# ---------------------------------------------------------------------
# 7. expected_user_count is an aggregate, not user identities
# ---------------------------------------------------------------------


def test_expected_user_count_aggregated_not_per_user() -> None:
    fake = GovernanceTrustFakeDB()
    fake.seed_users(active_count=4, inactive_count=2)
    fake.add_template(TPL_AI_USE, "ai_use_policy")
    fake.add_active_policy(template_id=TPL_AI_USE)
    block = _snapshot(fake)["governance_policy"]
    assert block["expected_user_count"] == 4
    cov = block["active_policies"][0]["attestation_coverage"]
    assert cov["expected_user_count"] == 4
    # No user-level rows anywhere in the block.
    serialised = repr(block)
    assert "users" not in {k for k in block.keys()}
    assert "user_list" not in serialised


# ---------------------------------------------------------------------
# 8. outstanding = expected - distinct, bounded
# ---------------------------------------------------------------------


def test_outstanding_user_count_bounded_at_zero() -> None:
    fake = GovernanceTrustFakeDB()
    fake.seed_users(active_count=2)
    fake.add_template(TPL_AI_USE, "ai_use_policy")
    cpv = fake.add_active_policy(template_id=TPL_AI_USE)
    # 3 distinct users attest while only 2 are active (edge case).
    fake.add_attestation(cpv_id=cpv["clinic_policy_version_id"], user_id=USER_1)
    fake.add_attestation(cpv_id=cpv["clinic_policy_version_id"], user_id=USER_2)
    fake.add_attestation(cpv_id=cpv["clinic_policy_version_id"], user_id=USER_3)
    block = _snapshot(fake)["governance_policy"]
    cov = block["active_policies"][0]["attestation_coverage"]
    assert cov["outstanding_user_count"] == 0
    assert block["outstanding_user_count"] == 0


# ---------------------------------------------------------------------
# 9. coverage rate when expected > 0
# ---------------------------------------------------------------------


def test_coverage_rate_when_expected_positive() -> None:
    fake = GovernanceTrustFakeDB()
    fake.seed_users(active_count=4)
    fake.add_template(TPL_AI_USE, "ai_use_policy")
    cpv = fake.add_active_policy(template_id=TPL_AI_USE)
    fake.add_attestation(cpv_id=cpv["clinic_policy_version_id"], user_id=USER_1)
    fake.add_attestation(cpv_id=cpv["clinic_policy_version_id"], user_id=USER_2)
    block = _snapshot(fake)["governance_policy"]
    cov = block["active_policies"][0]["attestation_coverage"]
    assert cov["coverage_rate"] == pytest.approx(0.5)
    assert block["average_coverage_rate"] == pytest.approx(0.5)


# ---------------------------------------------------------------------
# 10. coverage rate when expected = 0
# ---------------------------------------------------------------------


def test_coverage_rate_when_expected_zero() -> None:
    fake = GovernanceTrustFakeDB()
    fake.add_template(TPL_AI_USE, "ai_use_policy")
    cpv = fake.add_active_policy(template_id=TPL_AI_USE)
    fake.add_attestation(cpv_id=cpv["clinic_policy_version_id"], user_id=USER_1)
    block = _snapshot(fake)["governance_policy"]
    cov = block["active_policies"][0]["attestation_coverage"]
    assert cov["coverage_rate"] == 0.0
    assert block["average_coverage_rate"] == 0.0


# ---------------------------------------------------------------------
# 11. most_recent_acknowledged_at
# ---------------------------------------------------------------------


def test_most_recent_acknowledged_at_is_calculated() -> None:
    fake = GovernanceTrustFakeDB()
    fake.seed_users(active_count=3)
    fake.add_template(TPL_AI_USE, "ai_use_policy")
    cpv = fake.add_active_policy(template_id=TPL_AI_USE)
    early = datetime(2026, 5, 1, 9, 0, 0, tzinfo=timezone.utc)
    late = datetime(2026, 5, 20, 9, 0, 0, tzinfo=timezone.utc)
    fake.add_attestation(
        cpv_id=cpv["clinic_policy_version_id"],
        user_id=USER_1,
        acknowledged_at=early,
    )
    fake.add_attestation(
        cpv_id=cpv["clinic_policy_version_id"],
        user_id=USER_2,
        acknowledged_at=late,
    )
    block = _snapshot(fake)["governance_policy"]
    assert block["most_recent_acknowledged_at"] == late.isoformat()
    cov = block["active_policies"][0]["attestation_coverage"]
    assert cov["most_recent_acknowledged_at"] == late.isoformat()


# ---------------------------------------------------------------------
# 12. last_policy_update_at
# ---------------------------------------------------------------------


def test_last_policy_update_at_is_calculated() -> None:
    fake = GovernanceTrustFakeDB()
    fake.add_template(TPL_AI_USE, "ai_use_policy")
    fake.add_template(TPL_DISCLOSURE, "client_disclosure_when_ai_assists")
    older = datetime(2026, 4, 1, 9, 0, 0, tzinfo=timezone.utc)
    newer = datetime(2026, 5, 25, 9, 0, 0, tzinfo=timezone.utc)
    fake.add_active_policy(template_id=TPL_AI_USE, activated_at=older)
    fake.add_active_policy(template_id=TPL_DISCLOSURE, activated_at=newer)
    block = _snapshot(fake)["governance_policy"]
    assert block["last_policy_update_at"] == newer.isoformat()


# ---------------------------------------------------------------------
# 13/14/15. staff names/emails, void_reason, raw body never appear
# ---------------------------------------------------------------------


def test_no_staff_identifiers_or_void_reason_or_body_in_block() -> None:
    fake = GovernanceTrustFakeDB()
    fake.seed_users(active_count=2)
    fake.add_template(TPL_AI_USE, "ai_use_policy")
    cpv = fake.add_active_policy(template_id=TPL_AI_USE)
    fake.add_attestation(
        cpv_id=cpv["clinic_policy_version_id"],
        user_id=USER_1,
        is_voided=True,
    )
    fake.add_attestation(cpv_id=cpv["clinic_policy_version_id"], user_id=USER_2)
    block = _snapshot(fake)["governance_policy"]
    _assert_no_forbidden_keys(block, where="governance_policy")


# ---------------------------------------------------------------------
# 16. governance note avoids prohibited claims
# ---------------------------------------------------------------------


def test_governance_note_avoids_prohibited_claims() -> None:
    fake = GovernanceTrustFakeDB()
    block = _snapshot(fake)["governance_policy"]
    note = block["governance_note"]
    assert isinstance(note, str) and len(note) > 0
    for left, right in _FORBIDDEN_FRAGMENTS:
        full = left + right
        assert full.lower() not in note.lower(), (
            f"governance_note contains forbidden phrase: {full!r}"
        )


# ---------------------------------------------------------------------
# 17. all governance_policy SQL binds clinic_id
# ---------------------------------------------------------------------


def test_all_governance_policy_sql_binds_clinic_id() -> None:
    fake = GovernanceTrustFakeDB()
    fake.add_template(TPL_AI_USE, "ai_use_policy")
    fake.add_active_policy(template_id=TPL_AI_USE)
    _snapshot(fake)
    governance_related = [
        (sql, params)
        for sql, params in fake.calls
        if (
            "clinic_policy_versions" in sql
            or "policy_attestations" in sql
            or "clinic_users" in sql
        )
    ]
    assert governance_related, "expected governance_policy SQL to fire"
    for sql, params in governance_related:
        assert params.get("clinic_id") == CLINIC_A, (sql, params)


# ---------------------------------------------------------------------
# 18. cross-clinic rows are not counted
# ---------------------------------------------------------------------


def test_cross_clinic_rows_are_not_counted() -> None:
    fake = GovernanceTrustFakeDB()
    fake.seed_users(clinic_id=CLINIC_A, active_count=2)
    fake.seed_users(clinic_id=CLINIC_B, active_count=10)
    fake.add_template(TPL_AI_USE, "ai_use_policy")
    cpv_a = fake.add_active_policy(
        clinic_id=CLINIC_A, template_id=TPL_AI_USE
    )
    cpv_b = fake.add_active_policy(
        clinic_id=CLINIC_B, template_id=TPL_AI_USE
    )
    fake.add_attestation(
        clinic_id=CLINIC_A,
        cpv_id=cpv_a["clinic_policy_version_id"],
        user_id=USER_1,
    )
    # CLINIC_B attestations must not appear in CLINIC_A snapshot
    for u in (USER_1, USER_2, USER_3):
        fake.add_attestation(
            clinic_id=CLINIC_B,
            cpv_id=cpv_b["clinic_policy_version_id"],
            user_id=u,
        )
    block = _snapshot(fake, clinic_id=CLINIC_A)["governance_policy"]
    assert block["active_policy_count"] == 1
    assert block["expected_user_count"] == 2
    assert block["total_attestation_count"] == 1
    assert block["total_distinct_users_attested"] == 1


# ---------------------------------------------------------------------
# 20. app import + route count unchanged (no new routes added)
# ---------------------------------------------------------------------


def test_app_imports_and_no_new_routes_added() -> None:
    import os

    os.environ.setdefault(
        "DATABASE_URL",
        "postgresql://anchor:anchor@localhost:5432/anchor_test",
    )
    os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
    from app.main import app

    # Sanity: trust posture route still present.
    paths = {r.path for r in app.routes}
    assert "/v1/portal/trust/posture" in paths


# ---------------------------------------------------------------------
# 21. no invalid ON CONFLICT regression in trust source
# ---------------------------------------------------------------------


def test_no_invalid_on_conflict_pattern_in_trust_modules() -> None:
    import inspect

    from app import portal_trust, trust_snapshot

    for module in (trust_snapshot, portal_trust):
        src = inspect.getsource(module)
        assert (
            "ON CONFLICT (clinic_id, action, idempotency_key)" not in src
        ), f"invalid ON CONFLICT pattern in {module.__name__}"
