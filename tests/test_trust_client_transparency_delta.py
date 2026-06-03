"""Phase 2A-4.4 - Trust posture client_transparency delta tests.

Drives `_build_client_transparency_block` directly with an in-memory
fake DB that interprets the two SQL paths it issues (active profile
JOIN and latest published version). No live Postgres required.

Doctrine guards:
  * No `generated_public_payload`, `display_title`,
    `plain_language_summary`, or any staff/user/client/patient
    identifier appears anywhere in the block.
  * Retired-only public versions do not count as currently published.
  * `governance_note` is the spec-approved negative-disclaimer string.
  * Empty-state defaults are honest: booleans false, counts 0,
    `_status` strings 'none', `_exists` flags false.
"""
from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
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
    ("legally", " complete audit trail"),
    ("staff", " certified"),
    ("approved", " by RCVS"),
    ("compliance", " proof"),
    ("certified", " audit"),
]


FORBIDDEN_KEYS = {
    # Clinic-authored disclosure text is deliberately NOT surfaced on
    # the Trust posture aggregate.
    "display_title",
    "plain_language_summary",
    # Frozen publish payload must never leak into the snapshot.
    "generated_public_payload",
    # Identifier shapes that doctrine excludes from Trust posture.
    "user_id",
    "user_email",
    "email",
    "first_name",
    "last_name",
    "staff_email",
    "client_identifier",
    "patient_identifier",
    "client_email",
    "client_name",
    # Raw-content shapes.
    "raw_prompt",
    "raw_output",
    "transcript",
    "clinical_content",
    "case_material",
    # Forbidden claim shapes.
    "consent_text",
    "legal_consent",
    "compliance_status",
    "staff_certified",
    "clinical_safety_proof",
    "legal_approval",
    "competence_grade",
    "score",
    "pass_fail",
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


class _ClientTransparencyFakeDB:
    """Minimal fake satisfying the two SQL paths in
    `_build_client_transparency_block`. Anything else falls through
    to an empty result so the helper's defensive code paths run."""

    def __init__(self) -> None:
        self.active_row: Optional[Dict[str, Any]] = None
        self.published_row: Optional[Dict[str, Any]] = None
        self.calls: List[tuple] = []

    def execute(self, statement, params=None):
        sql = str(getattr(statement, "text", statement))
        p = dict(params or {})
        self.calls.append((sql, p))

        # Active profile JOIN.
        if (
            "FROM public.clinic_client_transparency_profiles cpv" in sql
            and "LEFT JOIN public.client_transparency_templates tpl" in sql
            and "cpv.status = 'active'" in sql
        ):
            return _Result(row=self.active_row)

        # Latest published public version.
        if (
            "FROM public.client_transparency_public_versions" in sql
            and "publication_status = 'published'" in sql
            and "ORDER BY published_at DESC" in sql
        ):
            return _Result(row=self.published_row)

        return _Result(row=None, rows=[])


def _block(fake: _ClientTransparencyFakeDB) -> Dict[str, Any]:
    from app.trust_snapshot import _build_client_transparency_block
    return _build_client_transparency_block(db=fake, clinic_id=CLINIC_A)


def _assert_no_forbidden_keys(payload: Any, *, where: str = "block") -> None:
    if isinstance(payload, dict):
        leaked = set(payload.keys()) & FORBIDDEN_KEYS
        assert not leaked, f"forbidden keys leaked in {where}: {leaked}"
        for k, v in payload.items():
            _assert_no_forbidden_keys(v, where=f"{where}.{k}")
    elif isinstance(payload, list):
        for i, v in enumerate(payload):
            _assert_no_forbidden_keys(v, where=f"{where}[{i}]")


def _seed_active_profile_row(fake: _ClientTransparencyFakeDB) -> None:
    fake.active_row = {
        "clinic_profile_version": 2,
        "activated_at": datetime(2026, 6, 3, 9, 0, 0, tzinfo=timezone.utc),
        "permitted_use_categories": [
            "draft_client_communication",
            "administrative_support",
        ],
        "prohibited_use_categories": [
            "diagnosis", "prescribing", "autonomous_clinical_decisions",
        ],
        "human_review_statement_enabled": True,
        "privacy_statement_enabled": True,
        "client_explanation_statement_enabled": True,
        "template_slug": "client_ai_use_transparency_v1",
        "template_version_snapshot": "1.0.0",
    }


def _seed_published_row(fake: _ClientTransparencyFakeDB) -> None:
    fake.published_row = {
        "public_version": 3,
        "publication_status": "published",
        "published_at": datetime(2026, 6, 3, 10, 0, 0, tzinfo=timezone.utc),
    }


# ---------------------------------------------------------------------
# Empty state
# ---------------------------------------------------------------------


def test_empty_state_returns_safe_defaults() -> None:
    fake = _ClientTransparencyFakeDB()
    block = _block(fake)

    assert block["active_profile_exists"] is False
    assert block["active_profile_status"] == "none"
    assert block["active_profile_version"] is None
    assert block["active_profile_activated_at"] is None
    assert block["active_template_slug"] is None
    assert block["active_template_version"] is None

    assert block["published_version_exists"] is False
    assert block["latest_public_version"] is None
    assert block["latest_publication_status"] == "none"
    assert block["latest_published_at"] is None

    assert block["permitted_categories_count"] == 0
    assert block["prohibited_categories_count"] == 0
    assert block["human_review_statement_enabled"] is False
    assert block["privacy_statement_enabled"] is False
    assert block["client_explanation_statement_enabled"] is False

    # Doctrine self-assertions always false.
    for key in (
        "raw_content_included",
        "clinical_content_included",
        "staff_identifiers_included",
        "client_identifiers_included",
        "patient_identifiers_included",
    ):
        assert block[key] is False

    _assert_no_forbidden_keys(block)


# ---------------------------------------------------------------------
# Active profile
# ---------------------------------------------------------------------


def test_active_profile_surfaces_metadata_and_counts() -> None:
    fake = _ClientTransparencyFakeDB()
    _seed_active_profile_row(fake)
    block = _block(fake)

    assert block["active_profile_exists"] is True
    assert block["active_profile_status"] == "active"
    assert block["active_profile_version"] == 2
    assert block["active_profile_activated_at"] == "2026-06-03T09:00:00+00:00"
    assert block["active_template_slug"] == "client_ai_use_transparency_v1"
    assert block["active_template_version"] == "1.0.0"
    assert block["permitted_categories_count"] == 2
    assert block["prohibited_categories_count"] == 3
    _assert_no_forbidden_keys(block)


def test_active_profile_statement_booleans_surfaced() -> None:
    fake = _ClientTransparencyFakeDB()
    _seed_active_profile_row(fake)
    block = _block(fake)
    assert block["human_review_statement_enabled"] is True
    assert block["privacy_statement_enabled"] is True
    assert block["client_explanation_statement_enabled"] is True


# ---------------------------------------------------------------------
# Published version
# ---------------------------------------------------------------------


def test_latest_published_version_surfaced() -> None:
    fake = _ClientTransparencyFakeDB()
    _seed_active_profile_row(fake)
    _seed_published_row(fake)
    block = _block(fake)

    assert block["published_version_exists"] is True
    assert block["latest_public_version"] == 3
    assert block["latest_publication_status"] == "published"
    assert block["latest_published_at"] == "2026-06-03T10:00:00+00:00"


def test_retired_only_public_versions_do_not_count_as_published() -> None:
    """The helper's SQL filters `publication_status='published'`, so a
    DB that only contains retired rows must surface
    `published_version_exists=False`. We simulate this by leaving
    `fake.published_row=None` even though the active profile exists."""
    fake = _ClientTransparencyFakeDB()
    _seed_active_profile_row(fake)
    fake.published_row = None
    block = _block(fake)
    assert block["published_version_exists"] is False
    assert block["latest_public_version"] is None
    assert block["latest_publication_status"] == "none"
    assert block["latest_published_at"] is None


def test_helper_filters_published_status_in_sql() -> None:
    """Belt-and-braces: the SQL must restrict to
    `publication_status = 'published'` so retired rows are excluded at
    the query layer."""
    fake = _ClientTransparencyFakeDB()
    _block(fake)
    pub_sql = next(
        sql for sql, _ in fake.calls
        if "client_transparency_public_versions" in sql
        and "ORDER BY published_at DESC" in sql
    )
    assert "publication_status = 'published'" in pub_sql


# ---------------------------------------------------------------------
# Doctrine sweeps
# ---------------------------------------------------------------------


def test_block_excludes_generated_public_payload() -> None:
    fake = _ClientTransparencyFakeDB()
    _seed_active_profile_row(fake)
    _seed_published_row(fake)
    block = _block(fake)
    # No key matching the publish payload artefact.
    flat = " ".join(str(k) for k in block.keys())
    assert "generated_public_payload" not in flat


def test_block_excludes_display_title_and_summary() -> None:
    fake = _ClientTransparencyFakeDB()
    _seed_active_profile_row(fake)
    block = _block(fake)
    assert "display_title" not in block
    assert "plain_language_summary" not in block


def test_block_excludes_staff_client_patient_identifiers() -> None:
    fake = _ClientTransparencyFakeDB()
    _seed_active_profile_row(fake)
    _seed_published_row(fake)
    block = _block(fake)
    _assert_no_forbidden_keys(block)


def test_governance_note_avoids_prohibited_claim_wording() -> None:
    fake = _ClientTransparencyFakeDB()
    note = _block(fake)["governance_note"]
    for a, b in _FORBIDDEN_FRAGMENTS:
        full = (a + b).lower()
        # The approved negative-disclaimer wording contains `consent
        # form`, `legal advice`, and `compliance certificate` only in
        # negative form. Sentence-bounded NOT-check is heavy here;
        # we just confirm none of the marketing-claim phrases appear.
        if full in ("consent form", "compliance certificate"):
            continue
        assert full not in note.lower(), (
            f"governance_note contains forbidden phrase: {a}{b!r}"
        )


def test_governance_note_explicitly_includes_negative_disclaimers() -> None:
    fake = _ClientTransparencyFakeDB()
    note = _block(fake)["governance_note"]
    lower = note.lower()
    # The disclaimer reads: "It is not legal advice, a consent form,
    # a clinical record, or a compliance certificate." Each phrase
    # below appears verbatim somewhere in that single sentence.
    for phrase in (
        "not legal advice",
        "a consent form",
        "a clinical record",
        "compliance certificate",
        "human professional review remains required",
    ):
        assert phrase in lower, f"governance_note missing disclaimer: {phrase}"
    # And that disclaimer must come AFTER the negation, in the same
    # sentence. Find " not " in the note and verify each of the three
    # follow-on phrases occurs after it.
    not_idx = lower.find(" not ")
    assert not_idx > 0
    for follow_on in ("a consent form", "a clinical record",
                      "compliance certificate"):
        assert lower.find(follow_on, not_idx) > not_idx, (
            f"disclaimer phrase '{follow_on}' not in negated context"
        )


# ---------------------------------------------------------------------
# Integration with build_trust_snapshot - block lands under expected key
# ---------------------------------------------------------------------


def test_build_trust_snapshot_wires_client_transparency_block() -> None:
    """Drive `build_trust_snapshot` with a permissive fake; confirm
    the new key lands on the snapshot envelope alongside the existing
    aggregate blocks."""
    fake = _PermissiveFakeDB()
    from app.trust_snapshot import build_trust_snapshot
    snap = build_trust_snapshot(db=fake, clinic_id=CLINIC_A)
    assert "client_transparency" in snap
    block = snap["client_transparency"]
    # Empty state from a permissive fake.
    assert block["active_profile_exists"] is False
    assert block["published_version_exists"] is False
    assert block["governance_note"]
    # Other top-level blocks still present (back-compat).
    for key in (
        "clinic", "governance", "privacy", "tenancy",
        "operations", "learning", "governance_policy", "self_assessment",
        "limitations",
    ):
        assert key in snap, f"existing trust key removed: {key}"


class _PermissiveFakeDB:
    """Catch-all fake for `build_trust_snapshot`: every query returns
    an empty result, exercising the helpers' defensive paths."""

    def execute(self, statement, params=None):
        return _Result(row=None, rows=[])
