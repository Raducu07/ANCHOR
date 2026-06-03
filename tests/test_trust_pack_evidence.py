"""Phase 2A-3.9B-1 - Trust Pack evidence-closure tests.

`_build_pack_response` is a pure function over a snapshot dict, so
these tests construct a minimal snapshot and assert on:

  * existing pack sections still present (back-compat)
  * five new metadata-only evidence sections present
  * no raw prompt / output / clinical content / policy body / raw
    self-assessment answer / staff name / staff email leaks
  * artifact_basis wording is the new readiness-evidence copy and
    avoids high-risk wording in clinic-facing text
  * mojibake fallback glyph (em-dash codepoint U+2014) no longer
    appears in pack
    bullets that used to carry it; ASCII `-` is used instead

No live DB, no HTTP, no router wiring - same pattern as
`_build_pack_response`'s callers.
"""
from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# Forbidden wording phrases assembled from fragments so this test
# source does NOT itself contain the full forbidden literals (which
# would otherwise trip broader repo-level wording scans).
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


# Forbidden keys that must never appear in the pack JSON.
FORBIDDEN_KEYS = {
    "policy_body",
    "policy_text",
    "policy_content",
    "raw_prompt",
    "raw_output",
    "raw_input",
    "prompt",
    "draft",
    "input_text",
    "output_text",
    "transcript",
    "clinical_content",
    "client_narrative",
    "competence_grade",
    "score",
    "pass_fail",
    "compliance_status",
    "staff_certified",
    "clinical_safety_proof",
    "legal_approval",
    "reflection",
    "staff_reflection",
    "email",
    "first_name",
    "last_name",
    "user_email",
    "reviewer_email",
}


def _minimal_snapshot(**overrides: Any) -> Dict[str, Any]:
    """Build a snapshot that mirrors the shape `build_trust_snapshot`
    produces. Only the keys `_build_pack_response` reads are
    populated. Override individual sub-blocks via kwargs."""
    base: Dict[str, Any] = {
        "snapshot_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_window": {
            "hours": 24,
            "from": "2026-06-01T00:00:00+00:00",
            "to": "2026-06-02T00:00:00+00:00",
        },
        "clinic": {
            "clinic_id": "00000000-0000-4000-8000-000000000001",
            "clinic_name": "Test Clinic",
            "clinic_slug": "test-clinic",
            "active_status": True,
        },
        "governance": {
            "policy_version": 3,
            "policy_versioning": True,
            "governance_receipts_active": True,
            "metadata_only_accountability": True,
            "stores_raw_content": False,
            "override_model": "append_only_admin_audit",
            "events_24h": 41,
            "interventions_24h": 2,
            "intervention_rate_24h": 0.049,
        },
        "privacy": {
            "privacy_controls_active": True,
            "privacy_controls_label": "Metadata-only accountability with privacy-aware controls",
            "hashed_ip_ua_logging": True,
            "stores_raw_prompt_output": False,
            "pii_warned_24h": 0,
            "pii_warned_rate_24h": 0.0,
        },
        "tenancy": {
            "hard_multi_tenancy": True,
            "rls_forced": True,
            "request_scoped_context": True,
            "clinic_scoped_portal_access": True,
            "tenant_isolation_testing_in_operating_model": True,
        },
        "operations": {
            "trust_state": "green",
            "signal_quality": "ok",
            "request_count_24h": 120,
            "events_24h": 41,
            "interventions_24h": 2,
            "intervention_rate_24h": 0.049,
            "pii_warned_24h": 0,
            "pii_warned_rate_24h": 0.0,
            "rate_5xx": 0.0,
            "p95_latency_ms": 240,
            "gov_replaced_rate": 0.0,
            "top_mode_24h": None,
            "top_route_24h": None,
        },
        "learning": {
            "enabled": True,
            "cards_available": True,
            "explainers_available": True,
            "dashboard_tie_in": True,
            "receipts_related_learning": True,
            "recommended_learning": {
                "title": "AI Literacy Foundations",
                "slug": "ai_literacy_foundations",
            },
        },
        "governance_policy": {
            "active_policy_count": 2,
            "active_policies": [
                {
                    "policy_template_id": "tpl-1",
                    "clinic_policy_version_id": "cpv-1",
                    "clinic_policy_version": 1,
                    "title": "AI Use Policy for Veterinary Teams",
                    "template_slug": "ai_use_policy",
                    "activated_at": "2026-05-30T10:00:00+00:00",
                    "attestation_coverage": {
                        "attestation_count": 5,
                        "distinct_user_count": 5,
                        "expected_user_count": 7,
                        "outstanding_user_count": 2,
                        "coverage_rate": 5 / 7,
                        "most_recent_acknowledged_at": "2026-06-01T08:00:00+00:00",
                    },
                },
                {
                    "policy_template_id": "tpl-2",
                    "clinic_policy_version_id": "cpv-2",
                    "clinic_policy_version": 1,
                    "title": "Client Disclosure When AI Assists",
                    "template_slug": "client_disclosure_when_ai_assists",
                    "activated_at": "2026-05-29T10:00:00+00:00",
                    "attestation_coverage": {
                        "attestation_count": 3,
                        "distinct_user_count": 3,
                        "expected_user_count": 7,
                        "outstanding_user_count": 4,
                        "coverage_rate": 3 / 7,
                        "most_recent_acknowledged_at": "2026-05-31T08:00:00+00:00",
                    },
                },
            ],
            "total_attestation_count": 8,
            "total_distinct_users_attested": 6,
            "expected_user_count": 7,
            "outstanding_user_count": 1,
            "average_coverage_rate": (5 / 7 + 3 / 7) / 2,
            "last_policy_update_at": "2026-05-30T10:00:00+00:00",
            "most_recent_acknowledged_at": "2026-06-01T08:00:00+00:00",
            "raw_policy_body_included": False,
            "governance_note": (
                "Governance policy evidence is metadata-only. It records "
                "active AI-use policy versions and staff acknowledgement "
                "coverage to support governance review and readiness "
                "evidence. Human review remains required; this is not "
                "legal advice."
            ),
        },
        "self_assessment": {
            "templates": [
                {
                    "template_slug": "rcvs_ai_governance_v1",
                    "template_version": "1.0.0",
                    "title": "RCVS AI Governance Self-Assessment",
                    "assessment_status": "submitted",
                    "latest_submitted_at": "2026-06-01T09:00:00+00:00",
                    "last_updated_at": "2026-06-01T09:00:00+00:00",
                    "clinic_assessment_version": 2,
                    "total_questions": 12,
                    "answered_questions": 12,
                    "readiness_summary_counts": {
                        "yes": 7, "partial": 2, "planned": 1,
                        "no": 1, "not_applicable": 1,
                    },
                    "linked_evidence_counts": {
                        "policy_library": 3, "staff_attestation": 2,
                        "learn_cpd": 1, "assistant_receipts": 1,
                        "trust_posture": 1, "manual_review": 0,
                    },
                    "gap_count": 4,
                },
            ],
            "latest_submitted_at": "2026-06-01T09:00:00+00:00",
            "submitted_assessment_count": 1,
            "raw_answers_included": False,
            "staff_identifiers_included": False,
            "governance_note": (
                "Self-assessment evidence is metadata-only and supports "
                "governance review and readiness evidence."
            ),
        },
        "client_transparency": {
            "active_profile_exists": True,
            "active_profile_status": "active",
            "active_profile_version": 2,
            "active_profile_activated_at": "2026-06-03T09:00:00+00:00",
            "active_template_slug": "client_ai_use_transparency_v1",
            "active_template_version": "1.0.0",
            "published_version_exists": True,
            "latest_public_version": 3,
            "latest_publication_status": "published",
            "latest_published_at": "2026-06-03T10:00:00+00:00",
            "permitted_categories_count": 2,
            "prohibited_categories_count": 3,
            "human_review_statement_enabled": True,
            "privacy_statement_enabled": True,
            "client_explanation_statement_enabled": True,
            "raw_content_included": False,
            "clinical_content_included": False,
            "staff_identifiers_included": False,
            "client_identifiers_included": False,
            "patient_identifiers_included": False,
            "governance_note": (
                "Client transparency evidence is metadata-only and indicates "
                "whether the clinic has an active, client-safe AI-use "
                "transparency statement and published version."
            ),
        },
        "incident_near_miss": {
            "window_days": 30,
            "records_total": 12,
            "records_last_30d": 7,
            "open_records": 2,
            "in_review_records": 1,
            "actioned_records": 1,
            "closed_records": 2,
            "voided_records": 1,
            "high_or_critical_records": 3,
            "privacy_related_records": 2,
            "linked_receipt_records": 4,
            "learning_recommended_count": 3,
            "policy_review_recommended_count": 2,
            "client_communication_review_recommended_count": 1,
            "last_reported_at": "2026-06-03T08:30:00+00:00",
            "raw_content_included": False,
            "clinical_content_included": False,
            "staff_identifiers_included": False,
            "client_identifiers_included": False,
            "patient_identifiers_included": False,
            "governance_note": (
                "Incident and near-miss evidence is metadata-only and "
                "supports governance review and learning."
            ),
        },
        "limitations": [
            "Evidence is metadata-only.",
            "Human review remains required.",
        ],
    }
    base.update(overrides)
    return base


def _pack(**overrides: Any) -> Dict[str, Any]:
    from app.portal_trust import _build_pack_response
    snapshot = _minimal_snapshot(**overrides)
    return _build_pack_response(snapshot)


def _section_by_id(pack_response: Dict[str, Any], section_id: str) -> Dict[str, Any]:
    sections = pack_response["pack"]["sections"]
    for s in sections:
        if s.get("id") == section_id:
            return s
    raise AssertionError(f"section not found: {section_id}")


def _walk_strings(obj: Any) -> List[str]:
    out: List[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_walk_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_walk_strings(v))
    return out


def _walk_keys(obj: Any) -> List[str]:
    out: List[str] = []
    if isinstance(obj, dict):
        out.extend(obj.keys())
        for v in obj.values():
            out.extend(_walk_keys(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_walk_keys(v))
    return out


# ---------------------------------------------------------------------
# Back-compat: existing sections still present
# ---------------------------------------------------------------------


EXISTING_SECTION_IDS = (
    "cover",
    "governance_controls",
    "privacy_data_handling",
    "tenant_platform_safeguards",
    "operational_assurance",
    "learning_safe_adoption",
    "artifact_basis",
)


def test_pack_retains_existing_sections() -> None:
    resp = _pack()
    ids = [s["id"] for s in resp["pack"]["sections"]]
    for sid in EXISTING_SECTION_IDS:
        assert sid in ids, f"existing section dropped: {sid}"


def test_pack_envelope_keys_unchanged() -> None:
    resp = _pack()
    assert set(resp.keys()) == {"generated_at", "pack", "snapshot"}
    pack = resp["pack"]
    for key in (
        "artifact_type",
        "artifact_version",
        "generated_at",
        "clinic_name",
        "trust_state",
        "sections",
        "evidence_window",
    ):
        assert key in pack


def test_pack_artifact_type_and_version_stable() -> None:
    resp = _pack()
    assert resp["pack"]["artifact_type"] == "trust_pack"
    assert resp["pack"]["artifact_version"] == "1.0"


# ---------------------------------------------------------------------
# New evidence sections present
# ---------------------------------------------------------------------


def test_pack_has_learning_evidence_section() -> None:
    s = _section_by_id(_pack(), "learning_evidence")
    assert s["title"] == "Learning and CPD evidence"
    assert s["raw_content_included"] is False
    assert s["staff_identifiers_included"] is False
    assert "metadata-only" in s["body"].lower()


def test_pack_has_governance_policy_evidence_section() -> None:
    s = _section_by_id(_pack(), "governance_policy_evidence")
    bullets_text = " ".join(s["bullets"]).lower()
    assert "active clinic policy versions: 2" in bullets_text
    assert "total non-voided attestations: 8" in bullets_text
    assert "distinct users with at least one attestation: 6 of 7" in bullets_text
    assert "outstanding users: 1" in bullets_text
    assert s["raw_policy_body_included"] is False
    assert s["staff_identifiers_included"] is False
    # Body is the governance_note carried from the snapshot.
    assert "metadata-only" in s["body"].lower()


def test_pack_has_staff_attestation_section() -> None:
    s = _section_by_id(_pack(), "staff_attestation_evidence")
    bullets_text = " ".join(s["bullets"]).lower()
    assert "expected users: 7" in bullets_text
    assert "distinct users attested: 6" in bullets_text
    assert "outstanding users: 1" in bullets_text
    assert s["staff_identifiers_included"] is False
    # No staff name/email keys appear in this section.
    assert FORBIDDEN_KEYS.isdisjoint(set(_walk_keys(s)))


def test_pack_has_self_assessment_section() -> None:
    s = _section_by_id(_pack(), "self_assessment_evidence")
    assert s["raw_answers_included"] is False
    assert s["staff_identifiers_included"] is False
    tpls = s["templates"]
    assert len(tpls) == 1
    tpl = tpls[0]
    assert tpl["assessment_status"] == "submitted"
    assert tpl["total_questions"] == 12
    assert tpl["answered_questions"] == 12
    assert tpl["readiness_summary_counts"]["yes"] == 7
    assert tpl["linked_evidence_counts"]["policy_library"] == 3
    # No raw answer rows.
    leaked = FORBIDDEN_KEYS & set(_walk_keys(s))
    assert not leaked, f"forbidden keys leaked in self_assessment section: {leaked}"


def test_pack_has_assistant_receipt_evidence_section() -> None:
    s = _section_by_id(_pack(), "assistant_receipt_evidence")
    bullets_text = " ".join(s["bullets"]).lower()
    assert "assistant receipt evidence surface is active" in bullets_text
    assert s["raw_content_included"] is False
    assert s["raw_prompt_included"] is False
    assert s["raw_output_included"] is False


# ---------------------------------------------------------------------
# Doctrine guards across the whole pack
# ---------------------------------------------------------------------


def test_pack_has_no_raw_content_keys() -> None:
    leaked = FORBIDDEN_KEYS & set(_walk_keys(_pack()))
    assert not leaked, f"forbidden keys leaked in pack: {leaked}"


def test_pack_has_no_raw_self_assessment_answers() -> None:
    resp = _pack()
    keys = set(_walk_keys(resp))
    for k in (
        "answers", "raw_answers", "answer_text", "answer_value",
        "free_text", "comment", "comments", "rationale", "rationale_text",
    ):
        assert k not in keys, f"raw self-assessment key leaked: {k}"


def test_pack_artifact_basis_uses_new_readiness_evidence_wording() -> None:
    s = _section_by_id(_pack(), "artifact_basis")
    body_l = s["body"].lower()
    assert "readiness evidence" in body_l
    assert "not legal advice" in body_l
    # Old wording must be gone.
    assert "legal certification" not in body_l
    assert "formal compliance attestation" not in body_l


def test_pack_avoids_high_risk_wording_in_clinic_facing_copy() -> None:
    """The pack's bullets/body strings must not contain the full
    forbidden marketing claims as positive claims. The approved
    `_LEARNING_EVIDENCE_NOTE` disclaimer uses some of these terms in
    negative ("is not certified CPD, proof of competence, or
    regulator-approved training") form. We accept that strictly
    negated form and reject all other usages.

    Fragments are assembled at runtime so this test source itself
    contains no full forbidden literal.
    """
    resp = _pack()
    haystack_lower = " ".join(_walk_strings(resp)).lower()
    # Approved negative-disclaimer windows: phrase must appear only
    # immediately preceded by a `not ` token within a short window.
    NEGATIVE_OK = {
        ("certified", " CPD"),
        ("proof", " of competence"),
    }
    for a, b in _FORBIDDEN_FRAGMENTS:
        phrase = (a + b).lower()
        if (a, b) in NEGATIVE_OK:
            # Allowed iff every occurrence is in negative-disclaimer
            # form: ` not ` appears in the same sentence before the
            # phrase. Matches the approved sentence
            # "It is not certified CPD, proof of competence, or
            # regulator-approved training." without permitting
            # positive marketing claims.
            idx = 0
            while True:
                pos = haystack_lower.find(phrase, idx)
                if pos < 0:
                    break
                # Sentence start = last sentence terminator before pos.
                sentence_start = max(
                    haystack_lower.rfind(". ", 0, pos),
                    haystack_lower.rfind("! ", 0, pos),
                    haystack_lower.rfind("? ", 0, pos),
                    0,
                )
                window = haystack_lower[sentence_start: pos]
                assert " not " in window, (
                    f"phrase {a}{b} appears in non-negated sentence"
                )
                idx = pos + len(phrase)
            continue
        assert phrase not in haystack_lower, (
            f"forbidden phrase leaked into pack copy: {a}{b}"
        )


# ---------------------------------------------------------------------
# Mojibake / ASCII fallback regression
# ---------------------------------------------------------------------


def test_pack_does_not_emit_em_dash_fallback() -> None:
    """The pack previously used the em-dash codepoint (U+2014) as a fallback
    glyph, which round-trips to mojibake in some clients. The new code
    uses ASCII '-'. Assert no em-dash codepoint appears in any pack
    string."""
    resp = _pack()
    for s in _walk_strings(resp):
        assert chr(0x2014) not in s, (
            f"em-dash fallback present in pack string: {s!r}"
        )


def test_pack_uses_ascii_hyphen_fallback_when_top_mode_missing() -> None:
    """Operational assurance section should show '-' (ASCII) when
    snapshot.operations.top_mode_24h is None."""
    resp = _pack()
    op = _section_by_id(resp, "operational_assurance")
    joined = " ".join(op["bullets"])
    assert "Top mode (24h): -" in joined


# ---------------------------------------------------------------------
# Robustness: empty / minimal snapshot evidence blocks
# ---------------------------------------------------------------------


def test_pack_handles_empty_governance_policy_block() -> None:
    resp = _pack(governance_policy={
        "active_policy_count": 0,
        "active_policies": [],
        "total_attestation_count": 0,
        "total_distinct_users_attested": 0,
        "expected_user_count": 0,
        "outstanding_user_count": 0,
        "average_coverage_rate": 0.0,
        "last_policy_update_at": None,
        "most_recent_acknowledged_at": None,
        "raw_policy_body_included": False,
        "governance_note": (
            "Governance policy evidence is metadata-only. It records "
            "active AI-use policy versions and staff acknowledgement "
            "coverage to support governance review and readiness "
            "evidence. Human review remains required; this is not "
            "legal advice."
        ),
    })
    s = _section_by_id(resp, "governance_policy_evidence")
    bullets_text = " ".join(s["bullets"]).lower()
    assert "active clinic policy versions: 0" in bullets_text
    assert "most recent acknowledgement: -" in bullets_text


def test_pack_handles_empty_self_assessment_block() -> None:
    resp = _pack(self_assessment={
        "templates": [],
        "latest_submitted_at": None,
        "submitted_assessment_count": 0,
        "raw_answers_included": False,
        "staff_identifiers_included": False,
        "governance_note": "Self-assessment evidence is metadata-only.",
    })
    s = _section_by_id(resp, "self_assessment_evidence")
    assert s["templates"] == []
    assert "submitted self-assessments on file: 0" in " ".join(s["bullets"]).lower()


# ---------------------------------------------------------------------
# Phase 2A-4.4 - client_transparency_evidence section
# ---------------------------------------------------------------------


def test_pack_has_client_transparency_evidence_section() -> None:
    s = _section_by_id(_pack(), "client_transparency_evidence")
    assert s["title"] == "Client transparency evidence"
    assert s["active_profile_exists"] is True
    assert s["published_version_exists"] is True
    # Doctrine flags always false on this section.
    for flag in (
        "raw_content_included",
        "clinical_content_included",
        "staff_identifiers_included",
        "client_identifiers_included",
        "patient_identifiers_included",
    ):
        assert s[flag] is False


def test_pack_client_transparency_section_includes_active_and_published() -> None:
    s = _section_by_id(_pack(), "client_transparency_evidence")
    text = " ".join(s["bullets"]).lower()
    assert "active client transparency profile: yes" in text
    assert "published client-safe version: yes" in text


def test_pack_client_transparency_section_includes_category_counts() -> None:
    s = _section_by_id(_pack(), "client_transparency_evidence")
    text = " ".join(s["bullets"]).lower()
    assert "permitted ai-use categories recorded: 2" in text
    assert "prohibited ai-use categories recorded: 3" in text


def test_pack_client_transparency_section_includes_statement_flags() -> None:
    s = _section_by_id(_pack(), "client_transparency_evidence")
    text = " ".join(s["bullets"]).lower()
    assert "human review statement enabled: yes" in text
    assert "privacy statement enabled: yes" in text
    assert "client explanation statement enabled: yes" in text


def test_pack_client_transparency_section_includes_honest_disclosure_rows() -> None:
    s = _section_by_id(_pack(), "client_transparency_evidence")
    text = " ".join(s["bullets"])
    assert "Raw content included: No." in text
    assert "Clinical content included: No." in text
    assert "Staff identifiers included: No." in text
    assert "Client identifiers included: No." in text
    assert "Patient identifiers included: No." in text


def test_pack_client_transparency_section_no_payload_or_clinic_text() -> None:
    s = _section_by_id(_pack(), "client_transparency_evidence")
    keys = set(_walk_keys(s))
    assert "generated_public_payload" not in keys
    assert "display_title" not in keys
    assert "plain_language_summary" not in keys
    # Strings should not embed the clinic-authored disclosure text from
    # the (test-only) snapshot fixture either - the section reads only
    # the aggregate block, not the clinic-authored fields.
    haystack = " ".join(_walk_strings(s))
    assert "How we use AI at the clinic" not in haystack


def test_pack_client_transparency_section_avoids_high_risk_wording() -> None:
    s = _section_by_id(_pack(), "client_transparency_evidence")
    haystack = " ".join(_walk_strings(s)).lower()
    # Reuse the file-wide forbidden-fragment table assembled at runtime.
    for a, b in _FORBIDDEN_FRAGMENTS:
        phrase = (a + b).lower()
        assert phrase not in haystack, (
            f"forbidden phrase leaked into client_transparency_evidence: {a}{b}"
        )


def test_pack_client_transparency_section_handles_empty_state() -> None:
    """No active profile, no published version."""
    resp = _pack(client_transparency={
        "active_profile_exists": False,
        "active_profile_status": "none",
        "active_profile_version": None,
        "active_profile_activated_at": None,
        "active_template_slug": None,
        "active_template_version": None,
        "published_version_exists": False,
        "latest_public_version": None,
        "latest_publication_status": "none",
        "latest_published_at": None,
        "permitted_categories_count": 0,
        "prohibited_categories_count": 0,
        "human_review_statement_enabled": False,
        "privacy_statement_enabled": False,
        "client_explanation_statement_enabled": False,
        "raw_content_included": False,
        "clinical_content_included": False,
        "staff_identifiers_included": False,
        "client_identifiers_included": False,
        "patient_identifiers_included": False,
        "governance_note": "ok",
    })
    s = _section_by_id(resp, "client_transparency_evidence")
    text = " ".join(s["bullets"]).lower()
    assert "active client transparency profile: no" in text
    assert "published client-safe version: no" in text
    assert "latest public version: -" in text
    # Statement enabled bullets are NOT emitted when no active profile.
    assert "human review statement enabled" not in text
    assert "privacy statement enabled" not in text
    assert "client explanation statement enabled" not in text
    # Honest-disclosure rows still present.
    raw_text = " ".join(s["bullets"])
    assert "Raw content included: No." in raw_text
    assert "Patient identifiers included: No." in raw_text


def test_pack_section_ordering_places_client_transparency_before_assistant_receipts() -> None:
    """Sanity check: the new section appears between the existing
    evidence sections and the assistant_receipt_evidence section, so
    Trust Pack rendering preserves a coherent narrative order."""
    sections = _pack()["pack"]["sections"]
    ids = [s["id"] for s in sections]
    assert ids.index("client_transparency_evidence") < ids.index(
        "assistant_receipt_evidence"
    )
    assert ids.index("self_assessment_evidence") < ids.index(
        "client_transparency_evidence"
    )


# ---------------------------------------------------------------------
# Phase 2A-5.4 - incident_near_miss_evidence section
# ---------------------------------------------------------------------


def test_pack_has_incident_near_miss_evidence_section() -> None:
    s = _section_by_id(_pack(), "incident_near_miss_evidence")
    assert s["title"] == "Incident and near-miss evidence"
    # Doctrine flags always false on this section.
    for flag in (
        "raw_content_included",
        "clinical_content_included",
        "staff_identifiers_included",
        "client_identifiers_included",
        "patient_identifiers_included",
    ):
        assert s[flag] is False


def test_pack_incident_near_miss_section_ordering() -> None:
    """Incident evidence sits after client_transparency_evidence and
    before assistant_receipt_evidence."""
    sections = _pack()["pack"]["sections"]
    ids = [s["id"] for s in sections]
    assert ids.index("client_transparency_evidence") < ids.index(
        "incident_near_miss_evidence"
    )
    assert ids.index("incident_near_miss_evidence") < ids.index(
        "assistant_receipt_evidence"
    )


def test_pack_incident_near_miss_bullets_present_for_populated_snapshot() -> None:
    s = _section_by_id(_pack(), "incident_near_miss_evidence")
    text = " ".join(s["bullets"]).lower()
    # Total + window counts.
    assert "total records recorded: 12" in text
    assert "records in last 30 days: 7" in text
    # Status counts.
    assert "open records: 2" in text
    assert "in review records: 1" in text
    assert "actioned records: 1" in text
    assert "closed records: 2" in text
    assert "voided records: 1" in text
    # Risk / privacy / linked aggregates.
    assert "high or critical records in window: 3" in text
    assert "privacy-related records in window: 2" in text
    assert "linked receipt records in window: 4" in text
    # Recommendation counts.
    assert "learning recommendations: 3" in text
    assert "policy review recommendations: 2" in text
    assert "client communication review recommendations: 1" in text


def test_pack_incident_near_miss_includes_honest_disclosure_rows() -> None:
    s = _section_by_id(_pack(), "incident_near_miss_evidence")
    text = " ".join(s["bullets"])
    assert "Raw content included: No." in text
    assert "Clinical content included: No." in text
    assert "Staff identifiers included: No." in text
    assert "Client identifiers included: No." in text
    assert "Patient identifiers included: No." in text


def test_pack_incident_near_miss_no_per_record_or_identifier_keys() -> None:
    s = _section_by_id(_pack(), "incident_near_miss_evidence")
    keys = set(_walk_keys(s))
    # No individual record IDs.
    assert "incident_id" not in keys
    assert "records" not in keys  # would imply per-record array
    # No staff / user identifier shapes.
    for k in (
        "created_by_user_id", "reviewed_by_user_id",
        "closed_by_user_id", "voided_by_user_id",
        "user_id", "user_email", "email",
    ):
        assert k not in keys
    # No linked target UUIDs.
    for k in (
        "linked_receipt_id", "linked_governance_event_id",
        "linked_assistant_run_id", "linked_clinic_policy_version_id",
    ):
        assert k not in keys


def test_pack_incident_near_miss_no_raw_or_clinical_content() -> None:
    s = _section_by_id(_pack(), "incident_near_miss_evidence")
    keys = set(_walk_keys(s))
    for k in (
        "raw_prompt", "raw_output", "transcript",
        "clinical_content", "client_identifier", "patient_identifier",
        "case_material", "note", "description", "narrative",
        "comments", "free_text",
    ):
        assert k not in keys


def test_pack_incident_near_miss_handles_empty_state() -> None:
    """No incidents recorded: all counts zero, last_reported_at '-'."""
    resp = _pack(incident_near_miss={
        "window_days": 30,
        "records_total": 0,
        "records_last_30d": 0,
        "open_records": 0,
        "in_review_records": 0,
        "actioned_records": 0,
        "closed_records": 0,
        "voided_records": 0,
        "high_or_critical_records": 0,
        "privacy_related_records": 0,
        "linked_receipt_records": 0,
        "learning_recommended_count": 0,
        "policy_review_recommended_count": 0,
        "client_communication_review_recommended_count": 0,
        "last_reported_at": None,
        "raw_content_included": False,
        "clinical_content_included": False,
        "staff_identifiers_included": False,
        "client_identifiers_included": False,
        "patient_identifiers_included": False,
        "governance_note": "ok",
    })
    s = _section_by_id(resp, "incident_near_miss_evidence")
    text = " ".join(s["bullets"]).lower()
    assert "total records recorded: 0" in text
    assert "records in last 30 days: 0" in text
    assert "last reported at: -" in text
    # Honest-disclosure rows still emitted.
    raw_text = " ".join(s["bullets"])
    assert "Raw content included: No." in raw_text
    assert "Patient identifiers included: No." in raw_text


def test_pack_incident_near_miss_section_avoids_high_risk_wording() -> None:
    s = _section_by_id(_pack(), "incident_near_miss_evidence")
    haystack = " ".join(_walk_strings(s)).lower()
    for a, b in _FORBIDDEN_FRAGMENTS:
        phrase = (a + b).lower()
        assert phrase not in haystack, (
            f"forbidden phrase in incident_near_miss_evidence: {a}{b}"
        )


def test_pack_still_includes_all_six_other_evidence_sections() -> None:
    """Back-compat: existing evidence sections still render after the
    incident evidence section is appended."""
    ids = [s["id"] for s in _pack()["pack"]["sections"]]
    for required in (
        "learning_evidence",
        "governance_policy_evidence",
        "staff_attestation_evidence",
        "self_assessment_evidence",
        "client_transparency_evidence",
        "assistant_receipt_evidence",
        # And the new one.
        "incident_near_miss_evidence",
    ):
        assert required in ids, f"evidence section missing: {required}"
