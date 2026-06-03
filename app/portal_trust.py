# app/portal_trust.py
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import SessionLocal, set_rls_context, clear_rls_context
from app.learn_models import TrustPackLearningDelta
from app.trust_snapshot import build_trust_snapshot

# IMPORTANT:
# Keep this aligned with the auth dependency used by your working
# clinic portal routes. If your working routes use a different symbol,
# swap only this import + the Depends(...) calls below.
from app.auth_and_rls import require_clinic_user


router = APIRouter(prefix="/v1/portal/trust", tags=["portal-trust"])


def _ctx_value(ctx: Any, key: str) -> Optional[Any]:
    # direct attr
    if hasattr(ctx, key):
        value = getattr(ctx, key)
        if value is not None:
            return value

    # dict style
    if isinstance(ctx, dict) and key in ctx and ctx[key] is not None:
        return ctx[key]

    # nested claims attr/dict
    claims = getattr(ctx, "claims", None)
    if isinstance(claims, dict) and key in claims and claims[key] is not None:
        return claims[key]

    if isinstance(ctx, dict):
        nested_claims = ctx.get("claims")
        if isinstance(nested_claims, dict) and key in nested_claims and nested_claims[key] is not None:
            return nested_claims[key]

    return None


def _ctx_ids(ctx: Any) -> Tuple[str, Optional[str]]:
    clinic_id = _ctx_value(ctx, "clinic_id")
    clinic_user_id = (
        _ctx_value(ctx, "clinic_user_id")
        or _ctx_value(ctx, "user_id")
        or _ctx_value(ctx, "sub")
    )

    if not clinic_id:
        raise HTTPException(status_code=401, detail="Missing clinic_id in authenticated context")

    return str(clinic_id), str(clinic_user_id) if clinic_user_id else None


def _build_snapshot_for_ctx(ctx: Any) -> Dict[str, Any]:
    clinic_id, clinic_user_id = _ctx_ids(ctx)

    with SessionLocal() as db:
        try:
            # Critical: restore tenant RLS context for this DB session
            set_rls_context(
                db,
                clinic_id=clinic_id,
                user_id=clinic_user_id,
            )
            snapshot = build_trust_snapshot(
                db=db,
                clinic_id=clinic_id,
            )
            return snapshot
        finally:
            try:
                clear_rls_context(db)
            except Exception:
                pass


def _posture_status_from_snapshot(snapshot: Dict[str, Any]) -> str:
    trust_state = snapshot["operations"]["trust_state"]
    signal_quality = snapshot["operations"]["signal_quality"]

    if trust_state == "red":
        return "attention_required"
    if trust_state == "yellow":
        return "monitoring"
    if signal_quality == "low":
        return "light_signal"
    return "healthy"


def _build_posture_response(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    trust_state = snapshot["operations"]["trust_state"]
    signal_quality = snapshot["operations"]["signal_quality"]
    policy_version = snapshot["governance"]["policy_version"]

    if trust_state == "red":
        headline = "Trust posture requires attention"
    elif trust_state == "yellow":
        headline = "Trust posture is stable but should be monitored"
    else:
        headline = "Trust posture is stable"

    if signal_quality == "low":
        summary = (
            "Current posture is derived from light recent evidence. Governance, privacy, tenancy, and learning controls are in place, "
            "but recent operational volume is limited."
        )
    else:
        summary = (
            "Current posture is derived from live governance and operational metadata. ANCHOR indicates a governance-first operating model "
            "with privacy-aware controls, tenant isolation, and staff enablement surfaces active."
        )

    sections: List[Dict[str, Any]] = [
        {
            "id": "governance",
            "title": "Governance posture",
            "status": "active",
            "items": [
                "Governance receipts are active.",
                "Policy versioning is active.",
                "Metadata-only accountability remains the core operating model.",
                f"Current active policy version: v{policy_version}.",
                "Override model is append-only and audit-oriented.",
            ],
        },
        {
            "id": "privacy",
            "title": "Privacy posture",
            "status": "active",
            "items": [
                "Raw prompts and outputs are not stored in this trust surface.",
                "Privacy-aware controls remain active.",
                "Logging discipline uses hashed IP and user-agent signals.",
                "Trust signals are derived from metadata and operational telemetry.",
            ],
        },
        {
            "id": "tenancy",
            "title": "Tenant isolation posture",
            "status": "active",
            "items": [
                "Hard multi-tenancy remains part of the platform model.",
                "FORCE RLS is treated as a core safeguard.",
                "Portal access is clinic-scoped.",
                "Tenant isolation testing remains part of the operating model.",
            ],
        },
        {
            "id": "operations",
            "title": "Operational trust posture",
            "status": _posture_status_from_snapshot(snapshot),
            "items": [
                f"Trust state: {trust_state}.",
                f"Recent intervention rate: {snapshot['operations']['intervention_rate_24h'] * 100.0:.1f}%.",
                f"Recent privacy warning rate: {snapshot['operations']['pii_warned_rate_24h'] * 100.0:.1f}%.",
                f"Top mode (24h): {snapshot['operations']['top_mode_24h'] or '-'}.",
                f"Top route (24h): {snapshot['operations']['top_route_24h'] or '-'}.",
            ],
        },
        {
            "id": "learning",
            "title": "Learning readiness posture",
            "status": "active",
            "items": [
                "ANCHOR Learn baseline is enabled.",
                "Explainers and microlearning cards are available.",
                "Receipts and governance events can link back into learning support.",
                f"Recommended reinforcement: {snapshot['learning']['recommended_learning']['title']}.",
            ],
        },
    ]

    return {
        "generated_at": snapshot["generated_at"],
        "headline": headline,
        "summary": summary,
        "sections": sections,
        "snapshot": snapshot,
    }


# ---------------------------------------------------------------------
# Phase 2A-3.9B-1 - Trust Pack evidence-closure helpers.
#
# Each builder consumes ONLY the metadata-only aggregates already on
# the snapshot. None of these helpers issues new SQL, and none touches
# raw self-assessment answers, raw policy body, staff identifiers, or
# raw prompts / outputs. If a surface isn't aggregated on the snapshot
# today, the section emits a conservative copy and points at the
# relevant Trust posture sub-endpoint rather than fabricating numbers.
# ---------------------------------------------------------------------


_LEARNING_EVIDENCE_NOTE = (
    "Learning evidence is metadata-only and supports staff AI-literacy "
    "readiness review. It is not certified CPD, proof of competence, or "
    "regulator-approved training."
)


def _build_learning_evidence_section(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    learning = snapshot.get("learning", {}) or {}
    recommended = (learning.get("recommended_learning") or {}).get("title") or "-"
    bullets: List[str] = [
        "Learn baseline enabled.",
        "Explainers and microlearning cards available.",
        "Per-staff CPD aggregates are exposed via the learning-delta posture endpoint, not duplicated in this artefact.",
        f"Recommended reinforcement focus: {recommended}.",
        "Evidence is metadata-only; no raw learning content or per-staff identifiers in this artefact.",
    ]
    return {
        "id": "learning_evidence",
        "title": "Learning and CPD evidence",
        "body": _LEARNING_EVIDENCE_NOTE,
        "bullets": bullets,
        "raw_content_included": False,
        "staff_identifiers_included": False,
    }


def _build_governance_policy_evidence_section(
    snapshot: Dict[str, Any],
) -> Dict[str, Any]:
    block = snapshot.get("governance_policy") or {}
    active_policy_count = int(block.get("active_policy_count") or 0)
    expected = int(block.get("expected_user_count") or 0)
    distinct = int(block.get("total_distinct_users_attested") or 0)
    outstanding = int(block.get("outstanding_user_count") or 0)
    average_coverage = float(block.get("average_coverage_rate") or 0.0)
    total_attestations = int(block.get("total_attestation_count") or 0)
    last_policy_update = block.get("last_policy_update_at")
    most_recent_ack = block.get("most_recent_acknowledged_at")
    governance_note = block.get("governance_note") or (
        "Governance policy evidence is metadata-only. It records active "
        "AI-use policy versions and staff acknowledgement coverage to "
        "support governance review and readiness evidence. Human review "
        "remains required; this is not legal advice."
    )

    active_titles: List[str] = []
    for p in (block.get("active_policies") or [])[:5]:
        title = str(p.get("title") or "").strip()
        version = p.get("clinic_policy_version")
        if title and version is not None:
            active_titles.append(f"{title} (v{version})")
        elif title:
            active_titles.append(title)

    bullets: List[str] = [
        f"Active clinic policy versions: {active_policy_count}.",
        f"Total non-voided attestations: {total_attestations}.",
        f"Distinct users with at least one attestation: {distinct} of {expected}.",
        f"Outstanding users: {outstanding}.",
        f"Average attestation coverage across active policies: {average_coverage * 100.0:.1f}%.",
        f"Most recent acknowledgement: {most_recent_ack or '-'}.",
        f"Most recent policy update: {last_policy_update or '-'}.",
    ]
    if active_titles:
        bullets.append("Active policies: " + "; ".join(active_titles) + ".")

    return {
        "id": "governance_policy_evidence",
        "title": "Governance policy evidence",
        "body": governance_note,
        "bullets": bullets,
        "raw_policy_body_included": False,
        "staff_identifiers_included": False,
    }


def _build_staff_attestation_section(
    snapshot: Dict[str, Any],
) -> Dict[str, Any]:
    block = snapshot.get("governance_policy") or {}
    expected = int(block.get("expected_user_count") or 0)
    distinct = int(block.get("total_distinct_users_attested") or 0)
    outstanding = int(block.get("outstanding_user_count") or 0)
    average_coverage = float(block.get("average_coverage_rate") or 0.0)
    most_recent_ack = block.get("most_recent_acknowledged_at")
    return {
        "id": "staff_attestation_evidence",
        "title": "Staff attestation evidence",
        "body": (
            "Staff attestation evidence aggregates acknowledgement coverage "
            "across active clinic policy versions. Per-user identifiers "
            "are not included in this artefact."
        ),
        "bullets": [
            f"Expected users: {expected}.",
            f"Distinct users attested: {distinct}.",
            f"Outstanding users: {outstanding}.",
            f"Average coverage rate: {average_coverage * 100.0:.1f}%.",
            f"Most recent acknowledgement: {most_recent_ack or '-'}.",
            "Staff names and emails are not surfaced in this artefact.",
        ],
        "staff_identifiers_included": False,
    }


def _build_self_assessment_evidence_section(
    snapshot: Dict[str, Any],
) -> Dict[str, Any]:
    block = snapshot.get("self_assessment") or {}
    templates = list(block.get("templates") or [])
    submitted_count = int(block.get("submitted_assessment_count") or 0)
    latest_submitted_at = block.get("latest_submitted_at")
    governance_note = block.get("governance_note") or (
        "Self-assessment evidence is metadata-only and supports governance "
        "review and readiness evidence. It does not replace professional "
        "judgement and should be reviewed by the clinic."
    )

    bullets: List[str] = [
        f"Submitted self-assessments on file: {submitted_count}.",
        f"Most recent submission: {latest_submitted_at or '-'}.",
    ]

    templates_summary: List[Dict[str, Any]] = []
    for tpl in templates:
        total_q = int(tpl.get("total_questions") or 0)
        answered_q = int(tpl.get("answered_questions") or 0)
        readiness = dict(tpl.get("readiness_summary_counts") or {})
        evidence = dict(tpl.get("linked_evidence_counts") or {})
        gap_count = int(tpl.get("gap_count") or 0)
        title = str(tpl.get("title") or "").strip() or "-"
        status = str(tpl.get("assessment_status") or "none")
        templates_summary.append(
            {
                "template_slug": str(tpl.get("template_slug") or ""),
                "template_version": str(tpl.get("template_version") or ""),
                "title": title,
                "assessment_status": status,
                "latest_submitted_at": tpl.get("latest_submitted_at"),
                "total_questions": total_q,
                "answered_questions": answered_q,
                "readiness_summary_counts": readiness,
                "linked_evidence_counts": evidence,
                "gap_count": gap_count,
            }
        )
        bullets.append(
            f"{title}: status {status}, answered {answered_q}/{total_q}, gaps {gap_count}."
        )

    return {
        "id": "self_assessment_evidence",
        "title": "Self-assessment evidence",
        "body": governance_note,
        "bullets": bullets,
        "templates": templates_summary,
        "raw_answers_included": False,
        "staff_identifiers_included": False,
    }


def _build_assistant_receipt_evidence_section(
    snapshot: Dict[str, Any],
) -> Dict[str, Any]:
    governance = snapshot.get("governance", {}) or {}
    events_24h = int(governance.get("events_24h") or 0)
    interventions_24h = int(governance.get("interventions_24h") or 0)
    return {
        "id": "assistant_receipt_evidence",
        "title": "Assistant receipt evidence",
        "body": (
            "Assistant receipt evidence is metadata-only. Receipts record "
            "the governance metadata around Assistant runs (hashes, policy "
            "version, validation profile, review state) and never the raw "
            "prompt, draft, or output."
        ),
        "bullets": [
            "Assistant receipt evidence surface is active.",
            f"Recent governance events (24h): {events_24h}.",
            f"Recent interventions (24h): {interventions_24h}.",
            "Per-run receipt metadata is exposed via the Assistant traceability endpoints, not duplicated in this artefact.",
            "Raw prompts, drafts, and outputs are not stored or surfaced.",
        ],
        "raw_content_included": False,
        "raw_prompt_included": False,
        "raw_output_included": False,
    }


_CLIENT_TRANSPARENCY_EVIDENCE_NOTE = (
    "Client transparency evidence summarises whether the clinic has "
    "configured and published a client-safe AI-use transparency "
    "statement. This supports clear communication about bounded, "
    "human-reviewed AI use without storing raw clinical content or "
    "client/patient identifiers."
)


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _build_client_transparency_evidence_section(
    snapshot: Dict[str, Any],
) -> Dict[str, Any]:
    block = snapshot.get("client_transparency") or {}
    active_exists = bool(block.get("active_profile_exists"))
    active_version = block.get("active_profile_version")
    published_exists = bool(block.get("published_version_exists"))
    latest_public_version = block.get("latest_public_version")
    latest_published_at = block.get("latest_published_at")
    permitted_count = int(block.get("permitted_categories_count") or 0)
    prohibited_count = int(block.get("prohibited_categories_count") or 0)
    human_review_enabled = bool(block.get("human_review_statement_enabled"))
    privacy_enabled = bool(block.get("privacy_statement_enabled"))
    client_explanation_enabled = bool(
        block.get("client_explanation_statement_enabled")
    )

    bullets: List[str] = [
        f"Active client transparency profile: {_yes_no(active_exists)}.",
    ]
    if active_exists:
        bullets.append(
            f"Active profile version: {active_version if active_version is not None else '-'}."
        )
    bullets.append(
        f"Published client-safe version: {_yes_no(published_exists)}."
    )
    bullets.append(
        f"Latest public version: {latest_public_version if latest_public_version is not None else '-'}."
    )
    if active_exists:
        bullets.append(
            f"Latest published at: {latest_published_at or '-'}."
        )
        bullets.append(
            f"Permitted AI-use categories recorded: {permitted_count}."
        )
        bullets.append(
            f"Prohibited AI-use categories recorded: {prohibited_count}."
        )
        bullets.append(
            f"Human review statement enabled: {_yes_no(human_review_enabled)}."
        )
        bullets.append(
            f"Privacy statement enabled: {_yes_no(privacy_enabled)}."
        )
        bullets.append(
            f"Client explanation statement enabled: {_yes_no(client_explanation_enabled)}."
        )
    bullets.extend([
        "Raw content included: No.",
        "Clinical content included: No.",
        "Staff identifiers included: No.",
        "Client identifiers included: No.",
        "Patient identifiers included: No.",
    ])

    return {
        "id": "client_transparency_evidence",
        "title": "Client transparency evidence",
        "body": _CLIENT_TRANSPARENCY_EVIDENCE_NOTE,
        "bullets": bullets,
        # Explicit boolean flags so a downstream consumer can drive
        # rendering / Trust Pack export logic without parsing bullet
        # text.
        "active_profile_exists": active_exists,
        "published_version_exists": published_exists,
        "raw_content_included": False,
        "clinical_content_included": False,
        "staff_identifiers_included": False,
        "client_identifiers_included": False,
        "patient_identifiers_included": False,
    }


def _build_evidence_sections(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        _build_learning_evidence_section(snapshot),
        _build_governance_policy_evidence_section(snapshot),
        _build_staff_attestation_section(snapshot),
        _build_self_assessment_evidence_section(snapshot),
        _build_client_transparency_evidence_section(snapshot),
        _build_assistant_receipt_evidence_section(snapshot),
    ]


def _build_pack_response(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    clinic_name = snapshot["clinic"]["clinic_name"]
    trust_state = snapshot["operations"]["trust_state"]
    policy_version = snapshot["governance"]["policy_version"]

    executive_summary = (
        f"{clinic_name} currently operates with ANCHOR as governance, trust, and learning infrastructure for safe AI use in veterinary settings. "
        "This pack is derived from metadata-only governance and operational evidence, with privacy-aware controls, governance receipts, "
        "tenant isolation safeguards, and staff enablement surfaces active."
    )

    sections: List[Dict[str, Any]] = [
        {
            "id": "cover",
            "title": "Executive summary",
            "body": executive_summary,
            "bullets": [
                f"Trust state: {trust_state}.",
                f"Active policy version: v{policy_version}.",
                "Generated from metadata-only evidence.",
            ],
        },
        {
            "id": "governance_controls",
            "title": "Governance controls",
            "body": (
                "ANCHOR provides governance-first oversight for AI use through policy versioning, governance receipts, "
                "metadata-only auditability, and operationally visible intervention signals."
            ),
            "bullets": [
                "Governance receipts active.",
                "Policy versioning active.",
                "Append-only override model.",
                "No raw prompt/output storage required for this surface.",
            ],
        },
        {
            "id": "privacy_data_handling",
            "title": "Privacy and data handling",
            "body": (
                "Trust reporting is generated without relying on stored raw prompts or outputs. Privacy-aware controls and hashed telemetry "
                "discipline support operational oversight while maintaining the metadata-only doctrine."
            ),
            "bullets": [
                "Metadata-only accountability.",
                "Privacy-aware controls active.",
                "Hashed IP / user-agent logging discipline.",
                "Raw prompt/output storage disabled in this trust surface.",
            ],
        },
        {
            "id": "tenant_platform_safeguards",
            "title": "Tenant and platform safeguards",
            "body": (
                "ANCHOR is designed around hard multi-tenancy and clinic-scoped access. Tenant isolation and request-scoped context are "
                "treated as platform-level safeguards rather than optional controls."
            ),
            "bullets": [
                "FORCE RLS posture in core tenant model.",
                "Request-scoped clinic context.",
                "Clinic-scoped portal access.",
                "Tenant isolation testing in operating model.",
            ],
        },
        {
            "id": "operational_assurance",
            "title": "Operational assurance",
            "body": (
                "Operational trust is summarised from recent governance and telemetry evidence, including intervention rates, privacy warnings, "
                "latency and error posture, and recent activity concentration."
            ),
            "bullets": [
                f"Recent intervention rate: {snapshot['operations']['intervention_rate_24h'] * 100.0:.1f}%.",
                f"Recent privacy warning rate: {snapshot['operations']['pii_warned_rate_24h'] * 100.0:.1f}%.",
                f"P95 latency (24h): {snapshot['operations']['p95_latency_ms']}ms.",
                f"Top mode (24h): {snapshot['operations']['top_mode_24h'] or '-'}.",
            ],
        },
        {
            "id": "learning_safe_adoption",
            "title": "Learning and safe adoption",
            "body": (
                "ANCHOR Learn supports safer institutional adoption through explainers, microlearning cards, and governance-linked learning "
                "reinforcement tied back to observed workflow patterns."
            ),
            "bullets": [
                "Explainers available.",
                "Microlearning cards available.",
                "Governance-to-learning tie-ins active.",
                f"Recommended learning focus: {snapshot['learning']['recommended_learning']['title']}.",
            ],
        },
    ]

    # ---------------------------------------------------------------------
    # Phase 2A-3.9B-1 - evidence closure sections.
    #
    # Reuses metadata-only aggregates already present on the snapshot
    # (governance_policy, self_assessment) plus conservative copy for
    # surfaces whose aggregates are not on the snapshot today (Learn /
    # CPD, Assistant receipt evidence) - those defer to the relevant
    # Trust posture sub-endpoints rather than introducing new SQL here.
    #
    # All sections are metadata-only. No raw policy body, no raw
    # self-assessment answers, no staff identifiers, no raw prompts /
    # outputs / clinical content.
    # ---------------------------------------------------------------------

    sections.extend(_build_evidence_sections(snapshot))

    sections.append(
        {
            "id": "artifact_basis",
            "title": "Artifact basis and limitations",
            "body": (
                "This trust pack is an operational leadership artifact. It "
                "summarises governance posture and safe adoption signals as "
                "readiness evidence. The clinic remains responsible for its "
                "own AI-use governance; this is not legal advice."
            ),
            "bullets": snapshot["limitations"],
        }
    )

    pack = {
        "artifact_type": "trust_pack",
        "artifact_version": "1.0",
        "generated_at": snapshot["generated_at"],
        "clinic_name": clinic_name,
        "trust_state": trust_state,
        "sections": sections,
        "evidence_window": snapshot["evidence_window"],
    }

    return {
        "generated_at": snapshot["generated_at"],
        "pack": pack,
        "snapshot": snapshot,
    }


def _build_materials_response(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    clinic_name = snapshot["clinic"]["clinic_name"]
    recommended_learning_title = snapshot["learning"]["recommended_learning"]["title"]

    materials: List[Dict[str, str]] = [
        {
            "id": "short_trust_statement",
            "title": "Short trust statement",
            "body": (
                f"{clinic_name} uses ANCHOR as governance, trust, and learning infrastructure for safe AI use in veterinary practice operations. "
                "ANCHOR provides metadata-only oversight, governance receipts, privacy-aware controls, and operational trust visibility."
            ),
        },
        {
            "id": "website_paragraph",
            "title": "Website / brochure paragraph",
            "body": (
                f"{clinic_name} uses ANCHOR to support safe and accountable use of AI in veterinary clinic workflows. "
                "The platform is governance-first and designed around metadata-only accountability, privacy-aware controls, tenant isolation, "
                "and trust surfaces that help leadership oversee operational AI use without relying on stored raw prompts or outputs."
            ),
        },
        {
            "id": "responsible_ai_operations",
            "title": "Responsible AI operations summary",
            "body": (
                "Our approach to AI use is governance-led. We use operational safeguards including policy versioning, governance receipts, "
                "privacy-aware controls, and oversight signals that help us monitor safe use, identify friction, and support responsible adoption."
            ),
        },
        {
            "id": "privacy_handling",
            "title": "Privacy handling statement",
            "body": (
                "Our trust reporting is generated from metadata-only governance and operational signals. "
                "This allows oversight and accountability while reducing reliance on stored raw prompts or outputs in the trust surface."
            ),
        },
        {
            "id": "safe_adoption_enablement",
            "title": "Safe adoption / staff enablement statement",
            "body": (
                "We combine governance controls with staff enablement. ANCHOR Learn provides explainers, learning cards, and governance-linked "
                "reinforcement so AI use can be introduced with clearer accountability, safer habits, and stronger operational understanding."
            ),
        },
        {
            "id": "leadership_faq",
            "title": "Leadership FAQ support line",
            "body": (
                "What helps make this operationally trustworthy? A governance-first model, metadata-only oversight, tenant isolation safeguards, "
                "governance receipts, and active staff learning support."
            ),
        },
        {
            "id": "procurement_support",
            "title": "Procurement / partnership support line",
            "body": (
                "ANCHOR is positioned as governance, trust, and learning infrastructure for safe AI use in veterinary clinics, rather than as a "
                f"clinical decision-making system. Current reinforcement focus: {recommended_learning_title}."
            ),
        },
    ]

    notes: List[str] = [
        "Use these materials as operational trust language, not as legal certification language.",
        "Avoid claims of formal compliance, certification, or guaranteed safety unless separately evidenced.",
        "Keep the framing governance-first and non-clinical.",
    ]

    return {
        "generated_at": snapshot["generated_at"],
        "materials": materials,
        "notes": notes,
        "snapshot": snapshot,
    }


@router.get("/profile")
def trust_profile(
    ctx: Any = Depends(require_clinic_user),
) -> Dict[str, Any]:
    snapshot = _build_snapshot_for_ctx(ctx)
    return {
        "clinic_name": snapshot["clinic"]["clinic_name"],
        "clinic_slug": snapshot["clinic"]["clinic_slug"],
        "trust_state": snapshot["operations"]["trust_state"],
        "policy_version": snapshot["governance"]["policy_version"],
        "governance_receipts_active": snapshot["governance"]["governance_receipts_active"],
        "privacy_controls_label": snapshot["privacy"]["privacy_controls_label"],
        "metadata_only_accountability": snapshot["governance"]["metadata_only_accountability"],
        "stores_raw_content": snapshot["governance"]["stores_raw_content"],
        "events_24h": snapshot["operations"]["events_24h"],
        "interventions_24h": snapshot["operations"]["interventions_24h"],
        "intervention_rate_24h": snapshot["operations"]["intervention_rate_24h"],
        "pii_warned_24h": snapshot["operations"]["pii_warned_24h"],
        "pii_warned_rate_24h": snapshot["operations"]["pii_warned_rate_24h"],
        "top_mode_24h": snapshot["operations"]["top_mode_24h"],
        "top_route_24h": snapshot["operations"]["top_route_24h"],
        "generated_at": snapshot["generated_at"],
        "snapshot": snapshot,
    }


@router.get("/posture")
def trust_posture(
    ctx: Any = Depends(require_clinic_user),
) -> Dict[str, Any]:
    snapshot = _build_snapshot_for_ctx(ctx)
    return _build_posture_response(snapshot)


@router.get("/pack")
def trust_pack(
    ctx: Any = Depends(require_clinic_user),
) -> Dict[str, Any]:
    snapshot = _build_snapshot_for_ctx(ctx)
    return _build_pack_response(snapshot)


@router.get("/materials")
def trust_materials(
    ctx: Any = Depends(require_clinic_user),
) -> Dict[str, Any]:
    snapshot = _build_snapshot_for_ctx(ctx)
    return _build_materials_response(snapshot)


# ---------------------------------------------------------------------
# Phase 2A-1 - Learning evidence delta (aggregate metadata only)
# ---------------------------------------------------------------------
#
# Aggregates only. No per-user data is surfaced here. completion_rate_by_role
# is keyed on the repo's ACCESS-CONTROL role (admin/staff) - the only role data
# that exists for users. Clinical roles (vet, nurse, ...) live solely as module
# audience metadata and are deliberately NOT invented as user attributes.
def _build_learning_delta(db: Session) -> TrustPackLearningDelta:
    staff_with_completions = int(
        db.execute(
            text(
                "SELECT COUNT(DISTINCT user_id) AS c FROM learning_completions "
                "WHERE is_voided = false"
            )
        ).scalar()
        or 0
    )
    total_minutes = int(
        db.execute(
            text(
                "SELECT COALESCE(SUM(cpd_minutes_credited), 0) AS c "
                "FROM learning_completions WHERE is_voided = false"
            )
        ).scalar()
        or 0
    )
    bias_detection_completions = int(
        db.execute(
            text(
                "SELECT COUNT(*) AS c FROM learning_completions lc "
                "JOIN learning_modules m ON m.module_id = lc.module_id "
                "WHERE lc.is_voided = false AND m.category = 'bias_detection'"
            )
        ).scalar()
        or 0
    )
    module_catalogue_count = int(
        db.execute(
            text(
                "SELECT COUNT(*) AS c FROM learning_modules WHERE is_active = true"
            )
        ).scalar()
        or 0
    )
    last_completion_at = db.execute(
        text(
            "SELECT MAX(completed_at) AS c FROM learning_completions "
            "WHERE is_voided = false"
        )
    ).scalar()

    role_rows = db.execute(
        text(
            """
            SELECT cu.role AS role,
                   COUNT(DISTINCT cu.user_id) AS total_users,
                   COUNT(DISTINCT lc.user_id) AS users_with_completions
            FROM clinic_users cu
            LEFT JOIN learning_completions lc
              ON lc.user_id = cu.user_id AND lc.is_voided = false
            GROUP BY cu.role
            """
        )
    ).mappings().all()

    completion_rate_by_role: Dict[str, float] = {}
    for r in role_rows:
        total_users = int(r["total_users"] or 0)
        with_completions = int(r["users_with_completions"] or 0)
        rate = round(with_completions / total_users, 4) if total_users else 0.0
        completion_rate_by_role[str(r["role"])] = rate

    return TrustPackLearningDelta(
        total_staff_with_completions=staff_with_completions,
        total_cpd_minutes_delivered=total_minutes,
        completion_rate_by_role=completion_rate_by_role,
        bias_detection_completions=bias_detection_completions,
        module_catalogue_count=module_catalogue_count,
        last_completion_at=last_completion_at,
    )


@router.get("/posture/learning-delta", response_model=TrustPackLearningDelta)
def trust_posture_learning_delta(
    ctx: Any = Depends(require_clinic_user),
) -> TrustPackLearningDelta:
    clinic_id, clinic_user_id = _ctx_ids(ctx)
    with SessionLocal() as db:
        try:
            set_rls_context(db, clinic_id=clinic_id, user_id=clinic_user_id)
            return _build_learning_delta(db)
        finally:
            try:
                clear_rls_context(db)
            except Exception:
                pass
