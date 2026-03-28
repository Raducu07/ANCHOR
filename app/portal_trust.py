# app/portal_trust.py
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import SessionLocal, set_rls_context, clear_rls_context
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
                f"Top mode (24h): {snapshot['operations']['top_mode_24h'] or '—'}.",
                f"Top route (24h): {snapshot['operations']['top_route_24h'] or '—'}.",
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
                f"Top mode (24h): {snapshot['operations']['top_mode_24h'] or '—'}.",
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
        {
            "id": "artifact_basis",
            "title": "Artifact basis and limitations",
            "body": (
                "This trust pack is an operational leadership artifact. It summarises governance posture and safe adoption signals but should not "
                "be presented as a legal certification or formal compliance attestation."
            ),
            "bullets": snapshot["limitations"],
        },
    ]

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
