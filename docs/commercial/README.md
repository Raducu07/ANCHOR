# ANCHOR Commercial / Legal Readiness Docs

> **Internal preparation only.** These documents are founder-side readiness outlines for the eventual paid-pilot / real-clinic-data conversation. **They are not legal advice.** **They are not finalised contracts.** **They do not authorise paid pilots or real clinic data.** Every document in this directory requires solicitor / legal-adviser review before any version of it is used externally.
>
> ANCHOR is **governance, trust, learning, intelligence, and accountability infrastructure** for safe AI use in veterinary clinics — **not clinical decision-making AI**. ANCHOR is **aligned with** professional governance expectations, **not certified against** them, **not RCVS-approved**, **not regulator-endorsed**. Live Workspace generation **remains production-off**. No paid pilot / no real clinic data is authorised by anything in this directory.

## Purpose

This directory collects the commercial / legal readiness outlines that the founder needs in place before a paid-pilot conversation can be binding. Operational evidence lives in `../operations/`; canonical doctrine lives in `../canonical/`; this directory is the commercial-readiness counterpart.

## Disclaimer

- **Not legal advice.** Nothing in this directory is, or substitutes for, legal counsel.
- **Internal prep only.** Every document is an outline / draft for solicitor handoff, not a finished artefact.
- **Solicitor review required** before any document is shared with a clinic, advisor, or third party.
- **No authorisation.** Existence of an outline here does **not** authorise a pilot, a clinic onboarding, or the acceptance of real clinic data.
- **Boundary preservation.** Every document must preserve the ANCHOR positioning boundaries (governance infrastructure, not clinical AI; aligned-not-compliant; no RCVS approval claimed; no regulator endorsement claimed; metadata-only governance).

## Current artefacts

- [`2026-06-08_privacy_data_boundary_outline.md`](./2026-06-08_privacy_data_boundary_outline.md) — **Privacy & Data Boundary Outline v1.** Internal founder / solicitor-preparation outline defining ANCHOR's intended privacy and data-boundary posture before any pilot. **Pre-legal review.** Restates the metadata-only core principle and ANCHOR positioning boundaries; maps 16 product data zones (auth, tenancy, governance events/receipts, telemetry, policies/attestations, Learn/CPD, Trust Pack, self-assessment, transparency layer, incident/near-miss, public intake, Workspace source/output, live Workspace generation, Assistant/provider integration, exports) to intended types, content boundaries, and current pilot status; enumerates what may and may not be collected by default; explains "metadata-only governance" (governance facts, not raw clinical content); records zone-specific boundaries (Workspace, transparency, incident, Learn/CPD, Trust Pack, public intake); references existing operational runbooks (`intake_retention.md`, `backup_restore.md`, `incident_response.md`); outlines subprocessor / hosting boundary (Render + Render Postgres active; Anthropic gated by live-generation production-off; GitHub not a clinic-data store; payment/email providers future/not active); enumerates clinic/user responsibilities, prohibited data before pilot approval, future changes requiring separate approval, and external-wording requirements; carries founder approval checklist and the standing hard stop conditions. **Status:** outline only; **must inform** the future DPA, Privacy Notice, Terms of Service, Pilot Agreement, Acceptable Use Policy, and Clinic Onboarding Checklist drafts. **No pilot / real clinic data authorised.**
- [`2026-06-08_legal_commercial_pack_outline.md`](./2026-06-08_legal_commercial_pack_outline.md) — **Legal & Commercial Pack Outline v1.** Internal founder readiness outline. Defines the documents required before paid pilots / real clinic data / commercial onboarding: Pilot Agreement, DPA, Privacy Notice, Terms of Service, Acceptable Use Policy, AI Governance Boundary Statement, Data Retention and Deletion Statement, Incident and Support Process Statement, Security and Operational Posture Summary, Commercial Order Form, Pricing / VAT / invoicing note, Cancellation / exit process, Support SLA, Clinic onboarding checklist, Internal founder approval checklist. Status: every required document is **`Required — not finalised`** or **`Draft outline only`**. Reaffirms hard stop conditions (no paid pilot, no real clinic data, no compliance / certification / RCVS / regulator claims, no clinical decision-making positioning, no live Workspace generation in production, no bypassing backup / retention / incident-response procedures, no destructive retention outside the approved runbook). Lists recommended follow-up outlines.

## Planned follow-up outlines

To be drafted in subsequent dated artefacts (outline first, solicitor review next, "draft" promotion only after solicitor input):

1. `pilot_agreement_outline.md`
2. `dpa_outline.md`
3. `privacy_data_boundary.md`
4. `acceptable_use_policy_outline.md`
5. `commercial_order_form_outline.md`
6. `clinic_onboarding_checklist.md`
7. `founder_pilot_approval_checklist.md`

## Cross-references

- Operations runbooks and operational evidence trail: [`../operations/`](../operations/).
- Founder-facing status summary: [`../operations/2026-06-08_founder_status_summary.md`](../operations/2026-06-08_founder_status_summary.md).
- Operational resilience checkpoint: [`../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md`](../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md).
- Canonical doctrine (roadmap, readiness map, decision memo addendum): [`../canonical/`](../canonical/). For any wording that will appear on a clinic-facing surface, check the Readiness Map (`ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md §2`) first.

This directory does not claim ANCHOR is secure, compliant, certified, vulnerability-free, RCVS-approved, regulator-endorsed, or commercially ready.
