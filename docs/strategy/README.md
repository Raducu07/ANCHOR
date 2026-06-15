# ANCHOR Strategy Artefacts

This directory holds internal **strategy / design** artefacts for future ANCHOR governance, evidence, connector, and trust-surface work. They exist to let future work be scoped deliberately rather than guessed.

These documents are **documentation only**. They **do not authorise** product implementation, pilots, paid use, real clinic data, external connectors, live Workspace generation, or public compliance claims. Nothing in this directory moves a gated future milestone into active build.

## Doctrine / non-claims

- ANCHOR is **governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics**.
- ANCHOR is **not** clinical decision-making AI, diagnostic AI, prescribing AI, treatment-planning AI, autonomous triage, an ambient scribe, an EHR/PMS, a GPAI provider, a compliance guarantee, a certified system, or a regulator-approved product.
- ANCHOR is **aligned, not compliant**: not RCVS-approved, not GDPR-certified, not EU AI Act-compliant, not regulator-endorsed, and carrying no protection from enforcement.
- Metadata-only by default. Live Workspace generation remains production-off.

## Current artefacts

- [`2026-06-11_anchor_ai_governance_receipt_schema_v0_1.md`](./2026-06-11_anchor_ai_governance_receipt_schema_v0_1.md) — Canonical future-facing evidence schema for governed AI-use records across native ANCHOR capture, future runtime/feed integrations, declared-use records, and ambient/ad hoc wrappers.
- [`2026-06-15_anchor_receipt_schema_gap_analysis_v0_1.md`](./2026-06-15_anchor_receipt_schema_gap_analysis_v0_1.md) — Comparison of the schema v0.1 against the live Class A ANCHOR receipt / governance / Trust Pack implementation.

## Current status

- **Native ANCHOR Class A receipt evidence exists** — implemented today (`assistant_run_receipts` and the governance / Trust Pack surfaces).
- **Evidence-source classes B–E are future / gated** — verified external runtime/feed, imported artefact, declared-use/manual attestation, and unverified narrative are not implemented.
- **Evidence-strength grading is a future design / implementation item** — Strong / Moderate / Limited / Weak grading is **not implemented**.
- **No external runtime ingestion is live** — there is no connector to any external runtime, scribe, EHR/PMS-adjacent system, or AI tool.
- **No connector capability should be claimed** — until one is built, tested, and evidence-graded.

## Roadmap relationship

- These artefacts support **2A-D strategy / release-candidate hardening**.
- They prepare — but do not start — future **M6.12 vendor-neutral connector layer**, **M6.13 ambient governance integration**, **Phase 2B AI Tool Governance Notes**, and future **insurer / procurement packs**.
- They do **not** move any of those future milestones into active build. M6.12 / M6.13 remain gated future and require an explicit founder decision recorded in an addendum.

## How to use these documents

- **Use them** when designing future receipt fields, evidence-strength display, connector ingestion, ambient-governance wrappers, or Trust Pack evidence language.
- **Do not use them** as proof that ANCHOR currently ingests external runtime logs — it does not.
- **Do not use them** for public compliance, certification, RCVS-approval, or regulator-endorsement claims.

## Next action

- Keep these as **strategy documentation** until the founder explicitly authorises an implementation brief.
- Any future implementation should start with a **scoped design brief for evidence-source class and evidence-strength grading** — not connector code.

## Related

- Operations runbooks and operational evidence trail: [`../operations/`](../operations/).
- Commercial / legal readiness outlines: [`../commercial/`](../commercial/).
- Canonical doctrine (roadmap, readiness map, decision memo addendum): [`../canonical/`](../canonical/). For any wording that will appear on a clinic-facing surface, check the Readiness Map (`ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md §2`) first.

This directory does not claim ANCHOR is secure, compliant, certified, vulnerability-free, RCVS-approved, regulator-endorsed, or commercially ready.
