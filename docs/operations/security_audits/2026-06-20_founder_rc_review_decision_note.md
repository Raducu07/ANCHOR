# Founder RC Review Decision Note — 2026-06-20

> **Founder / product-owner review note.** Documentation only. Internal RC review status recorded. **Not final commercial release.** Not legal advice, not solicitor review, not compliance certification, not RCVS / regulator approval, and **not authorisation** for paid pilots, real clinic data, clinic onboarding, live Workspace generation, Anthropic production subprocessor activation, Stripe / billing, external connectors, solicitor-approved claims, or compliance / certification / regulator-endorsement claims.
>
> ANCHOR is **aligned, not compliant** — not RCVS-approved, not regulator-endorsed, not certified. Live Workspace generation **remains production-off**.

## 1. Status

- Founder / product-owner review note.
- Documentation-only.
- Internal RC review status recorded.
- Not final commercial release.
- Not authorisation for paid pilots, real clinic data, clinic onboarding, live generation, Stripe / billing, connectors, solicitor-approved claims, compliance / certification claims, RCVS approval, or regulator endorsement.

This note records the founder / product-owner review decision taken after the RC sign-off readiness checklist ([`2026-06-20_rc_signoff_readiness_checklist.md`](./2026-06-20_rc_signoff_readiness_checklist.md), committed as `6f0ca99`). It is a decision / status note, **not** a release approval and grants no authority that did not already exist.

## 2. Decision

**Founder decision: proceed to internal RC review status, not commercial release.**

- ANCHOR is internally coherent and **ready for internal RC review / controlled founder demonstration using demo / test data only**.
- ANCHOR is **not yet commercially released** and is **not approved** for paid pilots, real clinic data, production live Workspace generation, billing, connectors, or customer onboarding.

## 3. Product boundary

ANCHOR is governance, trust, learning, intelligence, and readiness infrastructure for responsible AI use in veterinary clinics.

ANCHOR is **not**:

- diagnostic AI,
- prescribing AI,
- treatment-planning AI,
- autonomous clinical decision-making AI,
- autonomous triage,
- an ambient scribe,
- an EHR / PMS,
- clinical decision-support software,
- a GPAI model provider,
- RCVS-approved software,
- regulator-approved software,
- compliance certification,
- a replacement for veterinary judgement.

## 4. Evidence reviewed

The decision is based on the following evidence (recorded in this repository and the `anchor-portal` frontend repository / RC artefacts):

- RC sign-off readiness checklist committed as `6f0ca99` ([`2026-06-20_rc_signoff_readiness_checklist.md`](./2026-06-20_rc_signoff_readiness_checklist.md)).
- Frontend RC polish checkpoint committed as `1c6ba5b` in the frontend repository.
- Frontend production branch `anchor-portal-master` reached `29f72de` for the checkpoint and `0945916` for the marketing metadata deploy evidence.
- Frontend polish commits included Dashboard discoverability, SideNav order, the Assistant dashboard action, and marketing canonical metadata.
- Backend operational resilience checkpoint exists ([`2026-06-08_operational_resilience_checkpoint.md`](./2026-06-08_operational_resilience_checkpoint.md)).
- Dependency / CVE remediation and clean audit state recorded (CI `pip-audit` PASS for the scanned locked dependency set).
- Render deploy smoke evidence recorded previously (multiple PASS deploy / smoke records).
- `/v1/version` `git_sha` observability closed (`GIT_SHA` → `RENDER_GIT_COMMIT` fallback; production `git_sha` confirmed non-null).
- Legal / commercial founder-preparation pack exists (founder / solicitor-preparation outlines only).
- Solicitor handoff preparation exists ([`../commercial/2026-06-15_solicitor_handoff_preparation_pack.md`](../commercial/2026-06-15_solicitor_handoff_preparation_pack.md)).
- RC coherence closure exists ([`2026-06-16_rc_coherence_closure.md`](./2026-06-16_rc_coherence_closure.md)).
- Phase 2B AI tool governance alignment note exists, but **Phase 2B remains future / gated**.

## 5. What this decision allows

This decision allows **only**:

- internal founder review,
- demo / test-data walkthroughs,
- continued evidence review,
- preparation of solicitor / security / demo materials,
- controlled non-customer product inspection **without real clinic data**,
- further documentation / checklist hardening.

## 6. What this decision does not allow

This decision does **not** allow any of the following:

- paid pilot,
- real clinic data,
- real client / patient data,
- production live Workspace generation,
- Anthropic production subprocessor activation,
- Stripe / billing activation,
- external connectors,
- ambient transcript ingestion,
- customer onboarding,
- public compliance claims,
- RCVS / regulator-approved claims,
- GDPR / EU AI Act compliance claims,
- claims that receipts prove clinical correctness, patient safety, or competence.

## 7. Open gates before commercial / pilot use

All of the following must be satisfied and recorded before any commercial / pilot use:

- [ ] Solicitor review complete and recorded.
- [ ] Final legal terms / DPA / privacy / AUP / pilot agreement approved.
- [ ] Subprocessor position approved, including Anthropic if live generation or AI-provider routing is enabled.
- [ ] Operational backup/restore and incident-response evidence confirmed current.
- [ ] Support / security contact routes confirmed.
- [ ] Founder pilot approval checklist completed.
- [ ] Clinic onboarding procedure approved.
- [ ] Live generation safety gate passed before any production live generation.
- [ ] Production smoke after any app-behaviour deploy.
- [ ] Demo / test-data discipline maintained until approval.

## 8. Current hard stops

The following remain blocked unless a future dated approval artefact explicitly unlocks them:

- paid pilots,
- real clinic data,
- live generation,
- billing,
- connectors,
- ambient integrations,
- customer onboarding,
- compliance / certification / regulator-approval claims.

## 9. Deferred items

Non-blocking deferred items recorded for completeness:

- AppShell font warning.
- Broad visual redesign.
- TopBar avatar.
- M4.6 Learn maturity.
- M6.12 vendor-neutral connector layer.
- M6.13 ambient governance integration.
- M6-S sustainability module.
- Phase 2B AI Tool Governance Notes implementation.

## 10. Recommended next action

The next recommended action is **controlled founder review of the RC evidence pack** and, if accepted, a later **separate final internal RC sign-off artefact**. **Do not proceed directly to commercial release.**

## 11. Cross-references

- [`2026-06-20_rc_signoff_readiness_checklist.md`](./2026-06-20_rc_signoff_readiness_checklist.md) — RC sign-off readiness checklist (`6f0ca99`).
- [`2026-06-16_2a_d_current_status_checkpoint.md`](./2026-06-16_2a_d_current_status_checkpoint.md) — 2A-D current status checkpoint.
- [`2026-06-16_rc_coherence_closure.md`](./2026-06-16_rc_coherence_closure.md) — RC coherence lane closure.
- [`2026-06-08_operational_resilience_checkpoint.md`](./2026-06-08_operational_resilience_checkpoint.md) — operational resilience checkpoint.
- [`../commercial/2026-06-15_solicitor_handoff_preparation_pack.md`](../commercial/2026-06-15_solicitor_handoff_preparation_pack.md) — solicitor handoff preparation pack.
