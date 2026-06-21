# Solicitor / External Review Handoff Pack v2 — 2026-06-21

> **Documentation-only review handoff pack.** Prepared for founder / solicitor / external reviewer orientation. **Not legal advice. Not final legal terms. Not commercial release. Not paid pilot approval. Not real clinic data approval. Not customer onboarding approval. Not live generation approval. Not billing / Stripe approval. Not connector approval. Not compliance / certification / regulator approval.**
>
> ANCHOR is **aligned, not compliant** — not RCVS-approved, not regulator-endorsed, not certified, no protection from enforcement. Metadata-only by default. Live Workspace generation **remains production-off**. This pack **prepares** material for review; it **decides** nothing and **authorises** nothing.

---

## 1. Title

**Solicitor / External Review Handoff Pack v2 — 2026-06-21**

This is the v2 successor to the [Solicitor Handoff Preparation Pack v1](./2026-06-15_solicitor_handoff_preparation_pack.md). It reflects ANCHOR's current internally signed-off release-candidate (RC) state and gives a reviewer a concise map of what ANCHOR is, what it is not, what evidence exists, what remains blocked, and which questions need legal / security / commercial review. It does not duplicate the full text of the underlying outlines; it points to them.

## 2. Status

- Documentation-only review handoff pack.
- Prepared for founder / solicitor / external reviewer orientation.
- **Not** legal advice.
- **Not** final legal terms.
- **Not** commercial release.
- **Not** paid pilot approval.
- **Not** real clinic data approval.
- **Not** customer onboarding approval.
- **Not** live generation approval.
- **Not** billing / Stripe approval.
- **Not** connector approval.
- **Not** compliance / certification / regulator approval.

Nothing in this pack is solicitor-reviewed or solicitor-approved. The founder remains the decision-maker on commercial and product risk; the solicitor / external reviewer advises and drafts.

## 3. Current ANCHOR state

ANCHOR has passed **final internal RC sign-off for controlled founder / internal review and demo / test-data demonstration only**. This is an internal review milestone; it is explicitly **not** a statement that ANCHOR is release-ready, clinic-ready, pilot-ready, commercially ready, compliant, certified, safe, approved, RCVS-approved, or regulator-approved.

Reference evidence (recorded in this repository and cross-referenced from the `anchor-portal` frontend repository):

- **Final internal RC sign-off note** — `00fd492` ([`../operations/security_audits/2026-06-21_final_internal_rc_signoff_note.md`](../operations/security_audits/2026-06-21_final_internal_rc_signoff_note.md)).
- **Founder RC review decision note** — `576c216` ([`../operations/security_audits/2026-06-20_founder_rc_review_decision_note.md`](../operations/security_audits/2026-06-20_founder_rc_review_decision_note.md)).
- **RC sign-off readiness checklist** — `6f0ca99` ([`../operations/security_audits/2026-06-20_rc_signoff_readiness_checklist.md`](../operations/security_audits/2026-06-20_rc_signoff_readiness_checklist.md)).
- **Frontend screenshot / demo evidence** — `5cc03f1` (public screenshots refreshed), `bbeff48` (screenshot refresh checkpoint), `78c5524` (demo / walkthrough QA checkpoint), `6bda6e9` (`anchor-portal-master` production branch merge). These are recorded in the `anchor-portal` repository and cross-referenced here only.

The product remains:

- **pre-commercial**,
- **pre-pilot**,
- **pre-real-clinic-data**,
- **production live-generation-off**,
- **connector-off**,
- **billing-off**.

## 4. One-paragraph product description

ANCHOR is governance, trust, learning, intelligence, and readiness infrastructure for responsible AI use in veterinary clinics. It helps clinic teams evidence responsible AI-use practices through metadata-only governance records, human-review visibility, learning evidence, transparency surfaces, self-assessment, incident / near-miss logging, and trust posture. It is metadata-only by default (no raw prompts, outputs, drafts, transcripts, or clinical content stored; hashes only), human-review based, receipt-backed, multi-tenant and privacy-aware, standalone now and architected for integration later.

## 5. Product boundary

ANCHOR is **not**:

- diagnostic AI,
- prescribing AI,
- treatment-planning AI,
- autonomous clinical decision-making AI,
- autonomous triage,
- an ambient scribe,
- an EHR / PMS,
- clinical decision-support software,
- a GPAI (general-purpose AI) model provider — ANCHOR is a downstream integrator only,
- RCVS-approved software,
- regulator-approved software,
- compliance certification,
- a replacement for veterinary judgement.

## 6. Current evidence pack map

The following evidence exists and is available for review. Completion means *internal RC-hardening evidence exists*, not external approval, and not a security / compliance guarantee.

- **Operational resilience evidence** — dependency / reproducibility chain, deploy smokes, and observability consolidated ([`../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md`](../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md)).
- **Dependency / CVE clean audit state** — CI `pip-audit` PASS for the scanned locked dependency set (absence of known vulnerabilities at scan time, not a security guarantee).
- **Docker base digest pin** — `python:3.11-slim@sha256:a3ab0b96…49ac0` (mutable tag replaced by an immutable index digest).
- **GitHub Actions SHA pinning** — all active-workflow `uses:` refs pinned to immutable commit SHAs.
- **Render deploy smoke evidence** — multiple PASS deploy / smoke records against `anchor-api-prod`.
- **`/v1/version` `git_sha` observability** — `GIT_SHA` → `RENDER_GIT_COMMIT` fallback; production `git_sha` confirmed non-null.
- **RC coherence closure** — Trust Pack Assistant-receipt source-of-truth aggregate (metadata-only / counts-only) deployed and smoked ([`../operations/security_audits/2026-06-16_rc_coherence_closure.md`](../operations/security_audits/2026-06-16_rc_coherence_closure.md)).
- **RC sign-off readiness checklist** — `6f0ca99` (see §3).
- **Founder RC review decision** — `576c216` (see §3).
- **Final internal RC sign-off note** — `00fd492` (see §3).
- **Commercial / legal preparation pack** — full outline spine (Pilot Agreement, DPA, Privacy Notice, AUP, AI Governance Boundary, order form, onboarding checklist, founder approval checklist, etc.), all **founder / solicitor-preparation outlines only** ([`./README.md`](./README.md)).
- **Privacy / data boundary outline** — intended privacy and data-boundary posture across product data zones ([`./2026-06-08_privacy_data_boundary_outline.md`](./2026-06-08_privacy_data_boundary_outline.md)).
- **Personal data / data-flow inventory** — per-surface map of data flows and sub-processors ([`./2026-06-08_personal_data_data_flow_inventory.md`](./2026-06-08_personal_data_data_flow_inventory.md)).
- **Solicitor handoff preparation pack (v1)** — index + review brief + question list ([`./2026-06-15_solicitor_handoff_preparation_pack.md`](./2026-06-15_solicitor_handoff_preparation_pack.md)).
- **Public screenshot refresh evidence** — `5cc03f1`, `bbeff48` (frontend repository).
- **Demo / walkthrough QA checkpoint** — `78c5524`; no Critical / High / Medium findings; public visual mismatch gate closed (frontend repository).
- **Frontend RC polish checkpoint** — Dashboard-first navigation, Workspace / Assistant primary actions, governance & readiness surfacing (frontend repository).

## 7. Data boundary summary

ANCHOR is **metadata-only clinic-governance accountability by default**. Metadata-only narrows the privacy-risk surface; it does **not** mean *no personal data*.

Potential personal data may include: staff account details, reviewer attribution, learning / CPD completion metadata, policy attestations, governance event metadata, public-intake details, support / security contacts, and audit / admin logs. Several of these may be personal data under UK GDPR **even where no clinical content is involved** — the personal-data question is in scope the moment a real clinic admin signs up, not only when real clinical data is involved.

**Real clinic data and real client / patient data remain blocked** until legal / commercial / privacy gates are complete.

## 8. Current AI-provider / live-generation position

- Production live Workspace generation **remains off**.
- The current live-generation path, where developed, is **Anthropic-only and not enabled for production real clinic use**. Present-tense provider-neutrality is **not** claimed; ANCHOR is **architected for vendor-neutrality / vendor-neutral over time**.
- **No real clinic AI-provider routing is authorised by this handoff.**
- **Anthropic production subprocessor activation** for real clinic AI-provider routing **remains blocked** until legal / subprocessor approval and a live-generation safety gate (including the proven hard-refusal boundary on diagnosis / treatment / prescribing) are complete. Anthropic becomes a subprocessor the moment live generation is enabled — flag any change that would activate it.

## 9. Solicitor / legal review questions

- Are ANCHOR's proposed data roles (controller / processor / mixed, **by surface**) correctly framed for clinic use?
- Are metadata / governance records personal data in the expected scenarios, and how should they be treated in the DPA / privacy notice?
- What terms are needed before any paid pilot?
- What must the Pilot Agreement say about product boundaries and clinic responsibilities?
- What must the Acceptable Use Policy (AUP) prohibit?
- What privacy-notice wording is needed for public intake, clinic staff accounts, governance receipts, Learn / CPD evidence, incidents, and support / security contacts?
- What subprocessor wording is needed for hosting, email forwarding, analytics / database if used, and Anthropic if live generation is later enabled?
- What retention / deletion / offboarding language is required?
- What disclaimers are required around non-clinical AI, no diagnosis / prescribing / treatment planning, no autonomous decision-making, no compliance certification, and no regulator approval?
- What wording is needed before any testimonial, public claim, procurement response, or pilot invitation?

## 10. Security / operational review questions

- Is the operational resilience evidence adequate for controlled demo / test-data review?
- What additional evidence is required before real clinic data?
- Are backup / restore evidence, incident-response evidence, support / security routes, and vulnerability disclosure sufficient for the next gate?
- Are production smoke expectations adequate after app-behaviour deploys?
- Are the dependency / CVE audit and the lockfile / digest / Actions-pinning controls adequate for this stage?
- What security review should happen before external clinic access?

## 11. Commercial / pilot readiness questions

- What must be complete before a paid pilot?
- What pilot order form / pricing / VAT / invoice terms are needed? (Route VAT treatment to an accountant, not treated as legal advice.)
- What support expectations or SLA wording is appropriate for a founder-operated early product (best-effort, explicitly not a staffed desk / SLA / emergency channel)?
- What onboarding checklist must be completed before clinic access?
- What approval checklist must be signed before any real clinic data or paid pilot?

## 12. Hard stops

The following remain **blocked** unless and until a future dated approval artefact explicitly unlocks them:

- paid pilots,
- real clinic data,
- real client / patient data,
- customer onboarding,
- production live Workspace generation,
- Anthropic production subprocessor activation for real clinic AI-provider routing,
- Stripe / billing activation,
- external connectors,
- ambient transcript ingestion,
- compliance claims,
- certification claims,
- RCVS approval claims,
- regulator endorsement claims,
- claims that receipts prove clinical correctness, patient safety, staff competence, or clinical safety.

## 13. What reviewers may rely on

Reviewers may rely **only** on:

- the current internal RC sign-off for **controlled founder / internal review and demo / test-data demonstration only**;
- evidence that public screenshots and demo / walkthrough materials were refreshed / audited;
- evidence that backend operational resilience and dependency / security documentation exists;
- evidence that hard stops are documented and preserved.

## 14. What reviewers must not infer

Reviewers must **not** infer any of the following from the internal RC sign-off or from this pack:

- solicitor approval,
- legal terms finalised,
- privacy / DPA finalised,
- commercial release,
- paid pilot permission,
- real-data permission,
- clinical safety claim,
- regulatory approval,
- compliance / certification status,
- provider-neutral production operation,
- live-generation production approval.

## 15. Requested review output

The founder asks the solicitor / external reviewer to return:

- required amendments to legal / commercial documents,
- risk notes,
- missing documents,
- suggested wording changes,
- required approval gates before paid pilot or real clinic data,
- subprocessor / privacy / data-role position,
- any red flags that should block external access.

These are reviewer outputs; the founder then makes the commercial / product decisions.

## 16. Next recommended action

Send or prepare this pack for solicitor / external review together with the referenced evidence artefacts. **Do not proceed** to paid pilots, real clinic data, customer onboarding, live generation, billing, or connectors until the relevant gates are explicitly closed by future dated approval artefacts. Until then, every artefact referenced here remains internal founder / solicitor-preparation material only, and this pack authorises nothing.

## 17. Cross-references

- [`./2026-06-15_solicitor_handoff_preparation_pack.md`](./2026-06-15_solicitor_handoff_preparation_pack.md) — Solicitor Handoff Preparation Pack v1 (the document this v2 succeeds).
- [`./README.md`](./README.md) — commercial / legal readiness directory index and disclaimers.
- [`./2026-06-08_personal_data_data_flow_inventory.md`](./2026-06-08_personal_data_data_flow_inventory.md) — personal data / data-flow inventory.
- [`./2026-06-08_privacy_data_boundary_outline.md`](./2026-06-08_privacy_data_boundary_outline.md) — privacy & data boundary outline.
- [`../operations/security_audits/2026-06-21_final_internal_rc_signoff_note.md`](../operations/security_audits/2026-06-21_final_internal_rc_signoff_note.md) — final internal RC sign-off note (`00fd492`).
- [`../operations/security_audits/2026-06-20_founder_rc_review_decision_note.md`](../operations/security_audits/2026-06-20_founder_rc_review_decision_note.md) — founder RC review decision note (`576c216`).
- [`../operations/security_audits/2026-06-20_rc_signoff_readiness_checklist.md`](../operations/security_audits/2026-06-20_rc_signoff_readiness_checklist.md) — RC sign-off readiness checklist (`6f0ca99`).
- [`../operations/security_audits/2026-06-16_rc_coherence_closure.md`](../operations/security_audits/2026-06-16_rc_coherence_closure.md) — RC coherence lane closure.
- [`../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md`](../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md) — operational resilience checkpoint.
- Operative canon: [`../canonical/`](../canonical/) (Roadmap v2.6, Readiness Map v1.1, Decision Memo Addendum v1.3). For any clinic-facing wording, check Readiness Map v1.1 §2 first.
