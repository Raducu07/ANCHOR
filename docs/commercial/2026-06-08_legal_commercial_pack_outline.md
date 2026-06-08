# ANCHOR Legal & Commercial Pack Outline v1 — 2026-06-08

## 1. Purpose and status

- This document is an **internal founder readiness outline**.
- It defines the materials required before paid pilots, real clinic data, or commercial onboarding can be considered.
- **It is not legal advice.**
- **It is not a final legal pack.**
- It must be reviewed by an appropriate solicitor / legal adviser before any version of it is used with a clinic.
- **It does not authorise paid pilots.**
- **It does not authorise real clinic data.**
- It does not make ANCHOR compliant, certified, RCVS-approved, regulator-endorsed, or commercially ready by itself.
- It exists so the founder can see, at a glance, what has to be done — and who has to do it — before the paid-pilot conversation starts.

---

## 2. ANCHOR positioning boundaries

These boundaries must be preserved in every document drafted from this outline and in every conversation those documents support:

- ANCHOR is **governance, trust, learning, intelligence, and accountability infrastructure for safe AI use in veterinary clinics.**
- ANCHOR is **not clinical decision-making AI.**
- ANCHOR **does not replace professional judgement.**
- ANCHOR **does not diagnose, prescribe, triage, or recommend treatment.**
- ANCHOR **does not claim RCVS approval.**
- ANCHOR **does not claim regulator endorsement.**
- ANCHOR **does not claim certification or compliance by default.**
- ANCHOR is **aligned with** professional governance expectations, **not certified against** them.
- ANCHOR is a **downstream integrator only** — not a GPAI provider; Chapter V GPAI obligations do not apply.
- **Metadata-only governance accountability remains the default posture.**
- **Live Workspace generation remains production-off** until the local/staging safety gate and the hard-refusal harness pass on the live path.
- **Real clinic data and paid pilots remain gated** behind the documents listed below.

Any wording in any future pilot, DPA, ToS, marketing, or sales surface must not contradict this section.

---

## 3. Required legal / commercial documents before pilot

None of these exists in finalised form yet. All are required before a paid pilot or real clinic data can be discussed in a binding way.

| Document | Purpose | Owner / reviewer | Status | Notes |
|---|---|---|---|---|
| **Pilot Agreement** | Bilateral agreement governing the pilot relationship between ANCHOR and a clinic. | Founder + solicitor | **Required — not finalised** | Outline in §4. Must reference DPA + ToS by name. |
| **Data Processing Agreement (DPA)** | UK-GDPR Article 28 processor agreement; defines controller/processor roles, processing purpose, data categories, subprocessor list, security measures, retention/deletion, incident notification. | Founder + solicitor + (likely) clinic legal counsel | **Required — not finalised** | Outline in §5. Solicitor confirmation required on controller/processor role. |
| **Privacy Notice / Privacy Addendum** | Plain-English description of what ANCHOR collects, what it does not collect, what it stores, what it does not store, and how the clinic's responsibilities sit alongside ANCHOR's. | Founder + solicitor | **Required — not finalised** | Outline in §6. Must be linkable from clinic-facing surface. |
| **Terms of Service / SaaS Terms** | General platform terms (account, acceptable use, fair-use, suspension, termination, IP, liability framing) — the umbrella under which Pilot Agreement and DPA sit. | Founder + solicitor | **Required — not finalised** | Solicitor draft; this outline does not draft them. |
| **Acceptable Use Policy** | Boundary document — what ANCHOR may and may not be used for, with named prohibited uses (clinical diagnosis, prescribing, autonomous triage, ambient scribing, EHR replacement). | Founder + solicitor | **Required — not finalised** | Outline in §7. |
| **AI Governance Boundary Statement** | Standalone short statement reaffirming that ANCHOR is governance infrastructure, not clinical AI; not RCVS-approved; not regulator-endorsed; not certified; human review responsibility remains with the clinic. | Founder | **Required — not finalised** | Should be linkable from every clinic-facing surface and present in every pilot pack. |
| **Data Retention and Deletion Statement** | Public-facing summary of the metadata-only doctrine, the existing `intake_retention.md` runbook posture (dry-run, founder approval, `I-UNDERSTAND`, 50 000-row cap), and the exit-deletion process. | Founder + solicitor | **Required — not finalised** | Must not contradict the operational runbook. |
| **Incident and Support Process Statement** | Clinic-facing summary of the existing `incident_response.md` runbook in plain-English; defines what an incident is, how a clinic reports one, and how ANCHOR responds. | Founder | **Required — not finalised** | Should set deliberately modest support expectations. |
| **Security and Operational Posture Summary** | Plain-English summary of the operational evidence trail (lockfile, digest-pinned image, CI dependency audit PASS, deploy smoke evidence, backup/restore drill posture, retention dry-run posture, incident-response tabletop posture). | Founder | **Required — not finalised** | Must say "aligned, not compliant" and "not a security certification". |
| **Commercial Order Form / Pilot Order Form** | Per-pilot order form referencing the Pilot Agreement, DPA, ToS, and AUP; identifies clinic, named admin, pilot scope, pilot duration, fee/free status. | Founder + solicitor | **Required — not finalised** | Single page where practical. |
| **Pricing / VAT / invoicing note** | Internal pricing decision document; VAT position; invoice format; whether the first pilots are free / assisted / paid. | Founder (+ accountant if VAT-relevant) | **Required — not finalised** | Stripe or other payment provider not activated until pack is finalised. |
| **Cancellation / exit process** | What happens on pilot cancellation: notice period, billing handling, data export, data deletion evidence, evidence retention by ANCHOR for audit. | Founder + solicitor | **Required — not finalised** | Must align with DPA exit-deletion clauses. |
| **Support SLA / response-time statement** | Even if deliberately modest (e.g. "best-effort, business-hours response within N working days") — must be explicit and writable into the Pilot Agreement. | Founder | **Required — not finalised** | Do not overcommit; this is solo-operator infrastructure today. |
| **Clinic onboarding checklist** | Pre-go-live checklist for each clinic: documents signed, named admin in place, data-boundary expectations confirmed, founder approval recorded, smoke check, evidence capture. | Founder | **Required — not finalised** | See §10. |
| **Internal founder approval checklist** | Internal-only pre-onboarding sign-off; the founder's "do not cross this line without ticking these boxes" list. | Founder (self) | **Required — not finalised** | See §11. |

All entries above are status **`Required — not finalised`** or **`Draft outline only`** today. This row state is the gate.

---

## 4. Pilot Agreement outline

Outline only — not contractual language. A solicitor must draft the actual clauses.

The future Pilot Agreement should cover, at minimum:

- **Parties** — ANCHOR (legal entity TBC) and the pilot clinic; named clinic admin.
- **Pilot scope** — features made available; explicitly: governance review, policy library, attestations, transparency layer, incident/near-miss logging, learning/CPD, Trust Pack evidence; **explicitly excluding** clinical decision-making, ambient scribing, EHR replacement.
- **Pilot duration** — fixed term; explicit start and end dates; renewal-or-expiry default.
- **Pilot fee or free / assisted pilot status** — free, assisted, or paid; what's included.
- **Clinic eligibility** — minimum criteria (see §10).
- **Permitted users** — named clinic admin(s); user-management responsibility.
- **Permitted use** — see §7 Permitted.
- **Prohibited use** — see §7 Prohibited.
- **AI governance boundaries** — restatement of §2 inside the contract.
- **No clinical decision-making reliance** — explicit warranty by clinic that ANCHOR output is not used as the sole basis for any clinical decision.
- **Human review responsibility** — explicit allocation to the clinic.
- **Data categories allowed** — governance metadata; named-admin contact details; non-clinical content as defined.
- **Data categories prohibited** — identifiable patient records, clinical records, special-category data outside an explicitly approved process.
- **Metadata-only storage posture** — restatement of the doctrine.
- **Client / patient data handling expectations** — clinic-side responsibility; do-not-upload list.
- **Confidentiality** — standard mutual.
- **Support expectations** — reference to the Support SLA / response-time statement.
- **Incident reporting** — reference to the Incident and Support Process Statement.
- **Termination** — for cause, for convenience, on breach; notice periods.
- **Data deletion / return at exit** — what is deleted, what is retained for audit, what evidence is provided.
- **Limitation of liability** — to be drafted by solicitor.
- **Indemnity / insurance** — to be drafted by solicitor.
- **Governing law** — to be drafted by solicitor.

Do not draft legal clauses in this outline.

---

## 5. DPA / data processing outline

Outline only — solicitor must draft the binding agreement.

The future DPA should cover, at minimum:

- **Controller / processor role** — to be **legally confirmed**. ANCHOR's metadata-only posture argues for processor on most fields with controller-on-platform-account for admin/contact details; this needs solicitor confirmation.
- **Processing purpose** — governance, trust, learning, intelligence, accountability infrastructure as defined in §2.
- **Categories of data** — governance metadata, admin contact metadata; explicitly listed.
- **Data subject categories** — clinic staff using ANCHOR as named admins / users.
- **Metadata-only default posture** — restated.
- **Prohibited data** — patient records, identifiable client data, special-category data — until and unless a separate approved process exists.
- **Subprocessor list requirement** — the DPA must enumerate subprocessors (Render as hosting; Anthropic **only** if/when live Workspace generation is enabled in production, with notice obligation). Today there is no Anthropic processing of clinic data because live generation is production-off.
- **Security measures summary** — pointer to the Security and Operational Posture Summary (§3), without overclaiming.
- **Retention / deletion process** — pointer to `intake_retention.md` and the Data Retention and Deletion Statement.
- **Incident notification process** — defined notification window; pointer to `incident_response.md`.
- **International transfer assessment** — if relevant; Render region selection note.
- **Audit / information rights** — what the clinic can request; how ANCHOR responds.
- **Exit / deletion evidence** — operator-provided evidence at exit; format and timing.
- **Solicitor review required** before the DPA is shared with any clinic.

**Hard note: do not onboard real clinic data until the DPA position is reviewed and approved by a solicitor and the founder has explicitly authorised onboarding.**

---

## 6. Privacy and data boundary wording needed

Non-final wording requirements — the actual language must be drafted (and reviewed) before clinic use:

- **What ANCHOR collects.** Account/admin contact details; governance metadata generated during ANCHOR use (events, attestations, policy versions, receipt metadata, learning completions, exports).
- **What ANCHOR does not collect by default.** Raw prompts, raw model outputs, raw transcripts, raw clinical content, identifiable patient records.
- **What ANCHOR stores.** Hashes / metadata only for governance evidence; receipt metadata for governed interactions; admin audit events.
- **What ANCHOR does not store.** Raw content of the above; secrets are never persisted to evidence files.
- **What "metadata-only governance" means** in plain English — measurable, reviewable evidence without the underlying raw content.
- **What happens if a user submits personal data** — clinic responsibility; rejection / minimisation expectation; data-boundary doctrine.
- **Client-facing transparency boundary** — what the clinic can show clients about its AI use, and what is out of scope.
- **Clinic responsibility for source material** — original records remain in the clinic's own systems.
- **Human review responsibility** — restated.
- **No clinical decision-making reliance** — restated.

---

## 7. Acceptable use / prohibited use outline

### Permitted

- Governance review of AI use across the clinic.
- Policy acknowledgement and attestation by clinic staff.
- Client-facing transparency evidence.
- Incident / near-miss metadata logging.
- Learning / CPD evidence (CPD-Recordable AI Literacy).
- Trust Pack evidence packaging.
- Non-clinical operational governance workflows.

### Prohibited unless explicitly authorised later

- **Clinical diagnosis.**
- **Treatment recommendation.**
- **Emergency triage.**
- **Autonomous client communication** without human review.
- **Uploading unnecessary identifiable client / patient data.**
- **Uploading special-category or highly sensitive data** outside an approved process.
- **Using ANCHOR as a medical record system.**
- **Using ANCHOR as an ambient scribe.**
- **Using ANCHOR as a substitute for professional judgement.**

The Acceptable Use Policy should make breach a clear ground for suspension under the Pilot Agreement / ToS.

---

## 8. Commercial readiness checklist

- Pricing model chosen for pilot.
- Free vs paid pilot decision (assisted-pilot status considered).
- VAT position reviewed (with accountant if relevant).
- Invoicing / payment method chosen.
- Stripe / payment workflow, **if applicable, not activated until the pack is ready**.
- Refund / cancellation terms drafted.
- Support expectations defined and modest by intent.
- Founder approval required before any clinic is invited.
- **No sales copy can claim readiness beyond evidence.** Aligned-not-compliant wording is the default; any external statement is checked against `docs/canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md §2`.

---

## 9. Operational readiness dependencies

The following operational artefacts support readiness but **do not replace** legal / commercial review:

- **Backup / restore runbook and drill status** — `docs/operations/backup_restore.md`; first PASS drill recorded 2026-06-07.
- **Intake retention runbook and dry-run status** — `docs/operations/intake_retention.md`; first PASS dry-run recorded 2026-06-07; monthly pre-pilot cadence applies.
- **Incident response runbook and tabletop status** — `docs/operations/incident_response.md`; first tabletop (migration checksum mismatch) executed 2026-06-07; remaining scenarios pending.
- **Dependency / CVE audit PASS** for the locked scanned dependency set — `docs/operations/security_audits/2026-06-07_post_alembic_ci_audit.md` (CI run `#5` against `de966a9`).
- **Render deploy / smoke evidence** — `2026-06-08_render_deploy_smoke_cd9d966.md` and `2026-06-08_version_metadata_deploy_smoke_7451357.md`.
- **`/v1/version` runtime revision evidence** — `git_sha` now populated in production via `RENDER_GIT_COMMIT` fallback.
- **Operational resilience checkpoint** — `docs/operations/security_audits/2026-06-08_operational_resilience_checkpoint.md`.
- **Founder status summary** — `docs/operations/2026-06-08_founder_status_summary.md`.
- **Live Workspace generation production-off** — gate condition; must remain off until the local/staging safety gate and the hard-refusal harness pass on the live path.

These artefacts let the operator answer "what is the current operational posture?" honestly. They are **not** a substitute for solicitor-reviewed legal documents and **do not** authorise paid pilot, real clinic data, or commercial onboarding.

---

## 10. Pilot eligibility criteria

Minimum criteria for a future pilot clinic. A clinic that cannot meet any of these is not a pilot candidate, regardless of commercial appetite.

- **Understands ANCHOR is governance infrastructure, not clinical AI.**
- **Agrees human review remains mandatory** for any AI output referenced in any clinical-or-near-clinical context.
- **Agrees data boundary rules** in the DPA and Acceptable Use Policy.
- **Agrees no unnecessary personal data upload** (patient records, identifiable client data, special-category data).
- **Agrees incident reporting route** as defined in the Incident and Support Process Statement.
- **Has a named accountable user / admin** who signs on behalf of the clinic.
- **Accepts pilot limitations** (support window, feature scope, no clinical-decision-making reliance, no live Workspace generation in production).
- **Signs the required pack** before access (Pilot Agreement, DPA, AUP; ToS by acceptance).
- **Founder approves onboarding** explicitly per §11.

---

## 11. Founder approval checklist

To be ticked in writing before any clinic is invited to a pilot. Each box must be supported by a dated note or evidence reference.

- [ ] Pilot Agreement reviewed.
- [ ] DPA reviewed.
- [ ] Privacy / data boundary wording reviewed.
- [ ] Terms / SaaS terms reviewed.
- [ ] Pricing / VAT / invoicing reviewed.
- [ ] Support process reviewed.
- [ ] Incident process reviewed.
- [ ] Backup / restore confidence reviewed.
- [ ] Retention / deletion process reviewed.
- [ ] Workspace live generation remains **off** unless separately approved (and, if approved, only after the local/staging safety gate and hard-refusal harness pass on the live path).
- [ ] Clinic eligibility confirmed against §10.
- [ ] Founder explicitly authorises pilot (dated signed note).

Any unticked box is a hard stop.

---

## 12. Hard stop conditions

For the avoidance of doubt — these mirror and reaffirm the existing operational hard stops:

- **No paid pilot** before the legal / commercial pack is reviewed.
- **No real clinic data** before DPA / data boundary approval.
- **No sales claims of compliance, certification, RCVS approval, or regulator endorsement.**
- **No clinical decision-making positioning** in any external surface.
- **No live Workspace generation in production** until the local/staging safety gate and the hard-refusal harness pass on the live path.
- **No bypassing backup, retention, or incident-response procedures.**
- **No destructive retention outside the approved runbook** (dry-run first, founder approval, exact `I-UNDERSTAND` confirm literal, 50 000-row cap, evidence template).

---

## 13. Recommended next documents

The pack outline above is the index. The likely follow-up documents (to be drafted, solicitor-reviewed, then dated and filed under `docs/commercial/`):

1. `pilot_agreement_outline.md`
2. `dpa_outline.md`
3. `privacy_data_boundary.md`
4. `acceptable_use_policy_outline.md`
5. `commercial_order_form_outline.md`
6. `clinic_onboarding_checklist.md`
7. `founder_pilot_approval_checklist.md`

Each should start as an **outline-only internal draft**, carry the same disclaimer block as this document (not legal advice; requires solicitor review; does not authorise pilots or real clinic data), and be promoted from "outline" to "draft" only after solicitor input. Promotion from "draft" to "signed-ready" is a separate decision.

---

## 14. Non-actions in this patch

The following were **explicitly not done** in the creation of this outline:

- ❌ No code change.
- ❌ No test change.
- ❌ No dependency change.
- ❌ No Dockerfile change.
- ❌ No GitHub Actions workflow change.
- ❌ No migration change.
- ❌ No migrations run.
- ❌ No database query or mutation.
- ❌ No production endpoint call.
- ❌ No Render API call.
- ❌ No Render setting change.
- ❌ No deploy.
- ❌ No frontend change.
- ❌ No secret access.
- ❌ **No legal document finalised.** Every row in §3 is `Required — not finalised` or `Draft outline only`.
- ❌ **No pilot authorised.** The §11 founder approval checklist is entirely unticked.
- ❌ No commitment, claim, or representation made to any clinic, advisor, or regulator on the strength of this document.
- ❌ No commit. No push. (Per scope.)

What this outline **did** do: defined the materials required before paid pilots / real clinic data / commercial onboarding; restated ANCHOR's positioning boundaries that every downstream document must honour; enumerated the documents required, their owners, and their current status; outlined the shape of the Pilot Agreement, DPA, privacy / data boundary wording, acceptable use policy, commercial readiness, pilot eligibility criteria, and founder approval checklist; cross-referenced existing operational evidence; reaffirmed the hard stop conditions; listed the next documents to draft.
