# ANCHOR Solicitor Review Bundle Index v1 — 2026-06-08

## 1. Purpose and status

- This is an **internal founder / solicitor-review preparation index** for ANCHOR.
- It packages the current commercial / legal outlines and key operational evidence into one review map.
- It is intended to help a solicitor / legal adviser understand **what exists**, **what needs formal drafting**, and **what questions need legal advice**.
- **It is not legal advice.**
- **It is not a final legal pack.**
- **It is not a final clinic-facing document.**
- **It is not a contract.**
- **It is not Terms of Service.**
- **It is not a Pilot Agreement.**
- **It is not a DPA.**
- **It is not an Acceptable Use Policy.**
- **It is not an approved onboarding process.**
- **It does not authorise clinic access.**
- **It does not authorise pilots.**
- **It does not authorise paid pilots.**
- **It does not authorise real clinic data.**
- **It does not authorise live Workspace generation.**
- It does not make ANCHOR compliant, certified, RCVS-approved, regulator-endorsed, or commercially ready by itself.

---

## 2. Current review bundle contents

| Item | Path | Type | Review purpose | Status |
|---|---|---|---|---|
| Commercial README index | `docs/commercial/README.md` | Internal index | Orientation; per-artefact disclaimer; cross-references | Internal index; pre-legal review |
| Legal & Commercial Pack Outline v1 | `docs/commercial/2026-06-08_legal_commercial_pack_outline.md` | Internal outline | Full required document set (15 docs); founder approval workflow | Pre-legal review; not final |
| Privacy & Data Boundary Outline v1 | `docs/commercial/2026-06-08_privacy_data_boundary_outline.md` | Internal outline | Intended data boundaries; metadata-only doctrine; prohibited data; sub-processor posture | Pre-legal review; not final |
| DPA Outline v1 | `docs/commercial/2026-06-08_dpa_outline.md` | Internal outline | Data-processing structure: controller/processor model, processing purposes, data categories, sub-processors, international transfer, retention/deletion, incident notification, DPA schedule placeholders | Pre-legal review; not final |
| Pilot Agreement Outline v1 | `docs/commercial/2026-06-08_pilot_agreement_outline.md` | Internal outline | Pilot relationship boundary: scope, duration/phases, fee, eligibility, permitted/prohibited use, support/incident, retention/exit, suspension/termination | Pre-legal review; not final |
| Acceptable Use Policy Outline v1 | `docs/commercial/2026-06-08_acceptable_use_policy_outline.md` | Internal outline | Per-user behaviour boundaries: permitted use, prohibited clinical/communication/data-upload, account/tenant/security/governance misuse, consequences | Pre-legal review; not final |
| Clinic Onboarding Checklist v1 | `docs/commercial/2026-06-08_clinic_onboarding_checklist.md` | Internal outline | Practical pre-access process; onboarding modes; hard gates; module enablement; Day-0/Day-7/exit | Pre-legal review; not final; **not clinic-facing** |
| Founder Pilot Approval Checklist v1 | `docs/commercial/2026-06-08_founder_pilot_approval_checklist.md` | Internal outline | Final internal go / no-go decision record; 11 decision types; approval outcomes; re-approval triggers | Pre-legal review; not final; **internal-only** |
| Commercial / Legal Readiness Checkpoint v1 | `docs/commercial/2026-06-08_commercial_legal_readiness_checkpoint.md` | Internal outline | Founder-facing summary of the commercial/legal spine; readiness state; remaining work; recommended next decisions | Pre-legal review; not final; **internal-only** |
| Founder Status Summary | `docs/operations/2026-06-08_founder_status_summary.md` | Operational evidence (founder-facing) | Plain-English orientation note after the operational-resilience hardening chain | Internal-only; not clinic-facing |
| Operational Resilience Checkpoint | `docs/operations/security_audits/2026-06-08_operational_resilience_checkpoint.md` | Operational evidence | Engineering checkpoint summary across dependency / reproducibility / deploy-smoke / version-observability chain | Operational evidence; not legal pack |
| Backend environment reference | `docs/operations/env.md` | Runbook | Backend env var reference; fail-closed posture; smoke commands; stop conditions | Runbook; internal |
| Backup / restore runbook | `docs/operations/backup_restore.md` | Runbook | Render Postgres restore-to-new drill; first PASS 2026-06-07; cadence | Runbook; internal |
| Intake retention runbook | `docs/operations/intake_retention.md` | Runbook | `POST /v1/admin/intake/prune` procedure; dry-run-first; `I-UNDERSTAND` literal; 50 000-row cap; first PASS 2026-06-07 | Runbook; internal |
| Incident response runbook | `docs/operations/incident_response.md` | Runbook | SEV-0 → SEV-3 ladder; first-15-min checklist; eleven containment playbooks; first tabletop 2026-06-07 PASS | Runbook; internal |

---

## 3. ANCHOR positioning summary for solicitor

- ANCHOR is **governance, trust, learning, intelligence, and accountability infrastructure** for safe AI use in veterinary clinics.
- ANCHOR is **not clinical decision-making AI.**
- ANCHOR is **not an EHR / PMS.**
- ANCHOR is **not an ambient scribe.**
- ANCHOR **does not diagnose, prescribe, triage, or recommend treatment.**
- ANCHOR **does not replace veterinary professional judgement.**
- **Human professional review remains mandatory.**
- ANCHOR currently records **governance / accountability metadata by default, not raw clinical / source content by default**.
- **Live Workspace generation remains production-off.**
- **AI provider processing of real clinic data is not authorised.**
- The current system is **aligned to governance / professional expectations** — **not certified, compliant, RCVS-approved, or regulator-endorsed.**

---

## 4. What legal review needs to produce

| Required output | Source outline(s) | Solicitor role | Founder role | Status |
|---|---|---|---|---|
| **Pilot Agreement** | Pilot Agreement Outline v1; AUP Outline v1 | Draft contract; confirm scope/liability/indemnity/governing law clauses | Decide pilot scope, fee, eligibility, duration, risk appetite | Outline only — needs solicitor review |
| **DPA** | DPA Outline v1; Privacy & Data Boundary Outline v1 | Confirm controller/processor model; draft binding clauses; produce Schedules 1–8 | Decide data categories, sub-processor list at signing, retention windows | Outline only — needs solicitor review |
| **Privacy Notice / Privacy Addendum** | Privacy & Data Boundary Outline v1 | Draft external-facing plain-English notice | Decide what to surface publicly | Required — not finalised |
| **SaaS Terms / Terms of Service** | Legal & Commercial Pack Outline v1 | Draft umbrella terms | Decide commercial posture | Required — not finalised |
| **Acceptable Use Policy** | Acceptable Use Policy Outline v1 | Draft enforceable policy; suspension/termination wording | Decide enforcement appetite | Outline only — needs solicitor review |
| **AI Governance Boundary Statement** | Privacy & Data Boundary Outline v1; AUP Outline v1; CLAUDE.md doctrine | Confirm wording avoids clinical-claim implications | Decide what to publish | Required — not finalised |
| **Data Retention and Deletion Statement** | DPA Outline v1; intake_retention.md; backup_restore.md | Confirm what can be promised externally | Decide retention windows per data category | Required — not finalised |
| **Incident and Support Process Statement** | DPA Outline v1; incident_response.md | Confirm notification timing and obligation wording | Decide support posture | Required — not finalised |
| **Security / Operational Posture Summary** | Operational Resilience Checkpoint; CLAUDE.md doctrine | Confirm "evidence not guarantee" framing | Decide what evidence to surface | Required — not finalised |
| **Commercial / Pilot Order Form** | Pilot Agreement Outline §26; Legal & Commercial Pack Outline | Draft per-pilot order form | Decide per-pilot pricing/scope/duration | Required — not finalised |
| **Pricing / VAT / invoicing note** | Pilot Agreement Outline §7; Legal & Commercial Pack Outline | VAT position; invoice wording; payment-provider terms | Decide pricing model | Required — not finalised |
| **Cancellation / exit process** | Pilot Agreement Outline §24; DPA Outline §16 | Notice periods; survival clauses; deletion evidence | Decide exit posture | Required — not finalised |
| **Support SLA / support expectations** | Pilot Agreement Outline §17 | Confirm what is safe to promise legally | Decide solo-operator support boundary | Required — not finalised |
| **Clinic Onboarding Process (external)** | Clinic Onboarding Checklist v1 | Confirm which parts become contractual; convert internal to external | Decide which internal controls remain internal | Required — not finalised; **internal version exists, external version does not** |
| **Founder Approval Process** | Founder Pilot Approval Checklist v1 | Confirm record-keeping wording | Decide approval discipline | **Internal only**; should remain internal |
| **Sub-processor / international transfer schedule** | Privacy & Data Boundary Outline §14; DPA Outline §9 + §10 | Confirm SCCs / UK IDTA / addendum / adequacy position | Decide Render region | Required — not finalised |
| **DPA schedules (1–8)** | DPA Outline §19 | Draft each schedule per the binding DPA | Decide what to commit to in each | Required — not finalised |

---

## 5. Questions for solicitor — product positioning and regulatory claims

- Is the **governance-only / not-clinical-decision-making** positioning sufficiently clear in the proposed Pilot Agreement, AUP, and Privacy Notice wording?
- What wording should be used to avoid implying **clinical advice, clinical approval, or treatment recommendation**?
- What wording should be used around RCVS / professional alignment **without implying RCVS approval, regulator endorsement, certification, or compliance**?
- What disclaimers are appropriate for **governance receipts, Trust Pack, self-assessment, Learn / CPD, and transparency surfaces**?
- Are there **veterinary-professional-regulation considerations** specific to UK veterinary clinics that should be reflected (e.g. RCVS Code of Professional Conduct, practice standards, professional indemnity expectations)?
- What claims should be **prohibited in sales / demo materials** (e.g. "compliant", "certified", "RCVS-approved", "regulator-endorsed", "secure", "vulnerability-free", "clinically validated")?
- How should **human review and professional accountability** be expressed contractually (warranty by clinic; obligation; carve-out from ANCHOR liability)?

---

## 6. Questions for solicitor — controller / processor and DPA structure

- **Confirm controller / processor roles** for clinic-submitted data.
- **Confirm ANCHOR's role** for account, billing, support, and public-intake data.
- **Confirm whether ANCHOR acts as processor, controller, or both** in different contexts (working assumption: clinic controller for clinic-submitted; ANCHOR processor on clinic-submitted data + controller on its own business / account / admin data).
- **Confirm DPA schedule structure** (DPA Outline §19 lists placeholders 1–8).
- **Confirm data categories** (per §5 of the DPA outline, 17-row table).
- **Confirm data subject categories** (per §6 of the DPA outline).
- **Confirm how animal patient information that may indirectly identify human clients** should be described.
- **Confirm special-category / sensitive-data boundary** (DPA Outline §7).
- **Confirm what accidental submission process should say** (per privacy outline §6 / AUP §17).
- **Confirm audit / information rights wording** (DPA Outline §15).
- **Confirm return / deletion at pilot exit** (DPA Outline §16).
- **Confirm breach / incident notification wording and timing** (DPA Outline §13).
- **Confirm support for data subject rights** (DPA Outline §14).
- **Confirm liability position for data protection breaches** (DPA Outline + Pilot Agreement §23).

---

## 7. Questions for solicitor — privacy / data boundary

- Is the **metadata-only default** described accurately and safely?
- Is the **"metadata-only does not mean no data"** wording appropriate?
- What exact **Privacy Notice / Privacy Addendum wording** is required before any pilot?
- Which data categories can be used in **synthetic / demo-only access**?
- Which data categories require **DPA + explicit founder approval**?
- Which data must **remain prohibited**?
- What should the **clinic be responsible for** before submitting any source material?
- How should **public-intake contact data** be described (the three intake tables governed by `intake_retention.md`)?
- How should **exports and governance receipt metadata** be described?
- What **deletion / backup limitation wording** is required (`backup_restore.md` Render-managed backup retention is outside ANCHOR's direct control)?
- What **client / patient-identifiable data boundary** should be used?

---

## 8. Questions for solicitor — sub-processors and international transfers

Current posture:

- **Render / Render Postgres** — active hosting / sub-processor candidates.
- **GitHub** — used for source control and CI/CD; **not a clinic-data store**.
- **Anthropic** — only relevant if / when live Workspace generation or AI provider processing is enabled; today **not authorised for real clinic data**.
- **Payment provider** — future / not active.
- **Transactional email provider** — future / not active.

Questions:

- **Confirm current sub-processor list.**
- **Confirm whether GitHub needs to appear in clinic-facing sub-processor schedules** given no clinic-data storage.
- **Confirm Render / Render Postgres transfer basis and required wording.**
- **Confirm SCCs / UK IDTA / UK addendum / adequacy position** as applicable.
- **Confirm future Anthropic / provider sub-processor wording** before any live generation.
- **Confirm future payment / email provider wording.**
- **Confirm required notice / change-control process for adding sub-processors** (per DPA Outline §9 + Pilot Agreement §25).

---

## 9. Questions for solicitor — Pilot Agreement

- What should the **pilot scope** say for **synthetic / demo-only access**?
- What should the **pilot scope** say for **assisted pilot without real clinic data**?
- What should the **pilot scope** say if **limited real clinic data** is ever allowed?
- What should the **duration / termination** wording be?
- What should the **clinic obligations** be (Pilot Agreement Outline §10–§13)?
- What **support obligations** are safe for a **solo-founder product**?
- What **incident notification obligations** are appropriate?
- What **feedback / product-learning rights** are appropriate (Pilot Agreement Outline §21)?
- What **liability cap** is appropriate?
- What **indemnities** are required?
- What **warranty disclaimers** are required?
- What **governing law / jurisdiction** should apply?
- What **insurance / professional indemnity** wording is needed?
- What **audit / evidence access** is appropriate without exposing other tenants or secrets?

---

## 10. Questions for solicitor — Acceptable Use Policy

- Are the **prohibited clinical-use** categories sufficient (AUP Outline §6)?
- Are **prohibited communication uses** sufficient (AUP §7)?
- Are **prohibited data-upload** categories sufficient (AUP §8)?
- What **enforcement wording** should be used (AUP §20)?
- What **suspension / termination rights** are needed?
- How should **misuse reporting** be framed (AUP §21)?
- How should **governance misuse** be defined (AUP §14)?
- How should **account-sharing, tenant-access, and confidentiality responsibilities** be drafted (AUP §11 + §12)?
- What **user acknowledgement mechanism** is legally sufficient?
- **Should each user acknowledge AUP individually**, or can the **clinic admin accept on behalf of users**?

---

## 11. Questions for solicitor — onboarding and founder approval

- **Which onboarding checklist parts should become contractual obligations** (parts of `clinic_onboarding_checklist`)?
- **Which should remain internal operational controls** (Day-0 / Day-7 / exit checklists; founder approval record)?
- What **founder approval evidence** is useful but should **not be shared externally** (e.g. the per-clinic approval record template in §16)?
- What **clinic-facing onboarding wording** is safe?
- What **user / admin acknowledgements** are required?
- **What needs to be signed before:**
  - synthetic demo;
  - pilot;
  - paid pilot;
  - real clinic data?
- What **re-approval triggers** should be contractual (per founder approval checklist §19)?
- What should happen if a **clinic exceeds the agreed onboarding mode**?

---

## 12. Questions for solicitor — retention, deletion, backups, and exit

References:

- `docs/operations/intake_retention.md`
- `docs/operations/backup_restore.md`

Questions:

- What **retention wording** can be safely promised based on current runbooks?
- What should be said about **backup retention and deletion limitations** (Render-managed backups have their own retention window outside ANCHOR's direct control)?
- What should be said about **public-intake retention** (`demo_requests`, `start_requests`, `public_site_chat_events`; first PASS dry-run 2026-06-07; cap 50 000 rows per call; `I-UNDERSTAND` literal)?
- What should be said about **governance receipt / event metadata retention**?
- What **exit export / delete wording** is required?
- How should **destructive retention controls** be described without overpromising?
- What **deletion evidence** should be provided to clinics?
- Which retention commitments **must be reflected in the DPA** (Schedule 6)?

---

## 13. Questions for solicitor — incident / support / SLA

Reference: `docs/operations/incident_response.md` (SEV-0 → SEV-3 ladder; first-15-min checklist; never-capture list; eleven containment playbooks; first tabletop drill 2026-06-07 PASS).

Questions:

- What **support obligations** are safe for **pilot stage**?
- What should be **excluded** — **especially emergency clinical support**?
- What **incident categories** require contractual notice?
- What **breach notification timing** is required?
- What should the **security / privacy / governance incident process** say?
- What **evidence should be shared with clinics** after an incident (honouring the runbook's never-capture list)?
- How should the **solo-founder operational posture** be disclosed honestly?
- What **SLA wording should be avoided** until stronger operational cover exists?

---

## 14. Questions for solicitor — payment, VAT, invoicing, and commercial terms

- What **documents are required before charging a clinic**?
- What **VAT position** must be confirmed?
- What **invoice wording** is needed?
- What **cancellation / refund terms** are needed?
- What **payment-provider terms** are required?
- What should the **Order Form** contain (Pilot Agreement Outline §26 fields)?
- What should happen if a **paid pilot converts to full subscription**?
- What **consumer / business-customer distinctions** matter for **veterinary clinics**?
- What **accounting / tax evidence** should be retained?
- What **must be in place before Stripe / payment activation** (sub-processor addition; DPA update; Privacy Notice update; Pilot Agreement update; founder approval)?

---

## 15. Questions for solicitor — live Workspace generation and AI provider processing

Current default:

- **Live Workspace generation is production-off.**
- **AI provider processing of real clinic data is not authorised.**
- **Governance-only pilot does not require live generation.**

Questions:

- What **documents must be updated before live generation** (DPA + sub-processor + Privacy Notice + Pilot Agreement + AUP + Onboarding Checklist + Founder Approval record)?
- What **must be in the DPA** before AI provider processing?
- What **must be in the sub-processor schedule**?
- What **privacy notice wording** is required?
- What **user / clinic consent or acknowledgement** is required?
- What should be said about **prompts, outputs, logging, retention, and training-data use**?
- What **hard-refusal / human-review wording** is needed (diagnosis / treatment / prescribing)?
- What **extra safety evidence** should be attached before live generation (local/staging safety gate + hard-refusal harness PASS on live path)?
- What **contractual restriction** should prevent users using ANCHOR as cover for unsupported external AI workflows (per AUP §10)?

---

## 16. Questions for solicitor — liability, indemnity, insurance, and professional responsibility

- What **liability cap** is appropriate?
- Should **liability differ between free pilot, paid pilot, and full commercial service**?
- What **exclusions** are needed?
- What **indemnities** are needed from clinic and ANCHOR?
- What **professional responsibility disclaimers** are needed?
- What **clinical reliance disclaimers** are needed?
- What **security / data-protection liability cannot be excluded**?
- What **insurance should ANCHOR hold** before paid pilot?
- Should **professional indemnity interactions** be mentioned (clinic's PI policy + ANCHOR's role)?
- What **wording protects ANCHOR from being treated as a clinical decision-maker**?

---

## 17. Founder decisions that legal review should not decide alone

| Founder decision | Why founder must decide | Legal input needed? |
|---|---|:---:|
| Whether to run any pilot at all | Business / product risk | Yes — on terms once decided |
| Whether pilot is free or paid | Pricing model | Yes — on commercial terms once decided |
| Which clinic is eligible | Founder judgement on fit + risk | Light — clinic eligibility framework only |
| Whether to allow any real clinic data | Risk appetite + operational readiness | **Heavy** — DPA + privacy + AUP + Pilot Agreement |
| Whether to enable live generation | Doctrine + safety gate readiness | **Heavy** — DPA + sub-processor + privacy + Pilot Agreement + AUP + onboarding |
| Whether to use AI provider processing | Same as live generation | **Heavy** |
| Which modules are enabled | Product scope | Light — confirms module/contract alignment |
| What support level can honestly be provided | Operational capacity | Yes — on SLA wording |
| What retention / deletion commitments can operationally be met | Runbook + backup reality | Yes — on external wording |
| What pricing model to test | Commercial strategy | Yes — on invoicing / VAT / cancellation |
| What risk appetite is acceptable | Founder judgement | Yes — on caps / indemnities |
| When to stop / pause / exit a pilot | Operator judgement | Light — on contractual rights |

State: **solicitor can advise risk and draft terms, but founder must decide business / product risk posture.**

---

## 18. Documents that should become solicitor-drafted outputs

| Output document | Source outlines | Priority | Notes |
|---|---|---|---|
| Pilot Agreement | Pilot Agreement Outline v1; AUP Outline v1 | **High** | Required for any pilot |
| DPA | DPA Outline v1; Privacy & Data Boundary Outline v1 | **High** | Required for real clinic data |
| Privacy Notice / Privacy Addendum | Privacy & Data Boundary Outline v1 | **High** | Required for pilot and external surface |
| Acceptable Use Policy | AUP Outline v1 | **High** | Required for pilot |
| Terms / SaaS Terms | Legal & Commercial Pack Outline v1 | **High** | Required for paid pilot / commercial onboarding |
| Commercial / Pilot Order Form | Pilot Agreement Outline §26 | **High** | Required per pilot |
| Data Retention and Deletion Statement | DPA Outline §12; intake_retention.md; backup_restore.md | **High** | Required for pilot |
| Incident and Support Process Statement | DPA Outline §13; incident_response.md | **High** | Required for pilot |
| AI Governance Boundary Statement | Privacy & Data Boundary Outline; AUP Outline; CLAUDE.md doctrine | Medium | Linkable from every clinic-facing surface |
| Security / Operational Posture Summary | Operational Resilience Checkpoint | Medium | "Evidence not guarantee" framing |
| Support SLA | Pilot Agreement Outline §17 | Medium | Modest by intent |
| Clinic Onboarding external wording | Clinic Onboarding Checklist v1 | Medium | External-facing subset |
| Live generation / AI provider addendum | DPA Outline §9; AUP Outline §10; Pilot Agreement §25 | **Later / gated** | Only if live generation is ever approved |
| Sub-processor change notice template | DPA Outline §9 | **Later / gated** | Triggered by any sub-processor change |
| Paid subscription terms beyond pilot | Legal & Commercial Pack Outline | **Later / gated** | Only if conversion to full SaaS is approved |

---

## 19. Documents that should remain internal founder controls

| Document | Why internal | Note |
|---|---|---|
| Founder Status Summary | Plain-English founder orientation note | Not clinic-facing |
| Operational Resilience Checkpoint | Engineering evidence summary | Reference material for solicitor; not external |
| Commercial / Legal Readiness Checkpoint | Founder-facing summary of commercial spine | Not clinic-facing |
| Founder Pilot Approval Checklist | Internal go / no-go decision record | Per-clinic record contains business / risk decisions — internal only |
| Internal onboarding evidence notes | Per-clinic founder approval records | Internal only |
| Runbook evidence | Backup / retention / incident drill records | Internal only |
| Incident evidence | Per-incident records following `incident_response.md` | Internal only; subject to never-capture list |
| Secret / env / runbook details | Operational config | **Never external**; secrets never persisted |

State: **Internal controls can inform legal drafting, but should not be sent as-is to clinics without review / redaction.**

---

## 20. Suggested solicitor review pack order

Recommended reading order:

1. **Commercial / Legal Readiness Checkpoint** — orient against the current state.
2. **Legal / Commercial Pack Outline** — full document map.
3. **Privacy & Data Boundary Outline** — data posture and prohibited data.
4. **DPA Outline** — data-processing structure for solicitor handoff.
5. **Pilot Agreement Outline** — pilot relationship boundary.
6. **Acceptable Use Policy Outline** — per-user behaviour boundary.
7. **Clinic Onboarding Checklist** — practical pre-access process.
8. **Founder Pilot Approval Checklist** — final internal go / no-go record.
9. **Operational Resilience Checkpoint** — engineering evidence chain.
10. **Founder Status Summary** — plain-English orientation.
11. **Relevant runbooks as needed:** `env.md`, `backup_restore.md`, `intake_retention.md`, `incident_response.md`.

Why this order:

- **Start with the checkpoint** so the solicitor sees the state and the open questions before any individual outline.
- **Then the legal map** so the document set is clear.
- **Then data boundary / DPA** because controller/processor and data-category questions cascade into Pilot Agreement, AUP, Onboarding, and Approval.
- **Then pilot / AUP / onboarding** to see relationship, user behaviour, and pre-access flow.
- **Then operational evidence** to confirm that promised controls are actually backed by runbooks and drills.

---

## 21. Hard stop conditions for solicitor-review bundle

- **No clinic access without completed founder approval record.**
- **No pilot before Pilot Agreement reviewed.**
- **No paid pilot before legal / commercial pack reviewed.**
- **No real clinic data before DPA + privacy / data-boundary reviewed.**
- **No live Workspace generation in production.**
- **No AI provider processing of real clinic data** unless DPA / sub-processor / privacy / pilot / AUP / onboarding terms are updated first.
- **No client / patient-identifiable data without explicit approval.**
- **No clinical decision-making positioning.**
- **No compliance / certification / RCVS / regulator-endorsement claims.**
- **No deletion promises beyond tested / runbook-backed capabilities.**
- **No destructive retention outside the approved runbook.**
- **No external use of these documents before solicitor review.**

These mirror and reinforce the operational hard stops in `docs/operations/2026-06-08_founder_status_summary.md §4`, the legal/commercial pack outline §12, the privacy/data-boundary outline §20, the DPA outline §21, the Pilot Agreement outline §28, the AUP outline §24, the Clinic Onboarding Checklist §20, the Founder Pilot Approval Checklist §21, and the Commercial / Legal Readiness Checkpoint §6.

---

## 22. Non-actions in this patch

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
- ❌ **No legal document finalised.**
- ❌ **No solicitor review completed.**
- ❌ **No founder approval granted.**
- ❌ **No clinic access authorised.**
- ❌ **No Pilot Agreement approved.**
- ❌ **No DPA approved.**
- ❌ **No AUP approved.**
- ❌ **No onboarding process approved.**
- ❌ **No pilot authorised.**
- ❌ **No paid pilot authorised.**
- ❌ **No real clinic data authorised.**
- ❌ **No live Workspace generation authorised.**
- ❌ No sub-processor added or activated.
- ❌ No commitment, claim, or representation made to any clinic, advisor, or regulator on the strength of this index.
- ❌ No commit. No push. (Per scope.)

What this index **did** do: packaged the current commercial / legal outlines and key operational evidence into a single solicitor-facing review map; recorded the ANCHOR positioning summary for solicitor; enumerated the legal-review outputs (17-row table) with per-row solicitor-role / founder-role / status; recorded solicitor-facing questions across product positioning + regulatory claims, controller/processor + DPA structure, privacy / data boundary, sub-processors / international transfers, Pilot Agreement, AUP, onboarding + founder approval, retention/deletion/backups/exit, incident/support/SLA, payment/VAT/invoicing, live generation / AI provider processing, and liability / indemnity / insurance / professional responsibility; distinguished founder decisions (12-row table) from solicitor-drafted outputs (15-row table) and documents that must remain internal founder controls (8-row table); recorded the suggested solicitor review pack order; reaffirmed the standing hard stops.
