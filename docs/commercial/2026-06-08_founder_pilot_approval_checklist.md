# ANCHOR Founder Pilot Approval Checklist v1 — 2026-06-08

## 1. Purpose and status

- This document is an **internal founder go / no-go checklist** for future clinic access, pilot access, paid-pilot access, or real clinic data permission.
- **It is not legal advice.**
- **It is not a final legal document.**
- **It is not a clinic-facing document.**
- **It is not a Pilot Agreement.**
- **It is not Terms of Service.**
- **It is not a DPA.**
- **It is not an Acceptable Use Policy.**
- **It is not a final onboarding procedure.**
- It must be reviewed by an appropriate solicitor / legal adviser before it is used as part of any external process.
- **It does not authorise clinic access.**
- **It does not authorise pilots.**
- **It does not authorise paid pilots.**
- **It does not authorise real clinic data.**
- It does not make ANCHOR compliant, certified, RCVS-approved, regulator-endorsed, or commercially ready by itself.

---

## 2. Relationship to existing readiness documents

References:

- [`2026-06-08_legal_commercial_pack_outline.md`](./2026-06-08_legal_commercial_pack_outline.md) — full required document set.
- [`2026-06-08_privacy_data_boundary_outline.md`](./2026-06-08_privacy_data_boundary_outline.md) — data boundaries.
- [`2026-06-08_dpa_outline.md`](./2026-06-08_dpa_outline.md) — data-processing structure.
- [`2026-06-08_pilot_agreement_outline.md`](./2026-06-08_pilot_agreement_outline.md) — pilot relationship boundary.
- [`2026-06-08_acceptable_use_policy_outline.md`](./2026-06-08_acceptable_use_policy_outline.md) — user behaviour boundaries.
- [`2026-06-08_clinic_onboarding_checklist.md`](./2026-06-08_clinic_onboarding_checklist.md) — practical pre-access process.
- [`../operations/2026-06-08_founder_status_summary.md`](../operations/2026-06-08_founder_status_summary.md) — plain-English founder status note.
- [`../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md`](../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md) — operational evidence checkpoint.

Status:

- The legal/commercial pack outline defines the full document set.
- The privacy/data-boundary outline defines data boundaries.
- The DPA outline defines the data-processing structure.
- The Pilot Agreement outline defines the pilot relationship boundary.
- The Acceptable Use Policy outline defines user-behaviour boundaries.
- The Clinic Onboarding Checklist converts those documents into a practical pre-access process.
- **This Founder Pilot Approval Checklist is the final internal go / no-go decision record before access is granted.**
- **It must not be treated as final legal or external wording.**

---

## 3. Decision types covered

| Decision type | What it means | Can be approved today? | Minimum evidence required |
|---|---|---:|---|
| Internal founder-only review | Founder/operator exercise; no external | ✅ (with founder dated note) | Founder dated note |
| Solicitor / legal review preparation | Solicitor walkthrough under NDA | ✅ (with founder + NDA + dated note) | Founder dated note + NDA |
| Demo / synthetic-data walkthrough | External demo with synthetic content only | ⚠ Founder approval required; safer than clinic access; legal pack still required before any commitment | Founder dated note + AI Governance Boundary Statement |
| External clinic demo without access | Show-and-tell only, no access provisioned | ⚠ Founder approval required | Founder dated note + AI Governance Boundary Statement |
| Clinic access with synthetic/demo data only | Tenant provisioned; no real clinic data | ❌ Not authorised by this checklist | Pilot Agreement + AUP reviewed; founder approval record |
| Assisted pilot without real clinic data | Pilot relationship, synthetic content only | ❌ Not authorised by this checklist | Pilot Agreement + AUP solicitor-reviewed |
| Assisted pilot with approved limited clinic data | Pilot with narrow real-data scope | ❌ Not authorised by this checklist | DPA + privacy + AUP + Pilot Agreement solicitor-reviewed; founder approval record |
| Paid pilot | Commercial pilot with fee | ❌ Not authorised by this checklist | Legal/commercial pack reviewed; Pricing/VAT/invoicing reviewed |
| Full commercial onboarding | Standard SaaS onboarding | ❌ Not authorised by this checklist | Out of scope for current readiness state |
| **Live Workspace generation in production** | Workspace hitting Anthropic in prod | ❌ **Hard stop** | Local/staging safety gate + hard-refusal harness PASS on live path; DPA + sub-processor + privacy + pilot + AUP + onboarding updated |
| **AI provider processing of real clinic data** | Real clinic data sent to AI provider | ❌ **Hard stop** | Same as above |

Current posture: **internal / demo / synthetic-only pathways may be closest to readiness but still require founder approval**; clinic access, assisted pilot, paid pilot, real clinic data, live generation, and AI provider processing **are not authorised by this checklist**; real clinic data and paid pilots **remain hard-gated**.

---

## 4. Absolute hard-stop summary

- **No clinic access** without completed founder approval record.
- **No pilot** before Pilot Agreement reviewed.
- **No paid pilot** before legal / commercial pack reviewed.
- **No real clinic data** before DPA + privacy / data-boundary reviewed.
- **No live Workspace generation in production.**
- **No AI provider processing of real clinic data** unless DPA / sub-processor / privacy / pilot / AUP / onboarding terms are updated first.
- **No client / patient-identifiable data** without explicit approval.
- **No clinical decision-making positioning.**
- **No compliance / certification / RCVS / regulator-endorsement claims.**
- **No deletion promises beyond tested / runbook-backed capabilities.**
- **No destructive retention outside the approved runbook.**
- **No clinic-facing onboarding or approval process before solicitor review.**

---

## 5. Operational resilience evidence checklist

References: `docs/operations/security_audits/2026-06-08_operational_resilience_checkpoint.md`; `docs/operations/2026-06-08_founder_status_summary.md`.

- [ ] Operational resilience checkpoint reviewed.
- [ ] Dependency / CVE audit PASS for the locked scanned set reviewed (CI run `#5` against `de966a9`, `No known vulnerabilities found` for the 34-package set).
- [ ] Hashed runtime lockfile evidence reviewed (`requirements.txt` per-wheel SHA256 verified at install).
- [ ] Docker base digest pin evidence reviewed (`python:3.11-slim@sha256:a3ab0b96…49ac0`).
- [ ] GitHub Actions SHA pin evidence reviewed (`actions/checkout@34e1148…`, `actions/setup-python@a26af69…`).
- [ ] Stale `anchor-retention-prune.yml` workflow removal reviewed.
- [ ] `alembic` / `mako` / `markupsafe` removal reviewed.
- [ ] Render deploy smoke evidence reviewed (`cd9d966`, `7451357`).
- [ ] `/v1/version.git_sha` production observability reviewed (populated via `RENDER_GIT_COMMIT` fallback).
- [ ] Protected dashboard 401 unauthenticated smoke reviewed.
- [ ] Backup / restore runbook reviewed (first PASS drill 2026-06-07).
- [ ] Intake-retention runbook reviewed (first PASS dry-run 2026-06-07; monthly pre-pilot cadence).
- [ ] Incident-response runbook reviewed (first tabletop drill 2026-06-07 PASS).
- [ ] **Founder accepts that operational evidence is not a security / compliance guarantee.**

---

## 6. Legal / commercial document readiness checklist

- [ ] Legal / commercial pack outline reviewed.
- [ ] Pilot Agreement reviewed by solicitor.
- [ ] DPA reviewed by solicitor.
- [ ] Privacy Notice / Privacy Addendum reviewed by solicitor.
- [ ] Terms / SaaS Terms reviewed by solicitor, or pilot-specific terms approved.
- [ ] Acceptable Use Policy reviewed by solicitor.
- [ ] AI Governance Boundary Statement reviewed.
- [ ] Data Retention and Deletion Statement reviewed.
- [ ] Incident and Support Process Statement reviewed.
- [ ] Security / Operational Posture Summary reviewed.
- [ ] Commercial / Pilot Order Form reviewed.
- [ ] Pricing / VAT / invoicing reviewed.
- [ ] Cancellation / exit process reviewed.
- [ ] Support SLA / support expectations reviewed.
- [ ] Clinic Onboarding Checklist reviewed.
- [ ] Founder approval checklist completed and dated.

State:

- **Any unticked item blocks paid pilot and real clinic data.**
- For synthetic / demo-only access, founder must still decide which legal documents are required before external exposure.

---

## 7. Clinic eligibility checklist

- [ ] Clinic understands ANCHOR is **governance infrastructure, not clinical decision-making AI**.
- [ ] Clinic accepts **human review remains mandatory**.
- [ ] Clinic accepts no diagnosis / prescribing / triage / treatment reliance.
- [ ] Clinic accepts **data-upload boundaries**.
- [ ] Clinic accepts no unnecessary client / patient-identifiable data.
- [ ] Clinic accepts no full medical records or emergency triage content unless separately approved.
- [ ] Clinic accepts no secrets / passwords / API keys / bearer tokens / payment-card data.
- [ ] Clinic named accountable admin.
- [ ] Clinic named permitted users.
- [ ] Clinic accepts **incident-reporting route**.
- [ ] Clinic accepts support expectations.
- [ ] Clinic accepts pilot limitations.
- [ ] Clinic agrees **no RCVS / regulator / certification / compliance claims** will be made on ANCHOR's behalf.
- [ ] Clinic is appropriate for the selected onboarding mode.

---

## 8. Onboarding mode decision

| Onboarding mode | Selected? | Evidence / notes |
|---|:---:|---|
| Internal founder-only review | ☐ | — |
| Solicitor / legal review preparation | ☐ | NDA required |
| Demo / synthetic-data walkthrough | ☐ | Founder dated note + AI Governance Boundary Statement |
| External clinic demo without access | ☐ | Founder dated note |
| Clinic access with synthetic / demo data only | ☐ | Pilot Agreement + AUP solicitor-reviewed; founder approval record |
| Assisted pilot without real clinic data | ☐ | Pilot Agreement + AUP solicitor-reviewed |
| Assisted pilot with approved limited clinic data | ☐ | DPA + privacy + AUP + Pilot Agreement solicitor-reviewed; §10 completed |
| Paid pilot | ☐ | Legal/commercial pack reviewed; §11 completed |
| Full commercial onboarding | ☐ | Out of scope for current readiness state |

State:

- **Only one mode should be selected for a specific approval record.**
- **If mode includes clinic access, checklist sections 6–15 must be completed at the appropriate level.**
- **If mode includes real clinic data, DPA / privacy / legal approval evidence must be attached (§10).**
- **If mode includes payment, commercial / payment / VAT approval evidence must be attached (§11).**

---

## 9. Data-boundary go / no-go checklist

- [ ] Data boundary for the clinic / onboarding mode **documented**.
- [ ] **Metadata-only governance default** explained.
- [ ] **Prohibited data list** explained (privacy/data-boundary outline §16; AUP §8).
- [ ] **Public intake / contact data boundary** explained, if relevant (`intake_retention.md`).
- [ ] **Workspace source / output boundary** explained, if relevant.
- [ ] **Live Workspace generation confirmed production-off** unless separately approved.
- [ ] **AI provider processing confirmed off** unless separately approved.
- [ ] **Sub-processor list reviewed** (DPA outline §9).
- [ ] **International transfer position reviewed**, if relevant.
- [ ] **Backup / deletion limitations** explained.
- [ ] **Clinic admin acknowledged responsibility for user behaviour.**
- [ ] **Founder approves the specific data boundary.**

---

## 10. Real clinic data approval checklist

State:

- **This section must be completed only if real clinic data is being considered.**
- **Default answer is "not approved".**

- [ ] Real clinic data is **necessary** for the proposed mode.
- [ ] Synthetic / demo data is **insufficient** and rationale is documented.
- [ ] **DPA reviewed and approved.**
- [ ] **Privacy / data-boundary reviewed and approved.**
- [ ] **Pilot Agreement reviewed and approved.**
- [ ] **AUP reviewed and approved.**
- [ ] Clinic data categories **listed**.
- [ ] Prohibited data **remains prohibited**.
- [ ] Special-category / sensitive-data boundary reviewed.
- [ ] Client / patient-identifiable data boundary reviewed.
- [ ] Sub-processor / transfer position reviewed.
- [ ] Retention / deletion position reviewed.
- [ ] Incident / breach process reviewed.
- [ ] **Founder explicitly approves real clinic data.**
- [ ] **Approval date recorded.**

State:

- **Any unticked item means real clinic data is not approved.**

---

## 11. Paid pilot approval checklist

State:

- **This section must be completed only if payment is being considered.**
- **Default answer is "not approved".**

- [ ] Paid pilot rationale documented.
- [ ] Price confirmed.
- [ ] VAT position reviewed.
- [ ] Invoice process reviewed.
- [ ] Payment method reviewed.
- [ ] Payment provider status confirmed.
- [ ] **Payment-card data will not enter ANCHOR.**
- [ ] Refund / cancellation terms reviewed.
- [ ] Support expectations reviewed.
- [ ] Pilot duration reviewed.
- [ ] Conversion / exit path reviewed.
- [ ] **Founder explicitly approves paid pilot.**
- [ ] **Approval date recorded.**

State:

- **Any unticked item means paid pilot is not approved.**

---

## 12. Live Workspace generation / AI provider approval checklist

State:

- **This section must be completed only if live generation or AI provider processing is being considered.**
- **Default answer is "not approved".**

- [ ] **Live Workspace generation safety gate completed** (local/staging).
- [ ] **Local/staging hard-refusal harness passed on the live path** (diagnosis / treatment / prescribing).
- [ ] AI provider terms reviewed.
- [ ] AI provider sub-processor status reviewed.
- [ ] **DPA updated** for AI provider processing.
- [ ] **Privacy / data-boundary updated** for AI provider processing.
- [ ] **Pilot Agreement updated.**
- [ ] **AUP updated.**
- [ ] **Clinic Onboarding Checklist updated.**
- [ ] **Human review flow confirmed.**
- [ ] Prompt / output / content-retention position reviewed.
- [ ] Provider logging / training / data-use settings reviewed.
- [ ] Incident process updated.
- [ ] **Founder explicitly approves live generation / provider processing.**
- [ ] **Approval date recorded.**

State:

- **Any unticked item means live generation / AI provider processing is not approved.**

---

## 13. User / account provisioning approval checklist

- [ ] Clinic tenant creation approved.
- [ ] Clinic admin identified.
- [ ] Initial authorised users listed.
- [ ] Roles / permissions reviewed.
- [ ] **No shared accounts.**
- [ ] User-removal process explained.
- [ ] Account-security responsibilities explained.
- [ ] Tenant separation explained (RLS / FORCE RLS platform-side; bypass attempts out of bounds per AUP §12).
- [ ] Support access boundaries explained.
- [ ] AUP acknowledgement route defined.
- [ ] Privacy / data-boundary acknowledgement route defined.
- [ ] Founder approves provisioning.

State:

- **Do not provision clinic access until this section is complete for the selected onboarding mode.**

---

## 14. Product / module enablement approval checklist

| Surface / module | Enable? | Evidence / gate |
|---|---|---|
| Dashboard | ☐ | Tenant-scoped via RLS / FORCE RLS |
| Governance receipts / events | ☐ | Metadata-only |
| Policies / acknowledgements / attestations | ☐ | Named-staff acknowledgement metadata only |
| Learn / CPD | ☐ | Completion metadata only; not certified CPD; not proof of competence |
| Trust Pack / Trust posture | ☐ | Aligned-not-compliant wording; not a certification |
| Self-assessment | ☐ | Internal governance readiness only |
| Client-facing transparency layer | ☐ | Clinic editorial responsibility; no implication ANCHOR clinically approved an output |
| Incident / near-miss logging | ☐ | `incident_response.md` never-capture list applies |
| Public intake | Bounded (already-active surface) | `intake_retention.md` retention controls apply |
| Workspace front door | ☐ | Standing posture: no source content stored |
| **Workspace live generation** | **☐ (default: No — production-off)** | **Hard stop.** §12 required if considering enable. |
| Assistant / provider integration | **☐ (default: Gated)** | §12 required if considering enable |
| Exports | ☐ | **Role-gated**; metadata-only; no raw clinical content |
| Billing / payment | **☐ (default: Not active)** | §11 required if considering enable |

Current posture: **live Workspace generation off by default; Assistant/provider integration gated; billing/payment not active unless separately implemented/approved; exports role-gated; public intake bounded.**

---

## 15. Support / incident / retention readiness checklist

References: `docs/operations/incident_response.md`; `docs/operations/intake_retention.md`; `docs/operations/backup_restore.md`.

- [ ] Support route defined.
- [ ] Support expectations defined.
- [ ] **Emergency clinical support excluded.**
- [ ] Incident route defined.
- [ ] Security / privacy escalation route defined.
- [ ] Governance / near-miss route defined.
- [ ] Evidence capture boundaries explained (never-capture list).
- [ ] Retention posture explained.
- [ ] **Destructive retention runbook gate explained** (founder-approval-gated; `I-UNDERSTAND` literal; 50 000-row cap).
- [ ] Backup / restore implications explained.
- [ ] Exit export / deletion route explained.
- [ ] **No deletion promise beyond runbook-backed capability.**

---

## 16. External claims / communications approval checklist

- [ ] **No compliance claim.**
- [ ] **No certification claim.**
- [ ] **No RCVS approval claim.**
- [ ] **No regulator endorsement claim.**
- [ ] **No "secure" / "vulnerability-free" overclaim.**
- [ ] **No clinical decision-making AI claim.**
- [ ] **No claim that ANCHOR approves clinical output.**
- [ ] **No claim that Trust Pack proves legal compliance.**
- [ ] **No claim that Learn / CPD proves competence or certified CPD.**
- [ ] **No public use of clinic name / logo without permission.**
- [ ] **No case study / testimonial without written approval.**
- [ ] Founder approves all external wording.

---

## 17. Founder decision record template

```text
Decision record ID:
Date:
Founder:
Clinic / organisation:
Clinic legal entity:
Clinic address:
Clinic accountable admin:
Authorised users:
Decision type:
Onboarding mode:
Access approved? yes/no:
Pilot approved? yes/no:
Paid pilot approved? yes/no:
Real clinic data approved? yes/no:
Live Workspace generation approved? yes/no:
AI provider processing approved? yes/no:
Payment/billing approved? yes/no:
Data boundary summary:
Enabled modules:
Disabled modules:
Legal/commercial documents reviewed:
Operational evidence reviewed:
Support route:
Incident route:
Retention/deletion route:
External claims reviewed:
Outstanding conditions:
Founder decision:
Founder signature / typed approval:
Evidence references:
Notes:
```

State:

- **Any "yes" must be supported by evidence references.**
- **If a required evidence reference is missing, the decision must be "no".**
- **This template is internal until solicitor-reviewed.**

---

## 18. Approval outcomes

| Outcome | Meaning | Allowed next action |
|---|---|---|
| **No-go** | Approval refused | Document reasons; capture as evidence; revisit when conditions change |
| **More evidence needed** | Founder cannot yet decide | List missing evidence; recheck once supplied |
| **Internal-only demo approved** | Founder/operator-only exercise approved | Proceed internally; no external exposure |
| **Synthetic external demo approved** | External demo with synthetic data approved | Demo only; no clinic access provisioned; no real clinic data |
| **Clinic access with synthetic data approved** | Tenant provisioned for synthetic content only | Provision per onboarding checklist Day-0 (§17 of Clinic Onboarding Checklist); no real clinic data |
| **Assisted pilot without real clinic data approved** | Pilot relationship with synthetic content only | Pilot Agreement + AUP must be signed; no real clinic data |
| **Limited real clinic data pilot approved** | Pilot with narrow real-data scope | §10 fully completed; DPA + privacy + AUP + Pilot Agreement signed; data boundary explicit |
| **Paid pilot approved** | Commercial pilot with fee | §11 fully completed; legal/commercial pack + Pricing/VAT/invoicing reviewed |
| **Full commercial onboarding approved** | Standard SaaS onboarding | Out of scope for current readiness state — not expected from this checklist today |
| **Suspend / pause** | Existing access paused | Capture trigger; communicate to clinic; preserve evidence |
| **Exit / terminate** | Existing access terminated | Follow Clinic Onboarding Checklist §19 exit; capture closeout evidence |

State:

- **Any approval must be bounded by onboarding mode, modules, data categories, duration, and founder date / signature.**
- **Approval does not generalise to another clinic.**

---

## 19. Re-approval triggers

Founder approval **must be repeated** before any of:

- new clinic;
- new onboarding mode;
- paid pilot conversion;
- real clinic data permission;
- live Workspace generation;
- AI provider processing;
- new sub-processor;
- source material storage;
- prompt / output content storage;
- EHR / PMS integration;
- ambient audio / transcripts;
- payment provider activation;
- expanded user roles;
- materially changed support promise;
- materially changed deletion / retention promise;
- external marketing / case study;
- full commercial launch.

Each trigger requires its own dated decision record, the relevant document updates, and explicit founder authorisation.

---

## 20. Evidence storage and audit trail

- **Approval records should be stored** in the repository or another controlled founder evidence location.
- **Approval records must not contain secrets.**
- **Approval records should avoid unnecessary client / patient-identifiable data.**
- **Evidence references should point to dated docs, commits, runbooks, and signed / reviewed documents where applicable.**
- **Do not store signed legal contracts in the public repository** unless explicitly intended and safe.
- **Future private evidence storage may be needed** — capture under a separate operator decision before binding clinic agreements are stored anywhere.

---

## 21. Hard stop conditions

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
- **No external use of this checklist before solicitor review.**

These mirror and reinforce the operational hard stops in `docs/operations/2026-06-08_founder_status_summary.md §4`, the legal / commercial pack outline §12, the privacy / data-boundary outline §20, the DPA outline §21, the Pilot Agreement outline §28, the AUP outline §24, and the Clinic Onboarding Checklist §20.

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
- ❌ **No legal document finalised.** Every section is checklist outline / solicitor-prep only.
- ❌ **No founder approval granted.** The template in §17 is unfilled; every checkbox in §5–§16 is unticked.
- ❌ **No clinic access authorised.**
- ❌ **No Pilot Agreement approved.**
- ❌ **No DPA approved.**
- ❌ **No AUP approved.**
- ❌ **No onboarding process approved.**
- ❌ **No pilot authorised.**
- ❌ **No paid pilot authorised.**
- ❌ **No real clinic data authorised.**
- ❌ No sub-processor added or activated.
- ❌ No commitment, claim, or representation made to any clinic, advisor, or regulator on the strength of this checklist.
- ❌ No commit. No push. (Per scope.)

What this checklist **did** do: combined the operational resilience evidence chain (checkpoint, dependency audit, lockfile, Docker digest, Actions SHA, retention workflow removal, alembic removal, deploy smokes, `/v1/version` observability, runbooks) with the six commercial outlines (legal/commercial pack, privacy/data-boundary, DPA, Pilot Agreement, AUP, Clinic Onboarding Checklist) into a single founder go / no-go decision record; defined 11 decision types (with per-row "Can be approved today?" status and minimum evidence required); enumerated the absolute hard-stop summary; recorded operational resilience, legal/commercial document, clinic eligibility, onboarding mode, data-boundary, real-clinic-data, paid-pilot, live-Workspace-generation / AI-provider, user/account provisioning, product/module enablement, support/incident/retention, and external-claims approval checklists; recorded the founder decision record template with explicit "any yes must be supported by evidence references" rule; defined 11 approval outcomes; enumerated 17 re-approval triggers; recorded evidence-storage discipline and the standing hard stop conditions.
