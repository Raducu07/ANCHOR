# ANCHOR Clinic Onboarding Checklist v1 — 2026-06-08

## 1. Purpose and status

- This document is an **internal founder / operator / solicitor-preparation checklist** for future clinic onboarding.
- **It is not legal advice.**
- **It is not a final clinic-facing onboarding document.**
- **It is not a contract.**
- **It is not Terms of Service.**
- **It is not a DPA.**
- **It is not a Pilot Agreement.**
- **It is not ready to send to clinics.**
- It must be reviewed by an appropriate solicitor / legal adviser before any version of it is used externally.
- **It does not authorise pilots.**
- **It does not authorise paid pilots.**
- **It does not authorise real clinic data.**
- It does not make ANCHOR compliant, certified, RCVS-approved, regulator-endorsed, or commercially ready by itself.

---

## 2. Relationship to existing readiness documents

References:

- [`2026-06-08_legal_commercial_pack_outline.md`](./2026-06-08_legal_commercial_pack_outline.md) — required document set.
- [`2026-06-08_privacy_data_boundary_outline.md`](./2026-06-08_privacy_data_boundary_outline.md) — data boundaries.
- [`2026-06-08_dpa_outline.md`](./2026-06-08_dpa_outline.md) — data-processing structure.
- [`2026-06-08_pilot_agreement_outline.md`](./2026-06-08_pilot_agreement_outline.md) — pilot relationship boundaries.
- [`2026-06-08_acceptable_use_policy_outline.md`](./2026-06-08_acceptable_use_policy_outline.md) — user behaviour boundaries.
- [`../operations/2026-06-08_founder_status_summary.md`](../operations/2026-06-08_founder_status_summary.md) — plain-English founder status note.
- [`../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md`](../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md) — operational evidence checkpoint.

Status:

- The legal/commercial pack outline defines the required document set.
- The privacy/data-boundary outline defines data boundaries.
- The DPA outline defines the data-processing structure.
- The Pilot Agreement outline defines pilot relationship boundaries.
- The Acceptable Use Policy outline defines user behaviour boundaries.
- **This checklist converts those documents into an operational pre-access gate.**
- **It must not be treated as final legal or clinic-facing wording.**

---

## 3. Onboarding posture

- **Onboarding is not automatic.**
- **Every clinic must pass founder approval before access.**
- **Every clinic must have a named accountable admin.**
- **Every clinic must acknowledge ANCHOR's governance-only positioning.**
- **Every clinic must accept that human review remains mandatory.**
- **Real clinic data remains prohibited unless separately approved.**
- **Live Workspace generation remains production-off.**
- **ANCHOR must not be positioned as clinical decision-making AI.**

---

## 4. Onboarding modes

| Mode | Description | External clinic access? | Real clinic data? | Paid? | Status |
|---|---|---:|---:|---:|---|
| **Internal founder-only review** | Founder/operator-only exercise of the surface; no external clinic involved | No | No | No | Safest near-term mode |
| **Solicitor / legal review preparation** | Solicitor walkthrough of pack + product under NDA | Limited (solicitor only) | No | n/a | Permitted with founder approval |
| **Demo / synthetic-data walkthrough** | External demo to a prospective clinic; no real clinic data; synthetic content only | Yes (demo only) | **No** | No | Permitted with founder approval; internal documentation may be sufficient |
| **Assisted pilot, no real clinic data** | Hands-on pilot using synthetic / non-clinical data only | Yes (pilot tenant) | **No** | Optional | **Not authorised yet** — requires Pilot Agreement + AUP review |
| **Assisted pilot with approved limited clinic data** | Pilot using a narrowly approved subset of real clinic data | Yes | **Yes (narrow + approved)** | Optional | **Not authorised yet** — requires DPA + privacy/data-boundary + AUP + Pilot Agreement + founder approval |
| **Paid pilot** | Commercial pilot with fee | Yes | Per agreement | **Yes** | **Not authorised yet** — requires legal/commercial pack + Pricing/VAT/invoicing |
| **Full commercial onboarding** | Standard SaaS onboarding | Yes | Per agreement | Yes | **Not authorised yet** — out of scope for current readiness state |

State:

- **Internal / demo / synthetic-only is the safest near-term mode.**
- **Assisted / paid / real-data modes are not authorised yet.**
- **Real clinic data requires** legal/commercial pack + DPA / privacy review + operational approval + founder approval.

---

## 5. Pre-onboarding hard gates

To be ticked **before** any clinic provisioning begins:

- [ ] Founder has chosen onboarding mode.
- [ ] Legal/commercial pack status reviewed.
- [ ] Pilot Agreement reviewed by solicitor, if any pilot.
- [ ] DPA reviewed by solicitor, if any real clinic data.
- [ ] Privacy / data-boundary reviewed by solicitor.
- [ ] Acceptable Use Policy reviewed by solicitor.
- [ ] Terms / SaaS terms reviewed **or** pilot-specific terms approved.
- [ ] Pricing / VAT / invoicing reviewed, if paid.
- [ ] Support process reviewed.
- [ ] Incident process reviewed.
- [ ] Retention / deletion process reviewed.
- [ ] Backup / restore confidence reviewed.
- [ ] Workspace live generation status confirmed as **production-off unless separately approved**.
- [ ] Data boundary approved for the selected onboarding mode.
- [ ] Founder explicitly approves onboarding.

**Any unticked item blocks clinic access for the relevant onboarding mode.**

---

## 6. Clinic eligibility checklist

- [ ] Clinic understands ANCHOR is **governance infrastructure, not clinical decision-making AI**.
- [ ] Clinic accepts **human review remains mandatory**.
- [ ] Clinic accepts no clinical diagnosis / prescribing / triage / treatment reliance.
- [ ] Clinic accepts **data-upload boundaries**.
- [ ] Clinic agrees no unnecessary client / patient-identifiable data.
- [ ] Clinic agrees no full medical records or emergency triage content.
- [ ] Clinic agrees no secrets, passwords, API keys, bearer tokens, or payment-card details.
- [ ] Clinic identifies **accountable admin**.
- [ ] Clinic identifies **permitted users**.
- [ ] Clinic agrees **incident-reporting route**.
- [ ] Clinic agrees support expectations.
- [ ] Clinic agrees pilot limitations.
- [ ] Clinic agrees **no RCVS / regulator / certification / compliance claims** will be made on ANCHOR's behalf.

---

## 7. Legal / commercial document checklist

Status legend: ✅ required ; ⚠ recommended ; ➖ not required for this mode.

| Document | Demo / synthetic? | Pilot? | Paid pilot? | Real clinic data? | Status today |
|---|:---:|:---:|:---:|:---:|---|
| Pilot Agreement | ➖ | ✅ | ✅ | ✅ | Outline only; solicitor review pending |
| DPA | ➖ | ⚠ | ⚠ | ✅ | Outline only; solicitor review pending |
| Privacy Notice / Privacy Addendum | ⚠ | ✅ | ✅ | ✅ | Outline only; solicitor review pending |
| Terms / SaaS Terms | ➖ | ⚠ | ✅ | ✅ | Required — not finalised |
| Acceptable Use Policy | ⚠ | ✅ | ✅ | ✅ | Outline only; solicitor review pending |
| AI Governance Boundary Statement | ✅ | ✅ | ✅ | ✅ | Required — not finalised |
| Data Retention and Deletion Statement | ⚠ | ✅ | ✅ | ✅ | Required — not finalised |
| Incident and Support Process Statement | ⚠ | ✅ | ✅ | ✅ | Required — not finalised |
| Security / Operational Posture Summary | ⚠ | ✅ | ✅ | ✅ | Required — not finalised |
| Commercial / Pilot Order Form | ➖ | ✅ | ✅ | ✅ | Required — not finalised |
| Pricing / VAT / invoicing note | ➖ | ⚠ | ✅ | ⚠ | Required — not finalised |
| Cancellation / exit process | ➖ | ✅ | ✅ | ✅ | Required — not finalised |
| Support SLA / support expectations | ⚠ | ✅ | ✅ | ✅ | Required — not finalised |
| Clinic onboarding checklist | ✅ | ✅ | ✅ | ✅ | **This document** — outline only |
| Founder approval checklist | ✅ | ✅ | ✅ | ✅ | Outline only |

Conservative summary:

- **For real clinic data:** DPA + privacy/data-boundary + retention/deletion + incident/support **must be reviewed** by solicitor.
- **For paid pilot:** commercial terms, payment/VAT/invoicing, cancellation/exit, support expectations **must be reviewed**.
- **For any pilot:** Pilot Agreement + AUP **must be reviewed**.
- **For synthetic demo:** internal documentation may be sufficient, **but founder approval still required** before any external demo.

---

## 8. Data-boundary acknowledgement checklist

- [ ] Clinic has received data-boundary explanation.
- [ ] Clinic understands **metadata-only governance** default.
- [ ] Clinic understands metadata-only **does not mean "no data"**.
- [ ] Clinic understands ANCHOR **should not store raw clinical / source content by default**.
- [ ] Clinic understands **prohibited data list** (privacy/data-boundary outline §16).
- [ ] Clinic understands **public intake / contact data is separately bounded** (`intake_retention.md`).
- [ ] Clinic understands **live Workspace generation is production-off**.
- [ ] Clinic understands **AI provider processing of real clinic data is not active**.
- [ ] Clinic understands any **future data-boundary expansion requires approval**.
- [ ] Clinic admin acknowledges **responsibility for user behaviour**.

---

## 9. DPA / privacy readiness checklist

- [ ] Controller / processor position reviewed.
- [ ] Data categories reviewed.
- [ ] Data subject categories reviewed.
- [ ] Special-category / sensitive-data boundary reviewed.
- [ ] Subprocessor list reviewed.
- [ ] International transfer position reviewed.
- [ ] Retention / deletion reviewed.
- [ ] Incident / breach assistance wording reviewed.
- [ ] Data subject rights assistance reviewed.
- [ ] Pilot exit / deletion reviewed.
- [ ] AI provider / live-generation boundary reviewed.
- [ ] **Solicitor approval captured before real clinic data.**

---

## 10. User / account setup checklist

- [ ] Clinic tenant setup approved.
- [ ] Clinic admin named.
- [ ] Initial authorised users named.
- [ ] Roles / permissions reviewed.
- [ ] No shared accounts.
- [ ] User removal process explained.
- [ ] Account security responsibilities explained.
- [ ] Support access boundaries explained.
- [ ] Tenant separation principle explained (RLS / FORCE RLS is platform-side; users must not attempt bypass per AUP §12).
- [ ] User acknowledgement process planned.

State:

- **Do not provision a clinic until founder approval and legal/commercial gates for the selected onboarding mode are complete.**

---

## 11. Product / module access checklist

| Surface / module | Enable for onboarding? | Notes / gate |
|---|---|---|
| Dashboard | Yes | Tenant-scoped via RLS / FORCE RLS |
| Governance receipts / events | Yes | Metadata-only |
| Policies / acknowledgements / attestations | Yes | Named-staff acknowledgement metadata only |
| Learn / CPD | Yes | Completion metadata only; not certified CPD; not proof of competence |
| Trust Pack / Trust posture | Yes | Aligned-not-compliant wording; not a certification |
| Self-assessment | Yes | Internal governance readiness only |
| Client-facing transparency layer | Yes | Clinic editorial responsibility; no implication ANCHOR clinically approved an output |
| Incident / near-miss logging | Yes | `incident_response.md` never-capture list applies |
| Public intake | Bounded (already-active surface) | `intake_retention.md` retention controls apply |
| Workspace front door | Yes — surface only | Standing posture: no source content stored |
| **Workspace live generation** | **No — production-off** | Hard stop. Anthropic becomes a sub-processor the moment this is enabled. Separate approval required. |
| Assistant / provider integration | **Gated** | Not active for clinic data; separate approval required |
| Exports | Yes | **Role-gated**; metadata-only; no raw clinical content |
| Billing / payment | **No** | Not active unless separately implemented and approved |

Current posture: **live Workspace generation production-off; Assistant/provider integration gated; billing/payment not active unless separately implemented/approved; public intake must remain bounded; exports must be role-gated.**

---

## 12. Acceptable-use acknowledgement checklist

- [ ] User accepts **permitted-use boundary** (AUP outline §5).
- [ ] User accepts **prohibited clinical-use boundary** (AUP §6).
- [ ] User accepts **prohibited communication-use boundary** (AUP §7).
- [ ] User accepts **prohibited data-upload boundary** (AUP §8).
- [ ] User accepts **Workspace boundary** (AUP §9).
- [ ] User accepts **AI provider / live-generation boundary** (AUP §10).
- [ ] User accepts **account / access responsibilities** (AUP §11).
- [ ] User accepts **tenant / confidentiality responsibilities** (AUP §12).
- [ ] User accepts **security misuse prohibitions** (AUP §13).
- [ ] User accepts **governance misuse prohibitions** (AUP §14).
- [ ] User accepts **incident-reporting obligations** (AUP §17).
- [ ] User accepts **consequences of misuse** (AUP §20).

---

## 13. Support / incident route checklist

Reference: `docs/operations/incident_response.md` (SEV-0 → SEV-3 ladder, first-15-minutes checklist, evidence capture rules with explicit never-capture list, eleven per-class containment playbooks, post-incident review template; first tabletop drill executed 2026-06-07 PASS).

- [ ] Support channel defined.
- [ ] Support hours / expectations defined.
- [ ] **Emergency clinical support explicitly excluded.**
- [ ] Incident contact defined.
- [ ] Security / privacy incident route defined.
- [ ] Governance / near-miss route defined.
- [ ] Escalation path defined.
- [ ] Founder / operator responsibilities understood.
- [ ] Clinic responsibilities understood.
- [ ] Evidence capture boundaries explained (never-capture list).

---

## 14. Retention / deletion / exit checklist

References:

- `docs/operations/intake_retention.md` — public intake retention runbook (dry-run-first prune; 50 000-row hard cap; founder-approval-gated destructive runs; exact `I-UNDERSTAND` confirm literal).
- `docs/operations/backup_restore.md` — Render Postgres restore-to-new drill (first PASS 2026-06-07).

- [ ] Retention posture explained.
- [ ] Public intake retention controls explained, if applicable.
- [ ] **Destructive retention runbook gate explained** (founder-approval-gated; `I-UNDERSTAND` literal; 50 000-row cap).
- [ ] Backup / restore implications explained.
- [ ] Exit export options explained.
- [ ] Exit deletion / pruning process explained.
- [ ] Deletion limitations explained.
- [ ] **No deletion promise beyond runbook-backed capability.**
- [ ] Clinic exit contact identified.
- [ ] Founder approval required for destructive retention.

---

## 15. Commercial setup checklist

- [ ] Onboarding mode selected.
- [ ] Free / paid status selected.
- [ ] Pilot fee confirmed, if any.
- [ ] VAT position reviewed.
- [ ] Invoice / payment process reviewed.
- [ ] Payment provider status confirmed.
- [ ] **Payment-card details not entered into ANCHOR.**
- [ ] Cancellation / exit terms reviewed.
- [ ] Conversion path reviewed, if any.
- [ ] Founder approves commercial terms.

State:

- **Payment / billing automation is not active unless separately implemented and approved.**

---

## 16. Pre-access founder approval record

Template (per-clinic; capture as a dated note before any provisioning):

```text
Clinic name:
Clinic legal entity:
Clinic address:
Clinic admin:
Authorised users:
Onboarding mode:
Pilot start:
Pilot end:
Paid/free:
Real clinic data permitted? yes/no:
Live Workspace generation enabled? no / separately approved:
AI provider processing enabled? no / separately approved:
Documents reviewed:
Data boundary approved:
Support route:
Incident route:
Retention/deletion route:
Founder approval:
Founder name:
Date:
Evidence references:
Notes:
```

State:

- **If any answer is unclear, do not provision access.**
- **If "Real clinic data permitted?" is `yes`,** DPA / privacy / legal approval evidence **must be attached**.
- **If "Live Workspace generation enabled?" or "AI provider processing enabled?" is marked as enabled,** **separate approval evidence must be attached** (and the local/staging safety gate + hard-refusal harness must have passed on the live path).

---

## 17. Day-0 onboarding steps

- [ ] Confirm approved onboarding record (per §16).
- [ ] Confirm no outstanding hard stop (per §20).
- [ ] Provision tenant only if approved.
- [ ] Create / administer initial admin only if approved.
- [ ] Confirm user roles.
- [ ] Confirm AUP acknowledgement route.
- [ ] Confirm privacy / data-boundary acknowledgement route.
- [ ] Confirm support / incident route.
- [ ] Confirm Workspace live generation remains off unless separately approved.
- [ ] Confirm no real clinic data upload unless separately approved.
- [ ] Capture onboarding evidence note.

This is policy / process outline only — not a code-command list. Provisioning steps and operator-side commands are out of scope for this document.

---

## 18. Day-7 / early review checklist

- [ ] Review user access.
- [ ] Review any incidents / near-misses.
- [ ] Review any prohibited-data concerns.
- [ ] Review support issues.
- [ ] Review feedback.
- [ ] Confirm data boundary still respected.
- [ ] Confirm live generation remains off unless separately approved.
- [ ] Confirm no unapproved real clinic data.
- [ ] Decide continue / pause / exit.
- [ ] Capture review evidence.

---

## 19. Exit checklist

- [ ] Confirm exit reason.
- [ ] Confirm final export / evidence request.
- [ ] Confirm retention / deletion obligations.
- [ ] Confirm backup limitations.
- [ ] Remove / deactivate users where appropriate.
- [ ] Confirm no ongoing support obligation beyond terms.
- [ ] Capture exit evidence.
- [ ] Founder reviews closeout.

---

## 20. Hard stop conditions

- **No clinic access before founder onboarding approval.**
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
- **No clinic-facing onboarding checklist before solicitor review.**

These mirror and reinforce the operational hard stops in `docs/operations/2026-06-08_founder_status_summary.md §4`, the legal/commercial pack outline §12, the privacy/data-boundary outline §20, the DPA outline §21, the Pilot Agreement outline §28, and the AUP outline §24.

---

## 21. Non-actions in this patch

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
- ❌ **No onboarding checklist approved for external use.**
- ❌ **No Pilot Agreement approved.**
- ❌ **No DPA approved.**
- ❌ **No AUP approved.**
- ❌ **No pilot authorised.**
- ❌ **No paid pilot authorised.**
- ❌ **No real clinic data authorised.**
- ❌ **No clinic access authorised.**
- ❌ No sub-processor added or activated.
- ❌ No commitment, claim, or representation made to any clinic, advisor, or regulator on the strength of this checklist.
- ❌ No commit. No push. (Per scope.)

What this checklist **did** do: converted the five prior commercial outlines (legal/commercial pack, privacy/data-boundary, DPA, Pilot Agreement, AUP) into a **practical pre-access gate**; defined seven onboarding modes against external-access / real-clinic-data / paid / status columns; recorded pre-onboarding hard gates, clinic eligibility, the legal/commercial document checklist by onboarding mode, data-boundary acknowledgement, DPA/privacy readiness, user/account setup, product/module access (with live Workspace generation explicitly off and Assistant/provider integration gated), acceptable-use acknowledgement traceable to AUP sections, support/incident route, retention/deletion/exit, commercial setup, the founder pre-access approval record template, Day-0 / Day-7 / exit checklists; reaffirmed the hard stop conditions traceable through every prior outline.
