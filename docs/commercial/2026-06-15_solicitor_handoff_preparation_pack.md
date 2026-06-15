# ANCHOR Solicitor Handoff Preparation Pack v1

> **Internal founder / solicitor-preparation only.** This pack is a founder-prepared **review aid** for a UK solicitor. It is **not legal advice**, **not a final legal document**, **not externally effective**, and **not solicitor reviewed**. It **does not** authorise paid pilots, customer access, real clinic data, billing, Stripe activation, invoice issuance, VAT treatment, payment collection, live Workspace generation, or external connectors.
>
> Any future use requires solicitor review, accountant / VAT review where relevant, founder approval, security / operational readiness, and signed agreements. ANCHOR is **aligned, not compliant** — not RCVS-approved, not regulator-endorsed, not certified, no protection from enforcement. Live Workspace generation **remains production-off**.

---

## 1. Status and purpose

This pack is a **founder-prepared review aid** assembled so a qualified UK solicitor can quickly understand what to review, in what order, what working assumptions must be confirmed, and which ANCHOR documents are currently **outlines / pre-legal-review only**. It is an **index + review brief + question list** — it deliberately does **not** duplicate the full text of each commercial document; it points to them.

It is explicitly: **not legal advice**, **not solicitor review**, **not a final legal document**, **not externally effective**, and **not authorisation** for any gated activity (§11). Nothing here is solicitor-approved. The founder remains the decision-maker on commercial and product risk; the solicitor advises and drafts.

## 2. Product summary for solicitor

- **What ANCHOR is.** Governance, trust, learning, intelligence, and readiness **infrastructure for safe AI use in veterinary clinics**. It helps clinics evidence responsible AI governance practices. Metadata-only by default; human-review based; receipt-backed; multi-tenant and privacy-aware; trust-surface oriented.
- **What ANCHOR is not.** Not clinical decision-making AI. Not diagnostic, prescribing, treatment-planning, or autonomous-triage AI. Not an ambient scribe, EHR, or PMS. Not a clinical decision-support product. Not a GPAI (general-purpose AI model) provider — ANCHOR is a downstream integrator. Not a compliance guarantee, certified system, RCVS-approved product, or regulator-endorsed product. Not a replacement for veterinary judgement.
- **Current posture.** **Metadata-only by default** (no raw prompts, outputs, transcripts, drafts, or clinical content stored; hashes only). **Live Workspace generation is production-off**; the live path is built against Anthropic but is not enabled. **Aligned, not compliant** is the controlling wording doctrine across all public and clinic-facing copy.
- **Provider posture.** ANCHOR is **architected for vendor-neutrality / vendor-neutral over time**; present-tense vendor-neutrality is **not** claimed while a single provider is wired. **Anthropic becomes a subprocessor only if and when live generation is enabled**, which requires the safety gate and updated legal/subprocessor documentation first.
- **Jurisdiction.** UK-first, veterinary-first. EU AI Act exposure is treated as a conditional / future-proofing readiness theme, not a present-tense compliance claim and not the primary UK anchor.

## 3. Current legal/commercial artefact set

All artefacts below are **internal founder / solicitor-preparation outlines, pre-legal review** unless noted. None is a final legal document; none is solicitor-approved.

| Filename (`docs/commercial/`) | Purpose | Current status | Solicitor review need | Key risk / decision area |
| --- | --- | --- | --- | --- |
| `2026-06-08_legal_commercial_pack_outline.md` | Master index of documents required before paid pilots / real clinic data | Outline only | High — confirms the full required set | Completeness of the document set; sequencing |
| `2026-06-08_privacy_data_boundary_outline.md` | Intended privacy & data-boundary posture; 16 product data zones | Outline only | High — feeds Privacy Notice + DPA | Whether metadata-only wording is adequate and not misleading |
| `2026-06-08_dpa_outline.md` | Working controller/processor model; processing purposes; schedules | Outline only | High — controller/processor roles | Role confirmation; sub-processor list; international transfers |
| `2026-06-08_pilot_agreement_outline.md` | Pilot relationship, scope, obligations, exit | Outline only | High — controls clinic access | Free vs paid pilot; termination; liability placeholders |
| `2026-06-08_acceptable_use_policy_outline.md` | Permitted / prohibited use inside ANCHOR | Outline only | High — bounds clinical use | Prohibited clinical use; prohibited data uploads |
| `2026-06-08_clinic_onboarding_checklist.md` | Practical pre-access gate; onboarding modes | Outline only | Medium — operationalises the agreements | Which onboarding mode is permissible; user provisioning |
| `2026-06-08_founder_pilot_approval_checklist.md` | Founder internal go / no-go decision record | Outline only | Medium — internal control, solicitor context | Evidence-backed approval; default-not-approved gates |
| `2026-06-08_commercial_legal_readiness_checkpoint.md` | Founder-facing readiness summary of the spine | Outline only | Low/Medium — context | Honest "not ready for pilots" framing |
| `2026-06-08_solicitor_review_bundle_index.md` | Solicitor-facing review map + question banks | Outline only | Low — orientation aid | Solicitor vs founder role separation |
| `2026-06-08_solicitor_pack_dispatch_checklist.md` | Operator send/hold/never-send dispatch control | Outline only | Low — dispatch discipline | What to send vs withhold; no secrets / no PII |
| `2026-06-08_personal_data_data_flow_inventory.md` | Per-surface map of data flows & sub-processors | Outline only | High — grounds the DPA/privacy review | "No clinical data" ≠ "no personal data"; per-surface role |
| `2026-06-15_commercial_order_form_outline.md` | Future per-pilot / commercial order form shape | Outline only | High if any pilot proceeds | Pricing/VAT/Stripe placeholders; signed-agreement control |
| `README.md` | Directory index + disclaimers | Index | Low | Keeps the directory honest and discoverable |

Supporting (not in `docs/commercial/`, referenced for context): the wording-scan closure note and backend RC wording scan (`docs/operations/security_audits/2026-06-15_*`), the strategy receipt-schema artefacts (`docs/strategy/`), and the operative canon (`docs/canonical/` — Roadmap v2.6, Readiness Map v1.1, Addendum v1.3).

## 4. Documents the solicitor should review first

Recommended order, with rationale:

1. **Privacy / Data Boundary outline** — establishes what data exists and the metadata-only posture; everything else inherits from it.
2. **DPA outline** — controller/processor roles and schedules; the central legal-structure question.
3. **Personal Data / Data-Flow Inventory** — grounds (1) and (2) in actual per-surface data flows and sub-processors; corrects "no clinical data ≠ no personal data".
4. **Pilot Agreement outline** — the instrument that would actually control clinic access.
5. **AUP outline** — bounds permitted/prohibited use and prohibited data uploads.
6. **Commercial Order Form outline** — the per-pilot commercial wrapper (pricing/VAT/Stripe placeholders).
7. **AI Governance Boundary / public Legal + Trust posture** — the "what ANCHOR is / is not" and non-claim wording that must survive review.
8. **Security / Operational posture summaries** — how security/resilience evidence should be represented (no certification claims).
9. **Founder Pilot Approval Checklist** — the internal go/no-go gate that ties evidence to a decision.

Rationale: review flows **data → roles → instruments → commercial wrapper → public wording → operational evidence → decision gate**, so each later document is read against confirmed foundations rather than in isolation.

## 5. Key legal questions for the solicitor

- **Controller/processor roles** — is ANCHOR processor, controller, or mixed, **by surface**?
- **Staff/user personal data** — how should clinic staff/user accounts, roles, and credentials be treated?
- **Public intake data** — is public intake (demo/start/site-chat) controller-side to ANCHOR, and is it correctly separated from the clinic-governance perimeter?
- **Learn/CPD metadata** — how should staff learning/completion records be described and lawfully processed?
- **Governance receipts and reviewer attribution** — are receipt metadata and reviewer/user IDs personal data, and how should they be characterised?
- **Trust Pack / self-assessment / incident metadata** — does any aggregate or per-record metadata raise personal-data or confidentiality issues?
- **Special-category / sensitive / confidential** — could any captured data be special-category, sensitive, or otherwise confidential, even absent clinical content?
- **Retention / deletion / offboarding** — is the documented retention/deletion/exit posture sufficient and lawful?
- **DPA scope and schedules** — what schedules are required and what must each contain?
- **Sub-processors** — is the sub-processor list (Render + Render Postgres active; GitHub not a clinic-data store; Anthropic gated; payment/email future) complete and correctly described?
- **AI provider position** — if live Workspace generation is ever enabled, what terms and disclosures are required?
- **Anthropic subprocessor trigger** — confirm that enabling live generation makes Anthropic a production subprocessor and what must be updated **before** that.
- **Public Legal + Trust Centre copy** — is the public informational copy safe to remain public?
- **Limitation of liability / professional responsibility** — what liability, indemnity, and professional-responsibility wording is appropriate for founder-operated infrastructure?
- **Customer responsibilities** — is the clinic-responsibility allocation (professional judgement, lawful processing, human review, prohibited uploads) adequate?
- **Pilot terms and order form** — what must the Pilot Agreement and Order Form contain to be safe?
- **Free vs paid risk** — does free / evaluation / pilot access materially change the legal risk profile?
- **Paid pilot** — does a paid pilot require additional terms (and which)?
- **Cancellation / refund / payment wording** — what is needed, and how should it align with the DPA exit clauses?
- **VAT / accountant items** — which questions should be routed to an accountant rather than treated as legal advice?
- **Support / response caveats** — how should modest, founder-operated support expectations be framed to avoid implied SLAs?
- **Page status** — should any draft page be hidden, gated, or labelled differently before external use?

## 6. Data protection and privacy questions

Ask the solicitor to confirm:

- whether ANCHOR acts as **processor, controller, or mixed role by surface**;
- whether **public intake** is controller-side to ANCHOR;
- how **staff learning / completion records** should be described and lawfully grounded;
- whether **reviewer attribution / user IDs** are personal data and how to characterise them;
- the **Privacy Notice** requirements and audience;
- the **DPA schedules** required and their contents;
- the **retention basis** for each data category;
- **deletion / export obligations** on offboarding and exit;
- the **sub-processor notification** approach (advance notice / objection mechanism);
- the **international transfer** position (hosting region, transfer basis);
- whether the **metadata-only** wording is adequate and **not misleading** (metadata may still be personal data).

## 7. AI governance / professional boundary questions

Ask the solicitor to review:

- the **"aligned, not compliant"** wording and that no copy reads as a compliance/certification claim;
- the **RCVS professional accountability** framing (primary UK anchor; ANCHOR evidences governance posture, not clinical correctness);
- the **EU AI Act** wording as **conditional / future-proofing** only — Article 4 framed as an AI-literacy readiness theme, subject to legal review and amendment watch, with UK applicability dependent on EU nexus; cite Regulation (EU) 2024/1689 and Article 113 for dates; no headline fine figures;
- the **UK-first** positioning;
- the **non-claim wording** (no RCVS approval / certification / regulator endorsement / guaranteed protection);
- the **client-facing transparency** language;
- the **human-review** wording (review required before operational use);
- the **receipt / evidence non-claims** (receipts do not prove clinical correctness, patient safety, regulatory compliance, or competence);
- the **incident / near-miss** framing as reflective governance learning, **not** a statutory report, insurance submission, or regulator notification.

## 8. Commercial / pilot / order-form questions

Ask the solicitor (and, where flagged, an accountant):

- whether the pilot should be **free, paid, evaluation-only, or invite-only**;
- **what agreement controls access** (Pilot Agreement + Order Form + DPA + AUP);
- how to describe **pilot duration and termination**;
- **what must be in the order form** to be safe;
- **payment terms** (if any);
- **VAT / accountant dependency** (route VAT treatment to an accountant, not treated as legal advice);
- **Stripe / payment-processor activation conditions** (sub-processor addition, DPA/privacy/pilot/AUP updates, founder approval) — currently future-candidate / not active;
- **refund / cancellation** wording;
- whether **billing should remain inactive** until full terms are signed (current posture: yes).

## 9. Security / operational readiness questions

Ask the solicitor to review how security posture should be represented, specifically:

- that there is **no SOC 2 / ISO certification claim** and no "certified"/"secure-by-guarantee" wording;
- how to reference **backup/restore evidence** (drill executed; runbook in place) without overclaiming;
- how to reference the **incident-response runbook** (severity ladder; never-capture list);
- how to reference the **intake-retention dry-run** (operator-driven; dry-run-first; `I-UNDERSTAND` confirm; 50,000-row cap);
- how to reference **dependency / CVE audit evidence** (CI `pip-audit` PASS for the scanned set — absence of known vulnerabilities at scan time, not a security guarantee);
- how to describe **RLS / FORCE RLS / tenant isolation** (technical evidence, not a legal guarantee);
- the appropriate **operational-resilience caveats** (evidence, not warranty);
- whether the **current operational artefacts are sufficient** to support pilot negotiation, or what gaps remain.

## 10. Public wording and trust-centre questions

For context: a **backend-held wording/copy scan** and a **frontend public Legal + Trust / public-site wording scan** were both completed (both PASS WITH WATCH ITEMS, 0 issues, 0 blockers). The frontend WATCH item — Slice 2 status labels asserting "solicitor reviewed" / "Founder-approved public summary" — was **corrected** (softened to "prepared for solicitor review" / "Founder-prepared public summary — solicitor review pending") and merged to production. The 2A-D wording/copy scan lane is recorded as closed for internal RC purposes (see `docs/operations/security_audits/2026-06-15_wording_copy_scan_closure.md`).

Ask the solicitor to confirm:

- whether the public **Legal Centre pages can remain public** as informational pages;
- whether any **draft legal pages should be hidden, gated, or labelled** differently;
- whether **"prepared for solicitor review"** is an acceptable status label pending actual review;
- whether **procurement / request-access** pages create any obligations;
- whether **contact routes** imply support, SLA, DPO, or regulator-contact obligations (current framing: founder-operated, best-effort, explicitly not a staffed desk / SLA / emergency channel).

## 11. Explicit non-authorisations

This pack authorises **none** of the following:

- **No paid pilot authorised.**
- **No real clinic data authorised.**
- **No Stripe / payment activation.**
- **No live Workspace generation activation.**
- **No Anthropic production subprocessor activation.**
- **No external connector / runtime ingestion.**
- **No solicitor approval yet** (nothing here is solicitor-reviewed or solicitor-approved).
- **No final legal documents yet** (all artefacts are outlines / pre-legal review).
- **No public compliance claims** (aligned, not compliant; no certification / RCVS approval / regulator endorsement).

## 12. Suggested solicitor output

What the founder needs back from the solicitor:

- **redline or comments** on the **Pilot Agreement** outline;
- **DPA role confirmation** (controller/processor by surface) and schedule requirements;
- **Privacy Notice / Data Boundary** changes;
- **Terms / AUP** changes;
- **Order Form structure** comments;
- **sub-processor / international-transfer** advice;
- **liability / professional-responsibility** wording;
- **public Legal + Trust Centre copy** comments;
- a **go / no-go view for a free pilot**;
- a **go / no-go view for a paid pilot**;
- the **list of documents that must be complete and signed before any clinic access**.

These are solicitor outputs; the founder then makes the commercial/product decisions in §13.

## 13. Founder decision points after solicitor review

Decisions the founder must make **after** review (not before):

- **free vs paid pilot**;
- whether to **hide or keep draft public legal pages** (and how to label them);
- whether to **activate Stripe later** (and on what conditions);
- whether to **allow any real clinic staff accounts** (and under which onboarding mode);
- whether **live generation remains off** (default: yes, until the safety gate passes);
- whether to **proceed to one limited clinic pilot**;
- **what must be updated** before any external use (copy, terms, sub-processor docs, approvals).

## 14. Next action

The next action is to **provide this pack and the referenced artefacts to a qualified UK solicitor** (and an accountant for VAT/payment items). **No implementation, paid pilot, real clinic data, billing, Stripe activation, live Workspace generation, or connector work should proceed** until solicitor / accountant / founder review is complete and recorded. Until then, every artefact referenced here remains internal founder / solicitor-preparation material only, and this pack authorises nothing.
