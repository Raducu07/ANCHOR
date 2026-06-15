# ANCHOR Commercial Order Form Outline v1

> **Internal founder / solicitor-preparation only.** This is a **draft outline** for a future per-pilot / commercial order form. It is **not legal advice**, **not a final legal document**, **not externally effective**, and **not solicitor reviewed**. It **does not** authorise paid pilots, customer access, real clinic data, billing, Stripe activation, invoice issuance, VAT treatment, or payment collection.
>
> Any future use requires solicitor review, security / operational readiness, legal / commercial approval, founder approval, and a matching signed Agreement / DPA / Pilot Agreement. ANCHOR is **governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics** — **not** clinical decision-making AI. ANCHOR is **aligned, not compliant**: not RCVS-approved, not regulator-endorsed, not certified, no protection from enforcement. Live Workspace generation **remains production-off**.

---

## 1. Status and purpose

This is a **draft outline** for future solicitor / accountant review and commercial preparation only. It exists so that the *shape* of a future order form can be reasoned about deliberately, not so that any order form can be issued.

It is explicitly:

- Internal founder / solicitor-preparation material.
- Not legal advice.
- Not a final legal document.
- Not externally effective and not to be sent to any clinic as a binding commercial document.
- Not solicitor reviewed.

It authorises nothing. No paid pilot, no customer access, no real clinic data, no billing, no Stripe activation, no invoice issuance, no VAT treatment, and no payment collection follows from this outline.

## 2. Relationship to other documents

A future order form would **sit alongside or incorporate by reference** (not replace) the broader commercial / legal pack. Where any conflict exists, the **signed agreements would control**, not this order form and not this outline.

Documents a future order form would reference:

- **Pilot Agreement** — the master pilot relationship and terms.
- **DPA** — data-processing roles, instructions, and schedules.
- **Privacy Notice / Data Boundary** — privacy posture and the metadata-only boundary.
- **Acceptable Use Policy (AUP)** — permitted / prohibited use.
- **Security / TOMs (technical and organisational measures)** — security posture as evidence, not guarantee.
- **Data Retention / Offboarding** — retention, deletion, and exit posture.
- **Subprocessor register** — the current sub-processor list and transit map.
- **AI Governance Boundary** — the not-clinical-AI boundary statement.
- **Founder Pilot Approval Checklist** — the internal go / no-go gate.

This outline does not restate the substance of those documents; it points to them. The signed Pilot Agreement and DPA, once they exist and are executed, are the controlling instruments.

## 3. Order-form parties

Placeholders only. **No legal entity names, registration numbers, or addresses are invented here** — all are "to be confirmed" pending solicitor review and founder confirmation.

| Role | Placeholder | Notes |
| --- | --- | --- |
| ANCHOR legal entity / supplier | `<ANCHOR supplier entity — to be confirmed>` | Legal entity name, registration number, and registered address to be confirmed. Founder-operated; see §4 caveat. |
| Customer / clinic legal entity | `<clinic legal entity — to be confirmed>` | The contracting clinic / practice entity. |
| Billing contact | `<billing contact — to be confirmed>` | Name / role / email for any future invoicing correspondence. Not active. |
| Operational / admin contact | `<named admin — to be confirmed>` | The clinic's named ANCHOR administrator. |
| Privacy / DPA contact | `<privacy contact — to be confirmed>` | Contact for data-protection / DPA matters. |
| Security / procurement contact | `<security/procurement contact — to be confirmed>` | Contact for security questionnaires / procurement, if any. |

## 4. Order-form commercial details

Placeholders only — to be set per pilot after approval.

- **Order form ID** — `<order-form-id>`.
- **Version** — `<vN>`.
- **Effective date** — `<date — only once signed and approved>`.
- **Pilot start date** — `<date>`.
- **Pilot end date** — `<date>`.
- **Renewal / non-renewal position** — `<to be confirmed; default: no automatic renewal>`.
- **Trial / pilot scope** — `<free / assisted / discounted / paid / evaluation-only — to be confirmed>`.
- **Number of clinic sites** — `<n>`.
- **Number of users / seats** — `<n>`.
- **Permitted product surfaces** — see §5.
- **Excluded product surfaces** — see §5.
- **Support / contact route** — `<route — modest, best-effort by intent>`.
- **Founder-operated caveat** — ANCHOR is currently solo-operator infrastructure. Any support / availability expectation must be written modestly and explicitly; do not overcommit response times or uptime.

## 5. Product scope and access

A future order form could specify the included / excluded surfaces. The intent is a clear, bounded scope, not open-ended access.

A future order form could specify whether each of the following is **included or excluded**:

- ANCHOR modules / surfaces (dashboard, governance receipts/events).
- **Workspace live generation — disabled or enabled** (see default below).
- **AI provider routing — disabled or enabled** (see default below).
- Trust Pack / export features.
- Learn / CPD, policy library, staff attestation, self-assessment, client transparency, incident / near-miss logging.
- Any connector / runtime / ambient / EHR-PMS integration (see default below).

**Default position (unless explicitly and separately authorised after the relevant gates):**

- **Live Workspace generation remains production-off** unless explicitly authorised after the safety / legal gates (local/staging safety gate + hard-refusal harness on the live path).
- **External connectors are not included** unless separately agreed in writing.
- **No raw clinical content** is submitted or stored unless a specific authorised product flow and a lawful basis exist. Metadata-only is the default (see §7).

## 6. Pricing and payment placeholders

Placeholders only. **This outline creates no pricing promise and gives no VAT / accounting advice.**

- **Pilot fee** — `<to be confirmed; may be £0 / free / assisted>`.
- **Setup fee (if any)** — `<to be confirmed>`.
- **Subscription fee (if any)** — `<to be confirmed>`.
- **Invoice timing** — `<to be confirmed>`.
- **Payment terms** — `<to be confirmed>`.
- **Taxes / VAT treatment** — **to be confirmed by accountant / solicitor.** No VAT position is asserted here.
- **Refund / cancellation treatment** — **to be confirmed**; must align with the Pilot Agreement and DPA exit / deletion clauses.
- **Stripe / payment processor status** — **future candidate only.**

Statements:

- **Stripe is a future candidate only** unless and until activated through approved billing foundations (sub-processor addition, DPA update, Privacy Notice update, Pilot Agreement update, founder approval, accountant/VAT review).
- **This outline does not activate Stripe or any payment collection.** Payment-card data must never enter ANCHOR's own data store.

## 7. Data and security boundary

- **Real clinic data is not authorised** unless the required gates are complete (solicitor-reviewed DPA + Pilot Agreement + Privacy Notice, security / operational readiness, founder approval).
- **Metadata-only by default.** ANCHOR does not store raw prompts, outputs, transcripts, drafts, or clinical content by default.
- **The customer / clinic must not submit raw clinical / client / patient data** unless a specific authorised flow and lawful basis exist.
- **The DPA and Privacy / Data Boundary documents control** data roles (controller / processor) and processing detail — not this order form.
- **The sub-processor position must match the current sub-processor register** at the time of any signing. Render + Render Postgres are the active hosting sub-processors today; Anthropic is gated and not active for clinic data; payment / email providers are future / not active.

## 8. Pilot limitations and non-claims

- ANCHOR is **governance / readiness infrastructure** for safe AI use in veterinary clinics.
- **Not** clinical decision-making AI.
- **Not** diagnosis, prescribing, treatment planning, or autonomous triage.
- **Not** an ambient scribe or EHR / PMS.
- **Not** RCVS-approved, regulator-endorsed, certified, or a compliance guarantee. **Aligned, not compliant.**
- Receipts / evidence **do not prove** clinical correctness, patient safety, regulatory compliance, or staff competence. They evidence governance posture only.

## 9. Customer responsibilities

A future order form would record that the customer / clinic remains responsible for:

- Professional judgement and clinical decision-making.
- Lawful processing of personal data under its own controller obligations.
- Client confidentiality.
- Staff supervision.
- Appropriate use of AI tools.
- Avoiding prohibited data uploads (no unnecessary personal / clinical / client / patient data; no secrets; per the AUP).
- User management (no shared accounts; correct provisioning / deprovisioning).
- Human review before any operational use of AI output.
- Maintaining its own local records and discharging its own clinical and professional duties.

## 10. Approval checklist before use

A future order form must not be used until **all** of the following are recorded as complete:

- [ ] Solicitor review complete.
- [ ] DPA complete.
- [ ] Pilot Agreement complete.
- [ ] Privacy / Data Boundary complete.
- [ ] Acceptable Use Policy complete.
- [ ] Security / operational readiness accepted.
- [ ] Backup / restore and retention procedures current.
- [ ] Incident response current.
- [ ] Sub-processor list current.
- [ ] Stripe / payment processor position confirmed **if** payment is enabled.
- [ ] VAT / accounting review complete **if** invoicing / payment is enabled.
- [ ] Founder approval recorded.
- [ ] No live Workspace generation unless the safety gate is complete.

## 11. Open questions

- ANCHOR legal entity details (name, registration, registered address).
- Pricing model (free / assisted / discounted / paid / evaluation-only).
- VAT / payment treatment.
- Refund / cancellation position.
- Support expectations (and how modestly to frame them as solo-operator infrastructure).
- Pilot duration.
- Data limits (what, if anything, a pilot clinic may submit).
- Whether the pilot is free, paid, discounted, or evaluation-only.
- Whether the order form should be clinic-specific or a reusable template.

## 12. Next action

The next action is **solicitor / accountant review and founder approval** before this outline can become a draft order form. It should **not** be sent to clinics as a binding commercial document. Until then it remains internal founder / solicitor-preparation material only, and authorises nothing.
