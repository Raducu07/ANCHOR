# ANCHOR Public Copy Audit Checklist v1

**Status:** Internal product / readiness control
**Version:** v1
**Applies to:** All public, clinic-facing, and buyer-facing copy prior to external use
**Source controls:** `CLAUDE.md` (doctrine + wording discipline), `docs/canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1.docx` §2 (wording controls), `Phase_2A_1_Engineering_Brief_v1_1.md` §3.4 (Learn/CPD copy controls)

> This checklist is an **internal product and readiness control, not legal advice.** It does not establish, certify, or guarantee regulatory compliance. When wording risk is unclear, stop and escalate to founder review before publishing.

---

## 1. Purpose and scope

**Purpose:** Provide a practical, repeatable review for ANCHOR copy so that public, clinic-facing, and buyer-facing wording stays aligned with ANCHOR doctrine and avoids overclaiming.

**In scope:** marketing/website copy, login and onboarding text, in-product UI copy (Workspace, Assistant, Receipts, Learn/CPD, Trust, Intelligence), privacy/retention statements, and sales/demo talking points and decks.

**Out of scope:** raw clinical content (never used in copy), backend logs, and internal engineering notes not seen by external audiences.

**When to run:** before any new external surface ships, before a demo to a new buyer, and on a periodic re-audit of live surfaces.

---

## 2. Core positioning statement

> **ANCHOR is governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics.**

ANCHOR is **not** a clinical decision-making AI, an ambient scribe, an EHR, a GPAI provider, or a compliance guarantee. It surfaces **metadata-only evidence** so AI use is reviewable and accountable. Human review is required, not optional.

For Learn/CPD specifically: ANCHOR **supports CPD-recordable AI literacy activity** through metadata-only acknowledgement/completion evidence. It is **not** RCVS-accredited CPD, not proof of competence, not certified training, and not a regulatory compliance guarantee.

---

## 3. Safe wording table

| Use | Avoid | Why | Safer replacement wording |
|---|---|---|---|
| "governance and readiness infrastructure" | "compliance system", "compliance platform" | Implies a guaranteed regulatory outcome ANCHOR cannot promise | "governance and readiness infrastructure" |
| "aligned with RCVS AI literacy expectations" | "RCVS-approved", "RCVS-certified", "RCVS-accredited" | Claims a regulator endorsement that does not exist | "aligned with RCVS AI literacy expectations" |
| "EU AI Act Article 4 readiness" | "EU AI Act compliant" | Asserts legal compliance; ANCHOR supports readiness, not compliance | "supports EU AI Act Article 4 readiness" |
| "metadata-only evidence" | "chat history", "clinical record", "transcript" | ANCHOR deliberately stores no raw content; these imply it does | "metadata-only evidence", "not chat history" |
| "human review required" | "automated approval", "hands-off", "fully automated oversight" | Review is mandatory; copy must not imply automation removes accountability | "human review required" |
| "supports CPD-recordable AI literacy activity" | "certified CPD", "accredited CPD", "official CPD record" | ANCHOR records activity metadata, not accredited CPD | "supports CPD-recordable AI literacy activity" |
| "helps you recognise biased or misleading AI outputs" | "guarantees you can detect AI bias" | Guarantee language overstates an educational aid | "helps you recognise biased, inaccurate, or misleading AI outputs" |
| "not a clinical decision-making tool" | "diagnoses", "prescribes", "treats", "triages" | ANCHOR is explicitly not clinical AI | "not a clinical decision-making tool" |
| "reviewable and accountable AI use" | "protects you from enforcement", "audit-proof" | Promises a legal shield ANCHOR cannot provide | "supports reviewable, accountable AI use" |
| "clinic-scoped, metadata-only" | "stores everything", "full audit trail of content" | Misrepresents the privacy model | "clinic-scoped, metadata-only evidence" |

---

## 4. Surface-specific sections

### 4.1 Public website
- Lead with the core positioning statement. No certification, approval, or compliance claims.
- Frame outcomes as "readiness" and "alignment", never "compliance" or "guarantee".
- No regulator logos or implied endorsement.

### 4.2 Login / onboarding
- Keep to "clinic-scoped governance workspace" and "metadata-only oversight".
- Do not promise security/compliance guarantees during onboarding.

### 4.3 Workspace / Assistant
- Assistant is an aid; copy must state human review is required.
- Never imply diagnosis, prescribing, dosing, treatment planning, or autonomous triage.
- Make clear hard clinical safety rules cannot be disabled.

### 4.4 Receipts
- "metadata-only receipts", "governance evidence", "not chat history / not a clinical record".
- Receipts confirm governance metadata, not clinical correctness.

### 4.5 Learn / CPD
- "supports CPD-recordable AI literacy activity"; "metadata-only evidence of completed AI literacy modules".
- Completion confirmation: evidence of AI literacy practice — never "compliant with EU AI Act Article 4".
- Always retain the non-claim disclaimer: "not an RCVS-accredited CPD certificate or an official professional-body record."
- JSON export framed as a metadata-only record; export availability is an admin control, not an accreditation.

### 4.6 Trust posture / Trust Pack
- "Aligned with RCVS AI literacy expectations and EU AI Act Article 4 readiness."
- Aggregate-only language; no per-user data implied.
- Role rates use ANCHOR access-control roles, not clinical job titles.

### 4.7 Intelligence
- "metadata-only aggregation"; insights are operational signals, not clinical or compliance verdicts.
- Avoid implying predictive clinical or regulatory outcomes.

### 4.8 Privacy / memory / retention
- State plainly: no raw prompts, outputs, drafts, transcripts, or clinical content stored.
- Document retention and memory-consent behaviour before external use (mandatory readiness item).

### 4.9 Sales / demo conversations
- Same wording discipline as written copy — verbal overclaiming counts.
- No "approved/certified/compliant/guarantee" statements, even informally.
- If asked "is this compliant?": reframe to "aligned with / supports readiness for", and offer founder follow-up.

---

## 5. Forbidden or high-risk claims

Do not use any of the following (in copy, decks, or conversation) without explicit founder decision:

- "RCVS-approved"
- "RCVS-certified"
- "EU AI Act compliant"
- "compliance guarantee"
- "clinical safety guarantee"
- "certified CPD"
- "proof of competence"
- "official CPD record"
- "protects from enforcement"
- "replaces veterinary judgement"
- "diagnoses" / "prescribes" / "treats"

---

## 6. Required disclaimers / preferred framing

Where relevant to the surface, ensure copy carries the appropriate framing:

- **Human review required** — AI-assisted material still needs human review and accountability.
- **Metadata-only evidence** — ANCHOR records governance metadata, not raw content.
- **Supports CPD-recordable AI literacy activity** — not accredited or certified CPD.
- **Aligned with responsible AI governance expectations** — alignment, not compliance.
- **Not a clinical decision-making tool** — no diagnosis, prescribing, treatment, or triage.
- **Not an official professional-body CPD record** — recognition depends on the professional body.
- **Not a compliance guarantee** — readiness support, not a regulatory outcome.

---

## 7. Practical audit workflow

1. **Collect the copy surface** — capture the exact text/screen/deck slide under review.
2. **Identify the claim type** — positioning, capability, evidence, CPD, privacy, or regulatory.
3. **Flag high-risk words** — scan against §5 and the Avoid column in §3.
4. **Replace with safe wording** — substitute using §3 and §6 preferred framing.
5. **Record audit date / version** — log in the table in §8.
6. **Founder review before external use** — any residual risk or new claim type is escalated and signed off before publishing.

---

## 8. Reusable audit checklist table

Copy this table into each audit run:

| Surface | Copy reviewed | Risk found | Replacement wording | Status | Reviewer | Date |
|---|---|---|---|---|---|---|
| | | | | Pending / Cleared / Escalated | | |
| | | | | Pending / Cleared / Escalated | | |
| | | | | Pending / Cleared / Escalated | | |

---

## 9. Internal control note

This checklist is an **internal product and readiness control**. It is **not legal advice** and does not constitute, certify, or guarantee compliance with RCVS guidance, the EU AI Act, or any other regulatory regime. It exists to keep ANCHOR copy honest, aligned, and within doctrine. Where doctrine or wording risk is unclear, stop and obtain founder review before any external use.


