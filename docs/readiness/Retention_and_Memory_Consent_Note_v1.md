# ANCHOR Retention and Memory-Consent Note v1

**Status:** Internal readiness note
**Version:** v1
**Companion to:** `docs/readiness/Public_Copy_Audit_Checklist_v1.md`
**Source controls:** `CLAUDE.md` (doctrine), `docs/canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1.docx` §2 (wording controls)

> This is an **internal readiness note, not legal advice** and **not a public privacy policy**. It exists to guide product copy, clinic onboarding, and founder review before external use. Where retention or consent behaviour is unclear, stop and obtain founder review before any external clinic use.

---

## 1. Status and purpose

- Internal readiness note for product, onboarding, and founder review.
- Not legal advice; not a substitute for a published privacy policy.
- Intended to keep retention, storage, and memory-consent posture honest and aligned with ANCHOR doctrine before external clinic use.
- Pairs with the Public Copy Audit Checklist v1 so written and verbal claims stay consistent with how the product actually behaves.

---

## 2. Core doctrine

- **Metadata-only accountability by default** - ANCHOR surfaces governance metadata, not raw content.
- **No raw prompt or output storage by default.**
- **No clinical-content storage by default.**
- **Human review remains required** - AI-assisted material still needs human review and accountability.
- **Clinic-scoped governance evidence** - records are tenant-isolated; no cross-tenant data.

---

## 3. What ANCHOR stores

Metadata categories ANCHOR holds to make AI use reviewable and accountable:

- Clinic and user identifiers (clinic ID, user ID, clinic slug).
- Role and access metadata (access-control role, admin/staff distinction).
- Governance event metadata (decision, risk grade, reason code, timestamps).
- Receipt metadata (governance pointers, hashes, policy references, PII flags).
- Assistant workflow metadata (mode, run status, review status, input/output hashes, field keys, safety/refusal flags).
- Policy version and validation-profile metadata.
- Learn module metadata (slug, version, title, category, CPD minutes, role applicability, RCVS/EU AI Act mappings).
- Learn completion metadata (module ID, snapshotted version, completed-at, acknowledgement flag, CPD minutes credited, void state).
- CPD-recordable activity metadata (aggregated totals derived from completions).
- Trust and Intelligence aggregate metadata (clinic-level counts and rates).
- Operational telemetry / error-budget-style metrics (event counts, latency, intervention rates).

---

## 4. What ANCHOR should not store by default

ANCHOR should not, by default, store:

- Raw prompts.
- Raw AI outputs.
- Drafts.
- Transcripts.
- Client-identifiable case narratives.
- Full clinical records.
- Uploaded clinical files.
- Ambient recordings.
- Diagnosis, prescribing, or treatment decisions.
- Free-text personal data beyond what is operationally required.

If any future feature would require storing any of the above, that is a doctrine-level decision requiring explicit founder sign-off and matching copy/consent updates.

---

## 5. Retention posture

- Retention should be **configurable by clinic / privacy profile** where technically possible.
- **Governance metadata** may warrant a different (often longer) retention window than telemetry, because it is evidence material.
- **Learn / CPD completion evidence** may need **longer retention** as governance/evidence material that staff and admins may rely on over time.
- **Operational telemetry** can usually be **shorter-lived**.
- **Exported records become the clinic's / admin's responsibility once downloaded** - ANCHOR cannot control copies that have left the platform.
- A documented retention policy is a **mandatory readiness item** before external use; default windows are an open decision (see §12).

---

## 6. Memory-consent posture

- Distinguish **product memory** (any personalised state derived for convenience) from **governance metadata** (evidence ANCHOR records by design).
- ANCHOR should **not silently create personalised memory** from raw prompts or clinical content.
- Any future memory feature must be **explicit, scoped, revocable, and metadata-conscious**.
- Memory must **never become hidden clinical-record storage**.
- **Staff should know what is recorded and why** - transparency over surprise.
- **Admins should have visibility into metadata records, not raw clinical content.**

---

## 7. Learn / CPD evidence posture

- Current Learn records **acknowledgement and completion evidence only**.
- "Completion" means a module was **reviewed and acknowledged** - it does **not** demonstrate proven competence and is not a measure of competence.
- CPD-recordable framing must stay cautious: ANCHOR **supports CPD-recordable AI literacy activity**; it is **not** certified or accredited CPD.
- **Not RCVS-accredited** and **not an official professional-body CPD record** - recognition depends on the relevant professional body.
- The admin JSON export is **metadata-only evidence**, not an accreditation or a competence certificate.
- Future M4.6 work may add knowledge checks, scenario questions, role-based paths, attestation, and refresher cycles; until then, copy must not imply assessment or certification exists.

---

## 8. Governance receipts posture

- Receipts are **metadata-only governance evidence**.
- Receipts are **not chat transcripts**.
- Receipts **do not prove clinical correctness**.
- Receipts **do not replace professional judgement**.
- Receipts exist to **support reviewability and accountability**, nothing more.

---

## 9. Clinic / admin responsibility

- The **clinic remains responsible** for the professional use of AI in its workflows.
- The clinic decides **staff policy and local retention expectations**.
- **Admins should review exports before external use** and confirm they contain only intended metadata.
- **Downloaded or exported evidence must be handled according to clinic policy** and applicable privacy duties once it leaves ANCHOR.

---

## 10. External-use checklist

- [ ] Retention windows defined (governance, telemetry, Learn/CPD evidence).
- [ ] Memory-consent wording reviewed.
- [ ] Learn/CPD disclaimer present on relevant surfaces.
- [ ] Receipt disclaimer present.
- [ ] Public copy audit completed (per Checklist v1).
- [ ] Export handling explained to clinic/admin.
- [ ] Founder review complete.

---

## 11. Safe wording examples

| Use | Avoid |
|---|---|
| "metadata-only evidence" | "stores your chats" / "full content history" |
| "supports CPD-recordable AI literacy activity" | describing the activity as certified or accredited continuing professional development |
| "reviewed and acknowledged" | claiming it shows competence or proven competence |
| "not an official professional-body CPD record" | implying ANCHOR issues recognised CPD records |
| "aligned with responsible AI governance expectations" | claiming compliance with the EU AI Act |
| "supports EU AI Act Article 4 readiness" | stating the product is a compliance guarantee |
| "not endorsed or approved by the RCVS" | "RCVS approved" / "RCVS certified" |
| "human review required" | "automated approval" / "hands-off oversight" |
| "configurable retention by clinic" | "we keep everything forever" / "we delete instantly" (unless verified) |

---

## 12. Open decisions / TODOs

- Exact default retention windows for each data class.
- Whether clinic admins can configure retention windows in the UI.
- Whether Learn/CPD evidence is treated as a separate retention class.
- Whether any future memory feature is disabled by default.
- Whether a staff-facing consent banner is needed.
- Whether exported JSON should carry an embedded disclaimer block.

---

*This note is an internal product and readiness control. It does not establish, certify, or guarantee compliance with RCVS guidance, the EU AI Act, or any other regulatory regime. It guides honest, aligned product behaviour and copy. Escalate unclear cases to founder review before external use.*

