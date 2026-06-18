# AI Tool Governance Notes — Evidence and Positioning

| Field | Value |
| --- | --- |
| Status | Internal product-design / positioning note. Planning only — **not** an implementation authorisation. |
| Date | 18 June 2026. |
| Owner | Founder / Product Owner. |
| Doctrine governance | "Aligned, not compliant" (Roadmap v2.6 §1). Wording controlled by Readiness Map v1.1 §2. |
| Source base | [`../operations/source_notes/2026-06-18_veterinary_ai_vendor_transparency_source_note.md`](../operations/source_notes/2026-06-18_veterinary_ai_vendor_transparency_source_note.md). |

---

## 1. Canonical status check (what the repo actually says)

This note is grounded in the operative canon, not in external assumptions.

**Phase 2A-1 through 2A-5 — Complete / Built.**
- Roadmap v2.6 §2 records `Phase 2A | Regulatory Conversion Wedge | Complete` and lists 2A-1 CPD Literacy, 2A-2 Policy Library + Attestation, 2A-3 Self-Assessment, 2A-4 Client Transparency, 2A-5 Incident/Near-Miss as "all built". §6 records each feature `Built`.
- Phase 2A Build-Order Decision Memo Addendum v1.3 §2 records 2A-1 through 2A-5 as built / functionally complete.
- Readiness Map v1.1 §5 lists 2A-1 through 2A-5 each as `Built`.
- File references: [`../canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md`](../canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md); [`../canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md`](../canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md); [`../canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md`](../canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md).

**AI Tool Governance Notes / Phase 2B.**
- Roadmap v2.6 §2 lists `Phase 2B | Commercial Leverage Extensions | Future`, with named members including **AI Tool Governance Notes** (alongside mobile near-miss, locum governance, solo-professional SKU, acquisition/insurer packs, peer benchmarking).
- Readiness Map v1.1 §4 (EU AI Act Article 13 row) references "future AI Tool Governance Notes" and states: "AI Tool Governance Notes remain future/commercial extension."
- The repo therefore treats AI Tool Governance Notes as a **named but future Phase 2B extension** — not current work and not authorised for build.
- **Provenance update (18 June 2026):** the AI Provider Information Framework is now confirmed (RCVS news item, 17 June 2026) as an **RCVS and Digital Practice-led consultation draft** — regulator-adjacent and strategically material, but **not final RCVS guidance** and **not a compliance standard**. The improved provenance strengthens the Phase 2B rationale, but it does not change the current gating: no implementation without explicit founder prioritisation after RC/security/legal/design priorities. See the source note: [`../operations/source_notes/2026-06-18_veterinary_ai_vendor_transparency_source_note.md`](../operations/source_notes/2026-06-18_veterinary_ai_vendor_transparency_source_note.md).

**M6.12 / future vendor-neutral connector layer.**
- Roadmap v2.6 §2 lists `M6.12 | Vendor-Neutral Connector Layer | Future / gated`. §9 records detailed preconditions: local/staging live-generation safety gate passed; hard-refusal harness proven on the live path; security audit + legal/subprocessor coverage complete; production live generation off until the safety gate passes. It "may be brought forward only by an explicit founder decision (recorded as a memo addendum)".

**Live Workspace generation.**
- Roadmap v2.6 §4 ("Live generation note"), Addendum v1.3 §5, and Readiness Map v1.1 §1.7 / §7 all record live Workspace generation as **production-off**, Anthropic-coupled, and not vendor-neutral. It remains off until the local/staging safety gate (2A-C.5E) passes and the hard-refusal boundary is proven on the live path; Anthropic becomes a subprocessor the moment it is enabled.

**Legal / security / operational gates before real clinic data or paid pilots.**
- Roadmap v2.6 §7, §10, §11 and Addendum v1.3 §4 / §8 record two mandatory gates before paid pilots or real clinic data: (a) **security audit + operational resilience** (backups, tested restore, breach runbook), and (b) **legal/commercial pack with solicitor review** (ToS, Privacy, DPA, subprocessor list naming Anthropic, AUP, disclaimers, pilot agreement). Building proceeds on regulatory/professional-governance conviction; there is **no buyer-conversation/buyer-discovery gate** (Addendum v1.3).

> **No contradiction found** between the repo's canonical documents and the assumptions behind this note. This note does not overwrite any canonical status with prompt assumptions.

---

## 2. Current ANCHOR state (per repo canonical sources only)

ANCHOR's current governance surfaces, as recorded in Roadmap v2.6 §3/§4/§6 and Readiness Map v1.1 §3/§5/§6, govern **AI-use behaviour and evidence inside the clinic**:

- **Governance receipts** — metadata-only evidence from Assistant run → review → receipt → Intelligence → Trust (M6 loop, Roadmap §4).
- **Human review** — review-state workflow; review required before operational use (M6.4; RCVS Theme 2; EU AI Act Article 14 readiness).
- **Learn / CPD** — CPD-recordable AI literacy activity and metadata-only completion evidence (2A-1; RCVS Theme 3). Not certified/accredited CPD.
- **Policy library + staff attestation** — editable AI-use policy templates, clinic versions, metadata-only attestation (2A-2).
- **RCVS self-assessment** — templates/questions, assessment instances, evidence closure (2A-3).
- **Client transparency** — disclosure templates/profiles, publish surface, client-safe preview (2A-4).
- **Incident / near-miss logging** — vocabulary, create/list, review/close/void, Trust incident evidence (2A-5). Not statutory incident reporting.
- **Trust Pack** — aggregated, dated, exportable metadata governance posture (M5; Readiness Map §6).

All of the above are **metadata-only** by doctrine.

---

## 3. Gap statement

> The gap is **not** clinic AI-use governance. The gap is **third-party AI-tool due diligence**: what tools are used, what providers disclose, what is missing, who reviewed the tool, what questions were asked, and when the position should be revisited.

ANCHOR already governs how a clinic *uses* AI. It does not yet help a clinic structure the *review of the AI tools themselves* — the products it buys, trials, or already runs.

---

## 4. Positioning expansion

- **From:** "govern your AI use."
- **Toward:** "structure and evidence how your practice reviews the AI tools it uses."

This is a **positioning expansion**, not a re-platforming. It is consistent with ANCHOR's existing structurer role (governance, trust, evidence). It **requires an explicit founder decision before any build prioritisation** and must not displace the current release-candidate, security, legal, and design priorities.

The future wedge is *not* "ANCHOR rates AI tools." It is "ANCHOR helps practices structure the questions, evidence gaps, review records, and governance trail around AI tools they are considering or already using." ANCHOR stays the **structurer, not the arbiter**.

---

## 5. Liability boundary

- ANCHOR **structures questions and records evidence gaps**.
- ANCHOR does **not** rate, approve, certify, validate, recommend, endorse, accredit, or clinically assess third-party tools.
- ANCHOR does **not** determine GDPR lawful basis, consent requirements, special-category-data treatment, or clinical suitability.
- Consent / data-movement prompts must be framed as **"questions for your DPO / solicitor / provider"**, not as ANCHOR conclusions.

Every captured field is a **record of what the practice asked and what the provider did or did not disclose** — never an ANCHOR judgement about the tool.

---

## 6. Product wedge

- The **lower-liability first wedge** should be an **AI Tool Assessment Question Set**: a structured, buyer-side set of questions a practice can ask AI providers, with space to record answers, missing/unclear disclosures, and review routing. See the mapping draft: [`2026-06-18_ai_tool_assessment_question_set_mapping.md`](2026-06-18_ai_tool_assessment_question_set_mapping.md).
- A **full register / risk-band workflow is later** work, not the first artefact.
- The eventual MVP should likely be **tighter than the full planning map** — for example **8–10 high-value categories** rather than every possible category. The mapping draft is deliberately broad so the MVP can be narrowed *down* from it with intent.

---

## 7. Relationship to M6.12 / future connector layer

Supported by Roadmap v2.6 §9 (M6.12) and §2:

- A future AI Tool Governance Notes layer can become the **metadata spine** for the future vendor-neutral connector layer: an inventory of which tools a clinic uses, what was reviewed, and what was disclosed is exactly the registry a connector layer would later attach to.
- **Inventory first, connectors later.**
- **No connector / runtime ingestion before security and legal gates** — M6.12 preconditions (Roadmap §9) and the standing security/legal gates (§7/§10/§11) apply in full. Live generation remains production-off regardless.

---

## 8. Do-not-build-yet cautions

- Do **not** build before current RC / design / legal priorities unless the founder explicitly promotes it.
- Do **not** implement clinical-accuracy scoring.
- Do **not** create "framework-compliant" badges.
- Do **not** create automated approval, risk, consent, or GDPR decisions.
- Do **not** ingest vendor documents automatically in v1.
- Do **not** store raw clinical records, raw vendor contracts, patient identifiers, or client communications.
- Do **not** expose consent / GDPR determinations as ANCHOR conclusions.
- Do **not** treat the RCVS and Digital Practice-led consultation draft (not final RCVS guidance; not a compliance standard) as a product-requirements authority, and do **not** claim ANCHOR "aligns with" or "is built around" the RCVS framework or is "framework-compliant".

---

## 9. Conclusion

> This is not a blocker for ANCHOR's current RC path. It is a strong Phase 2B wedge if handled as **buyer-side question structuring and evidence-gap governance**, not as third-party tool validation.

*Evidence and positioning note — 18 June 2026 — planning/positioning only. Not legal advice. Not RCVS approval or guidance. Not a compliance, certification, or endorsement claim. Documentation only; authorises no build, no paid pilot, no real clinic data, no live generation, no connector.*
