# ANCHOR AI Governance Receipt Schema v0.1

> **Internal strategy artefact. Documentation only.** This document is a forward-looking schema and positioning artefact. It is **not product code**, **not a connector implementation**, **not a compliance certificate**, and **not legal advice**. It describes a canonical evidence model intended to guide future receipt, Trust Pack, connector, declared-use, and ambient-governance design.
>
> ANCHOR is **governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics** — **not** a clinical decision-making AI, diagnostic tool, ambient scribe, EHR/PMS, or replacement for veterinary judgement. ANCHOR is **aligned, not compliant**: it is **not RCVS-approved**, **not GDPR-certified**, **not EU AI Act-compliant**, **not regulator-endorsed**, and provides **no protection from enforcement**. Live Workspace generation **remains production-off**. Nothing in this document authorises a pilot, real clinic data, or any external connector.

---

## 1. Status and purpose

**Status.** Documentation-only strategy artefact, dated 2026-06-11. It sits alongside the operative canon in `../canonical/` and does not modify doctrine, code, schema, migrations, tests, or any clinic-facing surface.

This document is explicitly:

- **Documentation-only** — a strategy artefact, not an implementation contract.
- **Not product code** — it defines no endpoints, tables, or behaviour.
- **Not a connector implementation** — it builds no ingestion path to any external system.
- **Not a compliance certificate** — it certifies nothing and grants no assurance.
- **Not legal advice** — controller/processor analysis and regulatory applicability require qualified advice.

**Purpose.** Define a *canonical evidence schema* for governed AI-use records across the full range of evidence sources ANCHOR may one day represent, so that future receipt design, Trust Pack presentation, connector ingestion, declared-use capture, and ambient-governance wrappers can share one honest, gradable evidence model. The schema's job is to make AI use **legible and provable at a stated strength**, never to control or execute the AI use itself.

**Strategic framing.** ANCHOR must **not** become an agent-runtime-control platform. Runtime platforms may own tool execution, runtime control, approvals, orchestration, and raw logs. ANCHOR's defensible lane is **regulated evidence governance**: what proof exists, how strong it is, whether it is metadata-only, whether human review happened, and whether it maps to professional accountability.

- Runtimes do **control**.
- ANCHOR does **legibility and proof**.
- ANCHOR treats agent runtimes, ambient scribes, EHR/PMS-adjacent systems, and external AI tools as **future evidence feeds**, not systems ANCHOR controls.
- The moat is **not** the connector itself.
- The moat is the **evidence schema and honest evidence-strength grading**.

---

## 2. Scope

**In scope (what the schema is designed to represent):**

- **Native ANCHOR governed workflows** — governed Assistant / Workspace evidence captured directly by ANCHOR.
- **Future external runtime/feed ingestion** — structured evidence supplied by an external runtime, scribe, EHR/PMS-adjacent system, or AI tool, *if and when* a connector is built, tested, and evidence-graded.
- **Declared-use / manual records** — a human attestation that an AI tool was used, with no runtime capture.
- **Ambient / chatbot / ad hoc wrapper evidence** — lightweight governance wrappers around informal AI use.

**Out of scope (what the schema must never be read to include):**

- **Raw clinical record storage.** ANCHOR does not store raw clinical records.
- **Diagnosis / prescribing / treatment-recommendation logic.** The schema describes evidence *about* AI use; it performs no clinical reasoning.
- **Runtime control platform features.** No tool execution, approval gating, or orchestration is in scope.
- **Any claim that ANCHOR currently ingests external runtime logs.** As of this document, no external connector exists and no runtime ingestion capability is claimed.

---

## 3. Evidence source classes

The schema grades every record by the *class* of its source. Class is descriptive (where did this come from?) and feeds — but is distinct from — the strength grade in §4 (how good is the proof?).

### Class A — Native ANCHOR capture

- **Example source.** Governed Assistant run or Workspace workflow captured inside ANCHOR.
- **Evidence strength.** Typically **Strong** — ANCHOR observed the governed interaction directly.
- **Trust posture.** Highest available today; metadata captured at source within a governed flow.
- **Limitations.** Bounded to what ANCHOR's own governed surfaces capture; says nothing about AI use that never entered ANCHOR.
- **Raw content stored?** No — metadata and hashes only, per the metadata-only doctrine.
- **Human review evidenced?** Yes — review state is captured as part of the governed flow.

### Class B — Verified external runtime / feed

- **Example source.** A future agent-runtime, ambient scribe, or EHR/PMS-adjacent system that supplies structured logs with stable identifiers and timestamps through a built, tested, evidence-graded connector.
- **Evidence strength.** Up to **Moderate** — external structured evidence, not ANCHOR-observed.
- **Trust posture.** Conditional on the connector being verified; depends on the external system's identifiers and clock.
- **Limitations.** ANCHOR did not control the runtime; trust is inherited from the feed, not established by ANCHOR. No such connector exists today.
- **Raw content stored?** No — feeds must be minimised to metadata/hashes before persistence (see §6).
- **Human review evidenced?** Only if the feed carries a trustworthy review signal; otherwise review state is `unknown`.

### Class C — Imported artefact / structured upload

- **Example source.** A user-uploaded export, structured report, screenshot, or PDF describing AI use.
- **Evidence strength.** Typically **Limited** — artefact provided by the user, not captured at source.
- **Trust posture.** Depends entirely on artefact provenance, which ANCHOR cannot independently verify.
- **Limitations.** Tamperable; may be incomplete; provenance is asserted, not proven.
- **Raw content stored?** Default no. If a future, explicitly authorised flow ever stored an artefact, that requires its own legal basis and data-boundary decision (see §6); the receipt should reference the artefact, not embed raw clinical content.
- **Human review evidenced?** Only if the artefact itself records it; treat as `declared` unless independently corroborated.

### Class D — Declared-use / manual attestation

- **Example source.** A staff member records "I used tool X for purpose Y, reviewed before use" with no runtime capture.
- **Evidence strength.** **Weak** — declarative, no verifiable runtime evidence.
- **Trust posture.** Honest self-report; useful for coverage and culture, not for proof of what the tool did.
- **Limitations.** No independent corroboration; relies on the declarer.
- **Raw content stored?** No — declaration metadata only.
- **Human review evidenced?** Only as *declared*; the review claim is itself part of the attestation, not independently verified.

### Class E — Unverified narrative record

- **Example source.** Free-text note describing AI use after the fact, with no structure, identifiers, or attestation discipline.
- **Evidence strength.** **Weak** (weakest usable) — narrative only.
- **Trust posture.** Lowest; captured for completeness and signal, clearly labelled as unverified.
- **Limitations.** No identifiers, no timestamps guaranteed, no corroboration; easy to misremember or misstate.
- **Raw content stored?** No raw clinical content. Narrative metadata should be minimised and must not become a backdoor for raw case material.
- **Human review evidenced?** No, unless separately attested.

---

## 4. Evidence-strength grading

Strength is graded **independently and honestly**, and is the heart of the moat. A record's grade reflects *how verifiable the evidence is*, not how important the AI use was.

- **Strong** — ANCHOR directly captured metadata within a governed workflow (typically Class A).
- **Moderate** — an external system supplied structured logs with stable identifiers and timestamps through a verified feed (typically Class B).
- **Limited** — a user-uploaded artefact or exported report (typically Class C).
- **Weak** — a manual / declarative record with no verifiable runtime evidence (typically Class D or E).

**Honesty rule.** Weak evidence can still be useful — for coverage, culture, completeness, and demonstrating that a clinic is *trying* to govern AI use — **provided it is labelled honestly as weak**. A weak or declarative record must never be presented, exported, or marketed as strong evidence. Over-grading is a doctrine violation, not a presentation choice.

The class→strength mappings above are typical, not automatic. A Class B feed that lacks stable identifiers may grade **Limited**; a Class A capture missing review state may be flagged with an uncertainty state (see §9) even while remaining Strong on source.

---

## 5. Canonical receipt fields

The following is a *field model*, not a database schema or wire format. Exact naming, types, and serialisation are open questions (see §13). Every field below is metadata; none is intended to hold raw clinical, client, or patient content.

| Field | Intent |
| --- | --- |
| `receipt_id` | Stable unique identifier for the evidence record. |
| `receipt_version` | Schema version this record conforms to (e.g. `v0.1`). |
| `evidence_source_class` | One of Class A–E (§3). |
| `evidence_strength` | One of Strong / Moderate / Limited / Weak (§4). |
| `clinic_id` / tenant reference | Tenant the record belongs to; honours existing tenant-isolation posture. |
| `user` / staff role | Role-level attribution of who used the AI (role, not raw identity where avoidable). |
| `reviewer identity or reviewer label` | Who reviewed, or a reviewer label where identity is not stored. |
| `workflow_mode` | Native governed workflow / external feed / declared-use / ambient wrapper. |
| `ai_tool_identity` | The AI/tool involved, where known. |
| `ai_tool_version` | Tool version, where known (may be `unknown` — see §9). |
| `provider_vendor` | Provider/vendor, where known; vendor-neutral by design, never hardcoded. |
| `policy_governance_profile` | The governance/policy profile in force for this use. |
| `permitted_use_category` | The permitted-use category the use falls under. |
| `prohibited_use_boundary` | The prohibited-use boundary asserted (e.g. no diagnosis/prescribing/treatment). |
| `data_boundary` | Declared data boundary for the use (metadata-only / what was/ wasn't shared). |
| `raw_content_stored` | Boolean. Expected `false` by default across all classes. |
| `input_hash` / `output_hash` | Hashes where applicable; never the raw input/output. |
| `timestamps` | Creation and relevant event timestamps (source-supplied vs ANCHOR-observed should be distinguishable). |
| `human_review_state` | e.g. reviewed / not reviewed / declared / unknown. |
| `review_decision` | The reviewer's decision (e.g. approved / amended / rejected), where evidenced. |
| `output_use_decision` | Whether/how the AI output was used operationally after review. |
| `client_transparency_posture` | Whether client-facing AI-use disclosure applies (see §8). |
| `consent_disclosure_posture` | Consent/disclosure posture where applicable. |
| `safety_refusal_flags` | Safety/refusal signals (e.g. a hard-refusal boundary was triggered). |
| `incident_near_miss_linkage` | Link to any related incident / near-miss record. |
| `retention_posture` | Retention intent for this record. |
| `deletion_offboarding_posture` | Deletion / offboarding intent for this record. |
| `linked_artefacts` | References to related artefacts (not embedded raw content). |
| `standards_professional_mapping` | High-level mapping to professional/standards themes (see §10). |
| `non_claims` | The explicit non-claims this record carries (see §11). |

---

## 6. Data boundary model

- **Metadata-only by default.** The schema is metadata and hashes. This preserves the existing ANCHOR doctrine.
- **No raw content by default.** Raw prompts, outputs, transcripts, drafts, clinical notes, and identifiable case material are **not stored** unless a future, *explicitly authorised* product flow exists **and** a lawful basis is established for it. Absent both, `raw_content_stored` is `false`.
- **Metadata may still be personal data.** "Metadata-only" narrows risk; it does not remove personal-data analysis under UK GDPR / DPA 2018. Names, roles, reviewer attribution, timestamps, and identifiers can be personal data even with no clinical content.
- **Public / pre-clinic intake is a separate perimeter.** Public intake data (demo/start/site-chat) sits **outside** the clinic-governance metadata perimeter and must continue to be handled under its own UK-GDPR-governed posture and retention controls. It is not mixed into clinic-governance receipts.
- **External feeds must be minimised before ingestion.** Any future Class B feed must be transformed to metadata/hashes *before* persistence; raw external payloads are not landed verbatim. Whether transformation happens pre- or post-boundary is an open question (§13), but minimisation-before-persistence is the rule.

---

## 7. Human review and professional accountability

The schema is explicitly tied to ANCHOR's human-review doctrine:

- **Human review is required before operational use** of AI output. The `human_review_state` and `review_decision` fields exist to evidence that review, not to substitute for it.
- **Professional judgement remains with the vet / vet nurse / clinic.** ANCHOR never holds clinical accountability; it evidences governance posture around a human decision.
- **Receipts evidence governance posture, not clinical correctness.** A receipt shows that a governed process was followed and at what evidence strength — it does **not** assert that the clinical content was right, safe, or appropriate.

---

## 8. Client transparency and explainability posture

Where relevant, a record should carry posture (not raw content) on:

- **Whether client-facing AI-use disclosure exists** for the interaction.
- **Whether AI involvement was material** to a client communication.
- **Whether the workflow was internal-only** (no client-facing output).
- **Whether explanation to the service user / caregiver is required or not applicable** for this use.

These map to the existing client-transparency layer and are captured as posture flags so the Trust Pack can present an honest transparency picture without storing the underlying communication.

---

## 9. Failure, fallback, and uncertainty states

Honest governance requires first-class *uncertainty* states. The schema must represent, rather than hide, incomplete evidence:

- **Unknown tool version** — `ai_tool_version = unknown`.
- **Missing external log** — expected feed evidence absent.
- **Failed connector import** — a future ingestion attempt that did not complete.
- **Partial evidence** — some fields captured, others missing.
- **Manual declaration only** — Class D/E with no runtime corroboration.
- **No human review recorded** — `human_review_state = unknown` / `not reviewed`.
- **Content hash unavailable** — hashing not possible for this record.
- **External source not verified** — Class B feed whose provenance is not established.

A record in any of these states is still recorded — clearly labelled — rather than silently upgraded or dropped. Uncertainty labelled honestly is more defensible than false completeness.

---

## 10. Standards and accountability mapping

Mappings are **high-level and directional**, not claims of conformance. The hierarchy below is deliberate and must be preserved.

1. **RCVS Code and RCVS AI / professional-accountability expectations** — the **primary** UK veterinary anchor. ANCHOR's evidence model is oriented first to professional accountability for veterinary teams in the UK.
2. **UK GDPR / Data Protection Act 2018 / ICO AI and automated-decision-making guidance** — the personal-data and automated-decision-making anchors, at a high level. Metadata may be personal data; ADM/profiling considerations apply where relevant.
3. **ISO/IEC 42001** — a **voluntary** AI management-system / evidence-management reference. Useful as evidence-management logic; not a certification ANCHOR holds or claims.
4. **EU AI Act readiness** — **conditional / future-proofing only**, relevant **where EU exposure exists** (e.g. EU-facing clinic groups, cross-border clinics, insurers with EU exposure, education providers, or future EU expansion). It is **not** the primary anchor for UK-only veterinary use and **not** the schema's organising principle.

**Do not** make the EU AI Act the primary UK-only veterinary sales or schema anchor. **Do not** claim EU AI Act compliance. Legal applicability of any of the above requires qualified advice.

---

## 11. Non-claims

Every receipt carries, and this schema asserts, the following non-claims explicitly:

- A receipt **does not prove clinical correctness**.
- A receipt **does not prove patient safety**.
- A receipt **does not prove regulatory compliance**.
- A receipt **does not make a clinic RCVS-compliant, GDPR-compliant, or EU AI Act-compliant**.
- A receipt **does not replace professional judgement**.
- A receipt **does not prove that an external AI tool was safe**.
- A weak / declarative record **must not be marketed as strong evidence**.

ANCHOR remains **aligned, not compliant**. No RCVS approval, certification, regulator endorsement, or enforcement protection is claimed or implied by any receipt or by this schema.

---

## 12. Future roadmap integration

The schema is the connective tissue across current and future surfaces. It is a *target model* to design toward, not a description of shipped connectors.

- **Current native ANCHOR Workspace / receipts** — Class A is the present-tense reality; existing governed Assistant/Workspace receipts are the first instances of this model.
- **Future M6.12 vendor-neutral connector layer** — the future home of Class B verified external feeds. **Gated future work; not started.** No connector is implemented by this document.
- **Future M6.13 ambient governance integration** — the future home of ambient/chatbot/ad hoc wrapper evidence. **Gated future work; not started.**
- **Phase 2B AI Tool Governance Notes** — declared-use (Class D) and lightweight tool-governance records map here.
- **Future insurer / acquisition / procurement packs** — the evidence-strength grading is what makes these packs defensible; the schema is designed to feed them honestly.

**Hard guardrails:**

- **No external connector is implemented by this document.**
- **No runtime ingestion capability should be claimed** until a connector is built, tested, and evidence-graded. Until then, Class B exists in the schema as a *target*, not a live capability.
- M6.12 / M6.13 remain **gated future** and require an explicit founder decision recorded in an addendum before any build.

---

## 13. Open questions

- **Exact field naming** — the §5 names are intent labels, not final identifiers.
- **Which external systems are the likely first evidence feeds** — agent runtimes, ambient scribes, or EHR/PMS-adjacent systems, and in what order.
- **Whether external feed payloads should be transformed into metadata-only receipts before persistence** — the boundary placement of minimisation (pre-ingest vs at-ingest).
- **How to handle screenshots / PDFs / manual declarations** — Class C/D artefact referencing without storing raw clinical content.
- **How to display evidence strength in the Trust Pack** — presentation that communicates strength honestly without over-signalling weak records.
- **Whether future public copy should mention evidence grades** — and if so, how to do it without implying certification or over-claiming.

---

## 14. Recommended next action

The next action is **not** connector implementation.

The next action is to **review this schema against the existing ANCHOR receipt fields and the Trust Pack evidence model**, then **identify gaps for a future implementation brief**. That review should confirm where Class A already maps cleanly to shipped receipts, where the field model diverges from what is captured today, and which open questions in §13 must be resolved before any implementation brief is written. No build, connector, or runtime ingestion is authorised by this document.
