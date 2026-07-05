# RCVS / VATA Scenario Matrix

> **Documentation-only scenario planning (5 July 2026).** The final RCVS / VATA framework or post-consultation output has **not** been reviewed and its content is **not** assumed. These are contingency shapes, not predictions. No scenario text is public copy. ANCHOR is **aligned, not compliant**; nothing here claims approval, certification, or endorsement.

Each scenario uses the same eight fields. "Strongest ANCHOR surfaces" refers to shipped surfaces (Roadmap v2.6 §2–§6) unless marked *(experiment branch)* — items on `fable/roadmap-completion-experiment` are unmerged and gated.

---

## Scenario 1 — Provider-heavy framework

**What the document would likely say:** Most obligations and disclosure expectations fall on AI *providers/vendors* — documentation, validation disclosure, intended-use statements, support and escalation, data handling — with practices cast mainly as informed buyers.

**What this means for ANCHOR:** ANCHOR is not an AI provider of clinical tools and is a downstream governance layer, so direct obligations would mostly attach to *other* companies. The practice-side value shifts to helping clinics *consume* provider disclosures and record buyer-side diligence.

**Strongest surfaces:** Governance receipts and human-review trail (evidence of governed use regardless of tool); Policy Library + attestation; the future AI Tool Governance Notes rationale (Phase 2B — question structuring around provider disclosures); client transparency layer.

**Roadmap implications:** Strengthens the case for prioritising Phase 2B AI Tool Governance Notes *after* existing gates — a founder decision, not automatic. Core Phase 2A surfaces unchanged.

**Legal/commercial implications:** Check whether any provider-side expectations could be read as touching ANCHOR itself (e.g. disclosure expectations for *any* AI-adjacent software sold to practices). Solicitor question: does ANCHOR's own product documentation meet the spirit of provider disclosure expectations, given ANCHOR is not a clinical AI tool?

**Public wording implications:** Emphasise "ANCHOR helps practices structure the questions and record the evidence gaps around the AI tools they use" — structurer, not arbiter.

**What not to claim:** That ANCHOR assesses, validates, rates, accredits, or approves providers; that ANCHOR is exempt from the framework; "framework-compliant".

**Recommended next action:** Run the comparison protocol §4 (provider/practice orientation test); founder decision on Phase 2B timing; solicitor review of ANCHOR's own disclosure posture.

---

## Scenario 2 — Clinic/practice-heavy framework

**What the document would likely say:** The weight falls on *practices*: duties to inventory AI use, set policy, train staff, supervise outputs, inform clients, and keep records of AI-assisted work.

**What this means for ANCHOR:** Strongest plausible outcome for ANCHOR's current shape — nearly every practice-side duty maps to a shipped surface.

**Strongest surfaces:** Policy Library + staff attestation (2A-2); CPD-recordable AI literacy (2A-1); RCVS-style self-assessment (2A-3); client transparency (2A-4); incident/near-miss logging (2A-5); receipts + human-review workflow (M6); Trust Pack.

**Roadmap implications:** Validates the Phase 2A wedge as built. Possible acceleration pressure on M5.7 onboarding *(experiment branch)* so practices can adopt quickly — still gated behind security/legal.

**Legal/commercial implications:** Demand may firm up; the mandatory gates (security audit completion, legal pack with solicitor review) become the critical path to being able to say yes to anyone.

**Public wording implications:** "ANCHOR helps clinics evidence responsible AI governance practices aligned with emerging professional expectations" — the existing approved line already fits.

**What not to claim:** That using ANCHOR discharges any practice duty; "RCVS compliant"; that the framework requires ANCHOR or any software.

**Recommended next action:** Map each practice-side expectation to a surface via the protocol; refresh Readiness Map v1.1 §3 statuses; founder decision on pilot-gate sequencing.

---

## Scenario 3 — Evidence-heavy framework

**What the document would likely say:** Emphasis on *records*: documented human oversight, retained review decisions, auditable trails of AI-assisted outputs, and demonstrable training records.

**What this means for ANCHOR:** The receipt/traceability architecture becomes the headline. Metadata-only posture is a differentiator (evidence without storing clinical content).

**Strongest surfaces:** Governance receipts; assistant run traceability and review states; R3 evaluation registry; CPD exports with hashes; admin audit events; Trust Pack evidence aggregation.

**Roadmap implications:** Possible pressure to deepen evidence exports (receipt bundles, evidence packs). Check the receipt schema work (`docs/strategy/2026-06-11_anchor_ai_governance_receipt_schema_v0_1.md`) against any stated record expectations.

**Legal/commercial implications:** Retention questions sharpen — align with the R2 retention note; solicitor question on how long evidence should be retained versus what ANCHOR promises.

**Public wording implications:** "Metadata-only evidence of AI-use governance, human review, and traceability" — already the approved formulation.

**What not to claim:** That ANCHOR records prove clinical correctness or satisfy any statutory record-keeping duty; "audit-proof".

**Recommended next action:** Protocol §5 (evidence requirement test); gap list receipts vs stated record expectations; founder decision on evidence-export polish priority.

---

## Scenario 4 — Principle-only framework

**What the document would likely say:** High-level principles (accountability, transparency, oversight, proportionality) without operational specifics, metrics, or record requirements.

**What this means for ANCHOR:** No new hard requirements to map; the value story stays conviction-based (Addendum v1.3). Risk: buyers feel no urgency.

**Strongest surfaces:** The whole governed loop as a coherent story — principles need *some* operationalisation and ANCHOR is one credible way to do it.

**Roadmap implications:** No change. Do not invent requirements the document does not state.

**Legal/commercial implications:** No new legal exposure; commercial urgency argument must lean on professional-judgement and good-governance conviction, not obligation.

**Public wording implications:** Keep to "aligned with the direction of emerging professional expectations"; avoid implying the principles mandate anything specific.

**What not to claim:** That the framework requires records, tools, or training; that ANCHOR "implements" the framework.

**Recommended next action:** Terminology extraction only (protocol §11); light Readiness Map wording refresh; no roadmap change without founder decision.

---

## Scenario 5 — AI-literacy-heavy framework

**What the document would likely say:** Strong emphasis on staff understanding, competence to critically assess outputs, ongoing learning, and possibly role-specific expectations.

**What this means for ANCHOR:** Learn/CPD surfaces move to the front. Wording discipline becomes the hardest constraint: literacy emphasis will tempt competence claims, which remain forbidden.

**Strongest surfaces:** 2A-1 CPD-recordable AI literacy (catalogue, completions, exports); why-flagged → Learn linkage; attestation; M4.6 maturity surfaces *(experiment branch — self-checks, role paths, renewals; non-certifying by construction)*.

**Roadmap implications:** Possible founder decision to merge/ship the M4.6 experiment work earlier — reviewing its non-certifying wording first.

**Legal/commercial implications:** Solicitor question: what may ANCHOR say about training records if the framework references staff understanding? Keep "records of learning activity", never "evidence of competence".

**Public wording implications:** "CPD-recordable AI literacy activity and metadata-only completion evidence"; "not certified CPD; not proof of competence".

**What not to claim:** RCVS-accredited CPD; certified training; pass/fail competence; that completions demonstrate staff are competent.

**Recommended next action:** Protocol §6 (AI literacy test); wording sweep of all Learn/CPD copy; founder decision on M4.6 merge timing.

---

## Scenario 6 — Human-review / accountability-heavy framework

**What the document would likely say:** Qualified human oversight as the central control: outputs verified before use, clear responsibility for decisions, no delegation of professional judgement to AI.

**What this means for ANCHOR:** The human-review gate and review-state evidence are the core match; this echoes the current published RCVS advice, so continuity is high.

**Strongest surfaces:** Review workflow (reviewed_by/at, decisions); output-blocked path and hard clinical boundaries; refusal/safety codes; receipts carrying review posture; 2A-C.5E hard-refusal harness *(experiment branch)*.

**Roadmap implications:** Reinforces the live-generation safety gate discipline; no production change — the gate and founder decision remain preconditions.

**Legal/commercial implications:** Low new exposure; strengthens the existing narrative. Confirm review-responsibility wording says the clinic retains accountability.

**Public wording implications:** "Human review required"; "ANCHOR keeps professional review visible and required before operational use"; "does not replace veterinary judgement".

**What not to claim:** That ANCHOR performs or guarantees the review; that oversight duties are discharged by using ANCHOR.

**Recommended next action:** Protocol §7 (human review test); map review-state vocabulary against any terms the document introduces; adopt its terminology in labels only where accurate.

---

## Scenario 7 — Client-transparency-heavy framework

**What the document would likely say:** Practices should tell clients where AI is used, its role and limits, and possibly obtain or record consent/choice for some uses.

**What this means for ANCHOR:** 2A-4 becomes the lead surface. Watch for consent-recording expectations — ANCHOR currently evidences *disclosure*, not consent capture.

**Strongest surfaces:** Client-Facing Transparency Layer (templates, profiles, publish/preview); client-safe receipt framing; not-chat-history copy.

**Roadmap implications:** If consent/choice recording is emphasised, a metadata-only consent-evidence surface becomes a candidate — new scope, founder decision, privacy review required.

**Legal/commercial implications:** Consent language is legally sensitive — solicitor input before any consent-related copy or feature. UK GDPR framing questions likely.

**Public wording implications:** "Helps clinics communicate bounded AI-use practices clearly to clients"; never "obtains consent" or "ensures clients are informed".

**What not to claim:** That published statements satisfy any legal consent duty; Article 50 or UK GDPR conclusions for a specific clinic.

**Recommended next action:** Protocol §8 (client transparency test); compare disclosure template themes to any stated disclosure content; founder decision on consent-evidence scope.

---

## Scenario 8 — External-tool-inventory / declared-use-heavy framework

**What the document would likely say:** Practices should maintain an inventory of AI tools in use, assess providers against disclosure categories, and keep records of that diligence (the consultation draft's provider-disclosure themes suggest this is plausible).

**What this means for ANCHOR:** The strongest pull toward Phase 2B (AI Tool Governance Notes). ANCHOR's self-assessment already includes a tool/vendor inventory item; a fuller structured layer remains future/gated.

**Strongest surfaces:** Self-assessment (tool_vendor_inventory item); Policy Library; the Phase 2B question-set mapping (`docs/product/2026-06-18_ai_tool_assessment_question_set_mapping.md`) as design groundwork.

**Roadmap implications:** Strong candidate for the founder to promote Phase 2B — still explicitly a founder decision after RC/security/legal priorities (source note discipline), and ANCHOR stays a **structurer, not arbiter**.

**Legal/commercial implications:** Sharpen the non-arbiter boundary in any copy; solicitor question on liability wording if practices record diligence inside ANCHOR.

**Public wording implications:** "Practice-side question structuring and evidence-gap governance"; locked citation wording from the source note only.

**What not to claim:** That ANCHOR rates/validates/certifies/approves tools; that an ANCHOR record makes a procurement decision defensible; "framework-compliant" tool assessments.

**Recommended next action:** Protocol §9 (external tool inventory test); map disclosure categories in the final document against the question-set mapping; founder decision memo on Phase 2B.

---

## Scenario 9 — No strong new signal / broad cautious framework

**What the document would likely say:** A cautious post-consultation output — themes restated, further work signalled, no firm practice-side or provider-side operational expectations yet.

**What this means for ANCHOR:** Nothing changes materially. The discipline is to *not* manufacture significance. Position remains conviction-based per Addendum v1.3.

**Strongest surfaces:** Unchanged — the full existing stack.

**Roadmap implications:** None. Continue the existing gate sequence (security completion, legal pack, RC sign-off).

**Legal/commercial implications:** None new. Avoid marketing that overstates the document's weight.

**Public wording implications:** At most: "ANCHOR continues to track emerging professional expectations, including the RCVS and Digital Practice-led consultation." No stronger linkage.

**What not to claim:** Momentum, endorsement, or requirement that the document does not create; that ANCHOR "anticipated" the framework.

**Recommended next action:** Record a short source-note update with date/version; set the next review trigger; no other action.

---

*Documentation-only. No scenario is a prediction; no scenario text is public copy. Wording controls: Readiness Map v1.1 §2 and the 18 June 2026 source note.*
