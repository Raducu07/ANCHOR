# Veterinary AI Vendor Transparency — Source Note

| Field | Value |
| --- | --- |
| Status | Internal source-discipline note. |
| Date captured by ANCHOR | 18 June 2026. |
| Purpose | Record the source hierarchy and citation discipline for future **AI Tool Governance Notes** (Phase 2B commercial-leverage extension per Roadmap v2.6 §2). |
| Owner | Founder / Product Owner. |
| Doctrine governance | "Aligned, not compliant" (Roadmap v2.6 §1). All wording controlled by Readiness Map v1.1 §2. |

> This note records *evidence and source hierarchy only*. It does not authorise, schedule, or accelerate any build. AI Tool Governance Notes remain **Future / Phase 2B** per Roadmap v2.6 §2 and Readiness Map v1.1 §4 (Article 13). No feature work is implied.

---

## 0. Provenance update (18 June 2026)

When this note was first written, the AI Provider Information Framework was recorded conservatively as a "supplementary, unverified external draft working paper" by the Veterinary AI Transparency Alliance. That classification has been **corrected** following the RCVS news item published 17 June 2026, which confirms the Alliance is **led by the Royal College of Veterinary Surgeons (RCVS) and Digital Practice** and is consulting the veterinary professions on the framework.

- **Corrected classification:** Veterinary AI Transparency Alliance / AI Provider Information Framework — **RCVS and Digital Practice-led consultation draft; regulator-adjacent; not final RCVS guidance; not a compliance standard.**
- **Provenance source (RCVS news page):** https://www.rcvs.org.uk/about-us/news-and-views/news/transparency-alliance-consults-the-veterinary-professions-on-responsible-ai-framework (published 17 June 2026).
- **What this does not change:** it remains a **consultation draft**, not final RCVS guidance, not a compliance standard, and **not regulator endorsement of ANCHOR**. The improved provenance makes the framework strategically material as an RCVS-led consultation source, but it does **not** authorise Phase 2B implementation. AI Tool Governance Notes remain **future Phase 2B planning / source discipline only**, gated behind explicit founder prioritisation after RC / security / legal / design priorities. ANCHOR remains a **structurer, not an arbiter**.

---

## 1. Why this note exists

ANCHOR currently governs **AI-use behaviour and evidence inside the clinic** (receipts, human review, Learn/CPD, policy/attestation, self-assessment, client transparency, incident/near-miss, Trust Pack). A separate *future* layer may help clinics **structure due diligence around third-party AI tools** they buy, evaluate, or already use.

This note records the source base for that possible future layer so that, if and when the founder promotes it, the evidence and citation discipline are already fixed and defensible. It does not move the layer ahead of current release-candidate, security, legal, or design priorities.

**Positioning discipline (carried into every downstream artefact):** the future wedge is *not* "ANCHOR rates AI tools." It is "ANCHOR helps practices structure the questions, evidence gaps, review records, and governance trail around AI tools they are considering or already using." ANCHOR is the **structurer, not the arbiter**.

---

## 2. Source hierarchy

1. **RCVS AI in practice advice** — current UK professional advice / highest professional anchor for ANCHOR's UK-first veterinary positioning.
2. **RCVS and Digital Practice-led AI Provider Information Framework consultation** — regulator-adjacent consultation draft / emerging framework source; not final RCVS guidance; not a compliance standard. (Classification corrected 18 June 2026 — see §6 and the provenance update below.)
3. **Frontiers in Veterinary Science commercial veterinary AI transparency audit** — peer-reviewed evidence anchor for the vendor-transparency problem. North American market / public-documentation scope; single-study; must be cited with strict scope caveats.
4. **Earlier uploaded VATA draft text** — now treated as the draft framework content behind the RCVS-led consultation, not as an unverified standalone authority.

---

## 3. Explicit non-claims

This note (and anything built on it) does **not** constitute or imply:

- Legal advice.
- RCVS approval.
- RCVS guidance — *unless* a point is sourced directly to an RCVS URL below.
- A compliance standard.
- A certification basis.
- Evidence that ANCHOR is approved, required, compliant, or endorsed.
- Evidence that ANCHOR validates, rates, certifies, accredits, recommends, or approves third-party AI tools.

ANCHOR remains a **structurer of questions and evidence gaps**, never an arbiter of third-party tool safety, quality, or suitability.

---

## 4. RCVS AI in practice advice — UK professional anchor

**Direct RCVS sources:**

- RCVS Standards and Advice — Spring 2026 update:
  https://www.rcvs.org.uk/veterinary-professionals/conduct-and-guidance/resources-and-updates/standards-and-advice-spring-2026-update
- RCVS "Using artificial intelligence (AI) in practice — advice for the profession":
  https://www.rcvs.org.uk/veterinary-professionals/conduct-and-guidance/resources-and-updates/using-artificial-intelligence-ai-in-practice-advice-for-the-profession

**RCVS-supported points (source-linked directly to the two RCVS URLs above):**

- Professional and clinical decision-making must not be wholly delegated to AI.
- Veterinary surgeons and veterinary nurses remain responsible for their decision to use AI tools and for how outputs are used.
- The person using an AI tool should have sufficient understanding of the subject matter to critically assess the tool's outputs.
- Client confidentiality and rights under the Data Protection Act 2018 and UK GDPR should be considered and maintained.
- Where AI tools generate clinical records, outputs should be manually verified.
- The RCVS AI advice includes practical questions around: intended scope; limitations; data storage; training data; whether live client data is used for continued learning; and whether the tool is closed or accessible/editable by the developer.

This is the high-authority UK professional anchor for ANCHOR. The RCVS and Digital Practice-led consultation draft (see §6) is a regulator-adjacent consultation source that sits alongside it in the hierarchy, but as a **consultation draft it is not final RCVS guidance** and does not displace current published RCVS AI-in-practice advice.

---

## 5. Frontiers in Veterinary Science audit — peer-reviewed evidence anchor (scope-caveated)

**Source:**

- Title: "A systematic audit of transparency and validation disclosure in commercial veterinary artificial intelligence"
- Author: David Brundage
- Journal: Frontiers in Veterinary Science
- Published: 5 March 2026
- DOI: 10.3389/fvets.2026.1761038
- URL: https://www.frontiersin.org/journals/veterinary-science/articles/10.3389/fvets.2026.1761038/full

**Study facts (captured accurately):**

- Peer-reviewed, single-author, cross-sectional systematic audit.
- 71 commercially available clinical veterinary AI products.
- Products available in the **North American market**.
- Search strategy centred on North American veterinary conference exhibitor lists, US app stores, Crunchbase, LinkedIn, and US-based search methods.
- Administrative and direct-to-consumer tools were **excluded**.
- The audit was limited to **publicly available documentation**; vendors may hold private validation material not visible publicly.
- The audit used a 25-point **Veterinary AI Transparency Index (VATI)**.
- VATI was adapted from FDA Good Machine Learning Practice, CONSORT-AI, and CHAI Model Card framework sources.
- Mean unweighted transparency score across the cohort was **6.4%**.
- **63.3% (n = 45)** of vendors disclosed **none** of the audited transparency metrics. The correct public interpretation is that this means **no public information on model development, validation, or safety** for those products.
- **Only one vendor (1.4%) disclosed training-data signalment distribution and subgroup performance analysis.** *(Phrase exactly as written. Do not phrase this as "signalment or subgroup performance.")*

**Study limitations (must travel with any citation):**

- Single-rater primary audit.
- No second independent reviewer for the full dataset.
- No inter-rater reliability check across the full dataset.
- Nevertheless, the paper reports a **blinded re-audit of 20%** with high **intra-rater** reliability.
- Public citation wording must not universalise the finding beyond its North American / public-documentation / single-study scope.

**Useful strategic direction from the paper (for ANCHOR's structurer role only):**

- It proposes a veterinary model-card-style framework functioning like a "nutrition label" for AI.
- It proposes independent third-party accreditation.
- ANCHOR may use this only to support **structured disclosure capture, buyer-side question structuring, and evidence-gap governance**.
- ANCHOR must **not** build an accreditation, certification, validation, safety-rating, recommendation, or third-party approval layer.

### 5.1 Locked public-facing citation wording

Use exactly:

> "A 2026 peer-reviewed audit of 71 North American commercial clinical veterinary AI products found that 63.3% disclosed none of the audited transparency metrics — no public information on model development, validation, or safety."

### 5.2 Wording **not** to use

- "63.3% of veterinary AI vendors disclose no validation data."
- "Most veterinary AI vendors disclose no validation data."
- "UK veterinary AI vendors disclose no validation data."
- "Veterinary AI is unvalidated."
- "ANCHOR solves vendor validation."
- "ANCHOR validates AI tools."
- "ANCHOR accredits AI tools."

### 5.3 Exact training-data correction

Use exactly:

> "Only one vendor (1.4%) disclosed training-data signalment distribution and subgroup performance analysis."

Do **not** phrase this as "signalment or subgroup performance."

---

## 6. RCVS and Digital Practice-led AI Provider Information Framework — consultation draft (regulator-adjacent)

**Corrected classification (18 June 2026):** Veterinary AI Transparency Alliance / AI Provider Information Framework — **RCVS and Digital Practice-led consultation draft; regulator-adjacent; not final RCVS guidance; not a compliance standard.**

**Source:**

- Title: "AI Provider Information Framework for Veterinary Practice"
- Convened by: Veterinary AI Transparency Alliance — stakeholder organisations and individuals from across the veterinary, technology and regulatory worlds — **led by the Royal College of Veterinary Surgeons (RCVS) and Digital Practice**.
- Status: **RCVS-led consultation source**; open for consultation; **not final RCVS guidance**.
- Provenance source (RCVS news page): https://www.rcvs.org.uk/about-us/news-and-views/news/transparency-alliance-consults-the-veterinary-professions-on-responsible-ai-framework
- Published: 17 June 2026.

**Facts recorded from the RCVS source (17 June 2026):**

- The Veterinary AI Transparency Alliance is described as stakeholder organisations and individuals from across the veterinary, technology and regulatory worlds.
- The Alliance is led by the Royal College of Veterinary Surgeons (RCVS) and Digital Practice.
- The framework supports safe, proportionate and informed adoption of AI tools in veterinary settings through best-practice guidance for both AI providers and veterinary practices.
- It was developed over 18 months with input from veterinary professionals, developers, practices, regulators, insurers, educators, members of the wider practice team and animal owners.
- It contains 23 principles.
- It covers issues including human oversight requirements, data storage and usage, risk, and the potential impact of AI use on client consent and choice.
- It sets out information AI providers should disclose, why it matters, minimum guidance expectations, and notes for veterinary professionals on assessing provider information.
- The survey closes Monday 6 July at 5pm.

**Status discipline — still a consultation draft:**

- A **regulator-adjacent consultation draft**, not final RCVS guidance.
- Not a compliance standard.
- **Not regulator endorsement of ANCHOR.**
- Not regulator output / not adopted regulation.
- Not legal advice.
- Not a roadmap authority and **does not authorise Phase 2B implementation**.
- **Future Phase 2B planning / source discipline only** — not a reason to reshape ANCHOR ahead of current RC / security / legal / design priorities.

Useful as an **emerging-framework source for future planning**, describing buyer-side questions a practice *might* ask and the information providers should disclose.

**Useful themes:**

- Risk-proportionate scrutiny.
- Qualified human oversight.
- Visible limitations, contraindications, exclusions, and failure modes.
- Client and data transparency.
- Buyer-side questions practices may ask providers.
- Provider disclosure categories such as: intended use, excluded use, autonomy, integrations, versioning, human oversight, competency assumptions, support/escalation, client communication, consent/choice, veterinary involvement, validation/testing, evidence base, training data/provenance, third-party models, performance, failure modes, data inputs/storage/ownership/secondary use, and data-protection posture.

ANCHOR may borrow these *themes* to structure questions. ANCHOR must **not** describe any output as "framework-compliant", must not claim ANCHOR "aligns with" or "is built around" the RCVS framework, and must not treat the consultation draft as a product-requirements authority.

---

## 7. ANCHOR interpretation

- The demonstrated problem is **vendor transparency asymmetry**: across the audited North American cohort, most products publish little or nothing about model development, validation, or safety.
- Practices carry **professional responsibility** for their use of AI tools (RCVS), while often **lacking public provider disclosure** to inform that responsibility.
- ANCHOR can **structure the governance questions and record the evidence gaps** without becoming a validator, certifier, accreditor, recommender, or arbiter.
- This supports a future **AI Tool Governance Notes** layer but does **not** accelerate implementation before release-candidate, security, legal, and design gates.

---

## 8. Citation discipline

- Public claims should rely on **RCVS and peer-reviewed/official sources first**.
- Frontiers claims must preserve **North American / public-documentation / single-study** scope.
- The framework can only be described as an **RCVS and Digital Practice-led consultation draft** — regulator-adjacent, but **not final RCVS guidance**, not a compliance standard, and not regulator endorsement of ANCHOR.
- Do **not** use "framework compliant."
- Do **not** say ANCHOR assesses clinical safety or validates AI tools.

---

## 9. Review triggers

Re-open and re-check this note when any of the following occur:

- RCVS updates its AI advice.
- The RCVS / Digital Practice consultation closes (survey closes Monday 6 July at 5pm) or a final framework / final RCVS guidance is published.
- Solicitor review.
- Before any public copy references vendor-transparency claims.
- Before implementing AI Tool Governance Notes.
- Before any procurement/export feature is used with real clinics.

---

## 10. Related ANCHOR documents

- Evidence and positioning: [`../../product/2026-06-18_ai_tool_governance_notes_evidence_and_positioning.md`](../../product/2026-06-18_ai_tool_governance_notes_evidence_and_positioning.md)
- Question-set mapping draft: [`../../product/2026-06-18_ai_tool_assessment_question_set_mapping.md`](../../product/2026-06-18_ai_tool_assessment_question_set_mapping.md)
- Operative canon: `../../canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md`; `../../canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md`; `../../canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md`.

*Source note — 18 June 2026 — internal source-discipline only. Not legal advice. Not RCVS guidance except where sourced directly to RCVS. Documentation only; authorises no build, no paid pilot, no real clinic data.*
