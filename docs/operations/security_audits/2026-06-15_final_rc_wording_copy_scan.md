# ANCHOR 2A-D Final RC Wording / Copy Scan v1

> **Internal wording / copy audit artefact.** This is a release-candidate wording scan of ANCHOR **backend-held** canonical, operations, strategy, and commercial / legal documentation. It is **not legal advice**, **not solicitor review**, **not final RC sign-off**, and **not authorisation** for paid pilots, real clinic data, billing, Stripe activation, or live Workspace generation. It records findings only; it modifies no existing document.
>
> ANCHOR is **governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics** — **not** clinical decision-making AI. ANCHOR is **aligned, not compliant**. Live Workspace generation **remains production-off**.

---

## 1. Status and purpose

This artefact is an internal wording / copy audit run as part of 2A-D release-candidate hardening. Its purpose is to scan the backend-held document set for prohibited or risky claims, non-claim drift, and readiness-gap wording **before any external use**, and to classify each finding conservatively.

It is explicitly:

- **Not legal advice** and **not solicitor review**.
- **Not** final RC sign-off — it is one input to a future sign-off, not the sign-off itself.
- **Not** authorisation for pilots, real clinic data, billing, Stripe, live generation, or connectors.

No existing document was edited as a result of this scan. Findings live in this artefact only (per the brief: record issues here, do not modify source docs).

## 2. Scope reviewed

**Reviewed (backend-held docs):**

- **Canonical** — `docs/canonical/`: Roadmap v2.6 (`ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md`), Readiness Map v1.1 (`ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md`), Addendum v1.3 (`ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md`). The `.docx` counterparts were treated as mirrors of the `.md` operative text and not separately parsed.
- **Commercial / legal** — `docs/commercial/README.md` and all 12 artefacts (legal/commercial pack outline, privacy/data-boundary outline, DPA outline, pilot agreement outline, AUP outline, clinic onboarding checklist, founder pilot approval checklist, commercial/legal readiness checkpoint, solicitor review bundle index, solicitor pack dispatch checklist, personal data / data-flow inventory, commercial order form outline).
- **Operations** — `docs/operations/README.md`, `env.md`, `backup_restore.md`, `intake_retention.md`, `incident_response.md`, `2026-06-08_founder_status_summary.md`, and the `security_audits/` checkpoint trail (operational resilience checkpoint + dependency/deploy/version-metadata artefacts).
- **Strategy** — `docs/strategy/README.md`, `2026-06-11_anchor_ai_governance_receipt_schema_v0_1.md`, `2026-06-15_anchor_receipt_schema_gap_analysis_v0_1.md`.
- **Guardrail** — `CLAUDE.md`.

**Spot-checked, outside the primary scope list (flagged as a watch item):**

- `docs/governance/policies/*` and `docs/governance/client_transparency/*` — clinic-facing policy / transparency **templates**. These are not in the brief's scope list but are clinic-facing, so a spot-check was run (see §10 / §11).

**Intentionally NOT reviewed:**

- **Frontend public Legal + Trust Centre copy** (separate surface, `anchor-portal` repo). Out of this repository; flagged as the primary follow-up in §11.
- Application code, migrations, tests — out of scope for a wording scan and untouched by doctrine.

## 3. Legal skill / review method

**No dedicated Claude legal / solicitor / commercial / privacy skill is installed.** A search of `.claude/skills/` returned only three skills: `anchor-backend-safety-review`, `anchor-doctrine-check`, and `anchor-security-audit`. There is no `anchor-legal-prep` or any `*legal*` / `*solicitor*` / `*commercial*` / `*privacy*` skill.

**Method used.** The audit was conducted against:

- `CLAUDE.md` (project guardrail doctrine);
- the operative canon in `docs/canonical/` (Roadmap v2.6, Readiness Map v1.1 — especially **§2 wording controls** — and Addendum v1.3);
- the repository's own wording-control skill **`.claude/skills/anchor-doctrine-check/SKILL.md`**, whose hard-rejection list (compliance/certification claims, clinical-AI drift, present-tense vendor-neutrality, raw-content storage, buyer-discovery drift, gated-future-as-current, live-generation enablement, GPAI framing, aligned-not-compliant violations) was used as the classification rubric.

This is a doctrine/wording scan, **not** a legal review. It does not substitute for solicitor review.

## 4. Executive result

**Result: PASS WITH WATCH ITEMS.**

- **0 BLOCKERS** — no wording materially misrepresents ANCHOR and no document authorises a gated activity.
- **0 ISSUES** — no wording requires correction before internal founder/solicitor use.
- **3 WATCH families** — acceptable today, worth monitoring (strategy "vendor-neutral by design" field phrasing; clinic-facing governance templates outside primary scope; the canonically-required frontend final copy scan still outstanding).

Every occurrence of a prohibited term in the backend-held set appears in a **negated, conditional, avoid-list, or future-required-state** context (e.g. "does not grant compliance", "❌ No paid pilot authorised", "not solicitor reviewed", "not vendor-neutral today", "Outline → solicitor-reviewed draft"). The "aligned, not compliant" doctrine is applied consistently across canonical, operations, commercial, and strategy surfaces.

## 5. Non-claim scan results

| Phrase / claim family | Result | Location(s) | Notes | Required action |
| --- | --- | --- | --- | --- |
| RCVS approved / RCVS compliant | PASS | Readiness Map §2 avoid-list; `env.md`, `backup_restore.md`, `intake_retention.md`, `incident_response.md` disclaimers; commercial README | Only ever negated or in "do not claim" tables. | None. |
| Regulator approved / endorsed | PASS | Same disclaimer set | Always negated. | None. |
| Certified / certification | PASS | Readiness Map §2; ops disclaimers; readiness checkpoint ("does not mean ANCHOR is certified") | Negation / avoid-list only. | None. |
| Compliance guarantee / guaranteed | PASS | Roadmap §1; ops disclaimers; incident_response avoid-list ("Fully compliant" listed as ❌) | Negation / avoid-list only. | None. |
| GDPR compliant | PASS | `intake_retention.md` ("No claims of GDPR compliance"); commercial outlines | Negated. | None. |
| EU AI Act compliant / Article 4 compliant | PASS | Readiness Map §2 avoid-list; Roadmap "do not claim" | Avoid-list; Article 4 framed as readiness theme + amendment watch. | None. |
| Fine-proof | PASS | Readiness Map §2 avoid-list ("Fine-proof training records" as ❌) | Avoid-list only. | None. |
| Clinical decision support | PASS | Roadmap/Readiness "do not claim"; `anchor-doctrine-check` rubric | Negated / avoid-list. | None. |
| Diagnostic / diagnosis / prescribing / treatment planning / autonomous triage | PASS | Canonical avoid-lists; `docs/governance/*` templates ("AI is not used for diagnosis, prescribing, treatment planning…") | Clinical terms appear only in negation. | None (governance templates: see §10/§11 watch). |
| Ambient scribe / EHR / PMS / clinical record / patient record | PASS | "What ANCHOR is not" lists across canonical + commercial | Always "not an EHR / not an ambient scribe". | None. |
| Clinical correctness / patient safety | PASS | Strategy non-claims; Trust Pack notes ("do not prove clinical correctness / patient safety") | Stated as non-claims. | None. |
| Proof of competence / RCVS-accredited CPD / certified CPD | PASS | Readiness Map §2 ("no RCVS-accredited, certified, approved, or competence-proof claim") | Avoid-list. | None. |
| Vendor-neutral / provider-agnostic (present-tense) | PASS (2 WATCH) | `env.md` ("not vendor-neutral today"); Readiness Map §2 / Roadmap §1 (present-tense forbidden); op-resilience checkpoint ("not vendor-neutral"). **WATCH:** strategy schema §5 ("vendor-neutral by design, never hardcoded") and gap analysis line 65 ("Vendor-neutral; nullable by design") | Canonical/ops posture is correct ("over time" only). Strategy phrases describe a **field design intent** (`model_provider` nullable / not hardcoded), not a present-tense product capability. | Monitor; ensure these strategy phrases are never lifted into public copy as a present-tense capability. |
| Live generation active | PASS | `env.md`, op-resilience checkpoint, founder summary, incident_response §8.7 | Uniformly "production-off". | None. |
| Stripe active / payment processor active / billing live | PASS | DPA, privacy, pilot, readiness checkpoint, order form outline | Uniformly "future candidate / not active / reserved". | None. |
| Paid pilot authorised | PASS | Founder approval checklist, AUP, readiness checkpoint, order form outline | Always "❌ No paid pilot authorised". | None. |
| Real clinic data authorised | PASS | Same set | Always negated. | None. |
| Solicitor reviewed / solicitor-approved | PASS | Commercial set: "not solicitor reviewed", "until solicitor-reviewed", "Outline → solicitor-reviewed draft" | Only as a negated current state or a future required state. | None. |
| Externally effective / final legal document | PASS | Order form outline + commercial disclaimers | Always negated ("not externally effective", "not a final legal document"). | None. |
| Legal advice | PASS | Every commercial artefact header | Always "not legal advice". | None. |

## 6. Gated-activity scan results

| Gated activity | Status in backend-held docs | Result |
| --- | --- | --- |
| Paid pilots | Uniformly "not authorised" across commercial set. | PASS — not authorised. |
| Real clinic data | Uniformly "not authorised"; gated behind solicitor-reviewed DPA + Pilot Agreement + founder approval. | PASS — not authorised. |
| Live Workspace generation | "Production-off" everywhere; gated behind 2A-C.5E safety gate + hard-refusal harness. | PASS — blocked by design. |
| Stripe / payment / billing | "Future candidate only / not active / reserved"; payment-card data must never enter ANCHOR's store. | PASS — not active. |
| Solicitor-approved / final legal status | No document claims solicitor-approved or final status; all are "pre-legal review / outline only". | PASS — not claimed. |
| External connectors / runtime ingestion | Strategy docs explicitly state no connector exists and none should be claimed; M6.12/M6.13 gated future. | PASS — not claimed. |
| Anthropic / live AI provider subprocessor posture | Documented as becoming a subprocessor **only when** live generation is enabled, which remains off. | PASS — correct conditional framing. |

## 7. Doctrine scan results

| Doctrine point | Finding | Result |
| --- | --- | --- |
| ANCHOR not clinical AI | "What ANCHOR is not" consistently stated; clinical terms only negated. | PASS |
| Metadata-only posture | Stated across canonical, ops, commercial, strategy; gap analysis notes the boundary is `CHECK`-enforced in code. | PASS |
| Human review required | Present in strategy, Trust Pack notes, commercial outlines. | PASS |
| Receipt-backed evidence | Described as governance evidence, never as proof of clinical correctness. | PASS |
| Aligned, not compliant | Applied uniformly; canonical wording-control rows govern it. | PASS |
| Vendor-neutral-over-time wording | Canonical/ops correct ("over time" / "architected for"); 2 strategy field-design phrases flagged WATCH (§5). | PASS WITH WATCH |
| No current connector ingestion claims | Strategy explicitly disclaims; native-only `workflow_origin`. | PASS |

## 8. Commercial / legal document scan

- **Internal only** — every commercial artefact carries an internal founder/solicitor-preparation header.
- **Pre-legal review** — all marked pre-legal review; none claims solicitor-approved status.
- **Not final legal documents** — all marked outline/draft; none is externally effective.
- **Structurally complete** — the outline spine is present: legal/commercial pack outline, privacy/data-boundary, DPA, pilot agreement, AUP, clinic onboarding checklist, founder pilot approval checklist, readiness checkpoint, solicitor review bundle index, solicitor pack dispatch checklist, personal data/data-flow inventory, and (new) commercial order form outline. The README index and "planned" section are now accurate (no remaining named planned outline).
- **Remains for solicitor / accountant / founder** — solicitor review of every outline; accountant/VAT and payment-treatment confirmation; founder approval; promotion of outlines to solicitor-reviewed drafts; any further document the legal/commercial pack outline identifies as required.

Result: **PASS** — coherent, conservative, and non-authorising.

## 9. Strategy document scan

- The receipt schema v0.1 and the gap analysis remain **strategy-only**. Both carry documentation-only headers, disclaim implementation, and mark evidence-source classes B–E and evidence-strength grading as **future / not implemented**.
- The strategy README correctly frames the directory as design material that authorises nothing and does not move M6.12/M6.13/Phase 2B into active build.
- No strategy document implies a connector exists or that external runtime ingestion is live.
- One nuance (WATCH, not an issue): the field-design phrases "vendor-neutral by design" (schema §5) and "Vendor-neutral; nullable by design" (gap analysis) describe a schema field intent, not a present-tense product capability. In-context they are correct; they should not be quoted out of context.

Result: **PASS** (with the §5 WATCH carried forward).

## 10. Open watch items

These are **not blockers**; they should remain monitored:

- **Solicitor review not complete.** Every commercial/legal artefact is pre-legal-review; nothing is signed-ready.
- **Accountant / VAT / payment treatment not complete.** Pricing, VAT, refund/cancellation, and Stripe activation remain "to be confirmed / future / not active".
- **Frontend public final copy scan still required.** Readiness Map v1.1 §2 (and the 2A-D.4 line) explicitly records that the final copy scan across website, deck, Trust Pack, Learn/CPD, client transparency, social bios, pilot copy, demo script, and legal surfaces is still outstanding. This backend scan does **not** cover those public surfaces.
- **Clinic-facing governance templates** (`docs/governance/policies/*`, `docs/governance/client_transparency/*`) were outside the brief's primary scope. A spot-check found clinical terms used only in negation (PASS on spot-check), but these clinic-facing surfaces should be included in the frontend/public final copy scan rather than relied on as "covered" here.
- **Live Workspace safety gate still blocked.** 2A-C.5E + hard-refusal harness not passed; live generation must stay production-off.
- **No paid pilot / real clinic data authorisation.** Remains the standing gate.
- **Strategy "vendor-neutral by design" field phrasing** (§5 / §9) — keep in-context; do not surface as present-tense capability.

## 11. Required follow-up

**Next smallest recommended follow-up:** run the **frontend public Legal + Trust Centre wording scan** in `C:\Users\rggal\anchor-portal` (the public-surface counterpart of this backend scan), since that is the surface Readiness Map §2 / 2A-D.4 still flags as outstanding and the only place a wording slip would reach the public. Include the clinic-facing `docs/governance/*` templates in that pass.

**No correction patch is required from this backend scan** — zero ISSUES and zero BLOCKERS were found, so there is nothing to fix in the backend-held docs. (Had an issue been found, the follow-up would instead be a single targeted correction patch recorded against the offending file — not done here, because none was found.)

## 12. Conclusion

The backend-held canonical, operations, commercial/legal, and strategy documents are **safe for internal founder / solicitor preparation**. Wording discipline is consistent and conservative; the "aligned, not compliant" doctrine holds throughout; no gated activity is authorised; and no prohibited claim is made affirmatively.

They are **not yet cleared for external use**, for reasons that are readiness gaps rather than wording defects: solicitor review is not complete, accountant/VAT/payment treatment is unresolved, and — most importantly for copy risk — the **frontend public Legal + Trust Centre / Trust Pack / client-facing copy scan remains outstanding** and is the gating surface for any external claim. Until that public scan is complete and solicitor review is in, treat all of this material as internal preparation only.

This artefact authorises nothing. No paid pilot, no real clinic data, no billing, no Stripe activation, no live Workspace generation, no solicitor-approved status, and no connector capability follows from it.
