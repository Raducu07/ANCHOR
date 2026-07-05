# RCVS / VATA Scenario Preparation Pack — Index

> **Status: documentation-only scenario preparation. Prepared 5 July 2026.**
>
> **The final RCVS / VATA framework has NOT been reviewed — it does not yet exist as a final document as far as this repo's sources show.** Everything in this pack is contingency planning against *possible* shapes of the eventual output. Nothing here describes, quotes, or relies on final framework content.
>
> ANCHOR is **aligned, not compliant** — not RCVS-approved, not regulator-endorsed, not certified, and this pack makes no compliance, certification, or endorsement claim of any kind. It changes no application code, routes, migrations, or product behaviour, and it authorises none.

---

## 1. Purpose

When the final RCVS / VATA framework or post-consultation output becomes available, ANCHOR should be able to move from "document published" to "reviewed, compared, and decision-ready" in hours, not weeks. This pack pre-builds:

- the **scenarios** the final document could plausibly take (scenario matrix);
- the **protocol** for reviewing it rigorously and without over-claiming;
- the **decision tree** mapping each scenario to an ANCHOR response;
- **action-plan templates** at three intensities;
- **positioning options** with wording controls;
- **audience explanation drafts** (solicitor, practice owner, group, insurer, vendor);
- **reusable Claude Code prompts** for the comparison and update work.

## 2. Source assumptions

| Source | Status in this pack |
| --- | --- |
| `docs/operations/source_notes/2026-06-18_veterinary_ai_vendor_transparency_source_note.md` | **Primary provenance anchor.** Records that the "AI Provider Information Framework for Veterinary Practice" is a **Veterinary AI Transparency Alliance (VATA) consultation draft, led by RCVS and Digital Practice** — regulator-adjacent, **not final RCVS guidance, not a compliance standard, not regulator endorsement of ANCHOR**. 23 principles; developed over 18 months; covers human oversight, data storage/usage, risk, and client consent/choice themes. |
| Consultation timing | The RCVS news item (17 June 2026) records the **survey closing Monday 6 July at 5pm**. **6/7 July is a consultation/survey deadline, not a publication date.** No publication date for a final framework or post-consultation output is known to this repo. Wording throughout this pack: *"when the final RCVS / VATA framework or post-consultation output becomes available."* |
| RCVS "Using AI in practice" advice (URLs in the source note) | Current published UK professional anchor; remains operative regardless of the consultation outcome. |
| Operative canon | Roadmap v2.6; Readiness Map v1.1 (all wording controlled by its §2 table); Decision Memo Addendum v1.3. |
| Legal / commercial pack | `docs/commercial/` artefacts are **outlines pending solicitor review** — nothing in this pack upgrades their status. |
| Founder note "ANCHOR — Ce mai lipsește și ce așteptăm de la RCVS" | **Not present in this repo** (likely maintained in the founder's Claude Project knowledge pack). This pack was prepared without it; when reviewing the final document, cross-check that note's expectations manually. |

## 3. Warning — do not pre-empt the final document

- Do **not** treat any scenario in this pack as a prediction. The matrix exists to make *any* outcome fast to process, not to guess the outcome.
- Do **not** reuse scenario text as public copy. Public copy changes only follow the comparison protocol, the wording controls in Readiness Map v1.1 §2, and founder approval.
- Do **not** describe ANCHOR as aligned with, built around, mapped to, or compliant with the framework — in any tense — until the final document has been reviewed under the protocol *and* the founder has approved specific wording. Even then, "framework-compliant" is never available wording.

## 4. Documents in this pack

1. `2026-07-05_rcvs_scenario_preparation_index.md` — this index.
2. `2026-07-05_rcvs_scenario_matrix.md` — nine plausible framework shapes and what each means for ANCHOR.
3. `2026-07-05_rcvs_framework_comparison_protocol.md` — step-by-step review protocol for the final document.
4. `2026-07-05_anchor_response_decision_tree.md` — scenario → response branches with wording controls.
5. `2026-07-05_post_rcvs_action_plan_templates.md` — minimal / moderate / major action-plan templates.
6. `2026-07-05_rcvs_positioning_options.md` — positioning options with benefits, risks, and wording.
7. `2026-07-05_buyer_solicitor_insurer_explanation_pack.md` — draft-only audience explanations.
8. `2026-07-05_claude_code_post_rcvs_prompt_pack.md` — reusable prompts for the post-publication work.

## 5. What this pack does and does not authorise

**Does:** give the founder and future Claude Code sessions a ready-made, wording-safe process for the day the final RCVS / VATA framework or post-consultation output becomes available.

**Does not authorise:** any code change; any migration; any route or frontend change; any public copy change; any legal pack change; any compliance/approval/certification/endorsement claim; any paid pilot, real clinic data, live generation, live billing, deployment, merge, or push; any Phase 2B build (AI Tool Governance Notes remain Future / gated per Roadmap v2.6 §2); any repositioning without explicit founder decision.

*Documentation-only. Not legal advice. All wording subject to Readiness Map v1.1 §2 and solicitor review before external use.*
