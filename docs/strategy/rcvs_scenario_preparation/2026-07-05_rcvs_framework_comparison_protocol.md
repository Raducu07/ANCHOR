# RCVS / VATA Framework Comparison Protocol

> **Documentation-only protocol (5 July 2026).** To be executed **when the final RCVS / VATA framework or post-consultation output becomes available** — not before. Steps 1–13 are read-only analysis; steps 14–17 produce *proposals* that require founder decision. Nothing in this protocol authorises code, copy, legal, or roadmap changes by itself.

## Step 1 — Source capture

- Obtain the document from a primary source only (RCVS URL, or the Alliance's official channel as referenced by RCVS). Record the exact URL(s).
- Save a copy (PDF/HTML) outside the repo if it is copyright-restricted; store only citation metadata and short quotes in-repo.
- Confirm what the document *is*: final framework? post-consultation summary? revised draft? further consultation? Record the answer verbatim from the document's own self-description — do not upgrade its status.

## Step 2 — Date / version capture

- Record: publication date, version number/label, issuing body as printed, and whether RCVS presents it as guidance, best practice, framework, or consultation output.
- Update `docs/operations/source_notes/2026-06-18_veterinary_ai_vendor_transparency_source_note.md` provenance section (a dated addendum — never rewrite the original entries).
- Note explicitly whether the 23-principle structure survived, changed, or was replaced.

## Step 3 — Quote extraction

- Extract short verbatim quotes (with page/section references) for every statement that could affect ANCHOR: obligations, expectations, "should"/"must" language, disclosure lists, record expectations, training references, transparency references, risk categories.
- Distinguish "must"-type wording from "should"/"may" wording in a two-column table. Do not paraphrase at this step — paraphrase drift is how over-claiming starts.

## Step 4 — Provider / practice orientation test

- Classify every extracted expectation as: provider-facing, practice-facing, both, or ambiguous.
- Compute the rough weighting (count of practice-facing vs provider-facing expectations) → this selects the primary scenario row in `2026-07-05_rcvs_scenario_matrix.md`.
- Ask explicitly: could any provider-facing expectation be read to cover ANCHOR itself (as software sold to practices, even though not a clinical AI tool)? List candidates for the solicitor.

## Step 5 — Evidence requirement test

- List every place the document expects records, documentation, logs, or demonstrable evidence.
- For each: what artefact would satisfy it in spirit, and does ANCHOR produce a metadata-only analogue today (receipts, review states, attestation, CPD exports, incident records, Trust Pack)?
- Mark each as: covered / partially covered / not covered / out of ANCHOR's scope. Honest "not covered" beats a stretched mapping.

## Step 6 — AI literacy test

- Extract every staff-understanding / training / competence expectation.
- Map to 2A-1 Learn/CPD and attestation. Note whether the document uses "competence" language — if so, flag for wording review: ANCHOR records **activity**, never competence.
- Check whether role-specific expectations appear (relevant to the gated M4.6 experiment work).

## Step 7 — Human review test

- Extract oversight/verification expectations (who reviews, when, what is recorded).
- Compare with the review workflow vocabulary (review states, decisions, reviewer attribution, output-blocked path).
- Note any terminology the document introduces (e.g. a specific name for the reviewing role) — candidates for label alignment, not for claims.

## Step 8 — Client transparency test

- Extract client-facing disclosure/consent/choice expectations.
- Compare with 2A-4 disclosure templates and published-statement flow.
- Flag any *consent-recording* expectation separately — that is new scope requiring founder + solicitor review, not a copy tweak.

## Step 9 — External tool inventory test

- Extract any expectation that practices inventory, assess, or keep records about third-party AI tools.
- Compare with the self-assessment tool/vendor inventory item and the Phase 2B question-set mapping (`docs/product/2026-06-18_ai_tool_assessment_question_set_mapping.md`).
- If disclosure categories are enumerated, tabulate them against the question-set mapping: match / partial / absent. This table is the core input to any Phase 2B founder decision.

## Step 10 — Risk category extraction

- Record any risk tiers, proportionality tests, or excluded-use categories the document defines.
- Check none of ANCHOR's shipped behaviour falls into a discouraged category (it should not — ANCHOR performs no clinical function); record the reasoning, not just the conclusion.

## Step 11 — Terminology extraction

- Build a glossary of the document's key terms and definitions.
- Compare against ANCHOR's controlled vocabulary (Readiness Map v1.1 §2). Identify terms ANCHOR could *adopt* in labels for legibility, and terms ANCHOR must *avoid* because they would imply claims (e.g. anything reading as "assured", "approved", "validated").

## Step 12 — Comparison against Readiness Map v1.1

- Walk §3 (RCVS principle map) row by row: does the final document confirm, extend, reshape, or drop each mapped theme?
- Draft (do not apply) a v1.2 change list: status updates, new rows, wording-control updates. The Readiness Map is canon — updating it is a founder-approved reconciliation, like v1 → v1.1.

## Step 13 — Comparison against current product surfaces

- Produce a three-column table: framework expectation → ANCHOR surface (shipped) → gap/notes.
- Separately list the `fable/roadmap-completion-experiment` branch surfaces (M5.7 onboarding, M4.6 learn maturity, M5.8 billing foundations, M6-S, M6.13 shell, M6.12 connector) **clearly marked unmerged/gated** — relevant only as candidate accelerations for founder decision, never as "ANCHOR has" claims.

## Step 14 — Copy / website impact (proposal only)

- Sweep public copy, Trust Pack, Learn/CPD copy, client transparency templates, demo script against the terminology and non-claims findings.
- Output a proposed-change list with before/after wording, each checked against Readiness Map v1.1 §2. No copy changes without founder approval; externally visible copy also awaits solicitor review where legal-adjacent.

## Step 15 — Legal pack impact (questions only)

- Convert findings into solicitor questions (see the explanation pack for the format): provider-obligation exposure, record-retention alignment, consent language, liability wording for diligence records, any new defined terms with legal weight.
- Do not redraft legal documents; the legal pack remains solicitor-gated.

## Step 16 — Roadmap impact (proposal only)

- Map findings to the scenario matrix's roadmap rows. Output at most: (a) no change; (b) reprioritisation proposal within existing gated items; (c) new-scope proposal.
- Any of (b) or (c) requires a founder decision recorded as a memo addendum, consistent with Addendum v1.3 discipline.

## Step 17 — Founder decision checkpoints

Present a single decision sheet with, at minimum:

1. Which scenario(s) the final document most resembles, with the quote evidence.
2. Readiness Map v1.2 reconciliation — approve/defer.
3. Public copy change list — approve/edit/reject per item.
4. Solicitor question list — send/hold.
5. Phase 2B (AI Tool Governance Notes) — promote/keep future.
6. Experiment-branch accelerations (M4.6 / M5.7 etc.) — merge review/hold.
7. Positioning selection (see `2026-07-05_rcvs_positioning_options.md`) — confirm/adjust.
8. Action-plan intensity (minimal/moderate/major — see templates) — select.

Every checkpoint defaults to **no change** if not explicitly decided.

*Documentation-only. Not legal advice. Execution of steps 14–17 outputs proposals; nothing is applied without founder decision.*
