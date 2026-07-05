# Claude Code Post-RCVS Prompt Pack

> **Documentation-only reusable prompts (5 July 2026).** To be used **when the final RCVS / VATA framework or post-consultation output becomes available**. Prompts 1–8 are read-only / docs-only. **No code implementation prompts are included except the clearly marked "future only" stub at the end.** Every prompt inherits the standing rules: no compliance/approval/certification/endorsement claims; do not assume framework contents; wording controlled by Readiness Map v1.1 §2; founder decision required before anything produced by these prompts is applied.

Fill `<...>` placeholders before use. Paste the shared preamble first, then the specific prompt.

---

## Shared preamble (paste before every prompt)

```
Context: the final RCVS / VATA framework or post-consultation output is now
available. Source URL: <url>. Published: <date>. Self-description: <exact
self-description from the document>. Treat it as exactly what it says it is —
do not upgrade its status. ANCHOR is aligned, not compliant: never produce
wording that claims or implies RCVS approval, framework compliance, EU AI
Act / GDPR compliance, certification, endorsement, guaranteed compliance or
safety, proof of competence, or RCVS-accredited CPD. This session follows
docs/strategy/rcvs_scenario_preparation/2026-07-05_rcvs_framework_comparison_protocol.md.
Documentation-only unless a prompt explicitly says otherwise. Do not commit or
push unless I explicitly instruct.
```

## Prompt 1 — Read-only framework comparison

```
Run the comparison protocol steps 1–13 against the attached/linked final
document. Read-only: change no files. Produce (a) the classification against
the scenario matrix with verbatim quote evidence, (b) the must/should table,
(c) the expectation → ANCHOR surface → gap table (shipped surfaces only,
experiment-branch items listed separately and marked unmerged/gated), (d) the
terminology glossary with adopt/avoid recommendations, and (e) the draft
founder decision sheet per protocol step 17. Flag every point where the
document is ambiguous rather than resolving the ambiguity yourself.
```

## Prompt 2 — Readiness Map update (draft only)

```
Using the completed comparison output, draft a Readiness Map v1.1 → v1.2
reconciliation as a NEW markdown file under docs/strategy/
rcvs_scenario_preparation/ (do not edit the canonical Readiness Map). For each
§3 row: confirm / extend / reshape / drop, with quote references. Propose §2
wording-control additions for any new terminology. Preserve every existing
non-claim. Mark the file DRAFT — awaiting founder approval; canonical
promotion is a founder-authored step.
```

## Prompt 3 — Roadmap update (draft only)

```
Using the comparison output and the selected action-plan template (A/B/C),
draft the roadmap impact memo as a NEW file under docs/strategy/
rcvs_scenario_preparation/: (a) items unchanged, (b) reprioritisation
proposals within existing gated items with rationale and quotes, (c) any
new-scope proposals as gated designs only. State explicitly that the standing
gates (paid pilots, real clinic data, live generation, live billing) do not
move. Do not edit Roadmap v2.6; a v2.7 reconciliation is founder-authored.
```

## Prompt 4 — Website copy audit (report only)

```
Audit all public-facing copy sources available in this workspace (and listed
frontend copy files if the portal repo is present) against the comparison
output: (a) statements now stale (e.g. consultation described as open),
(b) statements that could over-claim in light of the final document,
(c) opportunities to adopt the document's terminology WITHOUT adding claims.
Output a before/after proposal table, each row checked against Readiness Map
v1.1 §2 and the non-claims list. Report only — change no copy.
```

## Prompt 5 — Trust Centre copy audit (report only)

```
Audit Trust-surface and trust-adjacent copy (trust posture blocks, Trust Pack
artefact labels, receipt-facing copy, docs/commercial trust/legal outlines)
line-by-line against the final document's terminology and the non-claims
list. Specifically hunt for: implied endorsement, implied compliance,
"framework" references outside the approved neutral sentence, competence
implications in Learn/CPD copy, and consent implications in transparency
copy. Output findings with proposed rewordings. Report only.
```

## Prompt 6 — Legal pack question generation

```
From the comparison output, generate the solicitor question list per protocol
step 15. Group by: provider-obligation exposure to ANCHOR itself; marketing
references to the framework; evidence retention alignment (cross-reference
the R2 retention note); client consent/choice wording boundaries; diligence-
record liability wording; new defined terms with potential legal weight.
Phrase each as a neutral question with the relevant quote attached. Do not
draft answers and do not modify any docs/commercial artefact.
```

## Prompt 7 — Product gap audit (report only)

```
Using the expectation → surface → gap table, produce a product gap audit:
for each "partially covered" or "not covered" practice-side expectation,
state (a) what a metadata-only, doctrine-compatible surface would look like,
(b) whether anything on fable/roadmap-completion-experiment already covers it
(marked unmerged/gated), (c) build cost class (S/M/L), and (d) which gates
apply before it could ship. Recommendations only — no code, no migrations,
no route changes. End with the items that should NOT be built even if gaps
exist (arbiter-drift, consent capture without legal review, anything storing
clinical content).
```

## Prompt 8 — Phase 2B external AI tool governance planning (design only)

```
Only if the founder has ticked decision checkpoint 17.5 (promote Phase 2B):
draft an AI Tool Governance Notes design brief as a NEW file under
docs/product/, built on 2026-06-18_ai_tool_assessment_question_set_mapping.md
and the 18 June 2026 source note. Constraints: ANCHOR is a structurer, not an
arbiter — no ratings, scores, approvals, or validation verdicts anywhere in
the design; metadata-only records of questions asked, provider answers
received/absent, and review decisions; clinic-scoped tables must specify RLS
+ FORCE RLS with USING and WITH CHECK; locked citation wording only. Design
document only — no implementation.
```

---

## Future-only implementation stub (do not use yet)

> **FUTURE ONLY — requires: final document reviewed, founder decision sheet signed, design brief approved, and an explicit founder instruction to build.** When all four exist, implementation prompts are written per approved brief and must each carry: branch discipline (no merge to main, no push without instruction), doctrine guardrails (metadata-only, RLS/FORCE RLS with USING and WITH CHECK, no raw content, human review preserved), gates off by default, focused tests + full suite + app import check, and the CLAUDE.md reporting block. No implementation prompt may be derived from this pack without that chain.

*Documentation-only. Not legal advice.*
