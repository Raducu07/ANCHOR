# Post-RCVS Action-Plan Templates

> **Documentation-only templates (5 July 2026).** One of these is selected at protocol Step 17.8, by founder decision, **when the final RCVS / VATA framework or post-consultation output becomes available**. Templates pre-stage the work; they authorise nothing. All copy changes remain subject to Readiness Map v1.1 §2 and, where legal-adjacent, solicitor review.

---

## Template A — Minimal update plan

*Use when: the output is principle-only, broadly cautious, or confirms existing direction without new operational expectations (scenario 4 or 9; possibly 6).*

- **Documents to update:** source note (dated provenance addendum with URL/version/date); a short comparison memo under `docs/strategy/rcvs_scenario_preparation/` recording the classification and "no material change" conclusion; Readiness Map v1.1 — at most a dated wording-refresh list held for the next scheduled reconciliation.
- **Website/public copy to review:** sweep only for statements that would now read as stale ("consultation is open" → past tense); no positioning change.
- **Trust Centre/legal copy to review:** none beyond the staleness sweep; confirm no copy anywhere implies the document endorses ANCHOR.
- **Roadmap changes:** none.
- **Solicitor questions:** none new, unless step-4 flagged a provider-obligation ambiguity — then one targeted question.
- **Buyer/insurer explanation changes:** refresh the one-line status sentence in the explanation pack ("the final output was published on [date]; it is [self-description]"). No claims added.
- **Claude Code implementation prompts needed:** read-only comparison prompt and website copy audit prompt only (see prompt pack). No code prompts.
- **Founder approval required:** classification memo sign-off; staleness-sweep wording list.

---

## Template B — Moderate repositioning plan

*Use when: the output materially emphasises one or two themes ANCHOR already covers (scenarios 2, 3, 5, 6, 7) and the response is emphasis + wording, not new build.*

- **Documents to update:** everything in Template A, plus: Readiness Map v1.1 → v1.2 reconciliation draft (row statuses, terminology adoptions, wording-control updates) for founder approval; positioning selection memo referencing `2026-07-05_rcvs_positioning_options.md`; explanation pack refresh for all five audiences.
- **Website/public copy to review:** full sweep against the new terminology and non-claims findings; re-order emphasis (which surface leads) without new claims; demo script and founder walkthrough updated to lead with the emphasised theme.
- **Trust Centre/legal copy to review:** trust posture copy re-checked line-by-line against §2 wording controls; any framework references added only in the approved "aligned with emerging professional expectations" form; disclaimer text re-confirmed.
- **Roadmap changes:** reprioritisation *within* existing items only (e.g. evidence-export polish forward; M4.6 or M5.7 experiment-branch merge review scheduled). Recorded as a founder memo addendum. No new scope.
- **Solicitor questions:** the protocol Step 15 list — typically: may we reference the framework by name in marketing; retention alignment; competence-wording boundaries; consent-language boundaries (if scenario 7).
- **Buyer/insurer explanation changes:** rewrite the audience drafts to lead with the emphasised theme; insurer/procurement version gets the evidence-mapping table (protocol Step 13) as an appendix, marked "internal mapping, not a compliance statement".
- **Claude Code implementation prompts needed:** comparison, Readiness Map update, website copy audit, Trust Centre copy audit, legal question-generation prompts (see prompt pack). Code prompts only if a merge review is approved — marked **future only** until then.
- **Founder approval required:** v1.2 reconciliation; positioning selection; every public copy change; the memo addendum for any reprioritisation; merge-review authorisation for any experiment-branch item.

---

## Template C — Major roadmap shift plan

*Use when: the output creates a genuinely new centre of gravity (most plausibly scenario 8 — external tool inventory/declared-use — or an unanticipated shape) such that ANCHOR's near-term build order should change.*

- **Documents to update:** everything in Template B, plus: a new Decision Memo addendum (v1.4-style) recording the shift, its evidence (quotes), the revised order, and what is explicitly *not* changing (doctrine, gates, non-claims); Roadmap v2.6 → v2.7 reconciliation draft; Phase 2B design brief (if scenario 8) built on the question-set mapping and the 18 June source note's structurer-not-arbiter boundary.
- **Website/public copy to review:** staged in two passes — immediate staleness/safety pass, then post-repositioning pass once the founder approves the new emphasis; nothing between passes may reference the framework beyond the approved neutral sentence.
- **Trust Centre/legal copy to review:** full legal-adjacent sweep with solicitor; subprocessor/data-flow notes re-checked if any new surface would touch new data categories; liability wording for diligence-record features drafted for solicitor review before any build.
- **Roadmap changes:** re-sequenced build order via the new addendum; experiment-branch items formally dispositioned (merge review / hold / abandon per item); new-scope items (e.g. consent evidence, tool-governance notes) enter as *gated designs*, each behind security/legal/privacy review — the standing gates (paid pilots, real clinic data, live generation, live billing) do not move.
- **Solicitor questions:** full pack — framework references in commerce; provider-obligation exposure; diligence-record liability; retention; consent; any defined terms with legal weight; whether any new surface changes the data-protection posture.
- **Buyer/insurer explanation changes:** rewritten around the new positioning after founder sign-off; insurer/procurement version reviewed by solicitor before first external use.
- **Claude Code implementation prompts needed:** the full prompt pack, plus **future only** implementation prompts drafted per approved design brief (each carrying doctrine guardrails: metadata-only, RLS/FORCE RLS, non-claims, gates off by default).
- **Founder approval required:** the new addendum (the central artefact — nothing moves without it); Roadmap v2.7; Phase 2B brief; every copy change; every merge; solicitor engagement scope.

---

## Selection rule

Default to the **lightest** template consistent with the evidence. Escalate A → B → C only on quoted, protocol-verified findings — never on enthusiasm. If in doubt between two templates, run the lighter one and schedule a re-review checkpoint.

*Documentation-only. Not legal advice. Templates stage work; founder decisions execute it.*
