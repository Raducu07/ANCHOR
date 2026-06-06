# ANCHOR frontend — Claude Code review layer

This file documents the `.claude/` optimisation layer for the ANCHOR frontend repo. It is a contributor- and reviewer-facing index, not a doctrine document. Doctrine lives in `CLAUDE.md` and in `docs/canonical/`.

## Purpose

Improve review quality, visual consistency, wording safety, and Phase 2A-D release-candidate discipline — without changing production code, without altering approved visual direction, and without relaxing any doctrine.

## Canonical baseline (as of Addendum v1.3, 6 June 2026)

- `docs/canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md` (+ .docx)
- `docs/canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md` (+ .docx)
- `docs/canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md` (+ .docx)

Older artefacts (Roadmap v2.5, Readiness Map v1, Memo v1.1, Addendum v1.2, Phase 2A-1 Engineering Brief, EU AI Act Source Note v1) are **historical record only**. Where they differ from v2.6 / v1.1 / Addendum v1.3, the newer artefacts win.

Current implementation target: **2A-D.0 — Canonical reconciliation / Release-candidate hardening**. This is not a feature-build phase.

## What the `.claude/` layer adds

### Skills (invoked by name in a session)

- `.claude/skills/anchor-doctrine-check/SKILL.md` — doctrine and wording audit for any clinic-facing diff. Catches compliance/certification/RCVS-approval claims, present-tense vendor-neutrality, chat-history/clinical-record drift, M4.6 / M6.12 / M6.13 scope creep, buyer-discovery reintroduction, and Workspace live-generation surfacing.
- `.claude/skills/anchor-security-audit/SKILL.md` — frontend security and privacy audit covering metadata-only enforcement, tenant scoping, deep-link safety, secrets, dependencies, headers, auth state, client storage, and the Workspace live-generation gate. Supports Phase 2A-D security-audit pre-pilot gate.
- `.claude/skills/anchor-frontend-visual-review/SKILL.md` — polish-only visual review across Workspace / Assistant / Receipts / Trust / Learn / Intelligence / Settings / Dashboard / Governance Events / Privacy / Support. Hierarchy, spacing, readability, state coverage, cross-page consistency. **No redesign authority.**

### Agents (read-only by default)

- `.claude/agents/anchor-security-reviewer.md` — runs the security audit checklist and reports findings; never edits.
- `.claude/agents/anchor-docs-reconciler.md` — finds stale references to v2.5 / v1 / Memo v1.1 / Addendum v1.2 / retired Phase 2A-1 Brief, plus doctrine-violation phrasing. Read-only by default; may edit doc/config files only on explicit instruction; never edits production code.
- `.claude/agents/anchor-frontend-polish-reviewer.md` — polish-only frontend reviewer; never proposes redesign, new colour systems, new typography, or new layout patterns; never touches AppShell or the custom-font warning.

### Hooks

- `.claude/hooks/README.md` — placeholder. **No hooks installed.** Lists candidate hooks for future founder-approved opt-in.

## How to use during a typical task

1. Before starting: open `CLAUDE.md` and re-read the current-target block.
2. When changing UI or copy: run `anchor-frontend-visual-review` and `anchor-doctrine-check` against the diff.
3. When touching receipts, trust, assistant, fetches, env vars, headers, or dependencies: run `anchor-security-audit` (or spawn the `anchor-security-reviewer` agent).
4. When the docs feel out of sync, or before any RC sign-off: spawn `anchor-docs-reconciler` (read-only); apply its patch only on explicit instruction.
5. Before declaring done: confirm `npm run build` passes and `npm run lint` is 0 errors with only the known AppShell custom-font warning.

## Hard prohibitions (this layer enforces by review, not by hook)

- No raw prompts/outputs/drafts/transcripts/free-text clinical content displayed, stored, or requested.
- No diagnostic / prescribing / triage / treatment-planning UI or copy.
- No "compliant" / "certified" / "RCVS-approved" / "regulator-approved" / "guarantees" / "high-risk AI compliance" / "GPAI provider [ANCHOR]" / "chat history" / "clinical record".
- No present-tense "vendor-neutral" / "multi-provider" / "provider-agnostic" — live path is Anthropic-coupled. Future-tense framing only ("architected for vendor-neutrality", "vendor-neutral over time").
- No EU AI Act enforcement-day specifics without the "from August 2026" softening and Article 4 amendment-watch caveat.
- No buyer discovery, "5–10 practice-owner conversations", or parallel listening cadence — corrected by Addendum v1.3.
- No work on M4.6 (deferred).
- No work toward M6.12 / M6.13 (gated future).
- No surfacing of live Workspace generation in production — production-off until the safety gate passes.
- No redesign, no new colour system, no new typography system, no new layout grid.
- No edits to `components/shell/AppShell.tsx`. No "fix" of the deferred custom-font warning unless explicitly requested.
- No new lint warnings; no new `any`, `@ts-nocheck`, or `eslint-disable` without an in-diff justification.
- No backend edits from this repo.
- No commit, no push, unless explicitly asked.

## Surface map (stable; do not redesign)

| Route | Status | Owner doctrine |
| --- | --- | --- |
| `/workspace` | shipped (live generation production-off) | metadata-only; safety gate |
| `/assistant` | shipped end-to-end | metadata-only Assistant evidence |
| `/receipts` | shipped; deep-link contract stable | `?assistantRunId=…`, `?assistantReceiptId=…` |
| `/trust`, `/trust/posture` | shipped | Assistant receipt evidence card + counts stable |
| `/learn` | shipped (2A-1) | CPD-recordable AI literacy activity only |
| `/intelligence` | shipped | metadata-only Assistant evidence |
| `/dashboard`, `/governance-events`, `/settings`, `/privacy`, `/support` | shipped | wording controls per Readiness Map v1.1 §2 |

## Phase status (per Roadmap v2.6)

- Phase 2A-1 → 2A-5: **shipped**.
- Phase 2A-C presentation hardening: **complete** (2A-C.4 backend Trust Pack polish and 2A-C.5E live Workspace smoke deferred).
- Phase 2A-D.0: **active** — canonical documentation reconciliation, then security audit + operational resilience, legal/commercial pack, RC coherence fixes, wording scan, RC sign-off.
- M6 honest gaps (formal evaluation registry; why-flagged → Learn linkage): **closed**.
- Readiness discipline R1–R4: **complete**.
- M4.6 Learn Maturity: **deferred by decision**.
- M6.12 / M6.13: **gated future**, with explicit preconditions (Roadmap §9).

## Reporting expectations (per CLAUDE.md)

After any frontend change, report:

1. Files changed (full paths).
2. Behaviour changed (short narrative; affected pages).
3. `npm run build` result.
4. `npm run lint` result (confirm 0 errors; list any new warnings — there should be none beyond the AppShell custom-font warning).
5. Backend or frontend touched (this repo is frontend; flag any backend need).
6. Metadata-only doctrine preserved — yes / no / explain.
7. Visual direction preserved — yes / no / explain.
8. Any limitations or deferred items — explicit list.

## Known drift to address separately (not changed by this scaffold)

- `CLAUDE.md` "Canonical documents" section still references v2.5 / v1 / Memo v1.1 docx files and the bridging note "Roadmap v2.6 and Readiness Map v1.1 supersede v2.5 and v1 once issued". v2.6 and v1.1 are now present; that wording is stale.
- `CLAUDE.md` lists `Phase_2A_1_Engineering_Brief_v1_1.md` and `Official_EU_AI_Act_Source_Note_v1.md`, both of which have been deleted from the working tree (uncommitted deletions).
- These doctrine-fidelity edits to `CLAUDE.md` are deliberately **not** made by this scaffold. Use `anchor-docs-reconciler` to surface them, and apply only on explicit founder instruction.

## Versioning

This `.claude/` layer was created against canonical state of 6 June 2026 (Roadmap v2.6, Readiness Map v1.1, Addendum v1.3). When any of those three artefacts is superseded, every file in this layer should be re-audited against the new artefact.
