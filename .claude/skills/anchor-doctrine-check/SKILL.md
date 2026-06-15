---
name: anchor-doctrine-check
description: Audit a proposed change, copy block, or PR diff for ANCHOR doctrine compliance — metadata-only, no clinical drift, no compliance/certification claims, no buyer-discovery reintroduction, M4.6 deferred, M6.12/M6.13 gated, live generation production-off. Use before merging any clinic-facing copy, any Workspace/Assistant/Receipts/Trust/Learn change, any public-page edit, or whenever wording or scope feels off.
---

# anchor-doctrine-check

## Canonical sources (read these first, in this order)

All in `docs/canonical/`:

1. `ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md` — OPERATIVE decision. Supersedes Memo v1.1 and Addendum v1.2 where they differ. Establishes conviction-based build with no buyer-discovery requirement.
2. `ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md` — canonical roadmap (as-built reconciliation). §1 doctrine; current phase 2A-D.0.
3. `ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md` — §2 wording controls operative for all clinic-facing copy; §3 RCVS principles; §4 EU AI Act articles.

Older artefacts (v2.5 Roadmap, v1 Readiness Map, Memo v1.1, Addendum v1.2, Phase 2A-1 Engineering Brief) are **historical record only**. Where they differ from v2.6 / v1.1 / Addendum v1.3, the newer artefacts win.

## When to run this skill

- Any copy edit visible to clinic users, clinic admins, or pet owners.
- Any change to `/assistant`, `/workspace`, `/receipts`, `/trust`, `/learn`, `/intelligence`, `/dashboard`, `/governance-events`, `/settings`, `/privacy`, `/support`.
- Any new component, page, or route.
- Any API/data-shape change that touches what the UI displays.
- Any time the words "compliant", "certified", "approved", "guarantees", "vendor-neutral", "multi-provider", "provider-agnostic", "chat history", "clinical record", "high-risk AI", "Article 6", "GPAI provider", or "buyer discovery" appear in a diff.
- Before declaring a task complete.

## Doctrine checklist (every item must be YES, or stop and report)

### 1. Metadata-only
- [ ] No raw prompts, outputs, drafts, transcripts, free-text clinical content displayed, requested, or stored.
- [ ] Receipts surface metadata fields only (ids, timestamps, status flags, hashes, counts, refusal/safety reason codes).
- [ ] No copy implies the portal stores or shows the substance of a clinical conversation.

### 2. Not clinical decision-making AI
- [ ] No diagnostic, prescribing, treatment-planning, triage, dose-calculation, or differential-list copy or UI.
- [ ] No copy that could read as clinical advice to a vet, nurse, or owner.
- [ ] Refusal/why-flagged copy frames the AI as out-of-scope, not as a clinical second opinion.

### 3. Human-review surfaced
- [ ] Review state visible wherever evidence is shown (Workspace ↔ Receipt coherence in particular).
- [ ] No copy that implies autonomous safety, "AI-checked", or "approved by ANCHOR".

### 4. Wording controls (Readiness Map v1.1 §2)
Reject the diff if any of the following appear in clinic-facing copy:

- "compliant" / "compliance system" / "fully compliant"
- "certified" / "certification" / "RCVS-certified"
- "RCVS-approved" / "RCVS-accredited" / "regulator-approved" / "endorsed by"
- "guarantees" / "guaranteed protection" / "ensures safety"
- "clinical record" / "medical record" / "chat history"
- "high-risk AI compliance" / "Article 6 compliant" / "Annex III compliant"
- "GPAI provider" applied to ANCHOR
- Present-tense **"vendor-neutral"**, **"multi-provider"**, **"provider-agnostic"**, **"works with any model"** — the live path is Anthropic-coupled.
- "EU AI Act compliant" / "fully aligned with EU AI Act" / specific enforcement-day dates without the "from August 2026" softening and Article 4 amendment-watch caveat.

Prefer (Readiness Map v1.1 §2):

- "governance and readiness infrastructure"
- "metadata-only evidence"
- "supports CPD-recordable AI literacy activity" (never "RCVS-accredited CPD")
- "aligned with" (RCVS principles, emerging EU AI Act expectations)
- "human review required"
- "not chat history"
- **"architected for vendor-neutrality"** / **"vendor-neutral over time"** (future-tense framing only)
- "from August 2026" + "Article 4 amendment watch" for EU AI Act dates

### 5. Build-stance discipline (Addendum v1.3)
- [ ] No reintroduction of buyer discovery, "5–10 practice-owner conversations", parallel listening cadence, or buyer-conversation gating language.
- [ ] No copy that frames ANCHOR as market-validated, customer-validated, or "proven with clinics" — building proceeds on regulatory and professional-governance conviction.

### 6. Scope discipline
- [ ] M4.6 (Learn Maturity) — **deferred**. No work, no UI prompts toward it.
- [ ] M6.12 / M6.13 — **gated future**. No surfacing, no teaser copy, no preconditioned UI.
- [ ] Live Workspace generation — **production-off** until the local/staging safety gate passes. No "generate live" CTA, no copy implying live model calls in production.
- [ ] Phase 2A-1 → 2A-5 — **shipped**. Do not rebuild, redesign, or "refresh" these surfaces without explicit founder instruction.
- [ ] Current target is **2A-D.0 reconciliation / RC hardening**, not feature build.

### 7. Repo discipline
- [ ] Frontend only. Backend changes → stop and report.
- [ ] No edits to `components/shell/AppShell.tsx` (custom-font warning is deferred tech-debt — do not "fix").
- [ ] Deep-link contracts preserved: `/receipts?assistantRunId=…` and `/receipts?assistantReceiptId=…`; Trust posture Assistant evidence card and counts.
- [ ] No new colour system, typography system, or layout pattern.
- [ ] No `any`, no `@ts-nocheck`, no lint suppressions without an in-diff justification.
- [ ] Lint baseline preserved: 0 errors, only the known AppShell font warning.

## Output format

When run, produce a report with these sections, in order:

1. **Verdict** — `PASS` / `FAIL` / `STOP-AND-ASK`.
2. **Doctrine items checked** — bullet list with ✓ / ✗ / n/a per item above.
3. **Wording violations** — quoted phrase, file:line, suggested replacement from §2.
4. **Scope violations** — anything touching M4.6, M6.12/M6.13, live generation, buyer discovery, redesign.
5. **Repo-discipline violations** — AppShell, deep links, lint, type discipline.
6. **Required action** — concrete next step (revert, reword, escalate to founder).

A single FAIL is enough to block the merge. A single STOP-AND-ASK halts work pending founder decision.
