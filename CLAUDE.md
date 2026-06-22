@AGENTS.md

# ANCHOR Frontend — Claude Code Context

This file is read automatically by Claude Code at session start. It is the project-level guardrail document. Do not duplicate strategy content here — point to canonical documents in `/docs/canonical/`.

---

## What ANCHOR is

ANCHOR is governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics.

ANCHOR is **not** a clinical decision-making AI, diagnostic tool, ambient scribe, EHR, or replacement for veterinary judgement.

Public one-liner: *"Governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics."*

---

## This repository

- **Stack**: Next.js (TypeScript)
- **Deployment**: Vercel
- **Public domain**: `https://anchorvet.co.uk`
- **Working branch**: `anchor-portal-main-clean`
- **Backend it talks to**: `https://anchor-api-prod.onrender.com`
- **Lint baseline**: 0 errors; 1 known warning (AppShell custom-font — **do not fix**)

### Existing pages

Workspace · Assistant · Dashboard · Receipts · Governance Events · Learn · Trust · Intelligence · Settings · Privacy/Policy · Support

The Governed Assistant evidence loop is shipped end-to-end. `/assistant`, `/receipts`, `/intelligence`, and `/trust/posture` are live with metadata-only Assistant evidence.

---

## Doctrine — never violate without explicit founder decision

1. **Governance-first** — every feature exists to make AI use reviewable and accountable
2. **Metadata-only by default** — never display, request, or store raw prompts, outputs, drafts, transcripts, or clinical content
3. **Not clinical decision-making AI** — no diagnosis, prescribing, treatment planning, autonomous triage
4. **Human-review based** — surface review state clearly; review is required, not optional
5. **Receipt-backed** — metadata receipts are the user-visible evidence
6. **Trust-surface oriented** — governance must surface as legible trust posture
7. **Multi-tenant and privacy-aware** — clinic-scoped views only; no cross-tenant data
8. **Vendor-neutral over time** — UI never hardcodes a single AI provider's branding
9. **Standalone now, integrable later** — the portal is the surface today; future embeds/sidecars must remain possible
10. **Aligned, not compliant** — never write copy that claims RCVS approval, EU AI Act compliance, certification, or regulator endorsement
11. **ANCHOR is not a GPAI provider** — copy must reflect this

---

## What NOT to touch without explicit instruction

- **Approved visual direction** — do not redesign pages
- **AppShell custom-font warning** in `components/shell/AppShell.tsx` — known deferred font architecture; do not "fix"
- **Existing Assistant page (`/assistant`)** — do not refactor; add to it
- **Existing Receipts page (`/receipts`)** — deep-link contract (`?assistantRunId=…`, `?assistantReceiptId=…`) is stable; do not break
- **Existing Trust posture (`/trust/posture`)** — Assistant receipt evidence card and counts are stable
- **Backend** — this is the frontend repo; if a backend change is needed, stop and report rather than edit cross-repo
- **Cross-cutting refactors** — keep changes targeted and incremental

---

## Coding rules

- **No `any`**, no `@ts-nocheck`, no lint suppressions without a documented reason in the same change
- **No new lint errors** — baseline must remain at 0 errors
- **No new warnings** beyond the existing AppShell font warning
- **Preserve existing approved visual direction** — do not introduce new colour systems, typography, or layout patterns without explicit instruction
- **Do not commit or push to git unless explicitly asked**

---

## Build and lint discipline

After any frontend change, run:

- `npm run build` — must pass
- `npm run lint` — must remain 0 errors; warnings unchanged
- Report exact results

Do not declare a change complete without passing build and lint.

---

## Reporting expectations after each session

Always report:

1. **Files changed** — full paths
2. **Behaviour changed** — short narrative; include affected pages
3. **`npm run build` result**
4. **`npm run lint` result** — confirm 0 errors; list any new warnings (there should be none beyond the AppShell font warning)
5. **Backend or frontend touched** — this repo is frontend; flag if a backend change is needed
6. **Metadata-only doctrine preserved** — yes / no / explain
7. **Visual direction preserved** — yes / no / explain
8. **Any limitations or deferred items** — explicit list

---

## Public copy discipline

Any copy that appears to a clinic user, a clinic admin, or a pet owner must be checked against the wording controls in `ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md` §2 (operative; v1 retained for historical reference only).

**Use**: "governance and readiness infrastructure", "metadata-only evidence", "supports CPD-recordable AI literacy activity", "aligned with", "human review required", "not chat history", "architected for vendor-neutrality", "vendor-neutral over time".

**Avoid**: "compliant", "certified", "RCVS-approved", "guarantees", "compliance system", "clinical record", "chat history", "vendor-neutral" / "multi-provider" / "provider-agnostic" as present-tense claims (the live path is Anthropic-only).

When in doubt, stop and ask.

---

## Current implementation target: 2A-D.0 — Canonical reconciliation / Release-candidate hardening

Authorised by `ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3` (6 June 2026), operative over Memo v1.1 and Addendum v1.2 where they differ.

**Built and shipped — do NOT rebuild or redesign:** Learn CPD catalogue/detail/completion/export and Trust Learning-Evidence tile (2A-1); Policy Library + Staff Attestation UI (2A-2); RCVS Self-Assessment admin page + Trust evidence (2A-3); Client-Facing Transparency Layer (2A-4); Incident / Near-Miss UI (2A-5); 2A-C presentation hardening. Why-flagged → Learn linkage shipped.

**Current target is reconciliation, not feature build.** No new feature pages without explicit founder instruction.

**Live generation is production-off** and the underlying Workspace path is Anthropic-coupled, not vendor-neutral. If asked to surface live generation in the UI, stop and report.

**M6.12 / M6.13 are gated future, not current work.**

**Next frontend tasks (RC hardening — only when explicitly instructed, with scope):** Workspace↔Receipt review-state coherence display; policy content-hash display fix/fallback; incident demo-state cleanup; tech-debt classification (AppShell font, portal visual consistency).

---

## When to stop and report rather than proceed

- Uncertain about doctrine or wording compliance → stop, report, ask
- Change requires a backend modification → stop, report, ask (this repo is frontend only)
- Change would alter the approved visual direction → stop, report, ask
- Scope would expand beyond the engineering brief → stop, report, ask
- Lint baseline would change (new errors or new warnings) → stop, report, ask

---

## M6 gap — CLOSED (informational)

- Why-flagged → Learn linkage — shipped. Assistant refusal/safety reasons deep-link into Learn cards.

---

## Canonical documents (cross-reference, do not duplicate doctrine here)

Located in `/docs/canonical/` in this repo.

**Operative set (current canonical state — defer to these):**

- `ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md` — operative roadmap; as-built reconciliation; §1 doctrine; current phase 2A-D.0 release-candidate hardening; M6.12 / M6.13 recorded as gated future; M4.6 deferred by decision; live Workspace generation Anthropic-coupled and production-off.
- `ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md` — operative readiness artefact; §2 wording controls (operative for all clinic-facing copy); §3 RCVS principles; §4 EU AI Act articles; vendor-neutrality framed as future-tense only.
- `ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md` — OPERATIVE decision; supersedes Memo v1.1 and Addendum v1.2 where they differ; authorises reconciliation (2A-D.0); records the conviction-based position (no buyer-discovery requirement, no parallel listening cadence).
- `Official_EU_AI_Act_Source_Note_v1_1.md` — operative EU AI Act source-discipline note; EUR-Lex is the only acceptable primary source; cite Article 113 for applicability dates; use "from August 2026" softening and Article 4 amendment-watch caveat.

**Historical / supporting records (NOT current targets; consult only for provenance):**

- `ANCHOR_Roadmap_v2_5_May_2026.docx` — superseded by v2.6.
- `ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1.docx` — superseded by v1.1.
- `ANCHOR_Phase_2A_Build_Order_Decision_Memo_v1_1.docx` — superseded by Addendum v1.3 where they differ; buyer-conversation framing in Memo v1.1 is corrected by Addendum v1.3.
- `Phase_2A_1_Engineering_Brief_v1_1.md` — Phase 2A-1 is shipped; brief retained as historical implementation record only; not the current Claude Code target.
- `Official_EU_AI_Act_Source_Note_v1.md` — superseded by v1.1.
