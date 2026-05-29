@AGENTS.md

# ANCHOR Frontend — Claude Code Context

This file is read automatically by Claude Code at session start. It is the project-level guardrail document. Do not duplicate strategy content here — point to canonical documents in `/docs/canonical/`.

---

## What ANCHOR is

ANCHOR is governance, trust, learning, intelligence, and sustainability infrastructure for safe AI use in veterinary clinics.

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

Any copy that appears to a clinic user, a clinic admin, or a pet owner must be checked against the wording controls in `ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1.docx` §2.

**Use**: "governance and readiness infrastructure", "metadata-only evidence", "supports CPD-recordable AI literacy activity", "aligned with", "human review required", "not chat history".

**Avoid**: "compliant", "certified", "RCVS-approved", "guarantees", "compliance system", "clinical record", "chat history".

When in doubt, stop and ask.

---

## Current implementation target: Phase 2A-1 — CPD-Recordable AI Literacy

Scope authorised by `ANCHOR_Phase_2A_Build_Order_Decision_Memo_v1_1.docx` and `Phase_2A_1_Engineering_Brief_v1_1.md`. Substantive build may proceed from the approved engineering brief. M5.6 buyer conversations run in parallel and may trigger in-flight scope revision, but they are not a build blocker.

**Frontend scope (provisional, full detail in engineering brief)**:

- `/learn` catalogue page enhancement — list modules with version, role applicability, CPD minutes, completion state for the logged-in user
- Module detail / completion flow — view module, mark complete with optional acknowledgement; correction/void behaviour is backend-governed and must not imply silent deletion
- CPD record export UI — generate and download metadata-only JSON per-staff CPD record in v1; PDF is deferred
- Trust Pack delta tiles — new tiles for total staff completed, total CPD minutes, completion rate by role, module catalogue summary
- At least one bias-detection module surfaced as a distinct trackable signal (RCVS Theme 8)
- All copy framed per wording controls above

**Out of scope for Phase 2A-1** (deferred to 2A-2 or M4.6):

- Staff Attestation UI
- Governance Policy Library UI
- Quiz/assessment grading UI
- Role-based learning path navigation
- Scenario onboarding flows
- Leadership dashboards on training uptake
- External LMS integration UI

---

## When to stop and report rather than proceed

- Uncertain about doctrine or wording compliance → stop, report, ask
- Change requires a backend modification → stop, report, ask (this repo is frontend only)
- Change would alter the approved visual direction → stop, report, ask
- Scope would expand beyond the engineering brief → stop, report, ask
- Lint baseline would change (new errors or new warnings) → stop, report, ask

---

## Honest M6 gap to be aware of (parallel work, not blocking)

- **Why-flagged → Learn linkage** — Assistant refusal codes and safety flags should deep-link into Learn cards. Phase 2A-1 creates the module catalogue this will deep-link into; if scope permits, fold in the linkage UI work as part of 2A-1.

---

## Canonical documents (cross-reference, do not duplicate doctrine here)

Located in `/docs/canonical/` in this repo:

- `ANCHOR_Roadmap_v2_5_May_2026.docx` — canonical roadmap; §1 doctrine; §4 M6 Assistant track as-built
- `ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1.docx` — §2 wording controls (operative for all clinic-facing copy); §3 RCVS principles; §4 EU AI Act articles
- `ANCHOR_Phase_2A_Build_Order_Decision_Memo_v1_1.docx` — Phase 2A ordering; buyer conversations parallel-not-blocking; §5 Phase 2A-1 scope; §10 wording controls for 2A-1
- `Phase_2A_1_Engineering_Brief_v1_1.md` — Phase 2A-1 implementation contract; confirmed implementation decisions; backend/frontend scope
- `Official_EU_AI_Act_Source_Note_v1.md` — source-discipline document for any EU AI Act reference; EUR-Lex is the only acceptable primary source; cite Article 113 for all applicability dates.
