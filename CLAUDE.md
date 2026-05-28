# ANCHOR Backend — Claude Code Context

This file is read automatically by Claude Code at session start. It is the project-level guardrail document. Do not duplicate strategy content here — point to canonical documents in `/docs/canonical/`.

---

## What ANCHOR is

ANCHOR is governance, trust, learning, intelligence, and sustainability infrastructure for safe AI use in veterinary clinics.

ANCHOR is **not** a clinical decision-making AI, diagnostic tool, ambient scribe, EHR, or replacement for veterinary judgement.

Public one-liner: *"Governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics."*

---

## This repository

- **Stack**: FastAPI + Postgres
- **Deployment**: Render
- **Production origin**: `https://anchor-api-prod.onrender.com`
- **Tenant isolation**: FORCE RLS on tenant tables; request-scoped tenant context via `current_setting('app.clinic_id')`
- **Auth**: clinic auth + admin auth, both live
- **Status**: Governed Assistant evidence loop shipped end-to-end (M6.1–M6.9.4)

---

## Doctrine — never violate without explicit founder decision

1. **Governance-first** — every feature exists to make AI use reviewable and accountable
2. **Metadata-only by default** — never store raw prompts, outputs, drafts, transcripts, or clinical content; hashes only
3. **Not clinical decision-making AI** — no diagnosis, prescribing, treatment planning, autonomous triage
4. **Human-review based** — AI outputs require human review before operational use
5. **Receipt-backed** — governed interactions produce metadata receipts
6. **Trust-surface oriented** — governance must surface as legible trust posture, not hidden backend logs
7. **Multi-tenant and privacy-aware** — RLS, FORCE RLS, strict tenant isolation
8. **Vendor-neutral over time** — never hardcode a single AI provider
9. **Standalone now, integrable later** — credible on its own; structurally compatible with future EHR/ambient/external AI
10. **Aligned, not compliant** — never claim RCVS approval, EU AI Act compliance, certification, regulator endorsement, or protection from enforcement
11. **ANCHOR is not a GPAI provider** — downstream integrator only; Chapter V GPAI obligations do not apply

---

## What NOT to touch without explicit instruction

- Tenant safety, RLS policies, FORCE RLS posture
- Authentication code, clinic auth, admin auth, invite flow, setup token logic
- Metadata-only storage posture — never add raw content fields without doctrine-level decision
- Existing Assistant evaluation suite — do not refactor; add to it
- Existing migrations — never retroactively edit, only add new
- Cross-cutting refactors — keep changes targeted and incremental
- FastAPI/OpenAPI deprecated-route warnings — deferred technical debt
- Pydantic v1-style configs already cleaned (M6.6.1) — do not regress

---

## Coding rules

- No type ignores (`# type: ignore`), no `Any` without justification, no suppression comments without a documented reason in the same change
- New migrations only if unavoidable. If needed, follow the existing pattern and **always** include RLS policies with both `USING` and `WITH CHECK` clauses
- New tables that hold clinic-scoped data must enable RLS and FORCE RLS
- Hash any identifier-shaped data (IPs, user agents) at write time; never store raw
- Endpoints must be tenant-scoped via the existing request-scoped tenant context pattern
- Do not commit or push to git unless explicitly asked

---

## Test discipline

After any backend change, run:

- The focused Assistant test suite (do not break existing tests)
- App import check (`python -c "from app.main import app"` or equivalent for this repo)
- Any new test suite covering the change
- Report exact results

Do not declare a change complete without passing tests.

---

## Reporting expectations after each session

Always report:

1. **Files changed** — full paths
2. **Behaviour changed** — short narrative
3. **Tests run** — names and results
4. **Build / import check result**
5. **Backend or frontend touched** — this repo is backend; flag if a frontend change is needed
6. **Metadata-only doctrine preserved** — yes / no / explain
7. **Tenant safety, RLS, and auth preserved** — yes / no / explain
8. **Any limitations or deferred items** — explicit list

---

## Current implementation target: Phase 2A-1 — CPD-Recordable AI Literacy

Scope authorised by `ANCHOR_Phase_2A_Build_Order_Decision_Memo_v1_1.docx` and `Phase_2A_1_Engineering_Brief_v1_1.md`. Substantive build may proceed from the approved engineering brief. M5.6 buyer conversations run in parallel and may trigger in-flight scope revision, but they are not a build blocker.

**Backend scope (provisional, full detail in engineering brief)**:

- New database objects: `learning_modules`, `learning_completions`, derived view `v_cpd_records`, and `cpd_exports`
- RLS + FORCE RLS on clinic-scoped tables (`learning_completions`, `cpd_exports`); `WITH CHECK (clinic_id = current_setting('app.clinic_id')::UUID)` required on every clinic-scoped RLS policy
- Endpoints (provisional): list modules; record completion; void completion with reason; generate per-staff CPD record export; aggregate Trust Pack delta
- Module metadata: `module_id`, `version`, `title`, `role_applicability`, `cpd_minutes`, `rcvs_principle_mappings[]`, `eu_ai_act_article_mappings[]`
- No raw learning content stored in the database; module content references markdown files in `docs/learn/modules/`
- All evidence artefacts metadata-only; completion corrections use a void-with-reason pattern, not silent deletion or overwrite

**Out of scope for Phase 2A-1** (deferred to 2A-2 or M4.6):

- Staff Attestation Layer
- Governance Policy Library
- Quiz grading / assessment scoring
- Role-based learning paths
- Scenario onboarding
- Adaptive recommendations
- Leadership dashboards on training uptake
- External LMS integration

---

## When to stop and report rather than proceed

- Uncertain about doctrine compliance → stop, report, ask
- Change touches tenant safety, RLS, auth, or metadata-only posture in any non-trivial way → stop, report, ask
- Scope would expand beyond the engineering brief → stop, report, ask
- Two viable approaches exist and the choice has doctrine implications → stop, report, ask

---

## Honest M6 gaps (informational, parallel to Phase 2A-1, not blocking)

- Formal Assistant evaluation / golden-test set — dual purpose: product safety + EU AI Act Article 12 record-keeping
- Why-flagged → Learn linkage — Phase 2A-1 creates the module catalogue this will deep-link into; closure can be folded in if scope permits

---

## Canonical documents (cross-reference, do not duplicate doctrine here)

Located in `/docs/canonical/` in this repo:

- `ANCHOR_Roadmap_v2_5_May_2026.docx` — canonical roadmap; §1 doctrine; §4 M6 Assistant track as-built; §6 sustainability design
- `ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1.docx` — Phase 2A defensibility artefact; §2 wording controls; §3 RCVS principles; §4 EU AI Act articles
- `ANCHOR_Phase_2A_Build_Order_Decision_Memo_v1_1.docx` — Phase 2A ordering; buyer conversations parallel-not-blocking; §5 Phase 2A-1 scope; §10 wording controls for 2A-1
- `Phase_2A_1_Engineering_Brief_v1_1.md` — Phase 2A-1 implementation contract; confirmed implementation decisions; backend/frontend scope

For any wording that will appear in API responses, error messages, or anywhere clinic-facing: check Readiness Map §2 first.
