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

## Current implementation target: 2A-D.0 — Canonical reconciliation / Release-candidate hardening

Authorised by `ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3` (6 June 2026), operative over Memo v1.1 and Addendum v1.2 where they differ.

**Built and shipped — do NOT rebuild:** Phase 2A-1 (CPD-Recordable AI Literacy), 2A-2 (Policy Library + Staff Attestation), 2A-3 (RCVS Self-Assessment + Evidence Closure), 2A-4 (Client-Facing Transparency Layer), 2A-5 (Incident / Near-Miss Logging), 2A-C presentation hardening, M6.10, M6.11. Readiness discipline R1–R4 complete. Both honest M6 gaps closed.

**Current target is reconciliation, not feature build.** No new feature work without explicit founder instruction. ANCHOR proceeds on regulatory/professional-governance conviction — there is no buyer-discovery step.

**Live generation is production-off.** The Workspace live integration (2A-C.5B/5C) is built directly on the Anthropic API and is NOT vendor-neutral. Do not enable live generation in production until the local/staging safety gate (2A-C.5E) passes and the hard-refusal boundary (diagnosis/treatment/prescribing) is proven on the live path. The hard-refusal harness ships *with* live LLM calls, never after. Anthropic becomes a subprocessor the moment live generation is enabled — flag any change that would activate it.

**M6.12 / M6.13 are gated future, not current work.** Do not start either without an explicit founder decision recorded in an addendum.

**Next backend tasks (RC hardening — only when explicitly instructed, with scope):** security audit (auth/JWT, admin token, RLS/FORCE RLS, route protection, RBAC, CORS, rate limiting, export/receipt access limits, dependency + secret scan); operational resilience (backups, tested restore); 2A-C.4 backend Trust Pack source-of-truth polish; Workspace↔Receipt review-state coherence; policy content-hash fix.

---

## When to stop and report rather than proceed

- Uncertain about doctrine compliance → stop, report, ask
- Change touches tenant safety, RLS, auth, or metadata-only posture in any non-trivial way → stop, report, ask
- Scope would expand beyond the engineering brief → stop, report, ask
- Two viable approaches exist and the choice has doctrine implications → stop, report, ask

---

## M6 gaps — CLOSED (informational)

* Formal Assistant evaluation / golden-test set — closed via R3 (Evaluation / Golden-Test Registry v1).
* Why-flagged → Learn linkage — closed; the Learn module catalogue it deep-links into now exists.

---

## Canonical documents (cross-reference, do not duplicate doctrine here)

Located in `/docs/canonical/` in this repo:

- `ANCHOR_Roadmap_v2_5_May_2026.docx` — canonical roadmap; §1 doctrine; §4 M6 Assistant track as-built; §6 sustainability design
- `ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1.docx` — Phase 2A defensibility artefact; §2 wording controls; §3 RCVS principles; §4 EU AI Act articles
- `ANCHOR_Phase_2A_Build_Order_Decision_Memo_v1_1.docx` — Phase 2A ordering; buyer conversations parallel-not-blocking; §5 Phase 2A-1 scope; §10 wording controls for 2A-1
- `Phase_2A_1_Engineering_Brief_v1_1.md` — Phase 2A-1 implementation contract; confirmed implementation decisions; backend/frontend scope
- `ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3` — OPERATIVE decision; supersedes Memo v1.1 and Addendum v1.2 where they differ; authorises reconciliation (2A-D.0); records the conviction-based (no buyer-discovery) position
- NOTE: Roadmap v2.6 and Readiness Map v1.1 supersede v2.5 and v1 once issued; until then treat v2.5/v1 status fields as stale and defer to Addendum v1.3

For any wording that will appear in API responses, error messages, or anywhere clinic-facing: check Readiness Map §2 first.
