# ANCHOR Review Playbook (backend)

This file tells Claude Code how to review work on the ANCHOR backend. It is the entry point for review sessions. Skills and agents below are project-local under `.claude/`.

## Operative canon

- `docs/canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md` (Roadmap v2.6)
- `docs/canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md` (Readiness Map v1.1)
- `ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3` (Addendum v1.3)

Older v2.5 / v1 / Memo v1.1 / Addendum v1.2 are stale where they conflict.

## Current target

**2A-D.0 — Canonical reconciliation / Release-candidate hardening.**
No new feature work without explicit founder instruction.

## Standing constraints (do not violate without explicit founder decision)

- Metadata-only doctrine — no raw prompts/outputs/drafts/transcripts/clinical content; hashes only for identifier-shaped data.
- ANCHOR is not a clinical decision-making AI, diagnostic tool, ambient scribe, EHR, or clinical record.
- No claims of compliance, certification, RCVS approval, regulator endorsement, guaranteed protection, "audit-proof", "high-risk AI compliance".
- Present-tense vendor neutrality is **not** claimed. ANCHOR is structurally compatible with future vendor neutrality; live Workspace generation currently uses the Anthropic API directly and is **production-off**.
- ANCHOR is a downstream integrator, **not** a GPAI provider under Chapter V.
- No buyer discovery, no "5–10 practice-owner conversations", no parallel listening cadence. The position is conviction-based per Addendum v1.3.
- M4.6 is deferred. M6.12 / M6.13 are gated future — not current work.
- Existing Assistant evaluation suite is additive-only. Existing migrations are never retroactively edited.

## Review modes

### 1. Doctrine check (any change touching wording, storage, or AI output)

Invoke skill: `anchor-doctrine-check`.
Pass the diff or candidate string. Skill reports PASS / FAIL with line-level findings and proposed rewordings grounded in Readiness Map v1.1 §2.

### 2. Backend safety review (any change to `app/`, `tests/`, `migrations/`)

Invoke skill: `anchor-backend-safety-review`.
Or spawn agent: `anchor-backend-rls-reviewer` for migrations and tenant-touching diffs specifically.

Required before declaring complete:
- App import check (`python -c "from app.main import app"`).
- Focused Assistant test suite passing.
- Any new test suite covering the change.
- Reporting block per CLAUDE.md "Reporting expectations".

### 3. Release-candidate security audit

Invoke skill: `anchor-security-audit`, or spawn agent: `anchor-security-reviewer`.
Scope: auth/JWT, admin tokens, RLS/FORCE RLS, route protection, RBAC, CORS, rate limiting, export/receipt access, dependency + secret scan, metadata-only doctrine, operational resilience flags.

### 4. Docs reconciliation

Spawn agent: `anchor-docs-reconciler`.
Walks markdown/docs for stale-canon, buyer-discovery drift, compliance claims, gated-future-treated-as-current, and present-tense vendor-neutrality slips. Read-only; reports proposed replacements.

## Reporting block (every review must end with this)

1. Files changed — full paths (or "none, review-only").
2. Behaviour changed — short narrative.
3. Tests run — names and results.
4. Build / import check result.
5. Backend or frontend touched — this repo is backend; flag if a frontend change is needed.
6. Metadata-only doctrine preserved — yes / no / explain.
7. Tenant safety, RLS, and auth preserved — yes / no / explain.
8. Any limitations or deferred items — explicit list.

## What never happens in a review session

- No commits or pushes.
- No edits to `app/`, `tests/`, `migrations/` from a review skill or review agent.
- No refactor of the existing Assistant evaluation suite.
- No retroactive edits to existing migrations.
- No enabling of live Workspace generation in production.
- No introduction of buyer discovery / parallel listening cadence.
- No new third-party plugins installed.
