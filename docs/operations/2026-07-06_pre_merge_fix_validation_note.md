# Pre-Merge Fix and Validation Note — Fable Experiment Branches

> **Status: dated validation/fix record, 6 July 2026.** Bounded pre-merge work on the experiment branches only, addressing the FIX items from the 5 July 2026 full-stack readiness audit. **No deploy, no merge to main/master, no push, and no production environment setting was changed.** Live generation remains production-off; live billing remains off; ambient ingestion remains disabled; OpenAI remains unconfigured; no real clinic data was used. ANCHOR is **aligned, not compliant** — nothing here is a compliance, certification, or approval claim.

---

## 1. Audit findings addressed

| Audit finding | Fix | Status |
|---|---|---|
| F1 — five 20260705 migrations never executed against real Postgres | FIX 1: fresh + upgrade paths run against a throwaway local PostgreSQL 16.12 | **Done — with one real defect found and fixed (§3)** |
| F2 — new admin write-paths lacked admin_audit_events rows | FIX 2: append-only audit events on all four paths, M6.10 precedent | **Done, test-covered** |
| F3 — preview surfaces showed generic errors on 404/503 | FIX 3: honest "not available on this backend" posture, ambient-style | **Done, build/lint green** |

## 2. Files changed

**Backend (`fable/roadmap-completion-experiment`):**
- `app/billing_foundations.py`, `app/learn_maturity.py`, `app/sustainability.py`, `app/ambient_governance.py` — module-local `_insert_admin_audit_event` + audit call after each successful admin write (FIX 2).
- `tests/test_billing_foundations.py`, `tests/test_learn_maturity_endpoints.py`, `tests/test_sustainability.py`, `tests/test_ambient_governance.py` — FakeDB audit-insert capture + 5 new focused tests (FIX 2).
- `migrations/20260705_02_learn_maturity_seed.sql` — two in-string semicolons reworded + runner-constraint comment (FIX 1 defect; §3).
- `docs/operations/2026-07-06_pre_merge_fix_validation_note.md` (this note) and an experiment-log row.

**Frontend (`fable/frontend-roadmap-completion-experiment`):**
- `components/experiment/InternalPreviewGate.tsx` — shared `isPreviewEndpointUnavailable()`, `previewAwareErrorMessage()`, `PREVIEW_ENDPOINT_UNAVAILABLE_MESSAGE`, `PreviewBackendUnavailableCard`.
- `components/onboarding/OnboardingReadinessSurface.tsx`, `components/billing/BillingFoundationsSurface.tsx` — full-surface unavailable card on primary-load 404/503 (ambient-style), preview-aware messages elsewhere.
- `components/learn/LearnMaturitySurface.tsx` (4 catches), `components/sustainability/SustainabilityGovernanceSurface.tsx` (13 catches) — preview-aware honest messages.

## 3. Migrations validated (FIX 1)

**Environment:** throwaway PostgreSQL 16.12 instance created from the locally installed binaries (`initdb`, own data dir in the session scratchpad, `127.0.0.1:55432`, trust auth, no real data), torn down after validation. The existing local PostgreSQL service and its data were **not touched**; no production database was involved.

- **Fresh path** (`anchor_mig_fresh`): `app/schema.sql` + `app/security.sql` base, then the experiment branch's full migration set — all 38 files applied, `status=ok`.
- **Upgrade path** (`anchor_mig_upgrade`): same base, then the **main-branch** migration set (33 files, via a read-only git worktree of `c9d958d`) to simulate the production-like state, then the experiment branch's runner — applied **exactly the five 20260705 files**, `status=ok`, all prior files skip-verified.
- **Defect found and fixed:** `20260705_02_learn_maturity_seed.sql` is the only new migration without dollar-quoting, so the runner splits it on every semicolon — and two seed explanation strings contained literal semicolons, chopping statements mid-string (SQL syntax error on both paths). The two strings were reworded (no semicolons; content meaning unchanged, still non-certifying) and a runner-constraint comment added. **These migrations exist only on the unmerged experiment branch and have never been applied to any real database**, so editing them (rather than stacking a correction) is consistent with the never-edit doctrine, which protects *applied* migrations. Re-run: both paths green.
- **Post-apply verification, both databases:** all 9 new clinic-scoped tables (`learning_check_attempts`, `learning_renewal_policies`, `clinic_billing_state`, `sustainability_config`, `sustainability_energy_readings`, `sustainability_waste_events`, `sustainability_workflow_footprint_estimates`, `sustainability_reports`, `ambient_governance_events`) report `relrowsecurity = t` **and** `relforcerowsecurity = t`; all 9 tenant policies report `qual IS NOT NULL` (USING) **and** `with_check IS NOT NULL`; global catalogue tables (`billing_plans`, `learning_module_checks`, `learning_role_paths`) correctly not RLS-enabled; `v_sustainability_rolling_12m` present; seeds correct (10 checks, 2 paths, 2 plans).

## 4. Audit events added (FIX 2)

Append-only, metadata-only `admin_audit_events` rows following the `governance_policy._insert_audit_event` / assistant-policy M6.10 precedent (no `ON CONFLICT` against the partial idempotency index; `ip_hash` from request state; `meta` as jsonb):

| Endpoint | Action | Meta contents | Explicitly excluded |
|---|---|---|---|
| `PUT /v1/portal/billing/state` | `billing_state_updated` | previous + new plan/activation/readiness | any secret-shaped data (none exists in the module) — test-asserted |
| `PUT /v1/learn/renewal-policy` | `learn_renewal_policy_updated` | `renewal_months` | learner answers, anything competence-framed |
| `PUT /v1/portal/sustainability/config` | `sustainability_config_updated` | posture booleans + factor-set flags | **free-text `factor_source_text` content** — test-asserted absent |
| `POST /v1/portal/ambient/events/{id}/review` | `ambient_event_reviewed` (target_id = event) | bounded decision category + resulting status | transcripts/audio/notes (schema-impossible anyway) |

Refused/failed writes (403/404) write no audit row — test-asserted. Auth/admin gates and RLS/FORCE RLS untouched.

## 5. Frontend soft-fail changes (FIX 3)

404/503 from experiment endpoints now renders the honest posture everywhere, with ambient's designed behaviour as the reference: onboarding and billing show a full-surface "not available on this backend" card on primary load; Learn maturity and sustainability sections show the honest posture message in place of generic errors; write actions report it too. `NEXT_PUBLIC_ANCHOR_INTERNAL_PREVIEW` remains off by default (build-time, unset in every deployed environment); no public links, no live billing affordance, no live provider toggle, no content inputs, and no new claims were added — the change is error-path presentation only.

## 6. Tests / build / lint results

- Backend focused suites (billing, learn maturity, sustainability, ambient): **69 passed** including the 5 new audit-event tests.
- Backend full suite: **1,658 passed, 0 failed** (one pre-existing `httpx` deprecation warning, already classified as deferred hygiene).
- App import check: **OK — 156 routes** (unchanged).
- Frontend `npm run build`: **success, exit 0, no errors, no new warnings**.
- Frontend `npm run lint`: **0 errors, 1 warning — exactly the known AppShell custom-font warning** (documented "do not fix" baseline).

## 7. Remaining WATCH items (unchanged from the 5 July audit)

Pre-existing `_deliver` webhook failure log includes `error=str(exc)[:240]` (could echo host fragments); sandbox billing webhook accepts unauthenticated JSON when flagged on in non-prod (keep flag off); build-time preview flag misconfiguration in CI would expose preview surfaces (server-side role checks still protect writes); preview pages have no client-side role gating (server enforces); sustainability clinic-controlled labels have no single-line guard (ambient's does); disabled "Enable live billing — unavailable" buttons are screenshot-sensitive.

## 8. What remains blocked before merge

Unchanged: founder decision recorded as a canonical addendum for the M6.12-adjacent work; founder wording review of all new surface strings; solicitor questions (subprocessor conditionality, billing clauses, ambient controller/processor mapping, sustainability data-flow row); adoption of the M6.13 clinical-content boundary spec DRAFT before its slice merges; the selective harvest order decision; and the standing gates — paid pilots, real clinic data, production live generation, live billing all remain closed.

## 9. Confirmation

**No deploy. No merge to main/master. No push performed by this task. No production environment setting changed. No production database touched. No real clinic data used. No gate opened.** All work is commits on the two experiment branches plus this note.
