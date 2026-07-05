# Fable Frontend Roadmap-Completion Experiment — Backend Contract Map (Slice F1)

> **Status: internal experiment artefact. 5 July 2026.**
>
> Branch: `fable/frontend-roadmap-completion-experiment` (frontend). Pairs with the
> backend experiment branch `fable/roadmap-completion-experiment` in the ANCHOR API
> repo, authorised by the backend repo's
> `docs/operations/2026-07-05_founder_code_completion_experiment_decision.md`.
>
> All production, commercial, and claims gates remain closed: no deploy, no merge to
> production, no push without explicit founder instruction, no public launch copy,
> no paid pilots, no live billing, live generation production-off, no ambient
> transcript capability, no provider switching in production. ANCHOR is aligned,
> not compliant — no RCVS / EU AI Act / GDPR compliance, certification, approval,
> or endorsement claims.

## Source of truth

Contracts below were read directly from the backend experiment branch source
(`app/portal_onboarding.py`, `app/learn_maturity.py`, `app/billing_foundations.py`,
`app/sustainability.py`, `app/ambient_governance.py`, `app/assistant_provider.py`)
on 5 July 2026 — not invented. The backend slice log
(`docs/operations/2026-07-05_fable_roadmap_completion_experiment_log.md`) records
the same prefixes. These endpoints exist **only on the backend experiment branch**;
against the production API they return 404. Every frontend surface built on them is
therefore gated behind `NEXT_PUBLIC_ANCHOR_INTERNAL_PREVIEW` (fail-closed, default
off).

All endpoints are clinic-scoped via the existing bearer-token auth (`apiFetch`);
the frontend never passes `clinic_id`. "Admin" means backend roles
`admin | owner | practice_manager` (403 `forbidden_not_admin` otherwise); the
frontend mirrors this set for discoverability only — backend remains the real
authority.

## M5.7 Assisted Onboarding — `/v1/portal/onboarding` (read-only)

| Method | Path | Access | Response |
|---|---|---|---|
| GET | `/v1/portal/onboarding/checklist` | any clinic user | `{ generated_at, completed_count, total_count, items[], governance_note }` |
| GET | `/v1/portal/onboarding/invites` | admin | `{ invites[], pending_count, used_count, expired_count, governance_note }` |

Checklist item: `{ key, title, done, available, count (nullable), guidance }`.
Items soft-fail independently — `available: false` means "honest unavailable",
never a fabricated zero. 9 items; `incident_reporting_ready` is informational
(done = available). Invite: `{ invite_id, email, role, status: pending|used|expired,
created_at?, expires_at?, used_at? }`. **No token material is ever returned.**

## M4.6 Learn Maturity — `/v1/learn` (non-certifying)

| Method | Path | Access | Notes |
|---|---|---|---|
| GET | `/v1/learn/checks/modules/{module_id}` | any | `{ module_id, questions[], self_check_note }`; question: `{ check_id, check_slug, kind, prompt, options[], display_order }` |
| POST | `/v1/learn/checks/modules/{module_id}/attempts` | any | body `{ answers: [{ check_id, selected_option_index }] }` (must cover **all** active checks, no duplicates; 400 `incomplete_self_check` / `duplicate_check_answer` / `invalid_option_index`); returns `{ attempt_id, module_id, module_version, questions_total, questions_correct, completed_at, feedback[], self_check_note }`; feedback: `{ check_id, correct, correct_option_index, explanation }`. Aggregate-only storage. |
| GET | `/v1/learn/paths` | any | `{ paths[], self_check_note }`; path: `{ path_id, path_slug, version, title, summary, role_applicability[], module_slugs[], completed_module_slugs[], completed_count, total_count }` |
| GET | `/v1/learn/renewals/me` | any | `{ renewal_months, entries[], self_check_note }`; entry: `{ module_id, module_slug, title, latest_completed_at, due_at, status: current|due_soon|overdue }` |
| GET | `/v1/learn/renewals/overview` | admin | `{ renewal_months, users[], total_current, total_due_soon, total_overdue, self_check_note }`; user: `{ user_id, modules_completed, current_count, due_soon_count, overdue_count }` |
| PUT | `/v1/learn/renewal-policy` | admin | body `{ renewal_months: 1..60 }`; returns `{ renewal_months, updated_at?, self_check_note }` |

Every response carries `self_check_note` (non-certifying wording). Frontend must
use "self-check", "learning reinforcement", "completion evidence", "renewal
reminder"; never "pass/fail", "competent", "certified", "RCVS-accredited",
"approved CPD".

## M5.8 Billing Foundations — `/v1/portal/billing` (sandbox-only)

| Method | Path | Access | Notes |
|---|---|---|---|
| GET | `/v1/portal/billing/state` | any | `{ plan_slug, activation_status, billing_readiness, stripe_mode, updated_at?, plans[], sandbox_note }`; defaults returned when no row exists (`internal_demo` / `internal_demo` / `not_ready` / `disabled`). Plan: `{ plan_slug, version, title, summary, monthly_price_pence (deliberately null), currency, display_order }` |
| PUT | `/v1/portal/billing/state` | admin | body `{ plan_slug?, activation_status?, billing_readiness? }`. API-settable activation: `internal_demo | pilot_candidate` only — anything else 403 `activation_gated_requires_founder_and_gates`. Readiness: `not_ready | sandbox_only | ready_pending_gates`. |

`stripe_mode` is never settable through the API and the schema cannot store
`live`. The Stripe webhook (`POST /v1/billing/webhook/stripe`) is a
structure-only, prod-refusing skeleton — **not a frontend surface**. Frontend
shows no payment buttons, no checkout, no subscribe-now language.

## M6-S Sustainability — `/v1/portal/sustainability` (metadata-only evidence)

| Method | Path | Access | Notes |
|---|---|---|---|
| GET/PUT | `/config` | GET any / PUT admin | `{ reporting_enabled (default false), baseline_year?, electricity_factor_g_co2e_per_kwh?, gas_factor_g_co2e_per_kwh?, waste_factor_g_co2e_per_kg?, factor_source_text?, updated_at?, sustainability_note }` |
| POST/GET | `/energy-readings` | create any / list any | create: `{ energy_type: electricity|gas|other, period_start, period_end, consumption_kwh>=0, supplier_label? }`; list: `{ readings[], sustainability_note }` with `{ reading_id, energy_type, period_start, period_end, consumption_kwh, supplier_label, is_voided, created_at }` |
| POST | `/energy-readings/{id}/void` | admin | body `{ void_reason: 3..500 chars }` → `{ voided: true }`; 404 `row_not_found_or_already_voided` |
| POST/GET | `/waste-events` (+ `/{id}/void`) | as above | `{ waste_stream: clinical|offensive|domestic|recycling|other, occurred_on, weight_kg>=0, supplier_label? }` |
| POST/GET | `/footprint-estimates` (+ `/{id}/void`) | as above | `{ workflow_label, period_start, period_end, estimated_kg_co2e>=0, factor_source_text? }` |
| GET | `/rolling-12m` | any | `{ months: [{ month, energy_kwh?, waste_kg?, estimated_kg_co2e? }], sustainability_note }` |
| POST | `/reports` | admin | generates immutable hashed report from rolling-12m; supersedes prior report |
| GET | `/reports` | any | `{ reports[], sustainability_note }`; report: `{ report_id, report_version, period_start, period_end, energy_kwh_total, waste_kg_total, estimated_kg_co2e_total, report_hash, superseded_at?, generated_at }` |
| GET | `/trust-summary` | any | `{ reporting_enabled, energy_reading_count, waste_event_count, footprint_estimate_count, report_count, latest_report_generated_at?, sustainability_note }` |

Wording: governance evidence only — "not an accredited carbon audit and not a
compliance certification" (backend note displayed verbatim).

## M6.13 Ambient Governance — `/v1/portal/ambient` (flag-gated shell)

**Every endpoint returns 503 `ambient_governance_disabled` unless the backend env
flag `ANCHOR_AMBIENT_GOVERNANCE_ENABLED` is truthy.** The frontend treats 503 as
the normal, expected "ingestion disabled" state and displays it as posture, not
as an error.

| Method | Path | Access | Notes |
|---|---|---|---|
| GET | `/events?review_status=pending_review|reviewed|discarded` | any | `{ events[], ambient_note }`; event: `{ ambient_event_id, source_label, event_type, occurred_at, duration_seconds?, workflow_reference_hash?, review_status, review_decision?, reviewed_at?, created_at, ambient_note }` |
| POST | `/events` | any | metadata-only create — **no frontend create UI is built in this experiment** (shell is list + review gate only) |
| POST | `/events/{id}/review` | any | body `{ review_decision: approved_for_record | amended_before_use | rejected }`; 404 `event_not_found_or_already_reviewed` if not pending |
| GET | `/summary` | any | `{ pending_review_count, reviewed_count, discarded_count, latest_event_at?, ambient_note }` |

Event types: `consult_recorded | note_generated | note_reviewed_externally | other`.
No transcript, audio, or note content exists anywhere in the schema; the
`workflow_reference_hash` field only accepts a SHA-256 hex digest.

## M6.12 Provider / Connector posture — **no portal API**

`app/assistant_provider.py` is an internal backend module (env-resolved adapter,
production allow-list = Anthropic only, OpenAI adapter non-prod + key-gated,
fail-closed). **No endpoint exposes provider posture to the portal**, and receipt
generation metadata display is out of scope for this experiment (Receipts page
contract is stable/do-not-touch). Slice F7 is therefore a static posture surface:
"architected for vendor-neutrality / vendor-neutral over time", live path
Anthropic-coupled, live generation production-off, provider switching disabled —
with a visibly disabled, clearly-unavailable control and no live toggle.

## Frontend gating

All surfaces built in this experiment are wrapped in an internal-preview gate
(`lib/internalPreview.ts` + `components/experiment/InternalPreviewGate.tsx`)
keyed on `NEXT_PUBLIC_ANCHOR_INTERNAL_PREVIEW` (truthy: `1|true|yes|on`;
build-time inlined; unset in every deployed environment). With the flag off —
the default — no new navigation link, tile, or section renders and no
experimental fetch is made.
