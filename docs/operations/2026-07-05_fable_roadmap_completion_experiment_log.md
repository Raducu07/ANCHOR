# Fable Roadmap-Completion Experiment — Running Slice Log

> Branch: `fable/roadmap-completion-experiment`. Authorised by `2026-07-05_founder_code_completion_experiment_decision.md`. All production/commercial/claims gates remain closed. This log is updated per slice and is the recovery point if a session is interrupted.

| Slice | Scope | Status | Evidence |
|---|---|---|---|
| 0 | Preserve reviewed backend experiment (safety-gate harness; provider skeleton; HTTPS webhook enforcement; pytest hygiene; docs) | **Committed** | Full suite 1,567 passed; app import OK (126 routes); runner smoke OK incl. prod refusal. Commits on branch. |
| 1 | M6.12 connector layer completion (gated) | **Committed** | Gated OpenAI adapter (stdlib HTTPS, non-prod only, key-gated, fail-closed); provider_latency_ms metadata in generation sub-object; cross-provider output-safety test. Focused suites 48 passed. |
| 2 | M5.7 assisted onboarding foundations (gated) | **Committed** | Read-only tenant-scoped onboarding checklist (9 items, soft-failing) + admin-only invite lifecycle visibility (pending/used/expired, no token material). Invite expiry/used-at handling verified already present in accept flow. 9 endpoint tests passed. |
| 3 | M4.6 Learn maturity (non-certifying) | **Committed** | Self-check/scenario questions (aggregate-only attempts, no per-answer storage), role paths with progress, renewal status + leadership overview, per-clinic renewal cadence. 2 migrations (RLS+FORCE with USING/WITH CHECK on both clinic tables). Every response carries the non-certifying note. 63 tests passed incl. existing Learn suite. |
| 4 | M5.8 billing foundations (sandbox-only) | **Committed** | Plan catalogue (prices deliberately NULL), clinic_billing_state (RLS+FORCE; stripe_mode constrained to disabled/test at schema level), activation API refuses active_limited/active_verified, structure-only webhook skeleton (503 by default; refuses in prod; processes/stores nothing). 17 tests passed. |
| 5 | M6-S sustainability module (metadata-only) | **Committed** | All §8 schema corrections re-checked and applied (separate per-stream aggregation in rolling view; USING+WITH CHECK on all 5 tables; live clinic_users FKs; supplier_label; void + report supersession; sustainability_workflow_footprint_estimates naming; factor_source_text provenance). Config (reporting_enabled defaults false), 3 evidence streams with void-with-reason, hashed reports with supersession, Trust summary. 18 tests passed. |
| 6 | M6.13 ambient governance shell (extreme caution) | Pending | — |
| 7 | Frontend roadmap work | **Not executable in this workspace** — the portal frontend repo is not present; backend contracts to be documented for a later frontend session. | — |

Standing deferrals recorded during the experiment (each with rationale, revisit under founder review):

- M6.12 per-clinic provider configuration — needs an assistant-policy migration + admin UI; platform-level selection shipped instead.
- M6.12 cross-provider fallback routing — deterministic fallback is the doctrine-preferred failure mode; provider-to-provider retry adds unreviewed complexity.
- M6.12 token/cost metadata — provider client returns a text-only tuple; changing that contract ripples through the safety-gate harness and tests; latency metadata shipped instead.
