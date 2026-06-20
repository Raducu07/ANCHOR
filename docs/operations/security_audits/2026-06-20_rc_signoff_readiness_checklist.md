# RC Sign-Off Readiness Checklist — 2026-06-20

> **Documentation-only readiness checklist.** Prepared after the frontend RC polish checkpoint. **Not final RC sign-off.** **No new authority granted.** Not legal advice, not solicitor review, not compliance certification, not RCVS / regulator approval, and not authorisation for paid pilots, real clinic data, clinic onboarding, customer access, billing / Stripe, live Workspace generation, Anthropic production subprocessor activation, external connectors, or production deployment.
>
> ANCHOR is **aligned, not compliant** — not RCVS-approved, not regulator-endorsed, not certified. Live Workspace generation **remains production-off**.

## 1. Status

- Documentation-only readiness checklist.
- Prepared after the frontend RC polish checkpoint.
- Not final RC sign-off.
- No new authority granted.

This document summarises where ANCHOR stands after backend operational resilience, commercial/legal founder-preparation, RC coherence closure, and frontend RC polish. It exists to support an internal founder review. It does **not** itself sign off the release candidate and grants no authority that did not already exist.

## 2. ANCHOR product boundary

ANCHOR is governance, trust, learning, intelligence, and readiness infrastructure for responsible AI use in veterinary clinics.

ANCHOR is **not**:

- diagnostic AI,
- prescribing AI,
- treatment-planning AI,
- autonomous clinical decision-making AI,
- autonomous triage,
- an ambient scribe,
- an EHR / PMS,
- clinical decision-support software,
- a GPAI model provider,
- RCVS-approved software,
- regulator-approved software,
- compliance certification,
- a replacement for veterinary judgement.

## 3. Evidence lanes completed

The following lanes are evidence-backed in this repository (operations / commercial / strategy directories) and in the `anchor-portal` frontend repository as noted. Completion here means *internal RC-hardening evidence exists*, not external approval.

- **Backend operational resilience baseline** — dependency / reproducibility chain, deploy smokes, and observability consolidated ([`2026-06-08_operational_resilience_checkpoint.md`](./2026-06-08_operational_resilience_checkpoint.md)).
- **Dependency / CVE remediation and clean audit state** — PyJWT and Starlette (via compound FastAPI/Pydantic bump) remediated; CI `pip-audit` PASS for the scanned locked dependency set.
- **Docker base digest pin** — `python:3.11-slim` pinned by multi-arch index digest (`@sha256:a3ab0b96…49ac0`).
- **GitHub Actions SHA pinning** — all `uses:` refs across active workflows pinned to immutable commit SHAs.
- **Stale retention workflow removal** — `anchor-retention-prune.yml` deleted; the manual operator runbook is the single retention control.
- **Alembic removal** — `alembic` (+ `mako` + `markupsafe`) removed from the runtime dependency set.
- **Render deploy smoke evidence** — multiple PASS deploy/smoke records against `anchor-api-prod`.
- **`/v1/version` production `git_sha` observability** — `GIT_SHA` → `RENDER_GIT_COMMIT` fallback; production `git_sha` confirmed non-null after the fallback.
- **Legal / commercial founder-preparation pack** — full outline spine (Pilot Agreement, DPA, Privacy Notice, AUP, AI Governance Boundary, onboarding checklist, founder approval checklist, data-flow inventory, etc.), all **founder/solicitor-preparation outlines only**.
- **Solicitor handoff preparation** — solicitor review bundle index, dispatch checklist, and handoff preparation pack ([`../commercial/2026-06-15_solicitor_handoff_preparation_pack.md`](../commercial/2026-06-15_solicitor_handoff_preparation_pack.md)).
- **RC coherence closure** — Trust Pack Assistant-receipt source-of-truth aggregate (metadata-only / counts-only) deployed and smoked; `output_blocked` run-status filter; frontend hash/seal-time presentation fixed; incident demo-state confirmed not present ([`2026-06-16_rc_coherence_closure.md`](./2026-06-16_rc_coherence_closure.md)).
- **Frontend RC polish checkpoint** — see §5.

## 4. Frontend state

Latest known frontend evidence (from the `anchor-portal` repository and recorded RC artefacts):

- Development branch `anchor-portal-main-clean` clean at `1c6ba5b`.
- Production branch `anchor-portal-master` clean at `29f72de`.
- Vercel deployment **Ready** for `29f72de`.
- Frontend RC polish checkpoint committed as `1c6ba5b`.
- Current UI state: Dashboard-first navigation; Workspace / Assistant primary actions; Governance & readiness card; `/marketing` canonical / `noindex`.
- No Critical / High frontend findings from the RC coherence audit.

This repository is the backend / canonical operations repo; the frontend facts above are recorded here for cross-reference only and were **not** changed by this checklist.

## 5. Backend state

Latest known backend posture:

- Operational resilience checkpoint exists ([`2026-06-08_operational_resilience_checkpoint.md`](./2026-06-08_operational_resilience_checkpoint.md)).
- Production smoke previously passed for:
  - `GET /health` → `200`,
  - `GET /v1/version` → `200` with non-null `git_sha` after the metadata fallback,
  - unauthenticated `GET /v1/portal/dashboard` → `401`.
- Live Workspace generation **remains production-off**.
- No new backend deploy is implied by this checklist.

## 6. Legal / commercial state

- The legal / commercial pack is **founder / solicitor-preparation only**.
- Solicitor review is **not complete** unless separately evidenced.
- The documents are **not final legal terms**.
- **No paid pilot or real clinic data is authorised.**

## 7. Required gates before paid pilot / real clinic data

All of the following must be satisfied and recorded before any paid pilot or real clinic data:

- [ ] Solicitor review complete and recorded.
- [ ] Final customer-facing legal terms approved.
- [ ] DPA / subprocessor position approved.
- [ ] Anthropic subprocessor coverage complete **before** live generation or real clinic AI-provider routing.
- [ ] Operational backup/restore and incident-response evidence confirmed current.
- [ ] Founder approval checklist completed.
- [ ] Clinic onboarding procedure approved.
- [ ] Demo / test data only until approval.
- [ ] Live generation safety gate passed before any production live generation.
- [ ] Production smoke run after any deploy that changes app behaviour.
- [ ] Support / security contact routes confirmed.

## 8. Explicit hard stops

Do not proceed to any of the following unless a later dated approval artefact explicitly authorises it:

- paid pilot,
- real clinic data,
- production live generation,
- Stripe / billing activation,
- external connectors,
- ambient transcript ingestion,
- customer onboarding,
- public compliance claims,
- RCVS / regulator-approved claims.

## 9. Remaining non-blocking / deferred items

- AppShell font warning in the frontend remains deferred.
- Broad visual redesign deferred.
- TopBar avatar cosmetic deferred.
- M4.6 Learn maturity deferred (by founder decision).
- M6.12 vendor-neutral connector layer — future / gated.
- M6.13 ambient governance — future / gated.
- M6-S sustainability — future / gated.
- Frontend refresh placement accepted as-is.

## 10. RC readiness conclusion

ANCHOR is **materially ready for internal RC sign-off review**, but this document does **not** itself sign off the release candidate. The next step should be founder review of this checklist and, if accepted, a **separate final RC sign-off artefact**.

## 11. Cross-references

- [`2026-06-16_2a_d_current_status_checkpoint.md`](./2026-06-16_2a_d_current_status_checkpoint.md) — 2A-D current status checkpoint.
- [`2026-06-16_rc_coherence_closure.md`](./2026-06-16_rc_coherence_closure.md) — RC coherence lane closure.
- [`2026-06-08_operational_resilience_checkpoint.md`](./2026-06-08_operational_resilience_checkpoint.md) — operational resilience checkpoint.
- [`2026-06-15_wording_copy_scan_closure.md`](./2026-06-15_wording_copy_scan_closure.md) — wording / copy scan closure.
- [`../commercial/2026-06-15_solicitor_handoff_preparation_pack.md`](../commercial/2026-06-15_solicitor_handoff_preparation_pack.md) — solicitor handoff preparation pack.
