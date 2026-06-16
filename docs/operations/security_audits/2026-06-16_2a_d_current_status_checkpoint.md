# ANCHOR 2A-D Current Status Checkpoint

> **Internal 2A-D release-candidate hardening checkpoint.** Documentation only. **Not final RC sign-off**, **not legal advice**, **not solicitor review**, and **not authorisation** for paid pilots, real clinic data, customer access, billing, Stripe activation, live Workspace generation, Anthropic production subprocessor activation, external connectors / runtime ingestion, or solicitor-approved / final legal status.
>
> ANCHOR is **aligned, not compliant** — not RCVS-approved, not regulator-endorsed, not certified. Live Workspace generation **remains production-off**.

## 1. Status and purpose

This is an internal 2A-D release-candidate hardening checkpoint that consolidates the state of the recently completed/closed lanes into one founder-readable orientation document. It is:

- An internal 2A-D RC hardening checkpoint.
- Documentation only.
- Not final RC sign-off.
- Not legal advice.
- Not solicitor review.
- Not authorisation for paid pilots, real clinic data, customer access, billing, Stripe activation, live Workspace generation, Anthropic production subprocessor activation, external connectors / runtime ingestion, or solicitor-approved / final legal status.

## 2. Executive summary

- 2A-D internal hardening is **materially advanced**.
- The **operational resilience baseline** is evidence-backed (dependency/reproducibility chain, deploy smokes, observability).
- The **legal/commercial founder-preparation pack** is structurally complete for solicitor / accountant review — as outlines, not final legal documents.
- The **wording/copy scan lane** is closed for current internal RC purposes (backend + frontend scans done; frontend WATCH item corrected; combined closure recorded).
- The **RC coherence lane** is closed for current internal RC purposes (Trust Pack receipt source-of-truth fixed/deployed/smoked; frontend hash/seal-time presentation fixed; incident demo-state confirmed not present).
- Remaining hard gates are **external legal / accountant / founder review**, **operational cadence timing**, and any **future pilot / real-data / billing / live-generation approvals**.

## 3. Completed lanes

### 3.1 Operational resilience baseline

- Dependency / CVE audit remediation (PyJWT, Starlette via compound FastAPI/Pydantic bump; CI `pip-audit` PASS for the scanned set).
- Lockfile / reproducibility (hashed compiled `requirements.txt`).
- Docker base-image digest pin.
- GitHub Actions SHA pinning across active workflows.
- Stale retention workflow removal (`anchor-retention-prune.yml` deleted; manual runbook is the single retention control).
- Alembic (+ Mako + MarkupSafe) removal from runtime dependencies.
- Backup/restore baseline (first restore-to-new drill PASS, runbook in place).
- Intake retention dry-run baseline (first production dry-run PASS; operator-driven, dry-run-first, `I-UNDERSTAND`, 50,000-row cap).
- Incident-response tabletop baseline (first tabletop PASS; runbook in place).
- `/v1/version` build metadata fallback (`GIT_SHA` → `RENDER_GIT_COMMIT`).
- Render deploy smoke evidence (multiple PASS deploy/smoke records).

Reference: [`2026-06-08_operational_resilience_checkpoint.md`](./2026-06-08_operational_resilience_checkpoint.md) and the founder status summary `../2026-06-08_founder_status_summary.md`.

### 3.2 Commercial/legal founder-preparation

Internal **founder / solicitor / accountant-preparation outlines only — not final legal documents**, none solicitor-approved:

- Legal / commercial pack outline.
- Privacy / data-boundary outline.
- DPA outline.
- Pilot agreement outline.
- Acceptable use policy (AUP) outline.
- Clinic onboarding checklist.
- Founder pilot approval checklist.
- Commercial / legal readiness checkpoint.
- Solicitor review bundle index.
- Solicitor pack dispatch checklist.
- Personal data / data-flow inventory.
- Commercial order form outline.
- Solicitor handoff preparation pack ([`../../commercial/2026-06-15_solicitor_handoff_preparation_pack.md`](../../commercial/2026-06-15_solicitor_handoff_preparation_pack.md)).

### 3.3 Wording/copy scan lane

- Backend-held final RC wording/copy scan completed ([`2026-06-15_final_rc_wording_copy_scan.md`](./2026-06-15_final_rc_wording_copy_scan.md)) — PASS WITH WATCH ITEMS, 0 issues / 0 blockers.
- Frontend public Legal + Trust / public-site wording scan completed — PASS WITH WATCH ITEMS, 0 issues / 0 blockers.
- Frontend WATCH item softened from "solicitor reviewed" / "Founder-approved public summary" to "prepared for solicitor review" / "Founder-prepared public summary — solicitor review pending".
- Combined wording/copy closure note created ([`2026-06-15_wording_copy_scan_closure.md`](./2026-06-15_wording_copy_scan_closure.md)).
- Backend `anchor-legal-prep` skill installed for future audit consistency.

### 3.4 Strategy/evidence schema lane

- AI governance receipt schema v0.1 ([`../../strategy/2026-06-11_anchor_ai_governance_receipt_schema_v0_1.md`](../../strategy/2026-06-11_anchor_ai_governance_receipt_schema_v0_1.md)).
- Receipt schema gap analysis v0.1 ([`../../strategy/2026-06-15_anchor_receipt_schema_gap_analysis_v0_1.md`](../../strategy/2026-06-15_anchor_receipt_schema_gap_analysis_v0_1.md)).
- Strategy README index ([`../../strategy/README.md`](../../strategy/README.md)).
- Class A native ANCHOR receipt evidence **exists** today (`assistant_run_receipts`).
- Evidence-source classes **B–E** and **evidence-strength grading** remain **future / gated** (require an explicit founder decision recorded in an addendum; M6.12 / M6.13 gated future).

### 3.5 RC coherence lane

- Trust Pack Assistant receipt evidence now uses **real `assistant_run_receipts` aggregate counts** (metadata-only / counts-only).
- `output_blocked` accepted as an assistant run-status filter.
- Backend patch deployed (commit `6074f1f`) and production-smoked (PASS).
- Frontend output-hash null rendering fixed (`No output generated`).
- Frontend sealed-receipt snapshot labelling clarified (`Receipt sealed at`).
- Incident demo-state cleanup reviewed and **confirmed not required** (no seed/demo data exists).

Reference: [`2026-06-16_rc_coherence_deploy_smoke_6074f1f.md`](./2026-06-16_rc_coherence_deploy_smoke_6074f1f.md), [`2026-06-16_rc_coherence_closure.md`](./2026-06-16_rc_coherence_closure.md).

## 4. Current blocked / gated items

- No paid pilot authorised.
- No real clinic data authorised.
- No customer access authorised.
- No billing or Stripe activation.
- No invoice issuance, VAT treatment, or payment collection authorised.
- No live Workspace generation activation.
- No Anthropic production subprocessor activation.
- No external connector / runtime ingestion.
- No solicitor-approved / final legal status.
- No compliance / certification / regulator-approval claim.

## 5. Deferred by founder decision

- `/start` notification / Discord webhook deferred (intake notification path remains stubbed).
- `/start` remains structured backend intake.
- `/demo` remains a walkthrough / email-preparation flow.
- Billing / Stripe future-candidate only (reserved, not active).
- Operational cadence repeat deferred until material backend/data change or immediately before a pilot / real-data readiness decision.
- Evidence-strength grading / connector work future-gated.
- Live Workspace generation production-off.

## 6. Remaining watch items

- Solicitor review not complete.
- Accountant / VAT / payment treatment not complete.
- Final decision on free vs paid pilot not made.
- Legal entity / order-form details not finalised.
- Operational cadence should be repeated before any pilot / real-data gate.
- AppShell custom-font lint warning remains known / non-blocking (frontend, unrelated to RC coherence).
- Future dependency / base-image / GitHub Actions refresh cadence (operational hygiene).
- Future frontend / back-office polish may still be needed for demonstration quality.

## 7. Recommended next decision

The next decision is **not another feature build by default**. There is no failing CI, no broken endpoint, and no open coherence defect forcing a code change. The founder should choose one of:

1. **Solicitor / accountant handoff outside the repo** — provide the solicitor handoff preparation pack and referenced artefacts for review.
2. **Operational cadence repeat** — only if preparing for external / pilot review (second backup/restore drill, second intake-retention dry-run, an incident-response tabletop, a fresh deploy smoke).
3. **Final RC status / sign-off checkpoint** — after solicitor / accountant feedback is in.
4. **Optional small hygiene / polish items** — only if they block demonstration quality.

Recommendation:

- **Solicitor / accountant handoff is the highest-value next external-readiness step** — engineering hygiene alone cannot move the pilot / real-data gate.
- **Operational drills should be repeated after material changes or before pilot / real-data readiness, not reflexively after every documentation patch.**

## 8. Evidence index

Backend commits (confirmed in `git log`):

- `ee8e154` — Add RC coherence closure note.
- `1b1e1c9` — Record RC coherence deploy smoke.
- `6074f1f` — Add assistant receipt Trust Pack aggregate (deployed; full SHA `6074f1f38447e0f447f89046b12cf4542c148868`).
- `2a24e1e` — Add solicitor handoff preparation pack.
- `7425996` — Add wording scan closure and legal prep skill.
- `eaab52e` — Add final RC wording copy scan.

Frontend (confirmed in `anchor-portal` git log / recorded artefacts):

- PR #44 — frontend public wording scan (`5290530` Add frontend public wording scan).
- PR #45 — softened legal review status labels (`133acda` Soften legal review status labels).
- PR #46 — clarified receipt hash and seal-time labels (branch commit `e2a327e` Clarify receipt hash and seal-time labels; merged to `anchor-portal-master` as `cd43de8` per the RC coherence closure note).

Key backend evidence artefacts (this directory unless noted):

- `2026-06-08_operational_resilience_checkpoint.md`
- `../2026-06-08_founder_status_summary.md`
- `2026-06-15_final_rc_wording_copy_scan.md`
- `2026-06-15_wording_copy_scan_closure.md`
- `2026-06-16_rc_coherence_deploy_smoke_6074f1f.md`
- `2026-06-16_rc_coherence_closure.md`
- `../../commercial/2026-06-15_solicitor_handoff_preparation_pack.md`
- `../../strategy/2026-06-11_anchor_ai_governance_receipt_schema_v0_1.md`, `../../strategy/2026-06-15_anchor_receipt_schema_gap_analysis_v0_1.md`

## 9. Conclusion

- For current internal 2A-D hardening, the **operational baseline, commercial/legal founder-preparation, wording/copy control, strategy evidence schema, and RC coherence lanes are materially closed**.
- This **does not equal final RC sign-off**.
- This **does not authorise** external commercial use, paid pilots, real clinic data, customer access, billing, Stripe activation, live Workspace generation, Anthropic production subprocessor activation, external connector / runtime ingestion, or legal reliance.
- The **next substantive gate is founder-led solicitor / accountant review and explicit founder approval.**
