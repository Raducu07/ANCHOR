# 2A-D.1 Security Audit Result Note

> **Status: PARTIAL — controls substantially evidenced; residual hard stops remain.**
>
> Internal documentation-only consolidation artefact. **Not** a penetration-test certification, SOC 2 / ISO certification, GDPR-compliance certification, RCVS approval, EU AI Act compliance statement, or legal advice. **Not** authorisation for paid pilots or real clinic data. It records existing evidence and does not change product behaviour, code, configuration, or deployment.
>
> ANCHOR is **aligned, not compliant**. Live Workspace generation **remains production-off**. Paid pilots and real clinic data **remain blocked**.

---

## 1. Title

**2A-D.1 Security Audit Result Note** — 2026-06-22

## 2. Status

**PARTIAL — controls substantially evidenced; residual hard stops remain.**

This is deliberately **not** a PASS. The operational-resilience half of 2A-D.1 is substantially evidence-backed; the security half's controls exist, are documented, and are partly CI-evidenced, but the consolidated security deliverable still has residual gaps (see §5).

## 3. Purpose

This note **consolidates existing 2A-D.1 evidence** that is otherwise distributed across `docs/operations/env.md`, `.github/workflows/`, the deploy-smoke docs, the dependency-audit chain, and the operational runbooks, into a single security-audit result record.

It **does not**:

- perform a new penetration test;
- perform a new secret scan;
- perform a legal / solicitor review;
- run a new dependency scan, test suite, or build;
- make any code, dependency, configuration, environment, or deployment change.

It is evidence reconstruction only. Where a control is documented and code-enforced but lacks a discrete audit-result artefact, that is stated honestly rather than upgraded to "complete".

## 4. Evidence-backed controls

All paths are relative to the backend repo (`C:\Users\rggal\ANCHOR`). "Evidence exists" means internal repo evidence exists — **not** external approval and **not** a security guarantee.

| Control | Evidence file(s) | Summary |
|---|---|---|
| CORS / default-secret hardening | `docs/operations/env.md` §2–§4 | Startup fail-closed asserts refuse default literals for JWT secret, hash salt, admin pepper, and rate-limit secret when `APP_ENV=prod`; CORS wildcard combined with credentials raises `RuntimeError` at startup. Controls documented and code-enforced. |
| Admin token / admin-mode lockdown | `docs/operations/env.md` §6; `docs/operations/incident_response.md` §8.5 | `ANCHOR_ADMIN_MODE=env` refused in prod (Patch 4B); DB-backed tokens are the prod default; bootstrap-token discipline documented; admin-token-exposure containment playbook in place. |
| Auth / JWT / session / invite posture | `docs/operations/env.md` §3, §5; `app/auth_and_rls.py`; `tests/test_security_config_hardening.py` | JWT signing secret fail-closed in prod; strict per-request DB re-validation (`ANCHOR_AUTH_STRICT_DB_CHECK`); server-side role allow-list; invite-token hashing. `INVITE_TOKEN_SALT` is now **fail-closed in prod** via `assert_invite_salt_for_prod` (wired into the `app/main.py` lifespan; tested) — the prior follow-up is closed. |
| RLS / FORCE RLS / tenant isolation | `.github/workflows/isolation-smoke.yml`; `scripts/anchor-smoke-isolation.ps1`, `scripts/anchor-verify-force-rls.ps1` (per `env.md` §13); `backup_restore.md` §11; `incident_response.md` §8.4 | Active tenant-isolation smoke runs on push/PR to `main`; read-only verification scripts; RLS/FORCE posture recorded in the restore drill; tenant-isolation containment playbook (SEV-0). |
| Rate limits | `.github/workflows/anchor-rate-limit-ci.yml`; `docs/operations/env.md` §7 | Active CI runs `pytest tests/test_rate_limit.py` with the limiter enabled; per-group windows/limits documented; `RATE_LIMIT_SECRET` required (fail-closed) when limiting is on. |
| Protected-route smoke checks | `security_audits/2026-06-08_render_deploy_smoke_cd9d966.md`; `…_version_metadata_deploy_smoke_7451357.md`; `…2026-06-16_rc_coherence_deploy_smoke_6074f1f.md` | `/v1/portal/dashboard` → 401 unauthenticated, `/health` → 200, `/v1/version` → 200; PASS across multiple deploys. |
| Dependency / CVE audit result | `security_audits/2026-06-07_post_alembic_ci_audit.md`; `…_operational_resilience_checkpoint.md` | CI `pip-audit` PASS for the locked 34-package set (run #5). Records absence of known vulnerabilities at scan time — not a guarantee. |
| PyJWT remediation | `security_audits/2026-06-07_pyjwt_remediation.md`; `…_post_pyjwt_ci_audit.md` | PyJWT bumped to 2.13.0; advisories cleared in CI. |
| Starlette / FastAPI remediation | `security_audits/2026-06-07_starlette_fastapi_compatibility_assessment.md`; `…_fastapi_starlette_remediation.md`; `…_post_starlette_ci_audit.md` | Compound FastAPI/Pydantic bump → starlette 1.2.1; advisory cleared in CI. |
| Hashed lockfile strategy | `security_audits/2026-06-07_lockfile_strategy_design.md`; `…_lockfile_implementation.md`; `…_post_lockfile_ci_audit.md`; `requirements.txt` | `pip-compile --generate-hashes` compiled lockfile (H4); install-time per-wheel hash verification. (Dockerfile explicit `--require-hashes` flag deferred.) |
| Docker base digest pin | `security_audits/2026-06-07_docker_base_digest_pin.md`; `Dockerfile` | `python:3.11-slim@sha256:a3ab0b96…49ac0` (immutable index digest). |
| GitHub Actions SHA pinning | `security_audits/2026-06-07_github_actions_sha_pin_implementation.md`; all 3 files under `.github/workflows/` | `checkout@34e1148…` and `setup-python@a26af69…` pinned across active workflows (verified live). |
| Stale retention workflow removal | `security_audits/2026-06-07_retention_workflow_decision.md`; `…_retention_workflow_removal.md` | `anchor-retention-prune.yml` deleted; only 3 workflows remain; manual operator runbook is the single retention control. |
| Alembic removal | `security_audits/2026-06-07_alembic_removal_proof.md`; `…_alembic_removal.md`; `requirements.in/.txt/-dev.txt` | `alembic` (+ `mako`, `markupsafe`) removed; absent from all requirements files. |
| `/v1/version` git SHA observability | `security_audits/2026-06-08_version_metadata_implementation.md`; `…_version_metadata_deploy_smoke_7451357.md` | `git_sha` populated in prod via `GIT_SHA` → `RENDER_GIT_COMMIT` fallback (non-null confirmed). |
| Render deploy-smoke evidence | the three deploy-smoke docs above | Multiple PASS deploy/smoke records against `anchor-api-prod`. |
| Backup procedure | `docs/operations/backup_restore.md` | Render Postgres restore-to-new runbook documented. |
| Tested restore drill | `docs/operations/backup_restore.md` §11 (Drill 2026-06-07) | Restore-to-new drill executed; result PASS. |
| Breach / incident-response runbook | `docs/operations/incident_response.md` | SEV-0→SEV-3 ladder, first-15-minutes checklist, never-capture list, 11 per-class containment playbooks, post-incident + evidence templates. |
| First tabletop exercise | `docs/operations/incident_response.md` §16 (2026-06-07) | Migration-checksum-mismatch tabletop walked end-to-end; result PASS. (Scenarios #2–#6 pending — cadence, non-blocking.) |
| Live Workspace generation production-off | `docs/operations/env.md` §9, §14; `CLAUDE.md`; RC sign-off chain | Flag unset / production-off; documented across the canon. |
| Paid-pilot / real-clinic-data gates closed | RC sign-off chain (`security_audits/2026-06-21_final_internal_rc_signoff_note.md`); `docs/commercial/` hard-stops | Gates documented as hard stops and remain blocked. |

Cross-reference: `security_audits/2026-06-08_operational_resilience_checkpoint.md` consolidates the dependency/reproducibility/deploy chain; `security_audits/2026-06-21_control_to_evidence_matrix.md` indexes controls to evidence more broadly.

## 5. Status of follow-ups and residual hard stops

### Addressed since this note was created (2026-06-22)

These three items, originally listed here as gaps, have since been addressed. They are recorded as addressed **with their caveats** — none is upgraded to a claim of full closure.

- **Secret scan — PARTIAL evidence added.** A bounded fallback tracked-file scan was run and recorded (`security_audits/2026-06-22_secret_scan_result.md`, commit `517d88c`): no likely committed secrets found in tracked files; no tracked `.env` / `*.pem` / `*.key` / `*.p12` / `*.pfx` files. **No dedicated scanner / git-history / entropy scan** was performed — stronger scanning remains optional future hygiene (see remaining list). Not a claim of full secret-scan closure.
- **Governance-metadata / CPD / incident retention + memory-consent — internal operational note added.** `docs/operations/2026-06-22_r2_retention_memory_consent_note_v1.md` (commit `734e498`) documents the current retention and memory-consent posture for clinic-governance surfaces, complementing `intake_retention.md`. **Final contractual retention remains pending solicitor review**; no deletion automation is implemented.
- **`INVITE_TOKEN_SALT` fail-closed — closed by code+tests patch** (commit `938c712`). Production now refuses to start if `INVITE_TOKEN_SALT` is unset, blank, or still the default sentinel, via `app/auth_and_rls.py::assert_invite_salt_for_prod` (wired into the `app/main.py` lifespan; covered by `tests/test_security_config_hardening.py`).

### Remaining hard stops (must not be treated as cleared)

- **Solicitor review not complete** (`security_audits/2026-06-21_final_internal_rc_signoff_note.md` §7).
- **Legal / commercial pack not final** — all artefacts in `docs/commercial/` are outlines / preparation packs pending solicitor review.
- **Live Workspace generation remains production-off** until the local/staging safety gate and the hard-refusal boundary (diagnosis/treatment/prescribing) are proven on the live path.
- **Paid pilots and real clinic data remain blocked.**
- **Stronger secret-scanning (dedicated scanner / git-history / entropy scan) remains optional future hygiene** — its absence is not a claim of full closure and is not, by itself, a release blocker.

## 6. Gate conclusion

**2A-D.1 is not fully closed. Operational resilience is substantially evidence-backed, but paid pilots and real clinic data remain blocked until the residual hard stops are resolved.**

## 7. Non-claims

This note is **not**:

- penetration-test certification;
- SOC 2 / ISO certification;
- GDPR compliance certification;
- RCVS approval;
- EU AI Act compliance;
- legal advice;
- authorisation for paid pilots or real clinic data.

## 8. Recommended follow-up sequence

Narrow next actions only (each separately authorised; none performed here):

1. ~~**Run and document a secret scan**~~ — **DONE 2026-06-22 (`517d88c`):** bounded fallback tracked-file scan recorded (PARTIAL; no likely committed secrets). A dedicated-scanner / git-history / entropy scan remains optional future hygiene.
2. ~~**Create a governance-metadata / CPD / incident retention and memory-consent runbook**~~ — **DONE 2026-06-22 (`734e498`):** R2 in-repo operational note added; final contractual retention pending solicitor review.
3. ~~**Assess whether `INVITE_TOKEN_SALT` needs a fail-closed code patch**~~ — **DONE 2026-06-22 (`938c712`):** `assert_invite_salt_for_prod` added (mirroring the hash-salt / admin-pepper asserts), wired into the lifespan, with tests.
4. **Solicitor review of the DPA / Pilot Agreement / SaaS terms** (founder-owned legal track).
5. **Keep live Workspace generation production-off** until the local/staging safety gate and hard-refusal proof are complete.

## 9. Cross-references

- [`2026-06-21_control_to_evidence_matrix.md`](./2026-06-21_control_to_evidence_matrix.md) — control-to-evidence index.
- [`2026-06-08_operational_resilience_checkpoint.md`](./2026-06-08_operational_resilience_checkpoint.md) — operational resilience consolidation.
- [`2026-06-21_final_internal_rc_signoff_note.md`](./2026-06-21_final_internal_rc_signoff_note.md) — final internal RC sign-off.
- [`../env.md`](../env.md), [`../incident_response.md`](../incident_response.md), [`../intake_retention.md`](../intake_retention.md), [`../backup_restore.md`](../backup_restore.md) — operations reference / runbooks.
- [`../../commercial/2026-06-08_personal_data_data_flow_inventory.md`](../../commercial/2026-06-08_personal_data_data_flow_inventory.md) — data-flow inventory (retention gap).
