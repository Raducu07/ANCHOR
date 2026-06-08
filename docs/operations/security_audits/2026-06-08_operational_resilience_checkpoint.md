# ANCHOR Operational Resilience Checkpoint â€” 2026-06-08

> **Documentation only.** This artefact summarises the current backend operational resilience state after the dependency / reproducibility / deploy-smoke / version-observability chain (Patches 11C â†’ 11D-c â†’ 11B-b2 â†’ 11B-b3 â†’ 11B-b4 â†’ 11B-b5 â†’ 11B-b6 â†’ 11B-b8). **No code changed.** No tests changed. No dependency changed. No Dockerfile changed. No workflow changed. No migration changed. No DB queried or mutated. No production endpoint called in this patch. No Render setting changed. No deploy performed by this patch. No frontend touch. No secret read, printed, or stored. Not compliance certification. Not a regulator endorsement. Not a claim that ANCHOR is secure, compliant, certified, vulnerability-free, RCVS-approved, or regulator-endorsed.

---

## 1. Purpose and scope

The recent backend operational-resilience chain ran across many narrow patches. This artefact pulls the state into one place so the founder can see â€” at a glance â€” what is genuinely improved, what is still open, what cannot be done without further decisions, and what the recommended next step is.

- Summary / inventory artefact only.
- No code changed.
- No tests changed.
- No dependency changed.
- No Dockerfile changed.
- No workflow changed.
- No migration changed.
- No DB queried or mutated.
- No production endpoint called in this patch.
- No Render setting changed.
- No deploy.
- Not compliance certification.
- Not a claim that ANCHOR is secure, compliant, certified, vulnerability-free, RCVS-approved, or regulator-endorsed.

---

## 2. Current checkpoint summary

| Item | State |
|---|---|
| Dependency / CVE audit (CI `pip-audit`) | âœ… **PASS** for the post-Alembic 34-package locked scanned dependency set. |
| Runtime lockfile reproducibility | âœ… Hashed compiled `requirements.txt` in place; `pip install` enters hash-checking mode automatically. |
| Docker base image | âœ… Digest-pinned (`python:3.11-slim@sha256:a3ab0b96â€¦49ac0`); no longer mutable by tag alone. |
| GitHub Actions | âœ… All five `uses:` refs across three workflows SHA-pinned; no mutable tags remain. |
| Stale `anchor-retention-prune.yml` | âœ… Removed; daily 404 + admin-bearer transmission stopped; manual `intake_retention.md` runbook is the active control. |
| `alembic` dead-weight dependency | âœ… Removed (with transitives `mako`, `markupsafe`); runtime surface 34 packages (was 37). |
| Render build/deploy after remediation | âœ… Two live + smoke-PASS deploys (`cd9d966`, `7451357`). |
| `/v1/version` runtime revision metadata | âœ… Populated in production via `RENDER_GIT_COMMIT` fallback. |
| Protected dashboard unauthenticated smoke | âœ… Returns 401 as expected (access-control intact). |
| Live Workspace generation in production | ðŸš« **Remains production-off.** |
| Paid pilot / real clinic data | âŒ **Not authorised.** |

---

## 3. Completed evidence chain

| Area | Evidence artefact / commit | Result |
|---|---|---|
| PyJWT CVE remediation | `2026-06-07_pyjwt_remediation.md`; `PyJWT==2.13.0` pin | PyJWT CVE rows cleared in CI |
| Post-PyJWT CI audit | `2026-06-07_post_pyjwt_ci_audit.md` (run `#2` against `97e78bd`) | PyJWT findings cleared; Starlette still open |
| Starlette / FastAPI compatibility assessment | `2026-06-07_starlette_fastapi_compatibility_assessment.md` | FastAPI-mediated remediation identified |
| Starlette remediation (compound FastAPI + Pydantic bump) | `2026-06-07_fastapi_starlette_remediation.md`; `fastapi==0.133.1`, `pydantic[email]==2.7.4`; resolves `starlette==1.2.1` | 1525/1525 tests passing |
| Post-Starlette CI audit | `2026-06-07_post_starlette_ci_audit.md` (run `#3` against `bfec5a0`) | **PASS** for the pre-lockfile scanned set |
| Dependency reproducibility inventory | `2026-06-07_dependency_reproducibility_inventory.md` (Patch 11B-b1) | Inventory recorded; recommended seven-patch sequence |
| Lockfile strategy design | `2026-06-07_lockfile_strategy_design.md` (Patch 11B-b2-a) | Layout A + hash posture H4 |
| Lockfile implementation | `2026-06-07_lockfile_implementation.md` (Patch 11B-b2-b, commit `4c64c37`) | 747-line hashed compiled lockfile; 1525/1525 tests passing |
| Post-lockfile CI audit | `2026-06-07_post_lockfile_ci_audit.md` (Patch 11B-b2-c, run `#4` against `32e9b94`) | **PASS** for the locked scanned set |
| Docker base digest probe | `2026-06-07_docker_base_digest_probe.md` (Patch 11B-b3-a) | Multi-arch index digest identified via Docker Registry HTTP API |
| Docker base digest pin | `2026-06-07_docker_base_digest_pin.md` (Patch 11B-b3-b, commit `f0d931d`) | `Dockerfile` `FROM` digest-pinned |
| GitHub Actions SHA pin design | `2026-06-07_github_actions_sha_pin_design.md` (Patch 11B-b4-a) | Five `uses:` refs identified; SHAs resolved via `git ls-remote` |
| GitHub Actions SHA pin implementation | `2026-06-07_github_actions_sha_pin_implementation.md` (Patch 11B-b4-b, commit `55c1acc`) | 5/5 refs pinned across 3 workflows |
| Retention workflow decision | `2026-06-07_retention_workflow_decision.md` (Patch 11B-b5-a) | Recommendation: delete |
| Retention workflow removal | `2026-06-07_retention_workflow_removal.md` (Patch 11B-b5-b, commit `eb98d1b`) | File deleted; manual runbook remains the active control |
| Alembic removal proof | `2026-06-07_alembic_removal_proof.md` (Patch 11B-b6-a) | Zero imports anywhere; recommendation: remove |
| Alembic removal implementation | `2026-06-07_alembic_removal.md` (Patch 11B-b6-b, commit `787783b`) | `alembic` + `mako` + `markupsafe` dropped; lockfile 645 lines, 34 packages; 1525/1525 tests passing |
| Post-Alembic CI audit | `2026-06-07_post_alembic_ci_audit.md` (Patch 11B-b6-c, run `#5` against `de966a9`) | **PASS â€” `No known vulnerabilities found`** for the post-Alembic 34-package set |
| Render deploy + smoke (post-remediation) | `2026-06-08_render_deploy_smoke_cd9d966.md` (Patch 11B-b6-d, commit `cd9d966`) | Smoke PASS; `git_sha=null` observability gap recorded |
| Version metadata design | `2026-06-08_version_metadata_design.md` (Patch 11B-b8-a) | Recommendation: `GIT_SHA` â†’ `RENDER_GIT_COMMIT` fallback |
| Version metadata implementation | `2026-06-08_version_metadata_implementation.md` (Patch 11B-b8-b, commit `7451357`) | One-line `app/main.py` edit + 5 precedence tests + `env.md` correction; full sweep 1530/1530 passing |
| Version metadata deploy + smoke | `2026-06-08_version_metadata_deploy_smoke_7451357.md` (Patch 11B-b8-c, commit `ad70634`) | Smoke PASS; `git_sha=7451357c6430be2105a490cbbb7fcb11db024d0c` confirmed populated from `RENDER_GIT_COMMIT` |

---

## 4. Production-smoke state

### 4.1 `cd9d966` â€” remediation deploy smoke

| Check | Observed | Result |
|---|---|---|
| `GET /health` | `200 {"status":"ok"}` | PASS |
| `GET /v1/version` | `200`, `env=prod`, **`git_sha=null`**, `build=null` | PASS with metadata observation |
| unauthenticated `GET /v1/portal/dashboard` | `401` | PASS |

Observation: build metadata gap identified â€” runtime did not surface deployed commit. Recorded as an open follow-up.

### 4.2 `7451357` â€” version metadata deploy smoke

| Check | Observed | Result |
|---|---|---|
| `GET /health` | `200 {"status":"ok"}` | PASS |
| `GET /v1/version` | `200`, `env=prod`, **`git_sha=7451357c6430be2105a490cbbb7fcb11db024d0c`**, `build=null/blank` | PASS |
| unauthenticated `GET /v1/portal/dashboard` | `401` | PASS |

Observation: build metadata gap **closed**. The 40-character `git_sha` matches the deployed commit's short form (`7451357`), confirming the `RENDER_GIT_COMMIT` fallback works end-to-end on Render with no operator-side env-var configuration.

---

## 5. What is now genuinely improved

- **Smaller runtime dependency surface** â€” 34 packages installed in every Render build (was 37; `alembic`/`mako`/`markupsafe` removed).
- **Hash-pinned runtime dependency set** â€” every wheel/sdist installed under per-wheel SHA256 verification (the lockfile is fully hashed; `pip install` enters hash-checking mode automatically).
- **CI audit evidence against locked dependency set** â€” `Anchor Dependency Audit (pip-audit)` run `#5` reports `No known vulnerabilities found` for the 34-package post-Alembic lockfile.
- **Docker base image no longer mutable by tag alone** â€” `python:3.11-slim@sha256:a3ab0b96â€¦49ac0` pinned to the multi-arch index digest captured at probe time; upstream re-tags can no longer silently change what Render builds.
- **GitHub Actions no longer use mutable action tags** â€” all five `uses:` refs across the three active workflows pinned to immutable commit SHAs (`actions/checkout@34e1148â€¦`, `actions/setup-python@a26af69â€¦`); trailing `# v<N> resolved 2026-06-07` comments preserve human readability and refresh auditability.
- **Broken scheduled retention workflow removed** â€” daily 404 + admin-bearer transmission stopped; the runbook's "Scheduler / cron: None. Pruning is operator-driven by design." doctrine is now structurally true.
- **`/v1/version` can now prove deployed revision from production** â€” `git_sha` populated from Render's `RENDER_GIT_COMMIT` with no operator-side configuration; explicit `GIT_SHA` retained as first-precedence override.
- **Future deploy smokes are more trustworthy** â€” operator can capture `env`/`git_sha` from `/v1/version` directly into a deploy log per `env.md Â§13`, instead of cross-referencing the Render dashboard for the deployed-commit field.

---

## 6. What is still open

### 6.1 Optional engineering hygiene

- **`httpx<2` / Starlette TestClient deprecation warning** â€” persistent single `StarletteDeprecationWarning` in every test run since the Starlette remediation; pure dev/test hygiene; held for optional Patch **11B-b7**.
- **Explicit Dockerfile `--require-hashes` install flag** â€” eligible to flip now (design posture H4 condition met: two successful Render builds under the hashed lockfile). Per-wheel verification is already in effect; the explicit flag only adds refusal of any future un-hashed entry.
- **Base-image digest refresh cadence** â€” recorded as an operational hygiene item; no formal cadence document yet.
- **`.github/dependabot.yml` for the `github-actions` ecosystem** â€” additive automation for SHA-pin refresh PRs.
- **Additional dependency audit cadence** â€” currently manual via `workflow_dispatch:`; no fixed schedule recorded.

### 6.2 Operational evidence still useful

- **Second backup/restore drill** â€” first PASS recorded 2026-06-07 in `backup_restore.md Â§11`; cadence applies.
- **Second intake-retention dry-run** â€” first PASS recorded 2026-06-07 in `intake_retention.md Â§7`; monthly pre-pilot cadence applies (next target ~2026-07-07).
- **Additional `incident_response.md Â§16` tabletop scenarios** â€” first tabletop (migration checksum mismatch) completed 2026-06-07; remaining scenarios pending.
- **Continued evidence packaging** â€” operator-facing summary of the standing evidence trail for any future founder / advisor / pilot conversation.

### 6.3 Non-engineering readiness gates

- **Legal / commercial pack per Addendum v1.3** â€” founder track; out of code scope.
- **Pilot agreement / DPA / ToS / VAT/payment flow clarity** â€” operator/founder commercial actions.
- **Founder decision on pilot timing.**
- **No paid pilot / real clinic data** until these are complete.

---

## 7. Hard stop conditions

State clearly, for the avoidance of doubt:

- **Do not enable live Workspace generation in production.** The Workspace live integration (2A-C.5B/5C) is built directly on the Anthropic API and is **not vendor-neutral**. It must not be enabled in production until the local/staging safety gate (2A-C.5E) passes and the hard-refusal boundary (diagnosis/treatment/prescribing) is proven on the live path. Anthropic becomes a subprocessor the moment live generation is enabled.
- **Do not onboard real clinic data.**
- **Do not start paid pilots.**
- **Do not claim compliance, certification, RCVS approval, or regulator endorsement.** ANCHOR is **aligned to** RCVS principles and EU AI Act articles where it can be; it is **not compliant with** them. ANCHOR is **not a GPAI provider**; downstream integrator only.
- **Do not market ANCHOR as clinical decision-making AI.** ANCHOR is governance / trust / learning / intelligence / readiness infrastructure for safe AI use in veterinary clinics. It is **not** a diagnostic tool, EHR, ambient scribe, or replacement for veterinary judgement.
- **Do not treat dependency PASS as proof of security.** The CI `pip-audit` PASS is for the dependency set and advisory data available to `pip-audit` at run time. It is not a guarantee that no vulnerabilities exist.
- **Do not run destructive retention** without the existing founder-approval-gated `intake_retention.md` runbook (dry-run-first, exact `I-UNDERSTAND` confirm literal, 50 000-row hard cap, evidence template).
- **Do not bypass incident / backup / retention procedures.** The runbooks (`incident_response.md`, `backup_restore.md`, `intake_retention.md`) are the active controls; engineering improvements do not replace them.
- **Tenant safety, RLS / FORCE RLS, admin auth, clinic auth, metadata-only doctrine, vendor-neutrality-over-time** all remain inviolate without an explicit founder decision recorded in an addendum.

---

## 8. Recommended next decision

Four candidate paths; **none is mandatory immediately**. The important shift is that engineering work should now be **deliberate** rather than reactive â€” there is no open CVE row, no broken workflow, no observability gap forcing an immediate code change.

- **A. Engineering hygiene path** â€” pick up Patch **11B-b7** (`httpx<2` deprecation cleanup) or the Dockerfile explicit `--require-hashes` flag flip. Both are small, low-risk, and tighten the existing posture without changing surface behaviour.
- **B. Operational evidence path** â€” schedule the next backup/restore drill, the next intake-retention dry-run, or another `incident_response.md Â§16` tabletop scenario. Builds the standing evidence trail needed before any paid-pilot conversation.
- **C. Commercial / legal readiness path** â€” the founder-track legal/commercial pack work per Addendum v1.3. This is the **only** path that can move the paid-pilot gate; engineering hygiene alone cannot.
- **D. Pause and prepare founder summary** â€” convert this checkpoint into a short founder-facing status note (one-page summary of where we stand, what's open, what cannot be done yet, recommended order), so the operator can step away from the engineering surface without losing context.

Recommendation: **D first** (capture the founder-facing summary while context is fresh), then **C** in parallel as the founder's track, with **A** or **B** as engineering fillers when bandwidth allows. None of this is urgent; what matters is that each step is deliberate.

---

## 9. Non-actions in this patch

The following were **explicitly not done** in Patch 11B-b9-a:

- âŒ No code change.
- âŒ No test change.
- âŒ No dependency change.
- âŒ No Dockerfile change.
- âŒ No GitHub Actions workflow change.
- âŒ No `requirements.in` / `requirements.txt` / `requirements-dev.txt` change.
- âŒ No migration change.
- âŒ No migrations run.
- âŒ No database query or mutation.
- âŒ No production endpoint called in this patch. (Production smoke endpoints referenced in Â§4 were executed under Patches 11B-b6-d and 11B-b8-c, not by this checkpoint patch.)
- âŒ No Render API call.
- âŒ No Render setting change.
- âŒ No Render env-var change.
- âŒ No deploy.
- âŒ No frontend touch.
- âŒ No live Workspace generation enabled.
- âŒ No secret value read, printed, stored, or pasted.
- âŒ No commit. No push. (Per scope.)
- âŒ No compliance / certification / regulator-approval / RCVS-approval claim.
- âŒ No paid-pilot or real-clinic-data authorisation.

What this patch **did** do: pulled the dependency / reproducibility / deploy-smoke / version-observability chain into a single founder-readable checkpoint; recorded the cleared engineering posture, the open optional hygiene items, the open operational-evidence items, and the open non-engineering readiness gates; reaffirmed the hard stop conditions (no live Workspace generation in production, no paid pilot / real clinic data, no compliance / certification / regulator-approval claim, no marketing as clinical decision-making AI); recommended a deliberate-not-reactive next decision; and updated the operations README.
