# ANCHOR Post-Alembic CI pip-audit Result â€” 2026-06-07

> **Audit evidence only.** This artefact records the CI dependency audit result after Patch 11B-b6-b removed the unused `alembic` runtime dependency (plus its transitives `mako` and `markupsafe`). **No dependency changed in this patch.** No requirements file changed in this patch. No Dockerfile changed. No application code changed. No tests changed. No migrations changed. No production endpoint called. No database queried or mutated. No Render setting changed. No deploy issued. No secret read, printed, or stored. Not compliance certification. Not a regulator endorsement. Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

---

## 1. Purpose and scope

The Patch 11B-b6-b implementation ([`2026-06-07_alembic_removal.md`](./2026-06-07_alembic_removal.md)) changed the runtime lockfile (`requirements.txt` recompiled, 34 packages vs 37, three packages dropped). The prior CI audit ([`2026-06-07_post_lockfile_ci_audit.md`](./2026-06-07_post_lockfile_ci_audit.md), run `#4`) reported PASS against the **pre-Alembic-removal** lockfile (37-package set). A fresh CI audit is required to confirm the post-Alembic 34-package set remains clean.

- Audit evidence only.
- No dependency changed in this patch.
- No requirements file changed in this patch.
- No Dockerfile changed.
- No application code changed.
- No tests changed.
- No migrations changed.
- No production endpoint called.
- No DB queried or mutated.
- No Render change.
- No deploy.
- Not compliance certification.
- Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

---

## 2. Source run

| Property | Value |
|---|---|
| Workflow | `Anchor Dependency Audit (pip-audit)` |
| Workflow file | `.github/workflows/dependency-audit.yml` |
| Run title | `Trigger post-Alembic dependency audit` |
| Run number | `#5` |
| Commit scanned | `de966a9` (local HEAD at the time of this evidence patch; the temporary path-filtered trigger commit) |
| Relationship to Patch 11B-b6-b commit | Direct descendant of `787783b` (`git log --oneline -4` shows `de966a9 Trigger post-Alembic dependency audit` â† `787783b Remove unused Alembic dependency`). The trigger commit's only change vs `787783b` is adding the temporary `push:` block to `dependency-audit.yml`; the scanned `requirements.txt` is byte-identical to `787783b`'s. |
| Branch | `main` |
| Trigger | Temporary path-filtered `push` trigger used **only** to fire this single post-Alembic audit (added to `on:` for one run, removed in this patch â€” see Â§6) |
| Runner | GitHub-hosted (`ubuntu-latest`) |
| Python | `3.11` (via SHA-pinned `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065`, Patch 11B-b4-b pin) |
| Job | `pip-audit -r requirements.txt` |
| Command | `python -m pip_audit -r requirements.txt` |
| Result | **PASS** |
| Exit code | `0` (inferred from successful job status â€” GitHub Actions marks the job green only when every step exits `0`; the `pip-audit` step is the final step) |
| Evidence | GitHub Actions page shows the dependency audit run `#5` succeeded against commit `de966a9`; the `Run pip-audit against requirements.txt` step captured stdout: `No known vulnerabilities found`. |

---

## 3. Result wording

**CI pip-audit reported `No known vulnerabilities found` in the `Run pip-audit against requirements.txt` step for commit `de966a9`; the job succeeded and the final `pip-audit` step returned exit code `0`.**

Phrased conservatively for the audit record:

> **No known vulnerabilities were reported by CI pip-audit for the post-Alembic locked dependency set scanned at commit `de966a9`.**

Caveats:

- This is **not** a guarantee that no vulnerabilities exist.
- This records only the dependency set and advisory data available to `pip-audit` at the time of the run (PyPI advisory DB + OSV).
- The result applies to the **34-package hashed compiled `requirements.txt`** produced by Patch 11B-b6-b â€” i.e. the full transitive closure with SHA256 hashes, after `alembic`, `mako`, and `markupsafe` removal.

---

## 4. Dependency state relevant to the pass

Patch 11B-b6-b shipped these changes; this audit confirms the locked set is clean for them:

- **`alembic==1.18.4` removed** from `requirements.in` (line 14 deleted).
- **`mako==1.3.12` removed** from compiled `requirements.txt` (was transitive `via alembic`; no other consumer).
- **`markupsafe==3.0.3` removed** from compiled `requirements.txt` (was transitive `via mako`; no other path back).
- **`requirements-dev.txt` unchanged** (`pip-tools==7.5.3`, `pytest==9.0.3`, `httpx==0.28.1` preserved).
- **`requirements.txt` remains hashed** â€” every distribution carries SHA256 hashes; `pip install -r requirements.txt` enters hash-checking mode automatically and verifies per-wheel hashes at install time on both the operator workstation and the Render builder.
- **Dockerfile continues installing `requirements.txt`** â€” `pip install --no-cache-dir -r requirements.txt`; no `--require-hashes` flag (deferred).
- **Docker base-image digest pin remains in place** â€” `python:3.11-slim@sha256:a3ab0b966bc4e91546a033e22093cb840908979487a9fc0e6e38295747e49ac0` (Patch 11B-b3-b).
- **GitHub Actions SHA pin remains in place** â€” five `uses:` lines across three workflows pinned to immutable commit SHAs (Patch 11B-b4-b: `actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5`, `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065`).
- **Stale retention workflow remains removed** (Patch 11B-b5-b).

The PASS therefore covers a **stricter and smaller** dependency set than run `#4` covered: pip-audit now reads 34 hash-pinned packages instead of 37.

---

## 5. Relationship to prior artefacts

- [`2026-06-07_alembic_removal_proof.md`](./2026-06-07_alembic_removal_proof.md) â€” Patch 11B-b6-a proof that `alembic` had zero runtime usage.
- [`2026-06-07_alembic_removal.md`](./2026-06-07_alembic_removal.md) â€” Patch 11B-b6-b implementation that produced the lockfile this audit scans.
- [`2026-06-07_post_lockfile_ci_audit.md`](./2026-06-07_post_lockfile_ci_audit.md) â€” prior CI audit (`#4` against `32e9b94`) recording PASS for the **pre-Alembic-removal** 37-package set.
- [`2026-06-07_retention_workflow_removal.md`](./2026-06-07_retention_workflow_removal.md) â€” Patch 11B-b5-b removal of the stale retention workflow.
- [`2026-06-07_github_actions_sha_pin_implementation.md`](./2026-06-07_github_actions_sha_pin_implementation.md) â€” Patch 11B-b4-b SHA pinning of the three remaining workflows (including this dependency-audit workflow's `uses:` refs).
- [`2026-06-07_docker_base_digest_pin.md`](./2026-06-07_docker_base_digest_pin.md) â€” Patch 11B-b3-b Docker base-image digest pin.

Status:

- **Pre-Alembic-removal dependency / CVE status was PASS** for the locked scanned set (Patch 11B-b2-c, run `#4`).
- **Alembic removal changed the runtime lockfile** â€” three packages dropped, no other version churn.
- This artefact records **PASS after that dependency change** â€” the change did not surface new findings.

---

## 6. Workflow cleanup

- The temporary path-filtered `push:` trigger (`push: paths: [".github/workflows/dependency-audit.yml"]`) was added to `.github/workflows/dependency-audit.yml` for the express purpose of firing run `#5`. It has now served that purpose.
- **In this patch, the temporary trigger was removed.** `.github/workflows/dependency-audit.yml` is restored to **manual `workflow_dispatch:` only**.
- No `schedule` trigger.
- No `pull_request` trigger.
- Not promoted to a required gate.
- No SHA-pinned `uses:` refs touched. No job-step or command change. No Python-version change.

This matches the workflow's posture after every prior temporary push-trigger use (Patches 11D-a `#2`, 11D-c `#3`, 11B-b2-c `#4`).

---

## 7. Stop-condition impact

| Operational gate | Status after this patch |
|---|---|
| **Dependency / CVE audit (CI pip-audit)** | âœ… **PASS** for the post-Alembic locked scanned dependency set (run `#5` against `de966a9`, 34 packages). |
| **Runtime dependency surface** | âœ… Smaller â€” three fewer wheels (`alembic`, `mako`, `markupsafe`) ship in every Render build; three fewer potential CVE rows in future `pip-audit` runs. |
| Dependency-file reproducibility | âœ… Closed by Patch 11B-b2-b; preserved by Patch 11B-b6-b. |
| Docker base-image digest pin | âœ… Closed by Patch 11B-b3-b. |
| GitHub Actions SHA pinning | âœ… Closed at the file layer by Patch 11B-b4-b. |
| Stale retention workflow removal | âœ… Closed by Patch 11B-b5-b. |
| Alembic dead-weight removal | âœ… Closed by Patch 11B-b6-b. |
| Dockerfile explicit `--require-hashes` flag | â³ Open â€” deferred. Per-wheel hash verification already in effect via the fully-hashed `requirements.txt`. |
| Optional `httpx<2` deprecation hygiene | â³ Open â€” optional **Patch 11B-b7**. |
| `github-actions` Dependabot SHA-refresh cadence | â³ Open â€” additive hygiene, separate follow-up. |
| Base-image digest refresh cadence | â³ Open â€” operational hygiene item. |
| Render deploy of post-Starlette + lockfile + digest + Actions-SHA + retention-cleanup + alembic-removal stack | â³ Open â€” operator decision. |
| Tenant Isolation Smoke #191 rate-limit | â³ Open â€” separate follow-up. |
| Legal / commercial pack per Addendum v1.3 | â³ Open â€” founder track. |

**No deploy decision made by this patch.** **Paid pilot / real clinic data remains blocked** by the standing operational gates.

---

## 8. Recommended next steps

1. **Commit and push** this evidence/cleanup patch.
2. **Confirm normal push workflows turn green** on the new commit (`Anchor Rate Limit CI`, `Tenant Isolation Smoke Test`).
3. **Confirm `Anchor Dependency Audit (pip-audit)` does not auto-run** on the cleanup push â€” its trigger is now `workflow_dispatch:` only again.
4. **Decide the next operator path:**
   - **Deploy-first** with production smoke â€” Render rebuild against the post-Starlette + lockfile + digest + Actions-SHA + retention-cleanup + alembic-removal stack, monitored carefully; or
   - **Optional hygiene first** â€” Patch 11B-b7 (`httpx<2` deprecation), explicit Dockerfile `--require-hashes` flag, base-image digest refresh cadence, `github-actions` Dependabot config; or
   - **Legal / commercial pack work** per Addendum v1.3 (founder track, parallel).

These three are independent; the reproducibility-first sequence that drove Patches 11B-b2 â†’ 11B-b6 is now complete at the file layer, and the next step is an operator decision rather than another technical patch in the same sequence.

---

## 9. Non-actions in this patch

The following were **explicitly not done** in Patch 11B-b6-c:

- âŒ No dependency changed.
- âŒ No `requirements.in` change.
- âŒ No `requirements.txt` change.
- âŒ No `requirements-dev.txt` change.
- âŒ No Dockerfile change.
- âŒ No GitHub Actions change **beyond** removing the temporary `push: paths:` trigger from `dependency-audit.yml`. (`anchor-rate-limit-ci.yml`, `isolation-smoke.yml` untouched. `anchor-retention-prune.yml` not re-added.)
- âŒ No SHA-pinned `uses:` ref changed.
- âŒ No application code change.
- âŒ No test change.
- âŒ No migration change.
- âŒ No migrations run.
- âŒ No database query or mutation.
- âŒ No Render setting change.
- âŒ No deploy.
- âŒ No frontend touch.
- âŒ No production endpoint call.
- âŒ No secret value read, printed, stored, or pasted.
- âŒ No compliance / certification / regulator-approval claim.
- âŒ No paid-pilot or real-clinic-data authorisation.

What this patch **did** do: removed the temporary path-filtered `push:` trigger from `.github/workflows/dependency-audit.yml` to restore it to manual `workflow_dispatch:` only; recorded the post-Alembic CI `pip-audit` PASS result for run `#5` against commit `de966a9` (34-package locked dependency set); and updated the operations README.
