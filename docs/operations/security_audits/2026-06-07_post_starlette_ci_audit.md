# ANCHOR Post-Starlette CI pip-audit Result — 2026-06-07

> **Tool-backed CVE re-scan after Patch 11D-b: PASS.** This artefact records the GitHub Actions `pip-audit` run captured after Patch 11D-b's FastAPI-mediated Starlette remediation. **Operational evidence only.** Not compliance certification. Not a regulator endorsement. Not a guarantee that no other vulnerabilities exist. Not a claim that ANCHOR is secure / compliant / certified / vulnerability-free.
>
> The dependency-audit workflow does **not** call any ANCHOR endpoint and does **not** query or mutate any database. **No dependency was changed in this patch.** Real secrets — admin tokens, API keys, `DATABASE_URL`, JWT secret, hash salt, admin pepper, GitHub secrets values — never appear in this artefact.

---

## 1. Purpose and scope

This artefact records the CI dependency audit result **after** Patch 11D-b's FastAPI-mediated Starlette remediation (commit `9733361`, *"Remediate Starlette CVE via FastAPI pin"*). It is the operational confirmation step the Patch 11D-b artefact (`2026-06-07_fastapi_starlette_remediation.md §7`) called out as required.

**In scope:**

- Recording the post-Starlette CI `pip-audit` run that succeeded.
- Confirming the Starlette `PYSEC-2026-161` finding (the last remaining row in the post-PyJWT scan) is no longer reported.
- Restoring `.github/workflows/dependency-audit.yml` to `workflow_dispatch`-only after the temporary path-filtered push trigger registered in commit `bfec5a0` did its single job (firing the post-Starlette scan).

**Out of scope:**

- Any dependency change. `requirements.txt`, `Dockerfile`, application code, migrations, tests, scripts, frontend, production env values, Render settings — all untouched in this patch.
- Calling production endpoints, querying / mutating the database, or changing Render settings.
- Deploying the dependency remediation stack to Render (separate operator decision after this patch lands).
- Compliance / certification claims of any kind.

**Disclaimers in plain language:**

- A clean tool result is **not** evidence of safety — only that the dependency set scanned, against the advisory data the tool had at the time, produced no findings.
- Tools can miss vulnerabilities (advisory database gaps, transitive resolution edge cases, zero-days, etc.).
- This artefact does not authorise any production change.

---

## 2. Source run

| Field | Value |
|---|---|
| Workflow                 | `Anchor Dependency Audit (pip-audit)` |
| Workflow file            | `.github/workflows/dependency-audit.yml` |
| Run title                | *"Trigger post-Starlette dependency audit"* |
| Run number               | `#3` |
| Commit scanned           | `bfec5a0` (the same SHA as the local HEAD at the time this artefact is written — `bfec5a0d4dc9` short → `bfec5a0` 7-char prefix in the GitHub UI) |
| Branch                   | `main` |
| Trigger                  | Temporary path-filtered `push` trigger added in commit `bfec5a0` *only* to fire the post-Starlette audit. Restored to `workflow_dispatch`-only in this patch (see §6). |
| Runner                   | GitHub-hosted (`ubuntu-latest`) |
| Python (runner)          | `3.11` (matches Render `python:3.11-slim` base image) |
| Job name                 | `pip-audit -r requirements.txt` |
| Command                  | `python -m pip_audit -r requirements.txt` |
| Run status               | **Success** |
| Exit code                | `0` (inferred from successful job status — the prior post-PyJWT FINDINGS run produced exit code `1`) |
| Job wall-time            | ~18 s |
| `Run pip-audit against requirements.txt` step wall-time | ~7 s |
| Evidence source          | GitHub Actions UI PDF supplied by the operator |

---

## 3. Result wording

**No known vulnerabilities were reported by CI pip-audit for the dependency set scanned.**

Caveats:

- This is **not** a guarantee that no vulnerabilities exist in the ANCHOR backend or in any of its dependencies. `pip-audit` can only report what its advisory data sources (PyPI advisories and OSV) know at the time of the run.
- The result reflects the **dependency set scanned at this commit** (`bfec5a0`) and the **advisory data available** at run time. A vulnerability published an hour later would not appear in this artefact.
- This artefact does not state any of the following:
  - ❌ "ANCHOR is secure."
  - ❌ "ANCHOR is compliant."
  - ❌ "ANCHOR is certified or regulator-approved."
  - ❌ "No vulnerabilities exist."
  - ❌ "The system is safe."

The state is **CI pip-audit PASS for the dependency set scanned**, not generalised safety.

---

## 4. Findings progression

| Patch | CI scan state | Detail |
|---|---|---|
| 11B-a3 (`2026-06-07_pip_audit_ci_findings.md`) | **FINDINGS — 8 rows / 2 packages** | 6 PyJWT advisory rows (`PyJWT==2.8.0`) + 1 Starlette advisory duplicated to 2 rows (`starlette==0.50.0`). |
| 11C / 11C-a (`2026-06-07_post_pyjwt_ci_audit.md`) | **FINDINGS — 2 rows / 1 package** | PyJWT cleared by the `2.8.0 → 2.13.0` bump. Starlette remained. |
| **11D-b / 11D-c (this artefact)** | **PASS — 0 rows / 0 packages** | Starlette cleared by the FastAPI-mediated bump (`fastapi==0.133.1` + `pydantic[email]==2.7.4`; Starlette resolves to `1.2.1` transitively). |

Current dependency / CVE audit state: **CI pip-audit PASS for the dependency set scanned**.

---

## 5. Dependency state relevant to the pass

`requirements.txt` at the audited commit (`bfec5a0`) carries:

| Line | Value | Source patch |
|---|---|---|
| `fastapi==0.133.1` | direct, pinned | Patch 11D-b |
| `uvicorn` | direct, unpinned | (Patch 11A P-1 carry-forward) |
| `psycopg[binary]` | direct, unpinned | (Patch 11A P-1) |
| `sqlalchemy[psycopg]` | direct, unpinned | (Patch 11A P-1) |
| `alembic` | direct, unpinned (dead weight — Patch 11A P-6) | (carry-forward) |
| **`PyJWT==2.13.0`** | direct, pinned | **Patch 11C** |
| **`pydantic[email]==2.7.4`** | direct, pinned | **Patch 11D-b** |
| `argon2-cffi` | direct, unpinned | (Patch 11A P-1) |
| `httpx` | direct, unpinned (test dep inlined) | (Patch 11A P-1) |
| `anthropic` | direct, unpinned | (Patch 11A P-1) |
| `starlette` | **NOT declared** — transitive of FastAPI | Patch 11D-b deliberately avoided a direct pin |
| `anyio` | not declared — transitive of Starlette | n/a |

Resolved Starlette version under this set:

- **Render fresh-install (and Patch 11D-b's local post-uninstall-Starlette install):** resolves Starlette transitively to `1.2.1` (well above the `1.0.1` advisory fix). This is the version actually deployed by Render's Docker build and the version present in the CI runner during this audit.
- Patch 11D-b's `--ignore-installed` dry-run confirmed the same resolution.

---

## 6. Workflow cleanup

The temporary path-filtered `push` trigger added in commit `bfec5a0` to `.github/workflows/dependency-audit.yml` did its single job — firing the post-Starlette CI scan whose successful result is captured in §2. The trigger has been removed in this patch. The workflow's `on:` block is now:

```yaml
on:
  workflow_dispatch:
```

- No `schedule:`.
- No `pull_request:`.
- Not a required gate.
- Other three workflows (`anchor-rate-limit-ci.yml`, `anchor-retention-prune.yml`, `isolation-smoke.yml`) untouched.

Future operator runs are explicit "Run workflow" clicks from the Actions tab — the third such restoration to `workflow_dispatch`-only (after Patch 11B-a3 and Patch 11C-a). The pattern is stable: the workflow is path-filtered-push-triggered only for the duration of a single intentional audit run, then immediately reverted.

---

## 7. Relationship to prior artefacts

| Artefact | Result | Carry-forward |
|---|---|---|
| [`2026-06-07_dependency_cve_audit.md`](./2026-06-07_dependency_cve_audit.md) (Patch 11A) | INCONCLUSIVE (tool unavailable) | Process / reproducibility findings P-1 … P-6 remain open. |
| [`2026-06-07_pip_audit_scan.md`](./2026-06-07_pip_audit_scan.md) (Patch 11B-a) | INCONCLUSIVE (workstation TLS failure) | CI runs remain the authoritative source. |
| [`2026-06-07_pip_audit_ci_workflow_note.md`](./2026-06-07_pip_audit_ci_workflow_note.md) (Patch 11B-a2) | Workflow created | Workflow now sits at `workflow_dispatch`-only after this patch. |
| [`2026-06-07_pip_audit_ci_findings.md`](./2026-06-07_pip_audit_ci_findings.md) (Patch 11B-a3) | **FINDINGS — 8 rows / 2 packages.** | PyJWT cleared in Patch 11C-a; Starlette cleared in this artefact. |
| [`2026-06-07_pyjwt_remediation.md`](./2026-06-07_pyjwt_remediation.md) (Patch 11C) | PyJWT bumped `2.8.0` → `2.13.0`; 282 focused tests passed. | Confirmed by Patch 11C-a CI scan. |
| [`2026-06-07_post_pyjwt_ci_audit.md`](./2026-06-07_post_pyjwt_ci_audit.md) (Patch 11C-a) | **FINDINGS — 1 distinct advisory (Starlette).** | Cleared by Patch 11D-b. |
| [`2026-06-07_starlette_fastapi_compatibility_assessment.md`](./2026-06-07_starlette_fastapi_compatibility_assessment.md) (Patch 11D-a) | `FASTAPI-MEDIATED REMEDIATION LIKELY AVAILABLE` — compound bump shape recommended. | Applied by Patch 11D-b. |
| [`2026-06-07_fastapi_starlette_remediation.md`](./2026-06-07_fastapi_starlette_remediation.md) (Patch 11D-b) | Compound bump applied: `fastapi==0.133.1`, `pydantic[email]==2.7.4`; resolves Starlette to `1.2.1`; 1525 / 1525 tests passed; local pip-audit INCONCLUSIVE (TLS). | CI re-scan is *this artefact*. |
| **`2026-06-07_post_starlette_ci_audit.md` (this artefact, Patch 11D-c)** | **PASS — 0 rows / 0 packages.** | Dependency / CVE audit gate cleared for the dependency set scanned. |

**Prior state:** FINDINGS across PyJWT and Starlette (eight advisory rows, two packages).
**Current state:** **CI pip-audit PASS for the dependency set scanned** (zero advisory rows, zero packages reported).

---

## 8. Stop-condition impact

The **dependency / CVE audit gate is cleared for the current scanned dependency set**. This does not clear other operational gates. Several gates remain open and must be addressed before paid pilot / real clinic data.

| Operational item                              | Status after Patch 11D-c                                                                                                                                                              |
|---|---|
| Env docs                                      | ✅ Patch 7                                                                                                                                                                  |
| Backup / restore drill                        | ✅ Patch 8 / 8C                                                                                                                                                              |
| Intake retention dry-run                      | ✅ Patch 9 / 9B                                                                                                                                                              |
| Incident-response runbook                     | ✅ Patch 10                                                                                                                                                                  |
| First tabletop drill                          | ✅ Patch 10B                                                                                                                                                                  |
| **Dependency / CVE audit (CI pip-audit)**     | **✅ PASS** for the dependency set scanned (this artefact). PyJWT and Starlette cleared.                                                                                       |
| Dependency pinning / reproducibility (Patch 11A P-1 … P-6) | ⏳ Open — Patch 11B-b candidate: pin currently unpinned direct dependencies; add transitive lockfile; pin Docker base by digest; pin GitHub Actions to commit SHAs; fix or delete `anchor-retention-prune.yml`; drop dead-weight `alembic`. |
| Broken `anchor-retention-prune.yml`           | ⏳ Open — folded into Patch 11B-b or its own follow-up.                                                                                                                       |
| Tenant Isolation Smoke rate-limit (#191)      | ⏳ Open — separate follow-up.                                                                                                                                                 |
| `httpx<2` / Starlette TestClient deprecation  | ⏳ Open — hygiene item surfaced by Patch 11D-b; not a blocker.                                                                                                                |
| Legal / commercial pack per Addendum v1.3     | ⏳ Open — out of code scope; founder track.                                                                                                                                   |

**No paid pilot / real clinic data** until all standing operational stop conditions are cleared — not just the dependency / CVE gate.

---

## 9. Recommended next steps

1. **Commit and push this evidence + cleanup patch.** Two file changes (`.github/workflows/dependency-audit.yml`, `docs/operations/README.md`) plus the new artefact. No code, no migration, no dependency change.

2. **Do not deploy automatically.** Render auto-deploy is disabled per `backup_restore.md §10.2`. Any deploy is an explicit operator action.

3. **Decide whether to deploy the dependency remediation stack now or first complete the dependency reproducibility track.** Two paths:

   - **Deploy-first path** — push the Patch 11C / 11C-a / 11D-b / 11D-c stack to Render, run the production smoke set, then come back to Patch 11B-b reproducibility work.
   - **Reproducibility-first path** — land Patch 11B-b (pin currently unpinned direct deps, add transitive lockfile, pin Docker base by digest, pin GitHub Actions to commit SHAs, etc.) before any production deploy. This produces a reproducible deploy *exactly* matching what CI scanned.

   The reproducibility-first path is the strictly safer order (smaller risk of Render's resolver picking a different transitive set than CI), but it lengthens the time to deploy. Founder decision.

4. **If deploying before reproducibility track**, perform a manual Render deploy followed by the production smoke set per `env.md §13`:

   - `GET /health` → `200`
   - `GET /v1/version` → `200`, `env=prod`, `git_sha` matching the deployed SHA
   - `GET /v1/portal/dashboard` without bearer → `401 missing_bearer_token`

   Any deviation triggers the relevant `incident_response.md §8` playbook.

5. **Proceed to Patch 11B-b / reproducibility track:**

   - Pin currently unpinned direct dependencies (`uvicorn`, `psycopg[binary]`, `sqlalchemy[psycopg]`, `argon2-cffi`, `httpx`, `anthropic`).
   - Add a transitive lockfile (`pip-tools` / `uv` / `poetry`).
   - Pin the Docker base image by digest (`python:3.11-slim@sha256:<digest>`).
   - Pin all four GitHub Actions workflows to commit SHAs.
   - Fix or delete `anchor-retention-prune.yml` (P-5).
   - Drop dead-weight `alembic` from `requirements.txt` (P-6).
   - Handle the `httpx<2` / Starlette TestClient deprecation as a separate hygiene item if still relevant after the lockfile lands.

---

## 10. Non-actions in this patch

The following were **explicitly not done** in Patch 11D-c:

- ❌ No dependency changed.
- ❌ No `requirements.txt` change. `fastapi==0.133.1`, `pydantic[email]==2.7.4`, `PyJWT==2.13.0`, and every other line are byte-identical to the post-Patch-11D-b state.
- ❌ No `Dockerfile` change.
- ❌ No GitHub Actions change beyond removing the temporary path-filtered `push` trigger from `dependency-audit.yml`.
- ❌ No application code change.
- ❌ No test change.
- ❌ No migration change.
- ❌ No migrations run.
- ❌ No database query or mutation.
- ❌ No Render setting change.
- ❌ No deploy.
- ❌ No frontend touch.
- ❌ No production endpoint call.
- ❌ No secret value printed, stored, or pasted anywhere.
- ❌ No compliance / certification / regulator-approval claim.
- ❌ No paid-pilot or real-clinic-data authorisation.

What this patch **did** do: record the CI dependency audit PASS, restore the dependency-audit workflow to `workflow_dispatch`-only, and identify the next operational track (Patch 11B-b reproducibility) and the deploy decision point.

---

## 11. Doctrine restatement

This artefact preserves the ANCHOR doctrine: governance-first, metadata-only by default, tenant safety, RLS / FORCE RLS, human review, receipt-backed, **aligned, not compliant**. It records:

- No secrets, no clinical content, no PII, no full bearer tokens, no `DATABASE_URL`, no Render env values.
- No claim of "no risk", "fully compliant", "certified", "regulator-approved", "guaranteed safe", or "no vulnerabilities exist".
- A single workflow edit (removing the temporary push trigger) plus a documentation artefact recording the CI PASS result. No code, no test, no migration, no dependency change, no production touch.

Audit follow-ups land as separate patches with their own evidence artefacts in this directory.
