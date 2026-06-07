# ANCHOR CI pip-audit Findings — 2026-06-07

> **Tool-backed CVE scan from GitHub Actions: FINDINGS.** This artefact records the first successful `pip-audit` run against the ANCHOR backend dependency surface from a CI environment. It is **operational evidence only** — not compliance certification, not a regulator endorsement, not a guarantee that no other vulnerabilities exist, not a claim that ANCHOR is secure / compliant / certified / vulnerability-free.
>
> The dependency-audit workflow itself does **not** call any ANCHOR endpoint and does **not** query or mutate any database. **No project dependency was updated in this patch.** Real secrets — admin tokens, API keys, `DATABASE_URL`, JWT secret, hash salt, admin pepper, GitHub secrets values — never appear in this artefact.

---

## 1. Purpose and scope

This is the **first actionable CVE-scan result** for ANCHOR's backend dependency surface, captured from a `pip-audit` run on a GitHub-hosted runner. It is the direct follow-up to:

- Patch 11A — dependency snapshot + INCONCLUSIVE local CVE scan (tool unavailable).
- Patch 11B-a — local pip-audit install + INCONCLUSIVE CVE scan (workstation TLS failure).
- Patch 11B-a2 — created `.github/workflows/dependency-audit.yml` as a reproducible execution path; manual-only at the time, no scan result yet recorded.

**In scope:**

- Recording the GitHub Actions run that produced the findings.
- Listing the per-advisory rows pip-audit reported.
- Proposing remediation patch shape and order.
- Recording the separate `Tenant Isolation Smoke Test #191` rate-limit failure as a distinct CI/runtime concern.
- Restoring `dependency-audit.yml` to `workflow_dispatch`-only after the temporary path-filtered push trigger registered the workflow.

**Out of scope:**

- Updating, pinning, or installing any project dependency.
- Editing `requirements.txt`, `Dockerfile`, application code, migrations, tests, or any other workflow.
- Calling production endpoints, querying / mutating the database, or changing Render settings.
- Investigating the `Tenant Isolation Smoke Test #191` rate-limit response in depth — it is recorded here for the trail, not remediated.
- Compliance / certification claims of any kind.

**Disclaimers in plain language:**

- A pip-audit FINDINGS result identifies *known* advisories in the *declared* dependency tree. It does not characterise exploitability in the ANCHOR runtime context, transitive closure beyond what pip-audit traversed, or any non-tool-known vulnerability.
- This artefact does not authorise any production change.

---

## 2. Source run

| Field | Value |
|---|---|
| Workflow                 | `Anchor Dependency Audit (pip-audit)` |
| Workflow file            | `.github/workflows/dependency-audit.yml` |
| Run number               | `#1` |
| Commit (audited)         | `87c2ab9` |
| Branch                   | `main` |
| Trigger                  | Temporary path-filtered `push` trigger added in commit `87c2ab9` *only* to register the workflow in the Actions tab. Restored to `workflow_dispatch`-only in this patch (see §11). |
| Runner                   | `ubuntu-latest` |
| Python (runner)          | `3.11` (matches the Render `python:3.11-slim` Dockerfile base) |
| Command                  | `python -m pip_audit -r requirements.txt` |
| Result                   | **FINDINGS** |
| Process exit code        | `1` |
| Local operator workstation involved? | **No.** The runner was a clean GitHub-hosted environment with a current TLS trust store — exactly the situation Patch 11B-a2 set up. |

---

## 3. Findings table

`pip-audit` reported **8 advisory rows across 2 packages**. The Starlette advisory appears as two duplicate rows in the pip-audit output table; that is preserved verbatim below.

| # | package    | scanned version | advisory ID       | fixed version reported by pip-audit | notes                                                                                       | proposed remediation patch |
|---|------------|-----------------|-------------------|--------------------------------------|---------------------------------------------------------------------------------------------|----------------------------|
| 1 | `pyjwt`    | `2.8.0`         | `PYSEC-2026-120`  | `2.12.0`                             | Direct dependency (pinned in `requirements.txt`).                                            | Targeted PyJWT bump — see §8 |
| 2 | `pyjwt`    | `2.8.0`         | `PYSEC-2025-183`  | (no fixed version shown by pip-audit) | Unknown whether the advisory metadata is incomplete or pip-audit omitted the field.         | Investigate during PyJWT bump |
| 3 | `pyjwt`    | `2.8.0`         | `PYSEC-2026-179`  | `2.13.0`                             | Direct dependency.                                                                           | Bundle with #1 / #4 / #5 / #6 |
| 4 | `pyjwt`    | `2.8.0`         | `PYSEC-2026-175`  | `2.13.0`                             | Direct dependency.                                                                           | Bundle with #1 / #3 / #5 / #6 |
| 5 | `pyjwt`    | `2.8.0`         | `PYSEC-2026-177`  | `2.13.0`                             | Direct dependency.                                                                           | Bundle with #1 / #3 / #4 / #6 |
| 6 | `pyjwt`    | `2.8.0`         | `PYSEC-2026-178`  | `2.13.0`                             | Direct dependency.                                                                           | Bundle with #1 / #3 / #4 / #5 |
| 7 | `starlette`| `0.50.0`        | `PYSEC-2026-161`  | `1.0.1`                              | **Transitive** of `fastapi`. Not in `requirements.txt`. Major-version bump (`0.x` → `1.x`). | Assess FastAPI compatibility before bumping Starlette — see §8 |
| 8 | `starlette`| `0.50.0`        | `PYSEC-2026-161`  | `1.0.1`                              | Duplicate row in pip-audit output for the same advisory.                                     | Same as #7 |

### 3.1 Per-package proposed remediation summary

- **`pyjwt`** — assess and bump to a single version that satisfies all six reported fixes (highest reported fix is `2.13.0`). Pair the bump with explicit re-run of the focused Assistant test suite, the auth-and-RLS tests, the rate-limit tests, and the security-config-hardening tests. Patch 1's startup fail-closed asserts and the JWT decode strictness in `app/auth_and_rls.py:197-267` (HS256-only, audience+issuer required, `verify_signature: True`, etc.) should be re-validated against the new PyJWT behaviour.
- **`starlette`** — **do not upgrade blindly to 1.0.1**. Starlette is transitively pulled in by `fastapi` (it is *not* listed in `requirements.txt`). A direct Starlette bump risks colliding with whatever `starlette<X` constraint `fastapi==<resolved-version>` carries. The doctrine-aligned move is: (a) inspect FastAPI's current version and its declared Starlette range; (b) bump FastAPI to a release that itself depends on a fixed Starlette (≥ 1.0.1 or whichever line carries the patch), rather than pinning Starlette directly; (c) re-run the full test set since FastAPI version bumps frequently touch routing / dependency-injection behaviour. If no such FastAPI release exists yet, hold and re-scan periodically.

---

## 4. Classification

**CVE status changed from INCONCLUSIVE to FINDINGS.** Patch 11A and 11B-a were INCONCLUSIVE; this is the first CI scan that completed end-to-end.

This artefact does **not** state any of the following:

- ❌ "PASS"
- ❌ "No known vulnerabilities."
- ❌ "No vulnerabilities exist."
- ❌ "ANCHOR is secure."
- ❌ "ANCHOR is compliant."
- ❌ "ANCHOR is certified or regulator-approved."

The state is **remediation-required**.

---

## 5. Tenant Isolation Smoke Test note

On the same commit (`87c2ab9`), **`Tenant Isolation Smoke Test #191` failed**. RLS / FORCE-RLS checks passed before the failure point. The failure surfaced when a downstream production call returned:

```json
{
  "detail": "rate_limited",
  "request_id": "545339fd-bdf8-4286-8e45-87515c24377d"
}
```

- This is a **`rate_limited`** response, not a tenant-isolation regression. The smoke script hit the rate-limit gate on a production endpoint while running from the CI runner.
- Treated here as a **separate CI/runtime rate-limit issue**. Recommended follow-up: investigate which endpoint the smoke script targeted at the moment of failure, identify whether the smoke is using a tighter per-IP / per-token bucket than expected (`env.md §7` rules), and decide whether to (a) widen the bucket for the smoke caller (e.g. via a dedicated drill / smoke admin token whose limiter group is sized for the script's burst), (b) slow the smoke down, or (c) accept the occasional 429 and have the smoke retry with backoff.
- **Do not** classify as a tenant-isolation failure based on the available evidence. RLS checks before the rate-limit response passed; the response itself is a 429, not a 200-with-wrong-tenant-data.
- **`Anchor Rate Limit CI #100` succeeded** on the same commit, which is consistent with the per-group rate-limiter behaving correctly in test mode; this further suggests the smoke failure is a production-rate-limit interaction, not a regression in the limiter itself.
- This patch records the note for the trail. The smoke-rate-limit interaction is **not** part of the CVE remediation track; it gets its own follow-up.

---

## 6. Relationship to prior artefacts

| Artefact | Result | Carry-forward |
|---|---|---|
| `2026-06-07_dependency_cve_audit.md` (Patch 11A) | INCONCLUSIVE (tool unavailable) | Process / reproducibility findings P-1…P-6 remain open. |
| `2026-06-07_pip_audit_scan.md` (Patch 11B-a) | INCONCLUSIVE (workstation TLS failure) | TLS path on the operator workstation still unfixed; this patch sidesteps via CI. |
| `2026-06-07_pip_audit_ci_workflow_note.md` (Patch 11B-a2) | Workflow created; no scan run yet | This artefact records the first scan that did run. |
| **`2026-06-07_pip_audit_ci_findings.md` (this artefact, Patch 11B-a3)** | **FINDINGS** | First actionable result. Remediation patches (Patch 11C / 11D) to follow. |

---

## 7. Risk summary

| Class                              | Items                                                                                                                                                                                                                                                                                  |
|---|---|
| **Known vulnerable packages**      | 2 (`pyjwt`, `starlette`).                                                                                                                                                                                                                                                              |
| **Advisory rows reported**         | 8 (Starlette row duplicated in the pip-audit output; underlying advisory count is **7 distinct advisories**: six PyJWT + one Starlette).                                                                                                                                                |
| **Critical findings (tool-backed)** | Severity was **not surfaced in the pasted pip-audit table**. The default `pip-audit` text output prints package / version / advisory ID / fix versions only. Severity remains **unknown** until either a `pip-audit --format json` re-run enriches the rows or the operator looks up each PYSEC ID. |
| **High findings (tool-backed)**    | Severity unknown — see above.                                                                                                                                                                                                                                                          |
| **Medium findings (tool-backed)**  | Severity unknown — see above.                                                                                                                                                                                                                                                          |
| **Low findings (tool-backed)**     | Severity unknown — see above.                                                                                                                                                                                                                                                          |
| **Process / reproducibility findings (open from Patch 11A)** | **P-1** unpinned direct deps; **P-2** no transitive lockfile; **P-3** Docker base tag-only pin; **P-4** Actions tag-only pin (now four workflows); **P-5** `anchor-retention-prune.yml` broken cron; **P-6** dead-weight `alembic` in `requirements.txt`. All carry forward. |
| **Unknown / inconclusive areas**   | • Exact exploitability in ANCHOR runtime context (e.g. is the PyJWT advisory in a code path ANCHOR uses?). • PyJWT compatibility target — single bump vs. step bumps. • FastAPI ↔ Starlette compatibility under any planned Starlette move. • Whether `PYSEC-2025-183` has no fixed version because the advisory is genuinely unfixed-upstream or because the pip-audit output truncated the field. |

### 7.1 Honest positive statement

The CI scan completed and produced a deterministic findings list. **The CVE half of the dependency question is now answered to "remediation required".** This artefact does not state that ANCHOR is safe, compliant, or vulnerability-free; it states that the scan found known advisories against two declared / transitive packages.

---

## 8. Recommended remediation order

Sequenced so each step lands independently with its own tests and its own dated re-scan artefact:

1. **`pyjwt` bump first.** PyJWT is a direct dependency, is **pinned** at `2.8.0` in `requirements.txt`, and is the auth/security surface — the JWT decode and encode paths in `app/auth_and_rls.py`. The recommended remediation patch (call it **Patch 11C**) is:
   - Update the `PyJWT==2.8.0` pin in `requirements.txt` to a release that satisfies all six reported fixes (highest reported fix is `2.13.0`); pin to an exact version, not a range.
   - Re-run the focused Assistant test suite, `tests/test_auth_role_allowlist.py`, `tests/test_clinic_login_error_consistency.py`, `tests/test_rate_limit.py`, `tests/test_security_config_hardening.py`, and the assistant rate-limit / receipt-lookup tests.
   - Re-trigger `Anchor Dependency Audit (pip-audit)` manually and append a fresh artefact under `docs/operations/security_audits/` recording the new state.

2. **FastAPI / Starlette compatibility assessment second.** Starlette is transitive of FastAPI (it is *not* in `requirements.txt`). The recommended remediation patch (call it **Patch 11D**) is:
   - Identify the FastAPI version currently resolved on Render (via `pip freeze` inside the Render shell once, captured into the operator's private notes — **not** into git).
   - Identify the FastAPI release that depends on a Starlette ≥ 1.0.1 (or whichever first carries the patch).
   - If such a FastAPI release exists: pin `fastapi==<that-version>` in `requirements.txt`. Do **not** pin Starlette directly; let FastAPI's constraint resolve it.
   - If such a FastAPI release does not yet exist: hold the Starlette finding under "remediation pending upstream" and re-scan weekly.
   - Re-run the full focused test set after any FastAPI bump.
   - Re-trigger `Anchor Dependency Audit (pip-audit)` manually and append a fresh artefact.

3. **Re-scan after each remediation, not after the batch.** One package at a time, one artefact at a time. This matches `incident_response.md §3` severity discipline.

4. **Patch 11B-b reproducibility track** (carried forward from Patch 11A §8) remains the right next operational tightening after CVE findings are cleared: pin currently unpinned direct dependencies; add a transitive lockfile; pin Docker base by digest; pin all four workflows' actions to commit SHAs; fix or delete `anchor-retention-prune.yml`; drop dead-weight `alembic`.

5. **Tenant Isolation Smoke Test rate-limit** — separate follow-up. See §5. Could land as a small workflow / smoke-script adjustment or a documented smoke-mode admin token with widened limiter group.

---

## 9. Stop-condition impact

**Dependency / CVE scan is no longer INCONCLUSIVE. Current status: FINDINGS — remediation required.** The operational stop condition remains active until findings are remediated and a clean follow-up scan is recorded in this directory.

| Operational item                              | Status after Patch 11B-a3                                                                                                                                                            |
|---|---|
| Env docs                                      | ✅ Patch 7                                                                                                                                                                  |
| Backup / restore drill                        | ✅ Patch 8 / 8C — 2026-06-07 PASS                                                                                                                                            |
| Intake retention dry-run                      | ✅ Patch 9 / 9B — 2026-06-07 PASS, all counts 0                                                                                                                              |
| Incident-response runbook                     | ✅ Patch 10                                                                                                                                                                  |
| First tabletop drill                          | ✅ Patch 10B — 2026-06-07 PASS                                                                                                                                                |
| Dependency / CVE audit (snapshot)             | **⚠ FINDINGS — remediation required.** First CI run completed (this artefact). Carries forward to Patch 11C (PyJWT) and Patch 11D (FastAPI/Starlette) before the operational gate can close. |
| Dependency pinning / reproducibility          | ⏳ Open — Patch 11B-b candidate, after CVE remediation lands.                                                                                                                 |
| Broken retention workflow                     | ⏳ Open — Patch 11C-prune candidate (could be folded into 11B-b).                                                                                                              |
| Tenant Isolation Smoke rate-limit             | ⏳ Open — separate follow-up, see §5.                                                                                                                                          |
| Legal / commercial pack per Addendum v1.3     | ⏳ Open — out of code scope; founder track.                                                                                                                                   |

This patch does **not** authorise paid pilot / real clinic data. The dependency / CVE remediation is now the gating operational item.

---

## 10. Non-actions in this patch

The following were **explicitly not done** in Patch 11B-a3:

- ❌ No project dependency was updated.
- ❌ No `requirements.txt` change. The `PyJWT==2.8.0` pin and the unpinned lines remain exactly as Patch 11A inventoried them.
- ❌ No `Dockerfile` change.
- ❌ No application code change.
- ❌ No migration change.
- ❌ No test change.
- ❌ No database query / mutation by this patch.
- ❌ No production endpoint call by this patch.
- ❌ No Render setting change.
- ❌ No deploy.
- ❌ No edit to other workflow files (`anchor-rate-limit-ci.yml`, `anchor-retention-prune.yml`, `isolation-smoke.yml`).
- ❌ No change to the smoke / rate-limit configuration referenced in §5.
- ❌ No simulated incident.
- ❌ No tabletop drill record.
- ❌ No compliance / certification / regulator-approval claim.

What this patch **did** do: record the FINDINGS, restore `dependency-audit.yml` to `workflow_dispatch`-only, and propose the remediation order. That is the entirety of the change set.

---

## 11. Workflow trigger restoration

The temporary path-filtered `push` trigger added in commit `87c2ab9` to register `Anchor Dependency Audit (pip-audit)` in the Actions tab has served its purpose — the workflow is now registered and has produced its first result (this artefact). The trigger has been removed in this patch; the workflow is back to **`workflow_dispatch`-only** posture:

```yaml
on:
  workflow_dispatch:
```

No schedule. No `pull_request`. Not a required gate. Future operator runs are explicit "Run workflow" clicks from the Actions tab, exactly as Patch 11B-a2 designed.

---

## 12. Doctrine restatement

This artefact preserves the ANCHOR doctrine: governance-first, metadata-only by default, tenant safety, RLS / FORCE RLS, human review, receipt-backed, **aligned, not compliant**. It records:

- No secrets, no clinical content, no PII, no full bearer tokens, no `DATABASE_URL`, no Render env values.
- No claim of "no risk", "fully compliant", "certified", "regulator-approved", "guaranteed safe", or "no vulnerabilities".
- No project dependency change, no migration change, no application code change, no production change.
- The Tenant Isolation Smoke rate-limit failure is recorded as a **separate** CI/runtime concern, not as a tenant-isolation regression.

Audit follow-ups land as separate patches with their own evidence artefacts in this directory.
