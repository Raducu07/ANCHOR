# ANCHOR Post-PyJWT CI pip-audit Result — 2026-06-07

> **Tool-backed CVE re-scan after Patch 11C: PyJWT findings cleared in CI; Starlette remains open.** This artefact records the CI dependency audit result captured after Patch 11C bumped `PyJWT` from `2.8.0` to `2.13.0`. It is **operational evidence only** — not compliance certification, not a regulator endorsement, not a guarantee that no other vulnerabilities exist, not a claim that ANCHOR is secure / compliant / certified / vulnerability-free.
>
> The dependency-audit workflow does **not** call any ANCHOR endpoint and does **not** query or mutate any database. **No dependency was changed in this patch.** Real secrets — admin tokens, API keys, `DATABASE_URL`, JWT secret, hash salt, admin pepper, GitHub secrets values — never appear in this artefact.

---

## 1. Purpose and scope

This artefact records the CI dependency audit result **after** Patch 11C (`PyJWT 2.8.0` → `2.13.0`, commit `901328d`). It is the operational confirmation step the Patch 11C artefact (`2026-06-07_pyjwt_remediation.md §7`) called out as required.

**In scope:**

- Recording the post-PyJWT CI `pip-audit` output.
- Confirming the six PyJWT advisory rows from `2026-06-07_pip_audit_ci_findings.md` are no longer present.
- Recording the remaining Starlette finding for Patch 11D scope.
- Restoring `.github/workflows/dependency-audit.yml` to `workflow_dispatch`-only after the temporary path-filtered push trigger registered in commit `97e78bd` did its single job (firing the post-PyJWT scan).

**Out of scope:**

- Any Starlette pin or FastAPI bump (deferred to Patch 11D).
- Any other dependency change.
- Application code, migrations, tests, scripts, Dockerfile, other workflows, production env values.
- Calling production endpoints, querying / mutating the database, or changing Render settings.
- Compliance / certification claims of any kind.

**Disclaimers in plain language:**

- A reduced findings count is not evidence of safety, only of the prior fix landing as expected against the tool's reference data.
- This artefact does not authorise any production change.

---

## 2. Source run

| Field | Value |
|---|---|
| Workflow                 | `Anchor Dependency Audit (pip-audit)` |
| Workflow file            | `.github/workflows/dependency-audit.yml` |
| Commit scanned           | `97e78bd` (or the exact commit shown in the run's "Show environment" step output) |
| Branch                   | `main` |
| Trigger                  | Temporary path-filtered `push` trigger added in commit `97e78bd` *only* to fire the post-PyJWT audit. Restored to `workflow_dispatch`-only in this patch (see §6). |
| Runner                   | `ubuntu-latest` |
| Python (runner)          | `3.11` (matches Render `python:3.11-slim` base image) |
| Command                  | `python -m pip_audit -r requirements.txt` |
| Result                   | **FINDINGS** — reduced from prior 8 advisory rows to 2 (Starlette only, duplicated by pip-audit text output) |
| Process exit code        | `1` |
| Run number               | Not captured in local notes; GitHub Actions run should be cross-referenced from the Actions page if needed. |

Verbatim CI output captured into this artefact:

```
Run python -m pip_audit -r requirements.txt
Found 2 known vulnerabilities in 1 package
Name      Version ID             Fix Versions
--------- ------- -------------- ------------
starlette 0.50.0  PYSEC-2026-161 1.0.1
starlette 0.50.0  PYSEC-2026-161 1.0.1
Error: Process completed with exit code 1.
```

---

## 3. Findings table

`pip-audit` reported **2 advisory rows across 1 package**. The Starlette advisory appears as two duplicate rows in the pip-audit output table; that is preserved verbatim.

| # | package    | scanned version | advisory ID       | fixed version reported by pip-audit | row status                                 | proposed remediation patch |
|---|------------|-----------------|-------------------|--------------------------------------|---------------------------------------------|----------------------------|
| 1 | `starlette`| `0.50.0`        | `PYSEC-2026-161`  | `1.0.1`                              | remaining open                              | **Patch 11D — FastAPI / Starlette compatibility assessment** |
| 2 | `starlette`| `0.50.0`        | `PYSEC-2026-161`  | `1.0.1`                              | duplicate row in pip-audit text output      | **Patch 11D — FastAPI / Starlette compatibility assessment** |

**Distinct advisory count: 1.** Underlying advisory: `PYSEC-2026-161` against `starlette==0.50.0`, fixed in `1.0.1`. Same row was reported twice in the source findings (`2026-06-07_pip_audit_ci_findings.md §3` rows #7 and #8); the duplication behaviour is unchanged across pip-audit runs.

---

## 4. PyJWT remediation confirmation

The six PyJWT advisory rows recorded in [`2026-06-07_pip_audit_ci_findings.md`](./2026-06-07_pip_audit_ci_findings.md) §3 (`PYSEC-2026-120`, `PYSEC-2025-183`, `PYSEC-2026-179`, `PYSEC-2026-175`, `PYSEC-2026-177`, `PYSEC-2026-178`) are **no longer present** in the post-PyJWT CI output captured in §2. The post-PyJWT scan reports exactly 2 advisory rows, both against `starlette`.

**This confirms Patch 11C cleared the PyJWT portion of the findings in CI.** The Patch 11C local install + 282 focused tests passing under PyJWT `2.13.0` is now backed by tool-side CI evidence.

**This artefact does *not* claim that the whole dependency audit passed.** Starlette remains open and is the gating CVE item until Patch 11D lands.

---

## 5. Remaining Starlette finding

- **Package:** `starlette`
- **Scanned version:** `0.50.0`
- **Advisory ID:** `PYSEC-2026-161` (reported twice in pip-audit text output)
- **Fixed version reported by pip-audit:** `1.0.1`
- **Source in the dependency tree:** transitive of `fastapi`. Not listed in `requirements.txt`. The version observed in CI is whatever the runner resolved `fastapi` against on this commit.

**Do not pin Starlette directly without assessing FastAPI compatibility.** The Patch 11C artefact §8.2 and the earlier `2026-06-07_pip_audit_ci_findings.md §8.2` both warn that a Starlette `0.x` → `1.x` bump is a major-version transition that risks colliding with FastAPI's declared Starlette range. The doctrine-aligned move is to identify a FastAPI release whose own `starlette` constraint pulls in `≥1.0.1` (or the first line carrying the fix), pin `fastapi==<that-version>` in `requirements.txt`, and let FastAPI's transitive resolution drive Starlette. If no such FastAPI release exists yet, the operator may either (a) hold the Starlette finding under "remediation pending upstream" with a documented periodic re-scan, or (b) record an explicit, founder-approved risk-acceptance note.

**Patch 11D scope (recommended sequence):**

1. Inspect FastAPI's current resolved version on Render (via a one-off `pip freeze` inside the Render shell captured to the operator's private notes — **not** to git).
2. Identify the smallest FastAPI version bump that brings transitive Starlette to `≥1.0.1`.
3. Pin `fastapi==<that-version>` in `requirements.txt`. Pair with a local install + integrity check + the same 282-focused-test set used in Patch 11C.
4. Re-trigger `Anchor Dependency Audit (pip-audit)` manually and append the next artefact.
5. If no compatible FastAPI release exists yet, write a separate documented risk-acceptance artefact rather than pinning Starlette directly.

---

## 6. Workflow cleanup

The temporary path-filtered `push` trigger added in commit `97e78bd` to `.github/workflows/dependency-audit.yml` did its single job — firing the post-PyJWT CI scan whose result is captured in §2. The trigger has been removed in this patch. The workflow's `on:` block is now:

```yaml
on:
  workflow_dispatch:
```

- No `schedule`.
- No `pull_request`.
- Not a required gate.

Future operator runs are explicit "Run workflow" clicks from the Actions tab, exactly as Patch 11B-a2 designed and Patch 11B-a3 restored. This matches the pattern: the workflow is path-filtered-push-triggered only for the duration of a single intentional audit run, then immediately reverted.

---

## 7. Relationship to prior artefacts

| Artefact | Result | Carry-forward |
|---|---|---|
| [`2026-06-07_dependency_cve_audit.md`](./2026-06-07_dependency_cve_audit.md) (Patch 11A) | INCONCLUSIVE (tool unavailable) | Process / reproducibility findings P-1 … P-6 remain open. |
| [`2026-06-07_pip_audit_scan.md`](./2026-06-07_pip_audit_scan.md) (Patch 11B-a) | INCONCLUSIVE (workstation TLS failure) | Local scan path still unfixed; CI runs are the authoritative source. |
| [`2026-06-07_pip_audit_ci_workflow_note.md`](./2026-06-07_pip_audit_ci_workflow_note.md) (Patch 11B-a2) | Workflow created | Workflow now sits at `workflow_dispatch`-only after this patch. |
| [`2026-06-07_pip_audit_ci_findings.md`](./2026-06-07_pip_audit_ci_findings.md) (Patch 11B-a3) | **FINDINGS — 8 rows / 2 packages.** PyJWT (6 rows) + Starlette (2 duplicated rows). | PyJWT cleared in this artefact; Starlette carried forward. |
| [`2026-06-07_pyjwt_remediation.md`](./2026-06-07_pyjwt_remediation.md) (Patch 11C) | PyJWT pin bumped `2.8.0` → `2.13.0`; 282 focused tests passed; CI re-scan required. | CI re-scan is *this artefact*. |
| **`2026-06-07_post_pyjwt_ci_audit.md` (this artefact, Patch 11C-a)** | **FINDINGS — 1 distinct advisory (Starlette).** | PyJWT confirmed cleared in CI. Starlette remediation = Patch 11D. |

**Prior state:** FINDINGS across PyJWT and Starlette.
**Current state:** FINDINGS across Starlette only.

---

## 8. Stop-condition impact

The dependency / CVE gate **remains active**. Paid pilot / real clinic data remains blocked until Starlette is remediated or formally risk-assessed / deferred with evidence and a follow-up audit artefact. The PyJWT portion is now cleared by CI evidence and no longer contributes to the gate.

| Operational item                              | Status after Patch 11C-a                                                                                                                                                              |
|---|---|
| Env docs                                      | ✅ Patch 7                                                                                                                                                                  |
| Backup / restore drill                        | ✅ Patch 8 / 8C — 2026-06-07 PASS                                                                                                                                            |
| Intake retention dry-run                      | ✅ Patch 9 / 9B — 2026-06-07 PASS, all counts 0                                                                                                                              |
| Incident-response runbook                     | ✅ Patch 10                                                                                                                                                                  |
| First tabletop drill                          | ✅ Patch 10B — 2026-06-07 PASS                                                                                                                                                |
| Dependency / CVE audit — PyJWT half           | ✅ Patch 11C + 11C-a — PyJWT findings cleared in CI; pin `PyJWT==2.13.0`.                                                                                                       |
| Dependency / CVE audit — Starlette half       | ⚠ **FINDINGS — Starlette `PYSEC-2026-161` remains open.** Patch 11D required to clear (FastAPI compatibility assessment), or a documented founder-approved risk acceptance. |
| Dependency pinning / reproducibility          | ⏳ Open — Patch 11B-b candidate, after Starlette is resolved.                                                                                                                 |
| Broken `anchor-retention-prune.yml`           | ⏳ Open.                                                                                                                                                                     |
| Tenant Isolation Smoke rate-limit (smoke #191)| ⏳ Open — separate follow-up.                                                                                                                                                 |
| Legal / commercial pack per Addendum v1.3     | ⏳ Open — out of code scope; founder track.                                                                                                                                   |

---

## 9. Non-actions in this patch

The following were **explicitly not done** in Patch 11C-a:

- ❌ No dependency changed.
- ❌ No `requirements.txt` change. The `PyJWT==2.13.0` pin from Patch 11C and every other dependency line are byte-identical.
- ❌ No `Dockerfile` change.
- ❌ No GitHub Actions change beyond removing the temporary path-filtered `push` trigger from `.github/workflows/dependency-audit.yml`. The other three workflows (`anchor-rate-limit-ci.yml`, `anchor-retention-prune.yml`, `isolation-smoke.yml`) are untouched.
- ❌ No application code change.
- ❌ No migration change.
- ❌ No migrations run.
- ❌ No database query or mutation.
- ❌ No Render setting change.
- ❌ No deploy.
- ❌ No frontend touch.
- ❌ No Starlette pin or FastAPI bump (Patch 11D scope).
- ❌ No production endpoint call.
- ❌ No secret value printed, stored, or pasted anywhere.
- ❌ No compliance / certification / regulator-approval claim.

What this patch **did** do: record the post-PyJWT CI audit result, restore the dependency-audit workflow to `workflow_dispatch`-only, and identify Patch 11D as the gating CVE remediation step.

---

## 10. Doctrine restatement

This artefact preserves the ANCHOR doctrine: governance-first, metadata-only by default, tenant safety, RLS / FORCE RLS, human review, receipt-backed, **aligned, not compliant**. It records:

- No secrets, no clinical content, no PII, no full bearer tokens, no `DATABASE_URL`, no Render env values.
- No claim of "no risk", "fully compliant", "certified", "regulator-approved", "guaranteed safe", or "no vulnerabilities".
- A single workflow edit (removing the temporary push trigger) plus a documentation artefact recording the CI audit result. No code, no migration, no production touch.

Audit follow-ups land as separate patches with their own evidence artefacts in this directory.
