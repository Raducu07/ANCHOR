# ANCHOR pip-audit CI Workflow — Implementation Note — 2026-06-07

> **Implementation note, not a scan result.** This artefact records the creation of `.github/workflows/dependency-audit.yml` as the reproducible execution path for `pip-audit` after the Patch 11B-a workstation TLS failure. **No CVE scan has run as a result of this patch.** The scan result will be captured in a separate dated artefact after the operator triggers the workflow manually.
>
> Operational evidence only. Not compliance certification. Not a regulator endorsement. Not a guarantee that no vulnerabilities exist. No production endpoint was called, no database was queried or mutated, no Render setting was changed, and no project dependency was updated.

---

## 1. Purpose and scope

Patch 11B-a (`2026-06-07_pip_audit_scan.md`) installed `pip-audit 2.10.0` on the operator workstation and confirmed the tool itself works, but both supported vulnerability sources (PyPI advisory and OSV) failed with the same workstation-side TLS verification error (`SSLCertVerificationError "unable to get local issuer certificate"`). The CVE scan was therefore classified **INCONCLUSIVE — TLS path**.

Patch 11B-a2's job was to establish a **reproducible execution path** for `pip-audit` from a clean environment with a current TLS trust store, before any dependency pinning / remediation work.

The brief's preferred order was:

1. Docker container locally → **not available** (probe below).
2. GitHub Actions workflow with `workflow_dispatch` only → **selected and implemented in this patch.**
3. Neither → would have been INCONCLUSIVE with no path forward.

This artefact is the implementation note for option (2). It does **not** record a PASS / FINDINGS / INCONCLUSIVE scan result, because no scan has been run as part of this patch — only the workflow that *enables* the scan.

---

## 2. Why GitHub Actions and not local Docker

`docker --version` from the operator workstation:

```
/usr/bin/bash: line 1: docker: command not found
```

`docker info` from the operator workstation:

```
/usr/bin/bash: line 1: docker: command not found
```

Docker is **not installed** on this workstation. The fallback path in the brief — a `workflow_dispatch`-only GitHub Actions workflow — was selected.

The CI runner (`ubuntu-latest`) provides:

- A current CA trust bundle (resolves the workstation's TLS verification failure that broke Patch 11B-a).
- A clean Python interpreter not influenced by the operator's local environment.
- `python-version: "3.11"` matched to the Render runtime base image (`python:3.11-slim` in the project `Dockerfile`), so the resolved dependency tree is closer to what production installs.

---

## 3. Workflow created

`.github/workflows/dependency-audit.yml` — full contents are in the workflow file itself; key properties only here:

| Property | Value |
|---|---|
| `name` | `Anchor Dependency Audit (pip-audit)` |
| Triggers | `workflow_dispatch: {}` **only** — not scheduled, not on push, not on PR |
| Runner | `ubuntu-latest` |
| Timeout | 10 minutes |
| Python version | `3.11` (matches Render `python:3.11-slim` base image) |
| Permissions | `contents: read` (read-only) |
| Concurrency group | `dependency-audit` (cancel-in-progress on re-trigger) |
| Action pins | `actions/checkout@v4`, `actions/setup-python@v5` — same mutable-tag posture as the other existing workflows (Patch 11A finding P-4 carries forward; not changed here) |
| Project dependencies installed in runner? | **No.** Only `pip` (upgraded) and `pip-audit` itself. `requirements.txt` is read by `pip-audit` but its contents are not installed into the runner — `pip-audit -r <file>` operates against the declaration, not the installed tree. |
| Secrets referenced? | **None.** No `secrets.*` reference, no env var read of any production credential, no admin token, no `DATABASE_URL`. |
| ANCHOR endpoints called? | **None.** The workflow performs no HTTP request to any ANCHOR surface. |

The workflow is intentionally **not** a required PR gate, **not** scheduled, and **not** push-triggered for this first pass. The operator runs it once manually from the Actions tab, captures the result, and a follow-up patch may flip the trigger shape after a clean baseline has been recorded.

---

## 4. Commands run during this patch

Locally on the workstation, before deciding on the GitHub Actions path:

```powershell
git status --short                          # → clean
git rev-parse --abbrev-ref HEAD             # → main
git rev-parse --short=12 HEAD               # → 549403265b49
python --version                            # → Python 3.12.10
python -m pip --version                     # → pip 25.0.1
docker --version                            # → command not found
docker info                                 # → command not found
```

**No `pip-audit` scan was attempted in this patch.** `pip-audit` is still available locally from Patch 11B-a, but the workstation TLS path remains unfixed, so re-running it from here would just reproduce the Patch 11B-a INCONCLUSIVE result. The next scan run lives in CI.

No production endpoint was called, no database was queried or mutated, no Render setting was changed, no project dependency was added / removed / upgraded / pinned, no `requirements.txt` edit, no `Dockerfile` edit, no edit to any existing workflow file (`anchor-rate-limit-ci.yml`, `anchor-retention-prune.yml`, `isolation-smoke.yml`).

---

## 5. How to run the workflow (operator step, separate from this patch)

After this patch merges to `main`:

1. GitHub repo → Actions tab → "Anchor Dependency Audit (pip-audit)" workflow → **Run workflow** → branch `main` → Run.
2. Wait ~2–5 minutes for the run to complete.
3. Open the run's log; capture the verbatim `python -m pip_audit -r requirements.txt` output (redact nothing — `pip-audit` output is metadata only).
4. Create a new dated artefact: `docs/operations/security_audits/<YYYY-MM-DD>_pip_audit_ci_scan.md` recording:
   - the run id and timestamp,
   - the SHA the runner checked out (visible from `git rev-parse --short=12 HEAD` in the "Show environment" step),
   - the classification (PASS / FINDINGS / INCONCLUSIVE),
   - if FINDINGS: a per-row table of package / installed version / vulnerability ID / severity / fixed version / short summary / proposed remediation patch,
   - if INCONCLUSIVE: the exact non-secret failure class.
5. Update `docs/operations/README.md` to reference the new artefact.

The operator should **not** auto-upgrade any dependency on the back of a single CI run's findings. Remediation is one package at a time with targeted tests, per `incident_response.md §3` severity classification.

---

## 6. Relationship to Patch 11A and 11B-a

### Carried-forward open items

- **From Patch 11A:**
  - **P-1** unpinned direct dependencies in `requirements.txt`.
  - **P-2** no transitive lockfile.
  - **P-3** Docker base image pinned by tag, not digest.
  - **P-4** GitHub Actions pinned by mutable tag, not SHA. **This new workflow uses the same mutable-tag posture as `anchor-rate-limit-ci.yml` for consistency**; tightening to commit-SHA pins is a Patch 11B-b decision that applies uniformly across all four workflows.
  - **P-5** `anchor-retention-prune.yml` cron calls a non-existent endpoint. **Untouched here.**
  - **P-6** `requirements.txt` includes `alembic` despite raw `.sql` migration usage.
- **From Patch 11B-a:**
  - The workstation TLS failure (`SSLCertVerificationError`) is still present. The CI runner sidesteps it; the workstation path will reproduce it on any rerun.

### What this patch changed

- **CVE-scan execution path only.** The tool is now wired into a reproducible environment. No scan result is recorded yet.
- **No project dependency change. No code change. No migration change. No production change.**

---

## 7. Risk summary

| Class | Items |
|---|---|
| **Critical findings (tool-backed)** | Not produced. No scan ran in this patch. |
| **High findings (tool-backed)** | Not produced. |
| **Medium findings (tool-backed)** | Not produced. |
| **Low findings (tool-backed)** | Not produced. |
| **Process / reproducibility findings (open from Patch 11A)** | P-1, P-2, P-3, P-4 (now applies to four workflows including the new one), P-5, P-6 — all carry forward unchanged. |
| **Unknown / inconclusive areas** | U-1 local CVE scan, U-2 Render-runtime CVE scan, U-3 transitive dependency set — all carry forward unchanged. |

### Honest positive statement

No claim of vulnerability-free posture is recorded here. The CVE half of the dependency question remains **open**, pending the operator's first manual run of the new `dependency-audit.yml` workflow.

---

## 8. Recommended follow-up

1. **Operator triggers the new workflow manually** from the Actions tab and captures the result in a new dated artefact under `docs/operations/security_audits/`. This is the next operational step; not a code patch.
2. **Patch 11B-a3 (or similar)** — once a clean baseline result is captured, flip the workflow trigger shape: add a weekly `schedule:` and consider whether to make it a required PR gate. **Not done in this patch** because there is no baseline result yet.
3. **Patch 11B-b — reproducibility track** carries forward from Patch 11A §8 unchanged: pin currently unpinned direct dependencies; add a transitive lockfile; pin Docker base by digest; pin GitHub Actions to commit SHAs (now applies to four workflows); **fix or delete `anchor-retention-prune.yml`** (P-5); drop dead-weight `alembic`.
4. **Patch 11B-c (optional)** — move `httpx` test dep into a new `requirements-dev.txt`.

None of these is implemented in Patch 11B-a2.

---

## 9. Stop-condition impact

**INCONCLUSIVE — no scan run.** The Patch 11A / 11B-a "CVE scan still INCONCLUSIVE" status is unchanged by this patch in *outcome* terms. What changed is *path availability*: the workflow now exists, so the next CI run will produce a real PASS / FINDINGS / INCONCLUSIVE result without depending on the operator workstation TLS configuration.

| Operational item                              | Status after Patch 11B-a2                                                                                                                                                            |
|---|---|
| Env docs                                      | ✅ Patch 7                                                                                                                                                                  |
| Backup / restore drill                        | ✅ Patch 8 / 8C — 2026-06-07 PASS                                                                                                                                            |
| Intake retention dry-run                      | ✅ Patch 9 / 9B — 2026-06-07 PASS, all counts 0                                                                                                                              |
| Incident-response runbook                     | ✅ Patch 10                                                                                                                                                                  |
| First tabletop drill                          | ✅ Patch 10B — 2026-06-07 PASS                                                                                                                                                |
| Dependency / CVE audit (snapshot)             | ⚠ Partially closed — Patch 11A captured the dependency surface and process findings. **CVE scan still INCONCLUSIVE.** Tool installed locally (Patch 11B-a). Reproducible CI execution path now exists (Patch 11B-a2). Next operator action: manual workflow run + capture artefact. |
| Dependency pinning / reproducibility          | ⏳ Open — Patch 11B-b candidate.                                                                                                                                              |
| Broken retention workflow (`anchor-retention-prune.yml`) | ⏳ Open — Patch 11C candidate (could also be folded into 11B-b).                                                                                                              |
| Legal / commercial pack per Addendum v1.3     | ⏳ Open — out of code scope; founder track.                                                                                                                                   |

This patch does **not** authorise paid pilot / real clinic data. The CVE half of the dependency question is still operator-action-pending.

---

## 10. Doctrine restatement

This artefact preserves the ANCHOR doctrine: governance-first, metadata-only by default, tenant safety, RLS / FORCE RLS, human review, receipt-backed, **aligned, not compliant**. It records:

- No secrets, no clinical content, no PII, no full bearer tokens, no `DATABASE_URL`, no Render env values.
- No claim of "no risk", "fully compliant", "certified", "regulator-approved", "guaranteed safe", or "no vulnerabilities".
- No project dependency change, no migration change, no application code change, no production change.
- A single new workflow file, narrowly scoped to `workflow_dispatch` only, with read-only permissions and no secret references.

Audit follow-ups land as separate patches with their own evidence artefacts in this directory.
