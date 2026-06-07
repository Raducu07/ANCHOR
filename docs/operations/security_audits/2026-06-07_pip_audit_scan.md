# ANCHOR pip-audit CVE Scan — 2026-06-07

> **Operational security evidence only.** Not a compliance certification. Not a regulator endorsement. Not a guarantee that no vulnerabilities exist in the ANCHOR backend or its dependency tree. ANCHOR is aligned to RCVS principles and EU AI Act articles where it can be; it is not compliant with them.
>
> No production endpoint was called, no database was queried or mutated, no Render setting was changed, and **no project dependency was updated** during this scan. `pip-audit` was installed as a user-level tool only on the operator workstation; `requirements.txt`, `Dockerfile`, GitHub Actions, and Render config were not touched.
>
> Real secrets — admin tokens, API keys, `DATABASE_URL`, JWT secret, hash salt, admin pepper, GitHub secrets values — never appear in this artefact.

---

## 1. Purpose and scope

This is a **tool-backed CVE scan** of the ANCHOR backend Python dependency surface, performed as the direct follow-up to the **INCONCLUSIVE** result recorded in Patch 11A (`2026-06-07_dependency_cve_audit.md §5`).

Goal: convert the Patch 11A CVE result from INCONCLUSIVE to **PASS** / **FINDINGS** / **INCONCLUSIVE-with-new-reason**.

**In scope:**

- Running `pip-audit -r requirements.txt` against the declared backend dependency file.
- Capturing the exact command set, results, and (if any) findings into a dated artefact.
- Recording any environment-level reasons the scan could not complete.

**Out of scope:**

- Updating, pinning, or installing any project dependency.
- Editing `requirements.txt`, `Dockerfile`, GitHub Actions, or Render config.
- Fixing the Patch 11A process / reproducibility findings (P-1 through P-6).
- Fixing the broken `anchor-retention-prune.yml` workflow.
- Calling production endpoints, querying / mutating the database, or changing Render settings.
- Compliance / certification claims of any kind.

**Disclaimers in plain language:**

- The absence of a tool finding is **not** evidence that no vulnerability exists. Tools can be unavailable, misconfigured, network-blocked, or missing advisories.
- This artefact does not authorise any production change.

---

## 2. Repo and environment

| Field | Value |
|---|---|
| Repo path                                | `C:\Users\rggal\ANCHOR` (founder local clone) |
| Current git branch                       | `main` |
| Current HEAD SHA                         | `531643d1c123` |
| `git status --short` at scan start       | clean (no modified files) |
| Python interpreter                       | Python `3.12.10` (Windows, Python.org build) |
| `pip` version                            | `25.0.1` |
| `pip-audit` version                      | `2.10.0` (installed during this patch — user-level only) |
| Date (UTC)                               | 2026-06-07 |
| Operator                                 | RGG |
| Tooling context                          | Local Windows / PowerShell. Render runtime uses Docker `python:3.11-slim`; the scan was **not** run inside the Render image. |

The local Python version (`3.12.10`) differs from the Render runtime (`3.11`). The scan therefore inspects the **declared dependency surface** in `requirements.txt`, not the Render-runtime resolved tree. Patch 11A §2 also recorded this caveat; it carries forward.

---

## 3. Commands run

All commands ran locally. No production endpoint was called, no database touched, no secret consumed or emitted.

```powershell
# Baseline
git status --short                              # → clean
git rev-parse --abbrev-ref HEAD                 # → main
git rev-parse --short=12 HEAD                   # → 531643d1c123
python --version                                # → Python 3.12.10
python -m pip --version                         # → pip 25.0.1
python -m pip check                             # → No broken requirements found.

# pip-audit availability probe (pre-install)
python -m pip_audit --version                   # → No module named pip_audit

# User-level install of pip-audit (allowed per Patch 11B-a brief)
python -m pip install --user pip-audit          # → Successfully installed pip-audit-2.10.0 (+ transitive)

# pip-audit availability probe (post-install)
python -m pip_audit --version                   # → pip-audit 2.10.0

# Primary scan
python -m pip_audit -r requirements.txt         # → SSL failure (see §5 for class)

# Fallback scan against OSV vulnerability source
python -m pip_audit -r requirements.txt -s osv  # → same SSL failure

# Confirm no temp JSON files were produced
ls pip-audit-output.tmp.json                    # → No such file or directory
git status --short                              # → clean wrt pip-audit; only new artefact untracked
```

**`pip-audit` was installed locally** on this patch via `python -m pip install --user pip-audit` per the brief. The install resolved 21 transitive packages into the user site-packages tree (`C:\Users\rggal\AppData\Roaming\Python\Python312\site-packages\`). The install is **outside the project virtualenv** and **does not touch `requirements.txt`**. Project dependencies are unchanged.

---

## 4. Dependency integrity check

Command:

```powershell
python -m pip check
```

Result:

```
No broken requirements found.
```

**PASS** (local interpreter, declared dependency tree as currently installed on the operator workstation). Same result as Patch 11A §4 — no version-conflict violations among installed dependencies. Does not verify the Render-runtime resolved tree.

---

## 5. pip-audit scan result

### 5.1 Primary attempt

Command:

```powershell
python -m pip_audit -r requirements.txt
```

Result: **`requests.exceptions.SSLError`** while contacting the PyPI advisory endpoint.

Failure class (exact, non-secret):

```
requests.exceptions.SSLError:
  HTTPSConnectionPool(host='pypi.org', port=443):
    Max retries exceeded with url: /pypi/pyjwt/2.8.0/json
    (Caused by SSLError(SSLCertVerificationError(1,
      '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed:
       unable to get local issuer certificate (_ssl.c:1010)')))
```

The scan aborted at the first package vulnerability lookup. The failure is *environmental* — the local SSL trust store could not validate the PyPI TLS chain. It is not a finding against any ANCHOR dependency.

### 5.2 Fallback attempt against the OSV vulnerability source

Command:

```powershell
python -m pip_audit -r requirements.txt -s osv
```

Result: **same `requests.exceptions.SSLError`** against `api.osv.dev`:

```
requests.exceptions.SSLError:
  HTTPSConnectionPool(host='api.osv.dev', port=443):
    Max retries exceeded with url: /v1/query
    (Caused by SSLError(SSLCertVerificationError(1,
      '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed:
       unable to get local issuer certificate (_ssl.c:1010)')))
```

Both supported vulnerability sources (PyPI advisories and OSV) failed for the same root cause — the workstation's Python `urllib3` / `requests` install cannot verify the TLS certificate chain. This is most plausibly a missing-or-stale CA bundle on the workstation, not a pip-audit defect or an ANCHOR dependency defect.

### 5.3 Classification

**INCONCLUSIVE — new reason.** The Patch 11A INCONCLUSIVE was *"tool unavailable"*; this patch's INCONCLUSIVE is *"tool available but network/TLS path to vulnerability sources cannot be validated from this workstation"*. The CVE half of the dependency question remains tool-unanswered.

This artefact does **not** state any of the following:

- ❌ "No known vulnerabilities were reported by pip-audit." (We don't know — the tool could not reach the advisory database.)
- ❌ "ANCHOR is secure / compliant / certified / vulnerability-free."
- ❌ "pip-audit confirmed no findings."

### 5.4 Recommended next investigation step (operator side)

In priority order:

1. **Run `pip-audit` from a network path with a valid TLS trust chain.** Most likely the cheapest fix is on a different workstation, a CI runner (GitHub Actions `ubuntu-latest`), or a clean Render shell. The Patch 11A `anchor-rate-limit-ci.yml` already runs Python 3.11 in CI — a one-line `pip-audit -r requirements.txt` step there would resolve the source-of-truth question.
2. If the scan must run on this workstation: update the local CA bundle (`python -m pip install --upgrade certifi`) or set `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` to a current trust store. This is workstation operator-config, not an ANCHOR change.
3. Re-run the same scan command and append a fresh `2026-MM-DD_pip_audit_scan.md` artefact under `docs/operations/security_audits/` recording the result.

---

## 6. Relationship to Patch 11A findings

### 6.1 What this patch changed

- **CVE-scan status only.** Patch 11A's INCONCLUSIVE (tool unavailable) is now INCONCLUSIVE (tool available but network/TLS path failed). The reason is different; the conclusion is unchanged.
- **`pip-audit` is now installed** on the operator workstation (user-level). Patch 11A's §8 recommendation to install pip-audit is therefore complete on this workstation; the tool is available for future re-runs once the TLS path is fixed.

### 6.2 What this patch did not change

The Patch 11A process / reproducibility findings remain **open**:

- **P-1.** Unpinned direct dependencies in `requirements.txt` (8 of 10 lines).
- **P-2.** No transitive lockfile.
- **P-3.** Docker base image pinned by tag (`python:3.11-slim`), not by digest.
- **P-4.** GitHub Actions pinned by mutable tag, not by commit SHA.
- **P-5.** **`anchor-retention-prune.yml`** cron calls a non-existent endpoint (`/v1/admin/retention/prune?days=90` vs the actual `/v1/admin/intake/prune` with JSON body). Re-stated as a separate Patch 11B-b follow-up; **not in scope here**.
- **P-6.** `requirements.txt` includes `alembic` despite raw `.sql` migration usage — dead weight.

Three **unknown / inconclusive** areas (Patch 11A §7) carry forward:

- **U-1.** CVE posture of the resolved local dependency tree — *still unscanned* (this patch's TLS failure).
- **U-2.** CVE posture of the Render-runtime resolved tree — still unscanned.
- **U-3.** Transitive dependency set — still not locked / not enumerated.

This patch is a **tooling-availability follow-up**, not a remediation. It does not resolve P-1 through P-6, and it does not convert any U-row into a positive answer.

---

## 7. Risk summary

| Class | Items |
|---|---|
| **Critical findings (tool-backed)** | None reported — but the tool could not reach the advisory database. **No statement of vulnerability-free posture follows.** |
| **High findings (tool-backed)** | None reported (same caveat). |
| **Medium findings (tool-backed)** | None reported (same caveat). |
| **Low findings (tool-backed)** | None reported (same caveat). |
| **Process / reproducibility findings (open from Patch 11A)** | **P-1** unpinned direct deps; **P-2** no transitive lockfile; **P-3** Docker tag-only pin; **P-4** Actions tag-only pin; **P-5** broken `anchor-retention-prune.yml` cron; **P-6** dead-weight `alembic`. |
| **Unknown / inconclusive areas** | **U-1** local CVE scan — *still unscanned in this patch* (TLS failure); **U-2** Render-runtime CVE scan — still unscanned; **U-3** transitive dep set — still not locked. |

### 7.1 Honest positive statement

The tool-backed CVE scan **could not complete** on this workstation in this patch's run window. **No claim of vulnerability-free posture is recorded.** The CVE half of the dependency question is still open.

---

## 8. Recommended follow-up

Per Patch 11A §8, follow-up was split into **11B-a** (make a tool-backed CVE scan possible) and **11B-b** (tighten reproducibility). This patch *partially* delivers 11B-a — it installs the tool — but does not deliver a working scan.

### 8.1 Re-scoped 11B follow-ups after Patch 11B-a's result

- **11B-a (continued).** Re-run `pip-audit -r requirements.txt` from a network path with a working TLS trust chain. Recommended location: add a single `pip-audit` step to `.github/workflows/anchor-rate-limit-ci.yml` (or a new `dependency-audit.yml`), running on every push to `main` and on a weekly schedule. The CI runner has a current TLS trust store. The result then converts the INCONCLUSIVE into a real PASS / FINDINGS.
- **11B-b.** Carry forward Patch 11A's reproducibility track unchanged: pin currently unpinned direct dependencies; add a transitive lockfile; pin Docker base by digest; pin Actions by SHA; **fix or delete `anchor-retention-prune.yml`** (P-5); drop dead-weight `alembic`.
- **11B-c (optional).** Split test deps — move `httpx` into a new `requirements-dev.txt`.

None of these is implemented in Patch 11B-a.

### 8.2 If the next scan run produces FINDINGS

- Treat per `incident_response.md §3` severity ladder. Patches must be one-package-at-a-time with targeted tests, not a `pip install --upgrade -r requirements.txt`.
- Document each upgrade in a new dated artefact under `docs/operations/security_audits/`.
- Re-run the scan after each upgrade; do not chain upgrades into one patch.

---

## 9. Stop-condition impact

**INCONCLUSIVE.** This patch installs the audit tool locally and confirms the workstation cannot currently reach PyPI advisories or OSV due to a TLS trust failure. The tool-backed CVE evidence remains unproduced for this dependency snapshot.

| Operational item                              | Status after Patch 11B-a                                                                                                                                                       |
|---|---|
| Env docs                                      | ✅ Patch 7                                                                                                                                                                  |
| Backup / restore drill                        | ✅ Patch 8 / 8C — 2026-06-07 PASS                                                                                                                                            |
| Intake retention dry-run                      | ✅ Patch 9 / 9B — 2026-06-07 PASS, all counts 0                                                                                                                              |
| Incident-response runbook                     | ✅ Patch 10                                                                                                                                                                  |
| First tabletop drill                          | ✅ Patch 10B — 2026-06-07 PASS                                                                                                                                                |
| Dependency / CVE audit (snapshot)             | ⚠ Partially closed — Patch 11A captured the dependency surface and process findings. **CVE scan still INCONCLUSIVE.** Tool now installed; next run needs working TLS path. |
| Dependency pinning / reproducibility          | ⏳ Open — Patch 11B-b candidate.                                                                                                                                              |
| Legal / commercial pack per Addendum v1.3     | ⏳ Open — out of code scope; founder track.                                                                                                                                   |

This patch does **not** authorise paid pilot / real clinic data. The CVE half of the dependency question is unanswered.

---

## 10. Doctrine restatement

This artefact preserves the ANCHOR doctrine: governance-first, metadata-only by default, tenant safety, RLS / FORCE RLS, human review, receipt-backed, **aligned, not compliant**. It records:

- No secrets, no clinical content, no PII, no full bearer tokens, no `DATABASE_URL`, no Render env values.
- No claim of "no risk", "fully compliant", "certified", "regulator-approved", "guaranteed safe", or "no vulnerabilities".
- No project dependency change, no migration change, no code change, no production change.

Audit follow-ups land as separate patches with their own evidence artefacts in this directory.
