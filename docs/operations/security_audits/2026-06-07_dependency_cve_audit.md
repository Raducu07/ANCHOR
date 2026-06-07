# ANCHOR Dependency / CVE Audit — 2026-06-07

> **Operational security evidence only.** Not a compliance certification. Not a regulator endorsement. Not a guarantee that no vulnerabilities exist in the ANCHOR backend or its dependency tree. ANCHOR is aligned to RCVS principles and EU AI Act articles where it can be; it is not compliant with them.
>
> No production endpoint was called, no database was queried or mutated, no Render setting was changed, and no dependency was updated during this audit. Real secrets — admin tokens, API keys, `DATABASE_URL`, JWT secret, hash salt, admin pepper, GitHub secrets values — never appear in this artefact.

---

## 1. Purpose and scope

This audit captures a dated snapshot of the ANCHOR backend's **dependency and runtime surfaces** so an operator can track which package set was deployed at a given point in time, what posture the pinning/reproducibility regime was in, and whether any tool-backed vulnerability scan was possible at the time.

**In scope:**

- Direct dependency declarations (`requirements.txt`).
- Runtime container surface (`Dockerfile`).
- CI / scheduled-job surface (`.github/workflows/*.yml`).
- Repo-level deploy config (`render.yaml`, if present).
- Local Python interpreter + pip integrity check.
- Local CVE scan if a scanner is available.

**Out of scope:**

- Anything that would update or modify a dependency.
- Anything that would call production endpoints or query/mutate the database.
- Anything that would alter Render settings, secrets, env values, or scheduled jobs.
- Frontend dependency review (ANCHOR backend repo only).
- Live-generation provider posture (covered by `env.md §9`).

**Disclaimers in plain language:**

- The absence of a tool finding is **not** evidence that no vulnerability exists. Tools can be unavailable, out of date, missing advisories, or unable to reach a sufficient subset of the dependency tree.
- The presence of a finding is **not** an automatic emergency. Findings must be triaged per `incident_response.md §3` and `§8` before remediation.
- This artefact does not authorise any production change.

---

## 2. Repo and environment

| Field | Value |
|---|---|
| Repo path                                | `C:\Users\rggal\ANCHOR` (founder local clone) |
| Current git branch                       | `main` |
| Current HEAD SHA                         | `bb92bd7a161f` |
| `git status --short` at audit start      | clean (no modified files) |
| Python interpreter                       | Python `3.12.10` (Windows, Python.org build) |
| `pip` version                            | `25.0.1` |
| Date (UTC)                               | 2026-06-07 |
| Operator                                 | RGG |
| Tooling context                          | Local Windows / PowerShell. Render runtime uses Docker `python:3.11-slim` (see §3). |

The local Python version (`3.12.10`) differs from the Render runtime (`3.11`). The audit therefore inspects the **declared dependency surface** in the repo, not the resolved Render runtime tree. A future Patch 11B could replicate this audit inside the Render image (or against a `pip install -r requirements.txt` in a clean `python:3.11-slim` container) to capture the resolved tree as actually deployed.

---

## 3. Dependency surfaces inspected

| File / path | Present? | Purpose | Notes |
|---|---|---|---|
| `requirements.txt`                                   | yes | Direct backend dependencies (Python). | Present at repo root. Mixed-pin posture (see §6). |
| `requirements-dev.txt`                               | **no** | Would hold test/dev tooling separately. | Absent. Test dependencies (`httpx`) are inlined in `requirements.txt`. |
| `pyproject.toml`                                     | **no** | Modern build / metadata config. | Absent. No `pip-tools` / `uv` / `poetry` discipline in repo. |
| `poetry.lock` / `Pipfile.lock` / `uv.lock` / `requirements.lock` | **no** | Would lock transitive dependencies. | Absent. No transitive lockfile in repo. |
| `Pipfile`                                            | **no** | Pipenv config. | Absent. |
| `constraints*.txt`                                   | **no** | Would constrain transitive resolution. | Absent. |
| `Dockerfile`                                         | yes | Runtime container. | `FROM python:3.11-slim` (tag, not digest). `COPY requirements.txt . && RUN pip install --no-cache-dir -r requirements.txt`. No `--require-hashes`. |
| `.github/workflows/anchor-rate-limit-ci.yml`         | yes | CI: rate-limit tests on push/PR/dispatch. | Pinned to mutable tags (`actions/checkout@v4`, `actions/setup-python@v5`). |
| `.github/workflows/anchor-retention-prune.yml`       | yes | **Scheduled cron** at 03:15 UTC daily. | See §3.1 below — calls a **non-existent endpoint**. Process finding. |
| `.github/workflows/isolation-smoke.yml`              | yes | Tenant-isolation smoke on push/PR/dispatch. | Pinned to mutable tags. Uses `secrets.ANCHOR_BASE`, `secrets.ANCHOR_ADMIN_TOKEN`, `secrets.ANCHOR_TEST_PASSWORD`. |
| `render.yaml` / `.render.yaml` / `render.json`       | **no** | Would capture Render service-as-code. | Absent. Render service config lives only in the dashboard. |

### 3.1 Note on `anchor-retention-prune.yml`

The cron workflow attempts:

```text
curl -sS -X POST "${ANCHOR_BASE}/v1/admin/retention/prune?days=90" \
     -H "Authorization: Bearer ${ANCHOR_ADMIN_TOKEN}" \
     -H "Content-Type: application/json" \
     --fail
```

The actual prune endpoint in the codebase is `POST /v1/admin/intake/prune` (Patch 3, `app/admin_intake.py`), with a JSON body shape of `{kind, older_than_days, dry_run, confirm?}`. The workflow path **does not exist on the API**, and the call carries no JSON body matching the documented shape. Likely outcome on every cron firing: `404 Not Found` (no `--fail` propagation needed; the call simply fails to do anything useful).

This is **not** a CVE finding. It is a **process / reproducibility finding** — a scheduled GitHub Action is firing daily against the production base using a real admin token from `secrets`, and is silently broken. Recorded in §6 / §7 / §8 for follow-up. **This patch does not edit the workflow.**

---

## 4. Local dependency integrity check

Command:

```powershell
python -m pip check
```

Result:

```
No broken requirements found.
```

**PASS** (local interpreter, declared dependency tree as currently installed on the operator workstation). The check confirms there are no version-conflict violations among installed dependencies at the time of the audit. It does not verify the Render-runtime resolved tree.

---

## 5. CVE audit command and result

Tool availability probe:

```powershell
python -m pip_audit --version
# → No module named pip_audit

python -m pip show pip-audit
# → WARNING: Package(s) not found: pip-audit
```

**`pip-audit` is not installed in the local Python 3.12 environment** at the time of this audit.

Per the Patch 11A brief, the tool was **not auto-installed**. The audit therefore could not enumerate CVEs against the declared `requirements.txt` from this workstation.

### 5.1 Recommended next-time command (operator approves install)

```powershell
python -m pip install --user pip-audit
python -m pip_audit -r requirements.txt
```

For a Render-runtime parity check, the recommended (more accurate) form is to run pip-audit inside a clean `python:3.11-slim` container after `pip install -r requirements.txt`, so the resolved-and-locked transitive tree matches what actually ships.

### 5.2 CVE audit result

**INCONCLUSIVE.** No tool-backed vulnerability scan was completed during this audit. There are no findings to report — and **there is no positive statement of vulnerability-free posture either**. The dependency surface remains tool-unscanned at the audit timestamp.

---

## 6. Pinning / reproducibility posture

### 6.1 Direct dependencies (`requirements.txt`)

Read verbatim, with pin status annotated:

```text
fastapi                  ← UNPINNED
uvicorn                  ← UNPINNED
psycopg[binary]          ← UNPINNED
sqlalchemy[psycopg]      ← UNPINNED
alembic                  ← UNPINNED (note: ANCHOR runtime uses raw .sql migrations,
                                       not Alembic — this line is dead weight)
PyJWT==2.8.0             ← PINNED
pydantic[email]==2.6.4   ← PINNED
argon2-cffi              ← UNPINNED
httpx                    ← UNPINNED (test dependency inlined)
anthropic                ← UNPINNED
```

**Pin posture:** **partial.** Two of ten lines are pinned (`PyJWT`, `pydantic[email]`). Eight are unpinned. Render rebuilds therefore resolve those lines against whatever PyPI offers at build time — the deployed package set drifts silently across deploys.

### 6.2 Transitive dependencies

**Not locked.** No `*.lock` file. No `--require-hashes`. No `constraints.txt`. The resolved transitive tree is reconstructed at every `pip install`.

### 6.3 Docker base image

`Dockerfile:1` → `FROM python:3.11-slim`. **Pinned by tag (`3.11-slim`), not by digest.** The image content can change without the tag changing. To pin by digest, the operator would substitute `python:3.11-slim@sha256:<digest>`. Not changed in this patch.

### 6.4 GitHub Actions

Three workflows; all pin Actions by mutable tag:

- `actions/checkout@v4`
- `actions/setup-python@v5`

**Pin posture: partial / tag-only.** The semver tags can be re-pointed to a new SHA by the action's maintainer. For supply-chain-aware deployments, the recommended posture is to pin Actions to immutable commit SHAs (`actions/checkout@<full-sha>`). Not changed in this patch.

### 6.5 Broad reproducibility risks (process)

- **Drifting deploys.** Unpinned direct dependencies + no transitive lock = same SHA can build a meaningfully different package set on Monday vs Friday.
- **Tag-only Docker image.** The `python:3.11-slim` tag is rebuilt by upstream; today's image is not the same bytes as last week's.
- **Tag-only Actions.** Same shape as Docker — a v4/v5 action SHA can move under the operator's feet.
- **`anchor-retention-prune.yml` is silently broken** (per §3.1). The scheduled call hits a non-existent endpoint. Not a CVE; is a process reliability bug. The operator should not assume any retention pruning is happening automatically; per `intake_retention.md`, retention pruning is operator-driven via the correct endpoint.
- **No `requirements-dev.txt`.** Test dependencies (`httpx`) inlined in the production requirements file. Not a security finding by itself but it broadens the production install surface for purely-test packages.
- **No `pyproject.toml` / lockfile discipline.** Future work could land `pip-tools` / `uv` / `poetry` to give the deploy a reproducible resolved tree.

---

## 7. Risk summary

| Class | Items |
|---|---|
| **Critical findings (tool-backed)** | None. No tool finding to report — `pip-audit` was not installed at the time of audit. |
| **High findings (tool-backed)**     | None reported by available tooling. |
| **Medium findings (tool-backed)**   | None reported by available tooling. |
| **Low findings (tool-backed)**      | None reported by available tooling. |
| **Process / reproducibility findings** | **P-1.** Unpinned direct dependencies in `requirements.txt` (8 of 10 lines). Render deploys drift silently. **P-2.** No transitive lockfile. **P-3.** Docker base image pinned by tag, not digest. **P-4.** GitHub Actions pinned by mutable tag, not SHA. **P-5.** `anchor-retention-prune.yml` cron calls a non-existent endpoint (`/v1/admin/retention/prune?days=90`) using a real admin token from `secrets`. **P-6.** `requirements.txt` includes `alembic` even though ANCHOR runs raw `.sql` migrations (dead weight). |
| **Unknown / inconclusive areas**   | **U-1.** CVE posture of the resolved dependency tree (no scan run). **U-2.** CVE posture of the Render-runtime resolved tree (the Render image was not introspected). **U-3.** Transitive dependency set (not locked, not enumerated). |

### 7.1 Honest positive statement

**No known vulnerabilities were reported by the tool run in this audit.** This statement reflects that no tool finding was produced; it does not reflect that no vulnerability exists. The audit was inconclusive on the CVE question.

This audit does **not** state any of the following:

- ❌ "ANCHOR is secure."
- ❌ "ANCHOR is compliant."
- ❌ "No vulnerabilities exist."
- ❌ "ANCHOR has passed a CVE audit."
- ❌ "ANCHOR is certified / approved / endorsed."

---

## 8. Recommended follow-up patch

**Patch 11B candidate** — split into two halves so each can land independently:

### 11B-a — Make a tool-backed CVE scan possible

1. **Install `pip-audit`** on the operator workstation and document the install line in `env.md` or `docs/operations/security_audits/README.md`. *(One-time op step; not a code change.)*
2. **Run `pip-audit -r requirements.txt`** and append the result table to a fresh dated audit artefact under `docs/operations/security_audits/`. This converts §5's INCONCLUSIVE into a PASS / FINDINGS / INCONCLUSIVE-with-reason.
3. Optionally, run `pip-audit` inside a clean `python:3.11-slim` container so the scan covers the Render-runtime resolved tree, not just the workstation's resolved tree.

### 11B-b — Tighten reproducibility

1. **Pin currently unpinned direct dependencies** in `requirements.txt` to the versions Render last installed (read from a `pip freeze` taken inside the Render shell once, then captured into the repo).
2. **Add a transitive lockfile.** Either move to `pip-tools` (`requirements.in` + `requirements.txt` generated) or `uv` / `poetry`. Whichever path is chosen, ship the lockfile and a CI check that `pip install` against the lockfile succeeds on `python:3.11-slim`.
3. **Pin the Docker base image by digest** (`python:3.11-slim@sha256:<digest>`). One-line edit to `Dockerfile`.
4. **Pin GitHub Actions to commit SHAs** for the three workflows. Use Dependabot's "Updates for GitHub Actions" auto-PRs to keep the pins fresh.
5. **Drop `alembic`** from `requirements.txt` (dead weight; runtime uses raw `.sql` migrations).
6. **Fix `anchor-retention-prune.yml` or disable it.** Either (a) point it at the correct endpoint (`POST /v1/admin/intake/prune`) with the documented body shape (`{kind, older_than_days, dry_run}`), or (b) delete the workflow entirely until an automated retention prune is genuinely wanted. Per `intake_retention.md`, the current operational posture is operator-driven prune; the cron should either match that posture or not exist.
7. **Add `docs/operations/security_audits/README.md`** once a second audit artefact ships, to orient future operators on the folder shape.

### 11B-c (optional, smaller still) — Split test deps

Move `httpx` (test dep) into a new `requirements-dev.txt`. Confirms the test surface is not bundled into the production install. Pairs naturally with 11B-b#5.

None of 11B is implemented in 11A.

---

## 9. Commands run

All commands run during this audit. **No secret values appear in any output below; the commands themselves do not consume or emit secrets.**

```powershell
git rev-parse --abbrev-ref HEAD                # → main
git rev-parse --short=12 HEAD                  # → bb92bd7a161f
git status --short                             # → (empty — clean)
python --version                               # → Python 3.12.10
python -m pip --version                        # → pip 25.0.1
python -m pip check                            # → No broken requirements found.
python -m pip_audit --version                  # → No module named pip_audit
python -m pip show pip-audit                   # → Package(s) not found: pip-audit
```

Repo inventory (read-only file listing):

```powershell
Get-ChildItem -Force -Path .                                # repo root
Get-ChildItem -Path .github\workflows                       # → 3 workflows
ls requirements*.txt pyproject.toml poetry.lock Pipfile* render.yaml constraints*.txt   # → only requirements.txt present
```

Read-only inspection of:

- `requirements.txt`
- `Dockerfile`
- `.github/workflows/anchor-rate-limit-ci.yml`
- `.github/workflows/anchor-retention-prune.yml`
- `.github/workflows/isolation-smoke.yml`

Secret-shape scan on the new artefact path (run after writing this file):

```powershell
Select-String -Path docs/operations/security_audits/* -Pattern "AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|xoxb-|ghp_[a-zA-Z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|postgresql://[^<]*:[^<]*@" -AllMatches
# expected: no matches
```

---

## 10. Stop-condition impact

**Result: INCONCLUSIVE.** This audit *partially* closes the dependency / CVE scan operational item. The repo's dependency posture is now captured in dated written evidence with explicit process-finding callouts and a recommended remediation patch shape. The CVE half of the question is **not yet answered** — `pip-audit` was unavailable at the time of audit, and per the brief was not auto-installed.

| Operational item                              | Status after 2A-D.2 Patch 11A                                                                                                                                              |
|---|---|
| Env docs                                      | ✅ Patch 7                                                                                                                                                                  |
| Backup / restore drill                        | ✅ Patch 8 / 8C — 2026-06-07 PASS                                                                                                                                            |
| Intake retention dry-run                      | ✅ Patch 9 / 9B — 2026-06-07 PASS, all counts 0                                                                                                                              |
| Incident-response runbook                     | ✅ Patch 10                                                                                                                                                                  |
| First tabletop drill                          | ✅ Patch 10B — 2026-06-07 PASS                                                                                                                                                |
| Dependency / CVE audit (snapshot)             | ⚠ Partially closed — this artefact (Patch 11A). Process findings recorded. CVE scan **INCONCLUSIVE**. Tool-backed CVE evidence pending Patch 11B-a.                            |
| Dependency pinning / reproducibility          | ⏳ Open — Patch 11B-b candidate.                                                                                                                                              |
| Legal / commercial pack per Addendum v1.3     | ⏳ Open — out of code scope; founder track.                                                                                                                                   |

This audit does **not** authorise paid pilot / real clinic data. The CVE half of the question remains unanswered until Patch 11B-a lands a tool-backed scan.

---

## 11. Doctrine restatement

This audit and any future audit artefact in `docs/operations/security_audits/`:

- Preserves the ANCHOR doctrine: governance-first, metadata-only by default, tenant safety, RLS / FORCE RLS, human review, receipt-backed, **aligned, not compliant**.
- Is operational evidence only — not legal advice, not compliance certification, not regulator endorsement, not guaranteed protection.
- Records no secrets, no clinical content, no PII, no full bearer tokens, no `DATABASE_URL`, no Render env values.
- Records no claim of "no risk", "fully compliant", "certified", "regulator-approved", or "guaranteed safe".

Audit follow-ups land as separate patches with their own evidence artefacts in this directory.
