# ANCHOR Dependency Reproducibility Inventory — 2026-06-07

> **Read-only inventory.** This artefact inventories dependency reproducibility after the clean CI `pip-audit` result captured in [`2026-06-07_post_starlette_ci_audit.md`](./2026-06-07_post_starlette_ci_audit.md). **No remediation in this patch.** No dependency was changed. No Dockerfile changed. No workflow changed. No production endpoint called. No database queried or mutated. No Render setting changed. No deploy issued.
>
> Operational evidence only. Not compliance certification. Not a regulator endorsement. Not a guarantee that no other vulnerabilities exist. Not a claim that ANCHOR is secure / compliant / certified / vulnerability-free.

---

## 1. Purpose and scope

Inventory the **dependency reproducibility surface** so the next operational patches (the **Patch 11B-b series**) can each land narrow, evidence-backed changes:

- direct-dependency pin posture in `requirements.txt`
- transitive resolved dependency surface
- Docker base-image reproducibility
- GitHub Actions reproducibility
- the `anchor-retention-prune.yml` workflow's validity against the current API
- whether `alembic` is dead weight
- recommended lockfile strategy
- recommended patch sequence

**Out of scope:**

- Any dependency change, pin, lockfile addition, or removal.
- Dockerfile / GitHub Actions / application code / migration / test / frontend change.
- Production endpoint call, database query/mutation, Render setting change, deploy.
- Compliance / certification claims.

---

## 2. Current audit state

| Item | State |
|---|---|
| CI `pip-audit` against `requirements.txt` | **PASS** for the scanned dependency set (Patch 11D-c, run `#3` against commit `bfec5a0`) |
| PyJWT findings | ✅ Cleared (Patch 11C / 11C-a) |
| Starlette finding | ✅ Cleared (Patch 11D-b / 11D-c) |
| Process / reproducibility findings (Patch 11A P-1 … P-6) | **Open** — this artefact restates them and adds the recommended remediation sequence |
| Render deploy of the remediation stack | **Not yet executed.** Operator decision point. |

This inventory does **not** state that ANCHOR is secure, compliant, certified, or vulnerability-free. It states that the CI `pip-audit` scan was clean for the dependency set scanned, and that reproducibility work is still open.

---

## 3. `requirements.txt` inventory

`requirements.txt` at audited commit `5308f57`:

```text
fastapi==0.133.1
uvicorn
psycopg[binary]
sqlalchemy[psycopg]
alembic
PyJWT==2.13.0

pydantic[email]==2.7.4
argon2-cffi

# Test dependency: required by fastapi.testclient (Starlette TestClient).
httpx

# Governed Vet Assistant — model provider (PR 2B). API key supplied via
# ANTHROPIC_API_KEY at runtime; missing key returns a safe 503.
anthropic
```

### 3.1 Line-by-line table

| # | Declaration              | Pinned? | Installed locally | Likely purpose                                                                          | Runtime / dev / unknown | Risk of pinning / removing | Recommended future action |
|---|--------------------------|---------|-------------------|-----------------------------------------------------------------------------------------|-------------------------|----------------------------|----------------------------|
| 1 | `fastapi==0.133.1`       | **yes** | `0.133.1`         | ASGI app framework — the whole `app/main.py` is FastAPI                                  | runtime                 | low (already pinned)        | keep pin; bump only via security or compat-driven patches |
| 2 | `uvicorn`                | no      | `0.47.0`          | ASGI server (`CMD … uvicorn app.main:app …` in Dockerfile)                              | runtime                 | low — `uvicorn` 0.x is API-stable | **pin to `0.47.0`** in 11B-b2 |
| 3 | `psycopg[binary]`        | no      | `psycopg==3.3.4`  | Postgres driver (psycopg v3, used by `app/db.py`)                                       | runtime                 | low — `psycopg` 3.x stable  | **pin to `3.3.4`** in 11B-b2; keep `[binary]` extra |
| 4 | `sqlalchemy[psycopg]`    | no      | `SQLAlchemy==2.0.49` | ORM + connection pool layer (used throughout `app/db.py` and every router with `db: Session = Depends(get_db)`) | runtime                 | low — SQLA 2.x stable       | **pin to `2.0.49`** in 11B-b2; keep `[psycopg]` extra |
| 5 | `alembic`                | no      | `1.18.4`          | **No imports anywhere in the codebase.** `app/migrate.py` runs raw `.sql` files; migration files under `migrations/` are bare SQL. See §8. | dev / unknown           | low (dead weight) — remove | **drop from `requirements.txt`** in 11B-b6 once §8 confirmed |
| 6 | `PyJWT==2.13.0`          | **yes** | `2.13.0`          | JWT encode/decode in `app/auth_and_rls.py`                                              | runtime                 | low (already pinned)        | keep pin (Patch 11C remediation) |
| 7 | `pydantic[email]==2.7.4` | **yes** | `pydantic==2.7.4` (`pydantic-core==2.18.4`) | Schema validation; every router model                                                   | runtime                 | low (already pinned)        | keep pin (Patch 11D-b remediation) |
| 8 | `argon2-cffi`            | no      | `25.1.0`          | Password hashing in `app/auth_and_rls.py` (`_hash_password` / `_verify_password`)        | runtime                 | medium — needs spot-check of `argon2.PasswordHasher` API stability between minor versions | **pin to `25.1.0`** in 11B-b2 |
| 9 | `httpx`                  | no      | `0.28.1`          | Per the inline comment: "Test dependency: required by `fastapi.testclient` (Starlette TestClient)". Used by `tests/*` via TestClient. **Now under a `StarletteDeprecationWarning` for `httpx<2`.** | dev (test infra)        | low — `httpx` 0.28.x stable | **move to `requirements-dev.txt`** in 11B-b2; consider `httpx>=2` upgrade for the deprecation in a follow-up hygiene patch |
| 10 | `anthropic`             | no      | `0.104.1`         | Anthropic Python SDK used by `app/assistant_anthropic_client.py`. **Live generation is production-off**; key absence returns safe 503. | runtime                 | medium — Anthropic SDK has had API churn historically | **pin to `0.104.1`** in 11B-b2 |

### 3.2 Pin posture summary

- **Pinned:** 3 of 10 (`fastapi`, `PyJWT`, `pydantic[email]`).
- **Unpinned:** 7 of 10. **Render's resolver picks whichever version PyPI offers at build time**, so today's deploy may install a different transitive set than CI's audit ran against.
- **No transitive lockfile** anywhere in repo (`*.lock`, `--require-hashes`, `constraints.txt` all absent).
- **No `requirements-dev.txt`.** Test-only dep (`httpx`) inlined in the production requirements file.

---

## 4. Transitive resolution inventory

Resolved local set under `fastapi==0.133.1` + `pydantic[email]==2.7.4` + `PyJWT==2.13.0` + the unpinned direct deps (mirrors what Render's fresh-install picks, modulo PyPI freshness drift):

| Package | Resolved version | Source | Direct in `requirements.txt`? |
|---|---|---|---|
| `fastapi` | `0.133.1` | pinned | yes |
| `starlette` | **`1.2.1`** | transitive of FastAPI (`starlette>=0.40.0`) | no — and **deliberately not pinned directly** per Patch 11D-b |
| `pydantic` | `2.7.4` | pinned | yes |
| `pydantic-core` | `2.18.4` | transitive of pydantic (`pydantic-core==2.18.4`) | no |
| `PyJWT` | `2.13.0` | pinned | yes |
| `uvicorn` | `0.47.0` | unpinned direct | yes |
| `psycopg` | `3.3.4` | unpinned direct (`psycopg[binary]`) | yes |
| `SQLAlchemy` | `2.0.49` | unpinned direct (`sqlalchemy[psycopg]`) | yes |
| `alembic` | `1.18.4` | unpinned direct (dead weight — §8) | yes |
| `argon2-cffi` | `25.1.0` | unpinned direct | yes |
| `httpx` | `0.28.1` | unpinned direct (test) | yes |
| `anthropic` | `0.104.1` | unpinned direct (live path production-off) | yes |
| `anyio` | `4.13.0` | transitive of Starlette (`anyio<5,>=3.6.2`) | no |

### 4.1 Key transitive constraint chains

- `fastapi==0.133.1` → `starlette>=0.40.0` (no upper cap) → `anyio<5,>=3.6.2`.
- `fastapi==0.133.1` → `pydantic>=2.7.0` (the constraint that forced the compound bump in Patch 11D-b).
- `pydantic==2.7.4` → `pydantic-core==2.18.4` (exact pin from upstream).
- Starlette `1.2.1` → `anyio<5,>=3.6.2` → currently `4.13.0` (transitive, unpinned anywhere).

### 4.2 What is *not* visible from this inventory

This inventory is captured against a **local Python 3.12.10 interpreter on Windows**, not the production `python:3.11-slim` runtime. The Render image's transitive set may differ at the 4th decimal place (or with a fresh PyPI release between this artefact and the next deploy). The audit gap is exactly the reason the Patch 11B-b lockfile recommendation exists.

---

## 5. Docker reproducibility

`Dockerfile` at audited commit (11 lines):

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

CMD sh -c "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"
```

### 5.1 Findings

| Property | State | Risk | Recommendation |
|---|---|---|---|
| Base image | `python:3.11-slim` | **tag, not digest** — upstream can re-tag silently | Patch 11B-b3: pin by digest (`python:3.11-slim@sha256:<digest>`) |
| Python major.minor | `3.11` (matches CI runner) | low | keep |
| `pip` version | **not pinned** | medium — `pip` resolver behaviour changes between major versions | consider pinning via `python -m pip install --upgrade "pip==<x>"` after the lockfile lands |
| Install command | `pip install --no-cache-dir -r requirements.txt` | no lockfile, no `--require-hashes`, no `--no-deps` | Patch 11B-b2 lockfile (with `--require-hashes` if `pip-tools`) |
| Build uses a lockfile? | **No** | high — resolver re-resolves transitive set on every build | Patch 11B-b2 |
| Deploy resolves transitive deps at build time? | **Yes** | high (same root cause) | Patch 11B-b2 |
| `COPY . .` | broad copy — picks up everything except `.dockerignore`d items | low — there is no `.dockerignore` in repo; `tests/`, `docs/`, `.git/`, etc. get into the image | optional follow-up: add `.dockerignore` to slim the image (out of scope here) |
| `CMD` shell form | uses `sh -c` to expand `${PORT}` (Render provides `PORT` env var) | low | keep |

### 5.2 Doctrine note

The image is currently **byte-irreproducible across deploys** — the same SHA can produce a meaningfully different runtime depending on PyPI freshness and Docker Hub re-tag history. Patches 11B-b2 (lockfile) and 11B-b3 (base-image digest pin) close that gap together.

---

## 6. GitHub Actions reproducibility

Four workflow files under `.github/workflows/`:

### 6.1 Per-workflow table

| File | Workflow name | Triggers | `actions/*` refs | Pinned by SHA? | Secrets used? | Calls production? | Issue / risk | Recommendation |
|---|---|---|---|---|---|---|---|---|
| `anchor-rate-limit-ci.yml` | `Anchor Rate Limit CI` | `push: branches:[main]`, `pull_request`, `workflow_dispatch` | `actions/checkout@v4`, `actions/setup-python@v5` | **No (tag)** | None | No (runs deterministic tests against `pytest -q tests/test_rate_limit.py` with hardcoded `RATE_LIMIT_SECRET: "ci-test-secret"`) | mutable-tag pin only | Patch 11B-b4: pin `@<sha>` |
| `anchor-retention-prune.yml` | `Anchor Retention Prune` | `schedule: cron: "15 3 * * *"` (daily 03:15 UTC), `workflow_dispatch` | None (uses raw `curl`) | n/a | `${{ secrets.ANCHOR_BASE }}`, `${{ secrets.ANCHOR_ADMIN_TOKEN }}` | **YES** — `curl -sS -X POST "${ANCHOR_BASE}/v1/admin/retention/prune?days=90"` with `Authorization: Bearer ${ANCHOR_ADMIN_TOKEN}` and `--fail` | **BROKEN.** Endpoint does not exist (see §7). Fires daily with a real admin token. | Patch 11B-b5: fix or delete |
| `dependency-audit.yml` | `Anchor Dependency Audit (pip-audit)` | `workflow_dispatch` only (Patch 11D-c restored this) | `actions/checkout@v4`, `actions/setup-python@v5` | **No (tag)** | None | No (talks only to PyPI / OSV) | mutable-tag pin only | Patch 11B-b4: pin `@<sha>` |
| `isolation-smoke.yml` | `Tenant Isolation Smoke Test` | `push: branches:[main]`, `pull_request: branches:[main]`, `workflow_dispatch` | `actions/checkout@v4` | **No (tag)** | `${{ secrets.ANCHOR_BASE }}`, `${{ secrets.ANCHOR_ADMIN_TOKEN }}`, `${{ secrets.ANCHOR_TEST_PASSWORD }}` | **YES** — runs `scripts\anchor-smoke-isolation.ps1` against `$Env:ANCHOR_BASE` (prod) on every push to main and every PR against main | calls prod on every push/PR; this is the source of the `#191` rate-limit failure | Patch 11B-b4: pin `@<sha>`. Separately: rate-limit interaction with prod is a known open item. |

### 6.2 Summary

- **None of the four workflows is pinned by commit SHA.** All four use semver tags (`@v4`, `@v5`) that can be re-pointed by the action maintainer.
- **Two workflows call production:** `anchor-retention-prune.yml` (broken — §7) and `isolation-smoke.yml` (working but tickles rate limits — separate follow-up).
- The two non-prod workflows (`anchor-rate-limit-ci.yml`, `dependency-audit.yml`) are tag-pinned only; the security benefit of SHA-pinning here is supply-chain-defence rather than correctness.

---

## 7. Retention workflow assessment

### 7.1 What the workflow does

```yaml
# .github/workflows/anchor-retention-prune.yml
on:
  schedule:
    - cron: "15 3 * * *"   # daily at 03:15 UTC
  workflow_dispatch: {}

jobs:
  prune:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - name: Call retention prune endpoint
        env:
          ANCHOR_BASE: ${{ secrets.ANCHOR_BASE }}
          ANCHOR_ADMIN_TOKEN: ${{ secrets.ANCHOR_ADMIN_TOKEN }}
        run: |
          set -e
          echo "Calling retention prune..."
          curl -sS -X POST "${ANCHOR_BASE}/v1/admin/retention/prune?days=90" \
            -H "Authorization: Bearer ${ANCHOR_ADMIN_TOKEN}" \
            -H "Content-Type: application/json" \
            --fail
          echo "Retention prune completed"
```

### 7.2 Does the targeted endpoint exist?

**No.** `grep -rEn "intake/prune|retention/prune|/v1/admin/retention" app/ docs/operations/` returns:

- The actual prune endpoint in the codebase is **`POST /v1/admin/intake/prune`** (`app/admin_intake.py`, Patch 3), with a JSON body of `{"kind","older_than_days","dry_run","confirm?"}`.
- `POST /v1/admin/retention/prune?days=90` is **not defined anywhere** in `app/`. The workflow's URL is wrong.

### 7.3 Operational implications

- The workflow fires **every day at 03:15 UTC** with a real `secrets.ANCHOR_ADMIN_TOKEN`.
- Likely outcome on every cron firing: **`404 Not Found`** (the path doesn't exist), which propagates through `curl --fail` as a non-zero exit and the workflow shows red in the Actions tab.
- **No production data is mutated** — the endpoint simply does not exist; no `DELETE` is issued.
- **The admin token is exposed in CI logs only as a header value masked by GitHub Actions' default secret masking.** Risk of leak is low but non-zero.
- **The workflow contradicts `intake_retention.md`**, which records that retention pruning is operator-driven (dry-run + confirm + 50 000-row cap), not scheduled.

### 7.4 Recommendation

- **Patch 11B-b5: fix OR delete.** Two paths:
  - **Fix** — point at `POST /v1/admin/intake/prune`, build a JSON body matching the schema (`{"kind":"all","older_than_days":90,"dry_run":true}` for daily dry-run only), drop the `--fail` and inspect the response, log counts. **But** `intake_retention.md` explicitly records the operational doctrine as operator-driven; an automated daily prune even in dry-run-only mode would contradict that. The fix path is therefore conceptually awkward.
  - **Delete** — remove the workflow file entirely. The operator continues to run `POST /v1/admin/intake/prune` per `intake_retention.md` cadence. **Recommended.**

Either way, the workflow should not silently keep firing 404 daily with a real admin token.

---

## 8. Alembic assessment

### 8.1 Where is `alembic` referenced?

Search: `grep -rEni "alembic" requirements.txt app/ tests/ scripts/ Dockerfile docs/ migrations/`.

| Location | Type of reference |
|---|---|
| `requirements.txt:5` | `alembic` declaration |
| `docs/operations/incident_response.md:597` | `"Do not run broad migrations blindly (e.g. alembic downgrade base style — and ANCHOR does not use Alembic at runtime regardless)."` — explicit documentation that Alembic is **not** used at runtime |
| `docs/operations/security_audits/*.md` | Six prior audit references documenting `alembic` as Patch 11A finding P-6 ("dead-weight `alembic`") |

### 8.2 Where is `alembic` *used*?

- **Zero imports** of `alembic` anywhere under `app/`.
- **Zero invocations** of `alembic` anywhere under `scripts/`, `Dockerfile`, or `tests/`.
- **Zero `.ini`** files (`alembic.ini` absent).
- **Zero `versions/`** directories under `migrations/`.
- `app/migrate.py` walks the **bare `migrations/*.sql`** directory and runs files via `db.execute(text(stmt))` with checksum verification (Patch 6). The migration runner is hand-rolled, not Alembic.

### 8.3 Conclusion

`alembic` is **dead weight in the production install**. It is installed at every Render build because of the `requirements.txt` line, but is never imported, never executed, and is explicitly documented as unused.

### 8.4 Proof required before removal

To minimise removal risk:

1. **Re-confirm** no module imports `alembic` (a second `grep` immediately before the removal patch).
2. **Re-confirm** `app/migrate.py` still walks raw `.sql` files (one read of the function bodies).
3. **Run the full test suite** under a local install that omits `alembic` (uninstall locally; `pytest -q tests/` must remain 1525 / 1525 passed).
4. **Re-trigger the CI dependency audit** after the requirements change — confirm no findings re-surface.

### 8.5 Recommendation

**Patch 11B-b6: drop the `alembic` line from `requirements.txt`** after Patch 11B-b2 lockfile lands (so the removal is recorded against a known-good baseline).

---

## 9. Lockfile strategy recommendation

Four options assessed:

| Option | Tool | Minimal disruption | Render compatibility | CI compatibility | `pip-audit` compatibility | Solo-operator maintainability | Hash pinning? | Migration complexity |
|---|---|---|---|---|---|---|---|---|
| **A** Keep `requirements.txt`, add `requirements.lock.txt` (raw `pip freeze`) | `pip freeze` | minimal — no new tool | yes (just `pip install -r requirements.txt`) | yes | yes (`pip-audit -r requirements.txt`) | high — one command (`pip freeze`) | no (raw) | trivial |
| **B** `requirements.in` → compiled `requirements.txt` via `pip-tools` | `pip-tools` (`pip-compile`) | small — adds one source-of-truth file | yes — Render still installs `requirements.txt` | yes — CI can run `pip-compile --check` to detect drift | yes | high — `pip-compile` is one command | **yes** (`--generate-hashes`) | small (rename existing file to `.in`, generate fresh `.txt`) |
| **C** `uv` lockfile | `uv` | medium — adds modern tool; needs Dockerfile change | yes (`uv pip install`) | yes — `uv` is fast | yes (`pip-audit` reads `uv`-generated requirements) | medium — newer tool, faster than `pip-tools`, less ecosystem maturity | yes | medium (Dockerfile change required) |
| **D** Poetry | `poetry` | larger — changes whole workflow | yes but requires Dockerfile rewrite for Poetry-aware install | yes | yes | medium — Poetry has its own conventions | yes | high |

### 9.1 Recommendation

**Option B — `pip-tools` (`requirements.in` + compiled `requirements.txt` with `--generate-hashes`).** Reasons:

- **Minimal Dockerfile change** — `pip install -r requirements.txt` continues to work; the only Dockerfile-side improvement is to add `--require-hashes` to the `pip install` line.
- **Source-of-truth split:** `requirements.in` is the human-edited declaration (the file Patches 11C / 11D-b currently edit); `requirements.txt` is the compiled output with full transitive closure and hashes. Reproducible across machines and across deploys.
- **CI lockfile-drift detection:** add a one-line step (`pip-compile --check`) to the dependency-audit workflow that fails if `requirements.in` was edited without recompiling `requirements.txt`.
- **`pip-audit` compatibility:** unchanged — `pip-audit -r requirements.txt` still reads the same file.
- **Solo-operator maintainability:** the operator runs `pip-compile` whenever `requirements.in` changes. One command, no new conceptual layer.
- **Future-proof for `--require-hashes`:** the strongest available supply-chain guarantee at install time.

**Not recommended:**

- **A (raw `pip freeze`)** — produces a flat list but loses the human-edited declaration surface and the hash discipline.
- **C (`uv`)** — promising but newer; the migration cost outweighs the speed benefit at ANCHOR's current scale.
- **D (Poetry)** — high migration cost, no doctrine-relevant advantage over `pip-tools` for this codebase.

---

## 10. Recommended patch sequence

Each patch lands narrowly with its own evidence artefact.

| Patch | Scope | Files changed (expected) |
|---|---|---|
| **11B-b2** Lockfile + direct pin tightening (the keystone) | Rename `requirements.txt` → `requirements.in` (kept as-is). Add `pip-tools` to a new `requirements-dev.txt`. Run `pip-compile --generate-hashes requirements.in -o requirements.txt`. Pin currently unpinned direct deps in `requirements.in` to the currently-resolved versions (`uvicorn==0.47.0`, `psycopg[binary]==3.3.4`, `sqlalchemy[psycopg]==2.0.49`, `argon2-cffi==25.1.0`, `anthropic==0.104.1`). Move `httpx==0.28.1` to `requirements-dev.txt`. Add CI step to verify `pip-compile --check` against `requirements.in`. | `requirements.in` (new), `requirements.txt` (regenerated), `requirements-dev.txt` (new), `Dockerfile` (`pip install --require-hashes -r requirements.txt`), `.github/workflows/dependency-audit.yml` (add `pip-compile --check` step) |
| **11B-b3** Docker base-image digest pin | `FROM python:3.11-slim` → `FROM python:3.11-slim@sha256:<digest>`. Read digest from the latest `python:3.11-slim` Docker Hub manifest at the time of the patch; record the digest in the artefact. | `Dockerfile` |
| **11B-b4** Pin all four GitHub Actions workflows to commit SHAs | `actions/checkout@v4` → `actions/checkout@<sha>`. `actions/setup-python@v5` → `actions/setup-python@<sha>`. Apply across all four workflows. Use Dependabot for ongoing SHA refresh. | All four workflows |
| **11B-b5** `anchor-retention-prune.yml` fix-or-delete | **Recommended: delete.** The operator-driven posture in `intake_retention.md` is the source of truth. | `.github/workflows/anchor-retention-prune.yml` (deleted) |
| **11B-b6** Drop dead-weight `alembic` | Remove the `alembic` line from `requirements.in`; re-run `pip-compile`; run full test sweep; re-trigger CI dependency audit; append a small evidence artefact. | `requirements.in`, `requirements.txt` |
| **Optional 11B-b7** `httpx<2` → `httpx>=2` hygiene | Address the `StarletteDeprecationWarning` surfaced by Patch 11D-b. May require test-side `httpx2` migration; needs spot-check first. | `requirements-dev.txt`, possibly `tests/` |
| **Optional 11B-b8** `.dockerignore` | Exclude `.git`, `tests/`, `docs/`, `migrations/migrations/` (already empty post-Patch-6), local `*.tmp.json` patterns from the image. Pure size optimisation; no security-doctrine implication. | `.dockerignore` (new) |

The recommended order is **11B-b2 first** because every other patch in the sequence becomes easier once the lockfile exists. **11B-b3** and **11B-b4** are independent and can land in either order after 11B-b2. **11B-b5** is independent of the lockfile work and could land any time. **11B-b6** must land after 11B-b2 so the removal's effect is recorded against the locked baseline.

---

## 11. Stop-condition impact

| Operational item                              | Status after Patch 11B-b1                                                                                                                                                              |
|---|---|
| Env docs                                      | ✅ Patch 7                                                                                                                                                                  |
| Backup / restore drill                        | ✅ Patch 8 / 8C                                                                                                                                                              |
| Intake retention dry-run                      | ✅ Patch 9 / 9B                                                                                                                                                              |
| Incident-response runbook                     | ✅ Patch 10                                                                                                                                                                  |
| First tabletop drill                          | ✅ Patch 10B                                                                                                                                                                  |
| Dependency / CVE audit (CI pip-audit)         | ✅ PASS for the scanned dependency set (Patch 11D-c).                                                                                                                       |
| **Dependency pinning / reproducibility**      | ⚠ **Open.** Inventoried by this artefact. Patch 11B-b2 → 11B-b6 sequence recommended.                                                                                       |
| Broken `anchor-retention-prune.yml`           | ⚠ **Open.** Recommended Patch 11B-b5 deletion.                                                                                                                              |
| Tenant Isolation Smoke #191 rate-limit        | ⏳ Open — separate follow-up.                                                                                                                                                 |
| `httpx<2` / Starlette TestClient deprecation  | ⏳ Open — optional 11B-b7 hygiene patch.                                                                                                                                      |
| Render deploy decision                        | ⏳ **Open.** No deploy issued. Reproducibility-first path recommended (11B-b2 → 11B-b3 → 11B-b4 → 11B-b6 → deploy).                                                            |
| Legal / commercial pack per Addendum v1.3     | ⏳ Open — out of code scope; founder track.                                                                                                                                   |

No paid pilot / real clinic data until **all** standing operational stop conditions are cleared.

---

## 12. Non-actions in this patch

The following were **explicitly not done** in Patch 11B-b1:

- ❌ No dependency changed. `requirements.txt` is byte-identical to the post-Patch-11D-b state.
- ❌ No pin added or removed.
- ❌ No lockfile added.
- ❌ No `requirements-dev.txt` added.
- ❌ No `Dockerfile` change.
- ❌ No GitHub Actions change.
- ❌ No `anchor-retention-prune.yml` fix or deletion.
- ❌ No `alembic` removal.
- ❌ No `httpx` upgrade.
- ❌ No `.dockerignore` added.
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

What this patch **did** do: inventory the dependency reproducibility surface (10-row table for `requirements.txt`, transitive resolved set, Dockerfile, four workflows, retention-workflow validity, alembic-usage proof), evaluate four lockfile strategies and recommend `pip-tools`, and propose a seven-patch sequence (Patches 11B-b2 → 11B-b8).

---

## 13. Doctrine restatement

This artefact preserves the ANCHOR doctrine: governance-first, metadata-only by default, tenant safety, RLS / FORCE RLS, human review, receipt-backed, **aligned, not compliant**. It records:

- No secrets, no clinical content, no PII, no full bearer tokens, no `DATABASE_URL`, no Render env values.
- No claim of "no risk", "fully compliant", "certified", "regulator-approved", "guaranteed safe", or "no vulnerabilities exist".
- A read-only inventory. No code, no test, no migration, no dependency change, no production touch.

Audit follow-ups land as separate patches with their own evidence artefacts in this directory.
