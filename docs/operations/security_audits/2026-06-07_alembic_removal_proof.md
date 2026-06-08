# ANCHOR Alembic Removal Proof — 2026-06-07

> **Proof / design only.** This artefact re-proves whether `alembic` can be safely removed from runtime dependencies, in advance of implementation Patch **11B-b6-b**. **No dependency changed.** No lockfile changed. No Dockerfile changed. No workflow changed. No application code changed. No tests changed. No migrations changed. No migrations run. No database queried or mutated. No production endpoint called. No Render setting changed. No deploy issued. No secret read, printed, or stored. Not compliance certification. Not a regulator endorsement. Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

---

## 1. Purpose and scope

The Patch 11B-b1 inventory ([`2026-06-07_dependency_reproducibility_inventory.md`](./2026-06-07_dependency_reproducibility_inventory.md) §8) flagged `alembic` as dead weight — declared in `requirements.txt` but with **zero imports anywhere** in the codebase. The lockfile design ([`2026-06-07_lockfile_strategy_design.md`](./2026-06-07_lockfile_strategy_design.md) §6) deferred removal to Patch **11B-b6**, on the explicit condition that the zero-import proof be **re-confirmed against the lockfile baseline** before removal. The lockfile implementation ([`2026-06-07_lockfile_implementation.md`](./2026-06-07_lockfile_implementation.md) §4) retained `alembic==1.18.4` as a kept-pinned-but-still-present line. The subsequent Patches 11B-b2-c (post-lockfile audit PASS), 11B-b3-b (Docker digest pin), 11B-b4-b (Actions SHA pin), and 11B-b5-b (retention workflow deletion) did not touch the dependency surface.

This patch is the **proof step** that precedes implementation Patch 11B-b6-b. Purpose:

- Re-confirm where `alembic` is declared under HEAD `bc0e81e`.
- Re-confirm where `alembic` is *used* (zero-import re-proof).
- Re-confirm the actual migration mechanism is the hand-rolled SQL runner.
- Decide the implementation shape: remove entirely vs move to dev vs keep.
- Record risk and rollback.

- Proof / design only.
- No dependency changed.
- No lockfile changed.
- No Dockerfile changed.
- No workflow changed.
- No app / test / migration / frontend change.
- No migration run.
- No production endpoint called.
- No DB queried or mutated.
- No Render change.
- No deploy.
- Not compliance certification.
- Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

**Out of scope** (held for later patches): optional `httpx<2` deprecation hygiene (Patch **11B-b7**), Dockerfile explicit `--require-hashes` flag flip (deferred), future `github-actions` Dependabot configuration, base-image digest refresh cadence, any deploy decision.

---

## 2. Current declaration state

Search: `Select-String -Path requirements.in,requirements.txt,requirements-dev.txt -Pattern "alembic"`.

| File | Line | Content | Classification |
|---|---|---|---|
| `requirements.in` | 14 | `alembic==1.18.4` | direct runtime declaration |
| `requirements.txt` | 7 | `alembic==1.18.4 \` (followed by two SHA256 hash lines) | compiled lockfile entry (direct) |
| `requirements.txt` | 398 | `# via alembic` (trailing comment on `mako==1.3.12`) | transitive — `mako` is pulled only because of alembic |
| `requirements.txt` | 489 | `# via mako` (trailing comment on `markupsafe==3.0.3`) | transitive — `markupsafe` is pulled only because of `mako`, which is pulled only because of `alembic` |
| `requirements.txt` | 717 | `# via alembic` (in the consolidated `typing-extensions` `via` block) | transitive — `typing-extensions` is *also* pulled by `alembic`, but is independently required by `anthropic`, `fastapi`, `psycopg`, `pydantic`, `pydantic-core`, `sqlalchemy`, `starlette`, and `typing-inspection` (per `requirements.txt:714-723`). Removing alembic does **not** drop `typing-extensions`. |
| `requirements.txt` | 726 | (line in another transitive `via` block) | transitive — same shape as line 717; another shared transitive that alembic incidentally also pulls. Will remain after removal. |
| `requirements-dev.txt` | — | not present | not a dev dep |

**Net effect of removing `alembic` from `requirements.in`:**

- `alembic==1.18.4` line drops out of `requirements.txt`.
- `mako==1.3.12` drops (no other consumer).
- `markupsafe==3.0.3` drops (its only path back is via `mako`).
- `typing-extensions` and other shared transitives **remain** (still required by `anthropic`, `fastapi`, `pydantic`, `sqlalchemy`, `starlette`, `psycopg`, etc.).

The lockfile diff is expected to be a small block removal (three packages × 3 lines each = ~10 line removals plus `via` adjustments), not a wholesale recompile.

---

## 3. Usage search results

Searches executed at HEAD `bc0e81e`:

| Search | Path | Pattern | Hits |
|---|---|---|---|
| Source imports | `app/` | `alembic\|Alembic` (case-insensitive) | **0 files** |
| Test imports | `tests/` | `alembic\|Alembic` | **0 files** |
| Script invocations | `scripts/` | `alembic` | **0 files** (only `anchor-smoke-isolation.ps1` and `anchor-verify-force-rls.ps1` exist; neither contains `alembic`) |
| `alembic.ini` glob | repo-root recursive | `**/alembic.ini` | **0 files** |
| `alembic/` directory | repo-root recursive | `alembic/**` | **0 files** |
| `mako` / `Mako` import | `app/`, `tests/` | `mako\|Mako` | **0 files** |
| Migration directory contents | `migrations/` | `**/*` glob | 35 files, **all `.sql`** (zero `.py`, zero `env.py`, zero `versions/` subdirectory) |

Non-source hits (recorded for completeness, all confirm Alembic is *not* used):

| File | Line | Hit | Classification |
|---|---|---|---|
| `requirements.in` | 14 | `alembic==1.18.4` | dependency declaration (the line this patch proposes to remove) |
| `requirements.txt` | 7, 398, 489, 717, 726 | direct + transitive entries | compiled lockfile (will be regenerated in 11B-b6-b) |
| `docs/operations/incident_response.md` | 597 | "*Do not run broad migrations blindly (e.g. `alembic downgrade base` style — and ANCHOR does not use Alembic at runtime regardless).*" | **explicit operational doctrine that Alembic is not used at runtime** |
| `.claude/hooks/README.md` | 12 | "*PreToolUse / Bash guard — block `git commit`, `git push`, `alembic upgrade`, `alembic downgrade` unless explicitly invoked by the user.*" | defensive proposal for a future Claude Code hook to refuse those commands — explicitly anticipates Alembic is **not** something ANCHOR should run; not a usage |
| `docs/operations/security_audits/*.md` (multiple files: lockfile design, implementation, retention decision/removal, Docker digest probe/pin, Actions SHA design/implementation, post-lockfile audit, etc.) | various | references to "P-6 dead-weight alembic" and "held for Patch 11B-b6" | audit-trail references documenting the open removal; not runtime usage |

**Conclusion:** zero runtime usage of Alembic anywhere in the project under HEAD `bc0e81e`. This is identical to the proof captured in Patch 11B-b1 §8, refreshed against the post-lockfile / post-digest / post-Actions-SHA / post-retention-removal baseline.

---

## 4. Current migration mechanism

Migration runner: **`app/migrate.py`**. Inspected (lines 1–60):

- Pure Python module, imports only `hashlib`, `json`, `logging`, `os`, `pathlib.Path`, `typing`, `sqlalchemy.text`, `sqlalchemy.orm.Session`.
- Walks `migrations/` non-recursively for `*.sql` files (`_list_sql_files`).
- Ensures a `public.schema_migrations` tracking table exists (`CREATE TABLE IF NOT EXISTS schema_migrations (filename PRIMARY KEY, applied_at)`).
- Per-file flow: read content, compute SHA256 checksum, compare against `schema_migrations.checksum` if column present (Patch 6 added the checksum column via `migrations/10016_schema_migrations_checksum.sql`), execute via `db.execute(text(stmt))`.
- Checksum verification env toggle: `ANCHOR_MIGRATION_VERIFY_CHECKSUMS` (`_TRUTHY` / `_FALSY` sets).
- **No Alembic import.** **No Alembic API call.** **No Alembic-style "revision" / "down_revision" / `env.py` / `script.py.mako`** anywhere in the runner or the migration files.

Migration file inventory (`migrations/*.sql`):

- 18 files in the `10000` / `1001x` series (RLS / FORCE RLS / clinic-slug / governance-events / admin-audit-events / `schema_migrations`-checksum / etc.).
- 17 files in the `2026MMDD_NN_<topic>.sql` series (idempotency, public intake, assistant runs/receipts, learn/CPD, governance policy library, self-assessment, client transparency, incident/near-miss).
- All `.sql`. **Zero `.py`. Zero `env.py`. Zero `versions/` subdirectory.**

Migration **execution** is via `app/migrate.py` called from app startup paths (and tests). Checksum verification is a hand-rolled SHA256 check on the raw file content, **not** Alembic's revision system. The `schema_migrations` table is a one-row-per-filename ledger, **not** an Alembic `alembic_version` table.

**Conclusion: Alembic is not involved anywhere in the migration mechanism.**

---

## 5. Options assessed

| Option | Description | Runtime risk | Deployment risk | Lockfile churn | Rollback ability | Consistency with current migration system | Solo-operator maintainability |
|---|---|---|---|---|---|---|---|
| **A** | **Remove** `alembic==1.18.4` from `requirements.in`; recompile `requirements.txt`; validate; commit. | none — zero imports anywhere | low — Render rebuild drops alembic + mako + markupsafe from the wheel set; install path is `pip install -r requirements.txt` which already verifies hashes | small — three direct packages drop, a few `via` lines update, no other package version changes | `git revert` of the implementation commit restores `alembic==1.18.4` and the three transitive lines | fully consistent — `app/migrate.py` continues to run raw `.sql` files; `incident_response.md §13.5` doctrine ("ANCHOR does not use Alembic at runtime") is now structurally true at the install layer | high — eliminates a misleading dependency line |
| **B** | Move `alembic` to `requirements-dev.txt`. | none | none | none | trivial | partial — dev install still has alembic, but it's used by no test and no script | low — declares a dev dep with no actual use; misleads future contributors into thinking alembic *might* be useful here |
| **C** | Keep `alembic` runtime for one more deploy cycle. | none | none | none | trivial | unchanged | medium — adds a deploy cycle of churn for no benefit |
| **D** | Keep forever as an explicit future-migration option. | none | none | none | trivial | misleading — the codebase explicitly documents Alembic is **not** used; the doctrine line in `incident_response.md:597` becomes contradictory if alembic is preserved "in case" | low — locks in a documented contradiction |

**Recommendation: Option A — remove `alembic` from `requirements.in` and recompile.**

Reasons:

- **Zero downside.** No imports, no scripts, no migrations, no tests reference Alembic; removing it cannot regress anything.
- **Aligns with explicit doctrine.** `incident_response.md:597` already records "ANCHOR does not use Alembic at runtime regardless." The runtime install layer should match the doctrine.
- **Shrinks the supply-chain surface.** Three fewer packages (`alembic`, `mako`, `markupsafe`) ship in every Render build; three fewer wheels to verify hashes against; three fewer potential CVE rows in future `pip-audit` runs.
- **Smallest-possible lockfile churn.** Only the three removed packages and their `via` comments change.
- **Rollback is `git revert`.** The lockfile commit is single-purpose; reverting it restores the prior install set exactly.
- **B and D actively mislead** future readers; C delays the same change for no operational benefit.

---

## 6. Recommended Patch 11B-b6-b

### 6.1 Implementation shape

**Remove `alembic==1.18.4` from `requirements.in`.** Do **not** move it to `requirements-dev.txt` (no evidence of dev use).

### 6.2 Files that change in 11B-b6-b

| File | Action |
|---|---|
| `requirements.in` | **modified** — remove line 14 (`alembic==1.18.4`); leave the rest byte-identical. |
| `requirements.txt` | **regenerated** — `py -3.11 -m piptools compile --generate-hashes --output-file requirements.txt requirements.in`. Expected diff: drop direct `alembic==1.18.4` block, drop transitive `mako==1.3.12` block, drop transitive `markupsafe==3.0.3` block (~10 lines plus `via` adjustments). No other resolved version should change. |
| `requirements-dev.txt` | **unchanged** — `pip-tools`, `pytest`, `httpx==0.28.1` remain pinned as in Patch 11B-b2 correction. |
| `docs/operations/security_audits/2026-06-07_alembic_removal_implementation.md` (or similar dated artefact for the implementation patch) | **new** — records the removal. |
| `docs/operations/README.md` | **modified** — append index entry. |

No other files change. **No application code change. No `Dockerfile` change. No workflow change. No test change. No migration change. No `intake_retention.md` or other runbook change.**

### 6.3 Exact compile command (in implementation patch)

Inside an existing Python 3.11 venv (or fresh `py -3.11 -m venv`) with `pip-tools==7.5.3` already installed (workstation-local TLS workaround `--trusted-host` permitted as in Patch 11B-b2-b):

```powershell
$env:PIP_TRUSTED_HOST = "pypi.org files.pythonhosted.org"
py -3.11 -m piptools compile --generate-hashes --output-file requirements.txt requirements.in
```

Then **strip the autogenerated `--trusted-host` directives** from the lockfile header if pip-tools writes them (same shape as the post-Patch-11B-b2-b clean-up).

### 6.4 Validation commands

```powershell
# 1. Diff is exactly the expected three-package removal block.
git diff -- requirements.in requirements.txt

# 2. Whitespace lint.
git diff --check

# 3. Fresh 3.11 venv install + hash verification.
py -3.11 -m venv .venv-alembic-removal
.\.venv-alembic-removal\Scripts\python -m pip install --upgrade pip
.\.venv-alembic-removal\Scripts\python -m pip install -r requirements.txt
.\.venv-alembic-removal\Scripts\python -m pip install -r requirements-dev.txt
.\.venv-alembic-removal\Scripts\python -m pip check

# 4. Confirm alembic is not installed.
.\.venv-alembic-removal\Scripts\python -c "import importlib.util; print('alembic_installed', importlib.util.find_spec('alembic') is not None)"
# Expected: alembic_installed False

# 5. App import.
.\.venv-alembic-removal\Scripts\python -c "from app.main import app; print('IMPORT OK')"

# 6. Migration runner import (the only path that could conceivably surprise us).
.\.venv-alembic-removal\Scripts\python -c "from app.migrate import _list_sql_files, _ensure_schema_migrations; print('MIGRATE OK')"

# 7. Focused security/auth/rate-limit/receipt suite (Patch 11B-b2-b shape).
.\.venv-alembic-removal\Scripts\python -m pytest tests/test_auth_role_allowlist.py tests/test_clinic_login_error_consistency.py tests/test_security_config_hardening.py tests/test_rate_limit.py tests/test_assistant_rate_limits.py tests/test_assistant_receipt_lookup.py -q

# 8. Migration-related tests, if any.
.\.venv-alembic-removal\Scripts\python -m pytest tests/ -q -k "migrate or migration or schema_migrations or startup"

# 9. Full sweep.
.\.venv-alembic-removal\Scripts\python -m pytest tests/ -q

# 10. Cleanup.
Remove-Item -Recurse -Force .\.venv-alembic-removal -ErrorAction SilentlyContinue
```

Required env stubs for the import + tests are the same as in Patches 11B-b2-b / 11B-b3-b (`DATABASE_URL` synthetic stub, `RATE_LIMIT_ENABLED=0`, stub `ADMIN_BEARER_TOKEN`, stub `ADMIN_AUTH_PEPPER`).

### 6.5 Validation success criteria

- `pip check` reports **no broken requirements**.
- `find_spec('alembic')` returns **`None`** — alembic is not installed.
- `from app.main import app` returns **`IMPORT OK`**.
- `from app.migrate import …` returns **`MIGRATE OK`**.
- Focused security suite passes (65/65 or current baseline).
- Full pytest sweep passes (1525/1525 or current baseline).
- No unexpected resolved-version drift in `requirements.txt` (only the three expected packages should drop; every other pinned version should be byte-identical to the pre-patch lockfile).

### 6.6 CI dependency audit

After commit + push, **manually re-trigger** `Anchor Dependency Audit (pip-audit)` via `workflow_dispatch:` against the new commit. Confirm it remains PASS for the locked scanned set (run number will be `#5`). Local pip-audit will continue to fail with the documented workstation TLS path; CI is the authoritative scan.

### 6.7 Render deploy remains held

The first Render build under the alembic-free lockfile is a **separate operator decision**. The reproducibility-first sequence (alembic removal → deploy) remains the recommended order. Patch 11B-b6-b does **not** include a deploy.

---

## 7. Risk and rollback

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | A code path imports `alembic` lazily (e.g. behind a try/except, behind a feature flag, in a dead-code branch). | very low — five separate searches (`app/`, `tests/`, `scripts/`, repo-root, plus the prior Patch 11B-b1 grep) returned zero hits | low — would surface as `ModuleNotFoundError` on import, easy to bisect | The validation matrix in §6.4 includes `find_spec('alembic')` and `from app.main import app` plus a full pytest sweep — any lazy import path would surface there before commit. |
| R2 | A migration `.sql` file references Alembic's `alembic_version` table or schema. | very low — `migrations/` is `.sql`-only and uses `public.schema_migrations`, not `alembic_version` | low | Validated by `Select-String` for `alembic_version` across `migrations/` (zero hits at HEAD `bc0e81e`). Implementation patch can re-run the search as a final pre-commit check. |
| R3 | A future contributor adds Alembic-based migrations without realising the project doesn't use Alembic. | medium — documentation is the only safeguard | medium | `incident_response.md:597` already records the doctrine; this removal makes the absence load-bearing at the install layer, which is the strongest signal. The optional `.claude/hooks/README.md` guard against `alembic upgrade/downgrade` adds a second line of defence if/when the hook is implemented. |
| R4 | `mako` or `markupsafe` is used by something we haven't checked. | very low — both showed zero matches in `app/` and `tests/` searches | low | Validated by the full pytest sweep in §6.4 step 9; a `mako`-using path would fail to import. |
| R5 | The lockfile recompile resolves an *unrelated* package to a different version. | low — `pip-compile` only relaxes resolution where constraints changed; removing alembic should not cascade | low | Implementation patch's `git diff -- requirements.txt` is the visible check. Any unexpected version delta is investigated before commit. |
| R6 | Render's build cache holds a stale `alembic` reference. | very low — Render rebuilds wheels per commit; the digest-pinned Dockerfile already establishes a clean base | low | First post-patch Render build is operator-monitored. |

### 7.1 Rollback

**Mechanism:** `git revert` the Patch 11B-b6-b commit restores `requirements.in` and `requirements.txt` to their post-Patch-11B-b5-b state (with `alembic==1.18.4` + `mako` + `markupsafe`). Render rebuilds against the restored lockfile. **No Render setting change required.** **No GitHub-side configuration change required.**

**Window of exposure:** zero. Patch 11B-b6-b does not include a deploy; the first Render deploy under the alembic-free lockfile is a separate operator decision, and is reversible by `git revert` + redeploy.

---

## 8. Stop-condition impact

| Operational gate | Status after this proof patch |
|---|---|
| Dependency / CVE audit (CI pip-audit) | ✅ PASS for the locked scanned dependency set ([`2026-06-07_post_lockfile_ci_audit.md`](./2026-06-07_post_lockfile_ci_audit.md), run `#4` against `32e9b94`). |
| Dependency-file reproducibility | ✅ Closed by Patch 11B-b2-b. |
| Docker base-image digest pin | ✅ Closed by Patch 11B-b3-b. |
| GitHub Actions SHA pinning | ✅ Closed at the file layer by Patch 11B-b4-b. |
| Retention workflow treatment | ✅ Closed by Patch 11B-b5-b. |
| **Alembic dead-weight removal** | ⏳ **Open.** This patch refreshes the zero-import proof. **Patch 11B-b6-b is what actually closes it.** |
| Dockerfile explicit `--require-hashes` flag | ⏳ Open — deferred. |
| Optional `httpx<2` deprecation hygiene | ⏳ Open — optional **Patch 11B-b7**. |
| `github-actions` Dependabot SHA-refresh cadence | ⏳ Open — additive hygiene, separate follow-up. |
| Base-image digest refresh cadence | ⏳ Open — operational hygiene item. |
| Render deploy of post-Starlette + lockfile + digest + Actions-SHA + retention-cleanup stack | ⏳ Open — operator decision. Reproducibility-first sequence still recommended (alembic removal → deploy). |
| Tenant Isolation Smoke #191 rate-limit | ⏳ Open — separate follow-up. |
| Legal / commercial pack per Addendum v1.3 | ⏳ Open — founder track. |

Reproducibility gate is **not fully closed** until the alembic line is actually removed and validated. **Dependency / CVE audit remains PASS** for the locked scanned set. **Docker base digest pin is complete.** **GitHub Actions SHA pin is complete.** **Retention workflow removal is complete.** **No deploy decision made by this patch.** **Paid pilot / real clinic data remains blocked** by the standing operational gates.

---

## 9. Non-actions in this patch

The following were **explicitly not done** in Patch 11B-b6-a:

- ❌ No `requirements.in` change. (The line `alembic==1.18.4` is still present at line 14.)
- ❌ No `requirements.txt` change. (Lockfile is byte-identical to the post-Patch-11B-b5-b state.)
- ❌ No `requirements-dev.txt` change.
- ❌ No `pip-compile` run. (`pip-tools` not invoked in this patch.)
- ❌ No Dockerfile change.
- ❌ No GitHub Actions change.
- ❌ No application code change.
- ❌ No test change.
- ❌ No migration change.
- ❌ No migrations run.
- ❌ No database query or mutation.
- ❌ No Render setting change.
- ❌ No deploy.
- ❌ No frontend touch.
- ❌ No production endpoint call.
- ❌ No secret value read, printed, stored, or pasted.
- ❌ No commit. No push. (Per scope.)
- ❌ No compliance / certification / regulator-approval claim.
- ❌ No paid-pilot or real-clinic-data authorisation.

What this patch **did** do: re-confirmed (read-only) that `alembic==1.18.4` is declared in `requirements.in:14` and resolves to the same direct + transitive (`mako`, `markupsafe`) block in `requirements.txt`; re-confirmed zero `alembic` imports anywhere under `app/`, `tests/`, `scripts/`, and no `alembic.ini` / `alembic/` env / `versions/` directory anywhere in the repo; re-confirmed `app/migrate.py` is a hand-rolled SQL runner that walks `migrations/*.sql` and uses a `schema_migrations` ledger with optional SHA256 checksum verification; assessed four treatment options against runtime risk, deployment risk, lockfile churn, and rollback; **recommended Option A (remove)** for Patch 11B-b6-b; recorded the exact compile + validation commands and success criteria; and updated the operations README.
