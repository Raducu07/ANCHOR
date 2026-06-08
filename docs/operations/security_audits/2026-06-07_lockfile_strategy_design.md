# ANCHOR Lockfile Strategy Design â€” 2026-06-07

> **Design-only artefact.** This is a written design for Patch 11B-b2 (dependency lockfile + direct-pin tightening). **No dependency, lockfile, Dockerfile, GitHub Actions, application code, test, migration, database, Render, production endpoint, deploy, or frontend change is made in this patch.** No production endpoint was called. No database was queried or mutated. No Render setting changed. No deploy issued. No secret read, printed, or stored.
>
> This is not compliance certification, not a regulator endorsement, and not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

---

## 1. Purpose and scope

The clean CI `pip-audit` result captured in [`2026-06-07_post_starlette_ci_audit.md`](./2026-06-07_post_starlette_ci_audit.md) closed the **CVE** dimension of the dependency gate for the scanned set. The inventory in [`2026-06-07_dependency_reproducibility_inventory.md`](./2026-06-07_dependency_reproducibility_inventory.md) (Patch 11B-b1) then opened a different dimension: **reproducibility**. Today's `requirements.txt` has 3 pinned and 7 unpinned direct dependencies, no transitive lockfile, a tag-only Docker base, and four mutable-tag GitHub Actions workflows.

This artefact is the **design step that precedes implementation Patch 11B-b2**. Its purpose:

- Lock in the **file layout** (where the source of truth lives; where the lock lives; where dev/test deps live).
- Lock in the **hash strategy** (whether `--generate-hashes` and `--require-hashes` land in 11B-b2 or a later patch).
- Lock in the **dev/test split** (specifically `httpx`, and where `pip-tools` itself lives).
- Lock in the **risk and rollback** posture so the implementation patch can be small.

Out of scope:

- Any actual dependency, lockfile, Dockerfile, workflow, application, test, migration, database, Render, or production change. **All of that is Patch 11B-b2 (implementation), not this design patch.**
- The Docker base-image digest pin (Patch 11B-b3), GitHub Actions SHA pinning (Patch 11B-b4), `anchor-retention-prune.yml` fix-or-delete (Patch 11B-b5), and `alembic` removal (Patch 11B-b6). Each is a separate later patch with its own evidence artefact.

---

## 2. Current state (carried forward from Patch 11B-b1)

| Item | State |
|---|---|
| CI `pip-audit -r requirements.txt` | **PASS** for the scanned set (Patch 11D-c against `bfec5a0`) |
| Direct pins in `requirements.txt` | 3 of 10 (`fastapi==0.133.1`, `PyJWT==2.13.0`, `pydantic[email]==2.7.4`) |
| Direct unpinned in `requirements.txt` | 7 of 10 (`uvicorn`, `psycopg[binary]`, `sqlalchemy[psycopg]`, `alembic`, `argon2-cffi`, `httpx`, `anthropic`) |
| Transitive lockfile | **none** |
| `requirements-dev.txt` | **none** |
| Test dep inlined into runtime requirements | `httpx` (with explicit comment marking it as test-only) |
| Dockerfile install line | `pip install --no-cache-dir -r requirements.txt` (no `--require-hashes`, no `--no-deps`) |
| Dockerfile base | `python:3.11-slim` (tag, no digest) |
| GitHub Actions pins | mutable semver tags (`@v4`, `@v5`) â€” not commit SHAs |
| `anchor-retention-prune.yml` | broken (targets nonexistent `/v1/admin/retention/prune`); separate fix-or-delete patch |
| `alembic` | dead weight (zero imports); separate removal patch |
| Render deploy of post-Starlette stack | **not yet executed** |

Reproducibility gate is **open**. The CVE gate is PASS for the scanned set, but Render's resolver re-resolves transitive deps on every build, so today's deploy can install a different runtime set than CI audited.

---

## 3. Candidate layouts assessed

Three layouts considered for Patch 11B-b2. Each is judged on Render compatibility, `pip-audit` compatibility, Dockerfile impact, CI impact, solo-operator maintainability, hash support, diff size, rollback simplicity, and risk of breaking current workflows.

### Layout A â€” Minimal `pip-tools` runtime lock

**Shape:**

- `requirements.in` â€” direct runtime dependencies (the human-edited declaration; what `requirements.txt` is today).
- `requirements.txt` â€” **compiled transitive lockfile** (`pip-compile`-generated; full closure; optional hashes).
- `requirements-dev.txt` â€” dev/test/tooling deps (`httpx`, `pytest`, `pip-tools` itself optionally).

**Render path:** Render continues to run `pip install -r requirements.txt`. Render reads the compiled lock; no Render setting changes. âœ…

**`pip-audit` path:** CI continues to run `pip-audit -r requirements.txt`. Because the lock is the full closure, `pip-audit` now sees pinned transitive packages too â€” strictly *more* coverage than today. âœ…

**Dockerfile impact:** zero structural change required for Patch 11B-b2. The existing `COPY requirements.txt . && pip install --no-cache-dir -r requirements.txt` works unchanged. Adding `--require-hashes` is **optional in this patch** (see Â§4).

**CI impact:** a single new optional step in `dependency-audit.yml` to run `pip-compile --check` against `requirements.in` and fail if `requirements.txt` drifted from it. The other three workflows are untouched.

**Solo-operator maintainability:** the operator edits `requirements.in` (just like `requirements.txt` today) and runs `pip-compile requirements.in -o requirements.txt` whenever the input changes. One command. âœ…

**Hash support:** native â€” `pip-compile --generate-hashes` produces a lock with SHA256 hashes per wheel.

**Diff size:** moderate. The new `requirements.txt` will be a long pinned/hashed transitive list; this is a one-time diff. `requirements.in` is small.

**Rollback simplicity:** trivial â€” `git revert` restores the old `requirements.txt` and removes `requirements.in` / `requirements-dev.txt`. Render rebuilds with the old direct-deps file.

**Risk of breaking current workflows:** **low.** The Render install path is unchanged. The CI install steps (`anchor-rate-limit-ci.yml`, `isolation-smoke.yml`) read `requirements.txt`; they see a stricter set and continue to install successfully.

**Verdict:** âœ… **recommended.** Source-of-truth split is clean. Behaviour is conservative. Migration cost is one `pip-compile` invocation.

---

### Layout B â€” Split direct/lock (`requirements.lock.txt`)

**Shape:**

- `requirements.in` â€” direct runtime dependencies.
- `requirements.lock.txt` â€” compiled transitive lock (new filename).
- `requirements.txt` â€” kept as a compatibility/direct-deps file, possibly identical to `requirements.in`.
- Dockerfile rewritten to install **`requirements.lock.txt`**, not `requirements.txt`.

**Render path:** **requires a Dockerfile change in Patch 11B-b2** (must point `pip install` at `requirements.lock.txt`). âŒ added scope.

**`pip-audit` path:** CI step must be changed to `pip-audit -r requirements.lock.txt`. âŒ added scope.

**Dockerfile impact:** **changes Dockerfile inside the same patch**. Couples lockfile work with Dockerfile work. This is exactly what Patch 11B-b3 is for; mixing them violates the narrow-patch posture.

**CI impact:** workflow file `dependency-audit.yml` must change which file it audits. Possibly other workflows too. âŒ added scope.

**Solo-operator maintainability:** the operator has to remember **two** filenames that look near-identical (`requirements.in` and `requirements.txt`) plus the lock. Higher cognitive overhead.

**Hash support:** same as Layout A.

**Diff size:** larger â€” touches Dockerfile and at least one workflow.

**Rollback simplicity:** moderate â€” `git revert` plus a possible Render rebuild.

**Risk of breaking current workflows:** **medium** â€” anything that reads `requirements.txt` (e.g. existing tooling, future contributors, copied-and-pasted command lines in audit artefacts) is now reading a non-authoritative file.

**Verdict:** âŒ **not recommended.** Bundles lockfile work with Dockerfile work; the layout's only advantage (visible "lock" filename) is not worth the coupling. Patch 11B-b3 is the right home for Docker changes.

---

### Layout C â€” Conservative pin-only (no lockfile)

**Shape:**

- `requirements.txt` kept as the single file.
- Every currently-unpinned direct dep is pinned (`uvicorn==0.47.0`, `psycopg[binary]==3.3.4`, `sqlalchemy[psycopg]==2.0.49`, `argon2-cffi==25.1.0`, `httpx==0.28.1`, `anthropic==0.104.1`, and `alembic==1.18.4` until 11B-b6 removes it).
- **No transitive lock.** No `requirements.in`. No `requirements-dev.txt`.

**Render path:** unchanged. âœ…

**`pip-audit` path:** unchanged. âœ…

**Dockerfile impact:** zero.

**CI impact:** zero.

**Solo-operator maintainability:** highest â€” one file, one tool (`pip`), no new concept. âœ…

**Hash support:** **none** â€” can't be added without a lockfile.

**Diff size:** tiny â€” six pin additions on existing lines.

**Rollback simplicity:** trivial.

**Risk of breaking current workflows:** **lowest** â€” semantically equivalent to today, just stricter.

**Reproducibility delta:** **partial only.** Direct deps are now reproducible, but transitive deps (e.g. `pydantic-core==2.18.4`, `anyio==4.13.0`, `starlette==1.2.1`) still float across builds. The Patch 11B-b1 finding â€” "Render's resolver picks whichever version PyPI offers at build time" â€” is **not** fully closed by this option.

**Verdict:** âš  **viable but insufficient.** Layout C delivers *some* reproducibility (direct deps) without the closure (transitive deps), and **does not buy hash discipline**. It also leaves dev/test split unaddressed (`httpx` still inlined into runtime). Layout A is strictly better at marginal cost.

---

### 3.x Summary table

| Criterion | Layout A (`pip-tools` lock) | Layout B (split filenames) | Layout C (pin-only) |
|---|---|---|---|
| Render compatibility | âœ… (no change) | âš  (Dockerfile change) | âœ… (no change) |
| `pip-audit` compatibility | âœ… (stricter coverage) | âš  (CI step change) | âœ… (same coverage) |
| Dockerfile impact in 11B-b2 | none | required | none |
| CI workflow impact in 11B-b2 | optional drift-check step | required step retarget | none |
| Solo-operator maintainability | high (one new command) | medium (two filenames) | highest (no new concept) |
| Hash support | âœ… native | âœ… native | âŒ |
| Transitive reproducibility | âœ… | âœ… | âŒ |
| Dev/test split | âœ… (new file) | âœ… (new file) | âŒ |
| Diff size / noise | moderate | larger | tiny |
| Rollback simplicity | âœ… (`git revert`) | âš  (revert + rebuild) | âœ… |
| Risk of breaking workflows | low | medium | lowest |

**Recommendation: Layout A.** Closes the transitive-reproducibility gap, adds dev/test split, opens the door to hashes â€” without touching the Dockerfile in this patch and with only one optional CI line.

---

## 4. Hash strategy assessment

Four hash postures considered:

| Posture | `pip-compile --generate-hashes` | Docker `pip install --require-hashes` | Lands in |
|---|---|---|---|
| **H0** No hashes ever | no | no | n/a |
| **H1** No hashes in 11B-b2, hashes later | no | no | deferred |
| **H2** `--generate-hashes` in 11B-b2, but **not** `--require-hashes` in Dockerfile | yes | no | 11B-b2 |
| **H3** `--generate-hashes` **and** `--require-hashes` in 11B-b2 | yes | yes | 11B-b2 |
| **H4** `--generate-hashes` in 11B-b2, `--require-hashes` in Dockerfile only after one successful deploy | yes | deferred to a follow-up | 11B-b2 + later |

### 4.1 Considerations

- **Extras (`psycopg[binary]`, `sqlalchemy[psycopg]`, `pydantic[email]`)** â€” `pip-compile --generate-hashes` resolves and hashes extras correctly in modern versions. Not a blocker.
- **Render Python 3.11 vs local Python 3.12** â€” `pip-compile` can be told to target 3.11 via `--python-version` or by running in a 3.11 venv. The compile must be performed in or against the Render runtime version to avoid environment-marker drift on wheels that ship per-Python tags (notably `psycopg-binary`, `argon2-cffi`, `pydantic-core`).
- **CI runner behaviour** â€” `actions/setup-python@v5` with `python-version: "3.11"` (already configured in `dependency-audit.yml` and `anchor-rate-limit-ci.yml`) matches Render. âœ…
- **Platform wheels** â€” `pydantic-core`, `psycopg-binary`, and `argon2-cffi` ship `manylinux`-tagged wheels distinct from the local Windows wheels. `--generate-hashes` records **all** acceptable wheel hashes for a given resolved version, so the hash set will include the manylinux wheel even if compiled from Windows. The risk is the operator running `pip-compile` on Windows and missing a platform-specific wheel; the mitigation is to compile inside a Linux container (`docker run --rm -v "$PWD":/app -w /app python:3.11-slim â€¦`) or in CI.
- **`pip-audit` compatibility** â€” `pip-audit` reads pinned `==` lines whether or not hashes are present. No change.
- **`--require-hashes` strictness** â€” under `--require-hashes`, **every** install line must have hashes. If even one transitive entry is missing a hash (e.g. due to a fresh PyPI release between compile and install), the build fails. This is the desired strictness for reproducibility but raises the bar on the first successful build.

### 4.2 Recommendation

**Posture H4 â€” `--generate-hashes` in 11B-b2, `--require-hashes` deferred to a one-step follow-up after the first successful Render build.**

Reasons:

- **Generating hashes is free** â€” `pip-compile --generate-hashes` produces a strictly stronger artefact for zero extra Dockerfile risk. It also unlocks H3 later with a one-line Dockerfile change.
- **Adding `--require-hashes` immediately couples the lockfile patch with a "first deploy under new lockfile" risk surface.** If the first Render rebuild encounters any platform-tag mismatch (e.g. a wheel that wasn't recorded because of the host-OS issue above), the deploy fails hard. Splitting `--require-hashes` into its own micro-patch keeps the failure mode isolated and bisectable.
- **Operational simplicity:** the operator can observe one successful Render build under the new lockfile (without `--require-hashes`), then flip on `--require-hashes` in a one-line follow-up. If `--require-hashes` then fails, the cause is unambiguous.
- **No regression vs current state:** today the Dockerfile has no `--require-hashes`; deferring it to a follow-up patch is not a step backwards, it's a step forwards held for one cycle.

H4 is therefore the recommended hash posture for Patch 11B-b2.

---

## 5. Dev/test dependency split assessment

### 5.1 `httpx`

Three options:

- **5.1.a Move to `requirements-dev.txt` immediately (in 11B-b2).** Stops `httpx` from being installed at Render at all. `httpx` is used solely by `fastapi.testclient` (via Starlette TestClient) inside `tests/`. The Render image ships application code only; no test path runs in production. âœ…
- **5.1.b Keep runtime until a later hygiene patch.** Conservative but contradicts the inline comment already in `requirements.txt` line 11 ("Test dependency: required by fastapi.testclient (Starlette TestClient).") which already declares it test-only.
- **5.1.c Keep runtime because TestClient/deprecation behaviour is still being watched.** The `StarletteDeprecationWarning` for `httpx<2` is about *future* behaviour; moving `httpx` from runtime to dev does not change what tests see today, because both CI test workflows (`anchor-rate-limit-ci.yml`) would install `requirements-dev.txt` alongside `requirements.txt`. The deprecation hygiene (`httpx>=2`) is **a separate optional Patch 11B-b7**.

**Recommendation: 5.1.a â€” move `httpx` to `requirements-dev.txt` in 11B-b2.** The inline comment already documents intent; honour it. The `httpx<2` deprecation is unrelated and is held for 11B-b7.

### 5.2 `pip-tools` itself

Four options for where `pip-tools` lives:

- **5.2.a Local-only operator tool** â€” operator installs into a personal venv; not declared in repo. âŒ â€” drops the "any operator can reproduce this" property.
- **5.2.b In `requirements-dev.txt`** â€” declared in the repo; the operator runs `pip install -r requirements-dev.txt` to get it. âœ… â€” discoverable, versioned with the repo, doesn't bloat the runtime image.
- **5.2.c CI-only install** (e.g. inside the `pip-compile --check` workflow step) â€” works but duplicates the source-of-truth. âš 
- **5.2.d Future script** â€” premature.

**Recommendation: 5.2.b â€” `pip-tools` lives in `requirements-dev.txt`.** The CI workflow step that runs `pip-compile --check` installs `requirements-dev.txt`, which gives it `pip-tools` with no separate declaration.

### 5.3 Other tooling

`pytest` is currently installed ad-hoc by `anchor-rate-limit-ci.yml` (`pip install pytest`). Moving it into `requirements-dev.txt` in 11B-b2 is **in scope** as part of the dev/test split, but the CI workflow change to read it (replacing the inline `pip install pytest`) is **deferred** to a later workflow-hygiene patch to keep 11B-b2 narrow. The workflow continues to do its own `pip install pytest` until then; no regression.

`pip-audit` is installed inside `dependency-audit.yml` (`pip install pip-audit`); leaving that pattern alone in 11B-b2 also keeps the patch narrow.

---

## 6. Alembic / retention workflow interaction

The Patch 11B-b1 inventory recorded two open items that **do not** belong in Patch 11B-b2:

- **`alembic` removal** â€” held for **Patch 11B-b6**. Removal needs the lockfile baseline first so the absence-of-alembic is recorded against a known transitive closure; trying to do it in the same patch as the lockfile creation conflates two evidence concerns.
- **`anchor-retention-prune.yml` fix-or-delete** â€” held for **Patch 11B-b5**. Unrelated to the dependency-reproducibility surface; bundling it would muddy the artefact.

Both are explicitly out of scope for the implementation patch this design covers (11B-b2) and for this design patch (11B-b2-a).

---

## 7. Recommended implementation shape for Patch 11B-b2

### 7.1 File plan

| File | Action |
|---|---|
| `requirements.in` | **new.** Copy the human-edited declaration content of today's `requirements.txt`, **add the six missing direct pins** (`uvicorn==0.47.0`, `psycopg[binary]==3.3.4`, `sqlalchemy[psycopg]==2.0.49`, `argon2-cffi==25.1.0`, `anthropic==0.104.1`; `alembic==1.18.4` kept pinned-but-present until 11B-b6 removes it), **remove the `httpx` line** (moves to dev), keep the comments. |
| `requirements.txt` | **regenerated** as the `pip-compile --generate-hashes` output from `requirements.in`. Full transitive closure with SHA256 hashes. **Not hand-edited.** Header comment documents the generation command. |
| `requirements-dev.txt` | **new.** Contains `pip-tools` (pinned to the operator-installed version, recorded at patch time), `httpx==0.28.1`, and `pytest` (pinned to the operator-installed version). |
| `Dockerfile` | **no change in 11B-b2.** The existing `pip install --no-cache-dir -r requirements.txt` already reads the new file. (`--require-hashes` is deferred per Â§4.2.) |
| `.github/workflows/dependency-audit.yml` | **no change in 11B-b2.** The existing `pip-audit -r requirements.txt` already audits the new file. (The optional `pip-compile --check` drift detector is held for a follow-up â€” keeps 11B-b2 minimal.) |
| `.github/workflows/anchor-rate-limit-ci.yml` | **no change in 11B-b2.** Continues to do `pip install -r requirements.txt` + ad-hoc `pip install pytest`. |
| `.github/workflows/isolation-smoke.yml` | **no change.** |
| `.github/workflows/anchor-retention-prune.yml` | **no change in 11B-b2.** Held for 11B-b5. |
| Application code | **no change.** |
| Tests | **no change.** |
| Migrations | **no change.** |
| `docs/operations/security_audits/2026-06-07_lockfile_implementation.md` (or similar dated artefact for the implementation patch) | **new** in 11B-b2. |
| `docs/operations/README.md` | reference the new artefact. |

### 7.2 Exact commands for the implementation patch

Run inside a Python 3.11 environment matching Render. Recommended container invocation (the operator runs this; **not run in this design patch**):

```powershell
docker run --rm -v "${PWD}:/work" -w /work python:3.11-slim sh -c "
  python -m pip install --upgrade pip &&
  python -m pip install pip-tools &&
  pip-compile --generate-hashes --output-file requirements.txt requirements.in &&
  pip-compile --generate-hashes --output-file requirements-dev.lock.txt requirements-dev.txt 2>/dev/null || true
"
```

(If a Linux container is not available, run `pip-compile` in a local 3.11 venv; verify the resulting hashes include `manylinux`-tagged wheels for `pydantic-core`, `psycopg-binary`, and `argon2-cffi`. A second compile from CI's Linux runner can be used to cross-check.)

The simpler operator-side flow (no Docker) for ANCHOR's solo operator:

```powershell
py -3.11 -m venv .lockenv
.\.lockenv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install pip-tools
pip-compile --generate-hashes --output-file requirements.txt requirements.in
deactivate
```

### 7.3 Validation

Inside the implementation patch (11B-b2), the operator runs:

```powershell
# 1. Fresh-install dry-run inside the 3.11 venv.
py -3.11 -m venv .verify
.\.verify\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pip check

# 2. App import.
python -c "from app.main import app; print('OK')"

# 3. Full focused test sweep.
python -m pytest -q

# 4. Trigger CI Anchor Dependency Audit workflow_dispatch and confirm PASS.
deactivate
```

### 7.4 Validation success criteria

- `pip check` reports no broken requirements.
- `from app.main import app` succeeds.
- Full pytest run is **green** (target: 1525 / 1525 passing or whatever the current baseline is at implementation time).
- CI `Anchor Dependency Audit` reports **no findings** against the new `requirements.txt`.
- Render is **not** redeployed inside Patch 11B-b2; deploy is a separate operator decision, held until the Patch 11B-b series is complete (lockfile â†’ Docker digest â†’ Actions SHAs â†’ retention-workflow fix-or-delete â†’ alembic removal).

---

## 8. Risk and rollback

### 8.1 Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | `pip-compile` resolves a transitive version that the test suite does not pass under | low | medium | Cross-check resolved versions against the `c7e4a41` Patch 11B-b1 baseline (transitive set recorded in Patch 11B-b1 Â§4). Any difference is an explicit signal. |
| R2 | Hash mismatch on Render rebuild after a future PyPI yank | low | medium | Hashes record what was on PyPI at compile time. If PyPI yanks a wheel, the next deploy fails closed â€” preferable to silently installing a different artefact. Resolved by recompiling and recording a new artefact. |
| R3 | Manylinux wheel missing from hash set due to compile on Windows | medium (if compiled on Windows) | high (Render install fails) | Compile inside `python:3.11-slim` container or in CI; spot-check hash count per package against `pip download --platform manylinux2014_x86_64` listing. |
| R4 | Lockfile drifts from `requirements.in` over time without anyone noticing | medium | low | Optional `pip-compile --check` step in `dependency-audit.yml` (deferred from 11B-b2 to keep patch narrow; can land in 11B-b2-b or 11B-b4 alongside SHA pinning). |
| R5 | Operator confused by two requirements files | low | low | `requirements.in` carries a top-of-file comment naming itself as the source of truth and `requirements.txt` as generated. |
| R6 | `pytest`'s ad-hoc CI install drifts from the `requirements-dev.txt` declaration | low | low | Tolerated in 11B-b2. CI workflow consolidation is deferred. |

### 8.2 Rollback

- **Mechanism:** `git revert` the implementation commit. Restores the pre-patch `requirements.txt` (3 direct pins, 7 unpinned, no lock). Removes `requirements.in`, `requirements-dev.txt`. Dockerfile is unchanged so nothing else needs reverting.
- **Render side:** Render builds the reverted commit using the pre-patch resolver behaviour. No setting change required.
- **Window of exposure:** the moment between landing the implementation patch and triggering a Render deploy under the new lockfile is **zero** because Patch 11B-b2 does **not** include a deploy. The first Render deploy under the lockfile is a separate operator decision.

---

## 9. Stop-condition impact

| Operational gate | Status |
|---|---|
| Dependency CVE audit (CI pip-audit) | âœ… PASS for scanned set (Patch 11D-c) |
| Dependency reproducibility | â³ **Open.** This design records the path to close it. **Patch 11B-b2 (implementation) is what actually closes it.** |
| Docker base-image digest | â³ Open â€” held for **Patch 11B-b3**. |
| GitHub Actions SHA pinning | â³ Open â€” held for **Patch 11B-b4**. |
| `anchor-retention-prune.yml` fix-or-delete | â³ Open â€” held for **Patch 11B-b5**. |
| `alembic` dead-weight removal | â³ Open â€” held for **Patch 11B-b6**. |
| `httpx<2` deprecation hygiene | â³ Open â€” optional **Patch 11B-b7**. |
| Render deploy of post-Starlette stack | â³ Open â€” operator decision; reproducibility-first sequence recommended (11B-b2 â†’ 11B-b3 â†’ 11B-b4 â†’ 11B-b5 â†’ 11B-b6 â†’ deploy). |
| Tenant Isolation Smoke #191 rate-limit | â³ Open â€” separate follow-up. |
| Legal / commercial pack per Addendum v1.3 | â³ Open â€” founder track. |

**No deploy decision is made in this patch.** No paid pilot / real-clinic-data authorisation. All standing operational stop conditions remain open until each is closed by its own dedicated patch.

---

## 10. Non-actions in this patch (11B-b2-a, design-only)

The following were **explicitly not done** in Patch 11B-b2-a:

- âŒ No dependency changed. `requirements.txt` is byte-identical to the post-Patch-11B-b1 state.
- âŒ No `requirements.in` added.
- âŒ No `requirements-dev.txt` added.
- âŒ No lockfile added or regenerated.
- âŒ No pin added or removed.
- âŒ No `pip-compile` invocation. `pip-tools` not installed.
- âŒ No `Dockerfile` change.
- âŒ No GitHub Actions change.
- âŒ No `anchor-retention-prune.yml` fix or deletion.
- âŒ No `alembic` removal.
- âŒ No `httpx` move or upgrade.
- âŒ No `.dockerignore` added.
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

What this patch **did** do: a written design covering candidate layout selection (A vs B vs C), hash strategy (H0â€“H4), dev/test split (`httpx`, `pip-tools`, `pytest`), risk and rollback posture, and the concrete file/command/validation shape for the subsequent implementation patch (11B-b2).

---

## 11. Doctrine restatement

This artefact preserves the ANCHOR doctrine: governance-first, metadata-only by default, tenant safety, RLS / FORCE RLS, human review, receipt-backed, **aligned, not compliant**. It records:

- No secrets, no clinical content, no PII, no full bearer tokens, no `DATABASE_URL`, no Render env values.
- No claim of "no risk", "fully compliant", "certified", "regulator-approved", "guaranteed safe", or "no vulnerabilities exist".
- A design document only. No code, no test, no migration, no dependency change, no production touch.

The implementation patch (11B-b2) lands separately, with its own evidence artefact in this directory.


