# ANCHOR `/v1/version` Build Metadata Design — 2026-06-08

> **Design only.** This artefact records the inventory and design for improving `/v1/version` build metadata observability in advance of implementation Patch **11B-b8-b**. **No code changed.** No tests changed. No dependency changed. No Dockerfile changed. No workflow changed. No migration changed. No DB queried or mutated. No production endpoint called in this patch. No Render API call. No Render setting change. No deploy issued. No secret read, printed, or stored. Not compliance certification. Not a regulator endorsement. Not a claim that ANCHOR is secure, compliant, certified, vulnerability-free, RCVS-approved, or regulator-endorsed.

---

## 1. Purpose and scope

The post-remediation Render deploy smoke ([`2026-06-08_render_deploy_smoke_cd9d966.md`](./2026-06-08_render_deploy_smoke_cd9d966.md)) recorded an observability gap: `GET /v1/version` returns `env=prod` correctly, but `git_sha` and `build` are `null` even though Render's dashboard separately shows the deployed commit (`cd9d966`). This is **not** a smoke failure — liveness, env identification, and route protection all work — but it removes a useful audit field. The deployed commit is the most informative single piece of metadata a smoke caller can capture into a deploy log.

This patch is the **design step** that precedes implementation Patch **11B-b8-b**. Purpose:

- Inventory the existing `/v1/version` route and the env vars it already attempts to read.
- Reconcile with `env.md`'s current claim about Render auto-injection.
- Decide the smallest safe way to populate the metadata.
- Record risk and rollback.

- Design only.
- No code changed.
- No tests changed.
- No dependency changed.
- No Dockerfile changed.
- No workflow changed.
- No migration changed.
- No DB queried or mutated.
- No production endpoint called in this patch.
- No Render API call.
- No Render setting change.
- No deploy.
- Not compliance certification.
- Not a claim that ANCHOR is secure, compliant, certified, vulnerability-free, RCVS-approved, or regulator-endorsed.

**Out of scope** (held for later patches): optional `httpx<2` deprecation hygiene (Patch 11B-b7), Dockerfile explicit `--require-hashes` flag flip, base-image digest refresh cadence, `.github/dependabot.yml`, any deploy decision, any paid pilot / real clinic data authorisation, legal / commercial pack work.

---

## 2. Triggering observation

Reference: [`2026-06-08_render_deploy_smoke_cd9d966.md`](./2026-06-08_render_deploy_smoke_cd9d966.md) (Patch 11B-b6-d).

- `GET /v1/version` returned `env=prod` (correct).
- `git_sha=null` (gap).
- `build=null` (gap).
- Render dashboard separately showed `Deploy live for cd9d966`, so the deployed commit is known on the Render side; it is simply not surfaced through the API.
- **Not a liveness or access-control failure.** Observability gap only.
- An operator's deploy log per `env.md §13` is expected to capture the `env` and `git_sha` fields from `/v1/version`; today only `env` is populated.

---

## 3. Current implementation inventory

### 3.1 Route definition

File: `app/main.py`, lines **410–418**:

```python
@app.get("/v1/version")
def version():
    return {
        "name": "ANCHOR API",
        "env": get_app_env(),
        "git_sha": os.getenv("GIT_SHA", None),
        "build": os.getenv("BUILD_ID", None),
        "now_utc": utc_iso(),
    }
```

### 3.2 Current response schema

| Field | Type | Source |
|---|---|---|
| `name` | string | hardcoded `"ANCHOR API"` |
| `env` | string | `get_app_env()` — reads `ANCHOR_ENV` via `app/env_runtime.py` (currently `"prod"` in production) |
| `git_sha` | string \| null | `os.getenv("GIT_SHA")` — currently `null` in production because no `GIT_SHA` env var is set on Render |
| `build` | string \| null | `os.getenv("BUILD_ID")` — currently `null` in production for the same reason |
| `now_utc` | string | `utc_iso()` — server time at request, ISO-8601 |

### 3.3 Env vars currently read

| Var | Read at | Currently set on Render? | Notes |
|---|---|---|---|
| `GIT_SHA` | `app/main.py:415` | **No** (confirmed null by smoke) | The code already expects this; it just isn't populated. |
| `BUILD_ID` | `app/main.py:416` | **No** (confirmed null by smoke) | Same. |
| `ANCHOR_ENV` (via `get_app_env()`) | indirectly | Yes — returns `"prod"` on Render | Not part of this design's scope. |

### 3.4 Existing tests

Grep `tests/` for `/v1/version`, `GIT_SHA`, `BUILD_ID`, `RENDER_GIT_COMMIT` — **no matches**. There is no test that asserts the `/v1/version` response shape or the env-var behaviour.

### 3.5 Existing docs

| Source | Line | Content | Accuracy |
|---|---|---|---|
| `docs/operations/env.md` | 56 | "`APP_VERSION` / `GIT_SHA` / `BUILD_ID` — Surfaced in every log line and in `/v1/version`. unset → omitted from response/logs. Render injects `GIT_SHA` automatically when the build is from a Git repo." | **The Render auto-injection claim is empirically false.** Production smoke confirms `GIT_SHA` is unset on Render. The auto-injected variable Render actually exposes is `RENDER_GIT_COMMIT` (a separate name). This needs an env-doc correction in the implementation patch. |
| `docs/operations/env.md` | 257 | "Capture into the deploy log: status codes, the `X-Request-ID` header from each response, and the `env`/`git_sha` fields from `/v1/version`." | Accurate as guidance — operator should capture these fields — but `git_sha` is currently always null in prod, defeating the purpose. |
| `docs/operations/intake_retention.md` `§5` / `§7` | various | Pre-run checklist asks the operator to note the "Deployed git SHA at call time" read from `/v1/version`'s `git_sha` field. | Same problem — the field is always null today, so the operator must use the Render dashboard as the source of truth. The implementation patch unblocks this. |
| `docs/operations/backup_restore.md` | (referenced for deploy-log usage) | Similar pattern. | Same. |
| `docs/operations/security_audits/2026-06-07_post_starlette_ci_audit.md` | (informational reference) | Cross-reference only. | n/a |

The runbooks **already assume `/v1/version.git_sha` is meaningful**. The implementation patch makes that assumption true.

---

## 4. Options assessed

| Option | Description | Safety | Render compat | Docker / image reproducibility | Secret-leak risk | Testability | Deploy-smoke usefulness | Operational simplicity |
|---|---|---|---|---|---|---|---|---|
| **A** | Read explicit app env vars only — `GIT_SHA` + `BUILD_ID`. Operator (or `render.yaml`) must wire these explicitly. | high | yes — but requires a Render dashboard env-var setup step **or** a `render.yaml` update | unchanged | none | easy — `monkeypatch.setenv` | high — but only after a separate Render-side step | medium — couples the patch to an out-of-band Render config action |
| **B** | Read `GIT_SHA` first, then fall back to **`RENDER_GIT_COMMIT`** (Render's actual auto-injected variable). Keep `BUILD_ID` with `None` fallback. | high | **yes — Render auto-injects `RENDER_GIT_COMMIT` for every build from a Git repo** | unchanged | none — both var names are non-secret build metadata | easy — `monkeypatch.setenv` covers both names | **high immediately** — works on the next Render rebuild with no Render setting change | high — single-file code change + tests + env-doc correction |
| **C** | Bake build args into Dockerfile using `ARG` / `ENV`. | high | needs the build to pass the SHA as a `--build-arg`; Render's image-build flow doesn't expose this by default | the digest pin from Patch 11B-b3-b stays valid because `ARG`/`ENV` don't change the FROM line | none | easy | medium — depends on the build pipeline | medium — adds a Dockerfile concept; conflicts with the recently-pinned image semantics |
| **D** | Shell out to `git rev-parse HEAD` at runtime. | **low** — would require a git installation in the runtime image and a `.git` directory on disk, neither of which exists in the deployed slim image | n/a | breaks reproducibility intent (the runtime container isn't a git checkout) | low | hard to test deterministically | n/a | low |
| **E** | Keep current `null` fields and document Render dashboard as the source of truth. | high (no change) | unchanged | unchanged | none | n/a | **low** — leaves the observability gap open; operator must cross-reference Render dashboard for every smoke | high (no change) |

**Recommendation: Option B.**

Reasons:

- **Render auto-injects `RENDER_GIT_COMMIT` for every Git-repo-backed deploy** — confirmed by Render's public documentation; the explicit production smoke result (`git_sha=null` when reading `GIT_SHA`) implicitly confirms the variable name mismatch.
- **Zero Render setting change required.** The fallback works on the next Render rebuild without any dashboard action.
- **Schema-stable.** The `/v1/version` response shape stays identical; only the value of `git_sha` changes from `null` to the deployed commit's full SHA when Render is the runtime.
- **`GIT_SHA` retained as the first-precedence source** so operator-set explicit overrides (and any future non-Render runtime) continue to work.
- **`BUILD_ID` retained as-is** with `None` fallback. Render doesn't expose a separate "build id" semantically distinct from the commit SHA; keeping `BUILD_ID` null in prod is honest reporting. (An operator can still set `BUILD_ID` explicitly via Render env vars if they want — but the patch doesn't require it.)
- **Testable** with `monkeypatch.setenv` / `monkeypatch.delenv` and `TestClient.get("/v1/version")`; no DB, no external call.
- **Reversible** by `git revert`.

Option A is technically equivalent end-to-end but requires a separate Render-side env-var setup step; B avoids that. Option C couples the metadata fix to Dockerfile semantics that the digest-pin patch deliberately froze. Option D is unsafe in the slim runtime image and breaks the reproducibility intent. Option E leaves the gap open.

---

## 5. Recommended Patch 11B-b8-b

### 5.1 Implementation shape

**Single file edit** in `app/main.py`:

- Replace `os.getenv("GIT_SHA", None)` with a precedence chain: `os.getenv("GIT_SHA") or os.getenv("RENDER_GIT_COMMIT")` — preserves the `None` semantics when both are absent (`or` short-circuits on the empty string and on `None`; an unset env var returns `None` from `os.getenv`).
- `os.getenv("BUILD_ID", None)` **unchanged** — Render doesn't inject a build-id concept distinct from the commit SHA; the operator can still set `BUILD_ID` explicitly via Render env vars if desired.

Final shape (illustrative — Patch 11B-b8-b applies it):

```python
@app.get("/v1/version")
def version():
    return {
        "name": "ANCHOR API",
        "env": get_app_env(),
        "git_sha": os.getenv("GIT_SHA") or os.getenv("RENDER_GIT_COMMIT"),
        "build": os.getenv("BUILD_ID", None),
        "now_utc": utc_iso(),
    }
```

### 5.2 Files that change in 11B-b8-b

| File | Action |
|---|---|
| `app/main.py` | **modified** — one-line change to `git_sha` assignment in `version()`; everything else byte-identical. |
| `tests/test_version_endpoint.py` (new) | **new** — pytest module covering the fallback precedence (see §5.3). |
| `docs/operations/env.md` | **modified** — correct the `GIT_SHA` row (line 56) to record the actual Render-auto-injected variable (`RENDER_GIT_COMMIT`) and the fallback precedence; keep the `BUILD_ID` row truthful (no Render auto-injection). |
| `docs/operations/security_audits/2026-06-08_version_metadata_implementation.md` (new) | **new** — implementation evidence artefact. |
| `docs/operations/README.md` | **modified** — append index entry. |

No `requirements.in` / `requirements.txt` / `requirements-dev.txt` / `Dockerfile` / `.github/workflows/*` / `migrations/*` / frontend change.

### 5.3 Test additions

A new `tests/test_version_endpoint.py` covering at least the four `git_sha` precedence cases:

| Test case | Setup | Expected `git_sha` value |
|---|---|---|
| Both env vars unset | `monkeypatch.delenv("GIT_SHA", raising=False)` + `monkeypatch.delenv("RENDER_GIT_COMMIT", raising=False)` | `null` (JSON `None`) |
| Only `RENDER_GIT_COMMIT` set | `monkeypatch.setenv("RENDER_GIT_COMMIT", "abc1234…")` + `delenv("GIT_SHA")` | `"abc1234…"` |
| Only `GIT_SHA` set | `monkeypatch.setenv("GIT_SHA", "deadbeef…")` + `delenv("RENDER_GIT_COMMIT")` | `"deadbeef…"` |
| Both set | both `setenv` | `"deadbeef…"` (the `GIT_SHA` value wins — `GIT_SHA` takes precedence) |

Optionally a fifth case for `BUILD_ID` (unset → `null`; set → echoes the value); and a smoke assertion that `env`, `name`, and `now_utc` shapes remain stable.

No DB, no admin auth, no clinic auth, no rate limiter required — `TestClient(app).get("/v1/version")` is sufficient.

### 5.4 Documentation update (`env.md`)

Replace the line-56 row's claim. New text (illustrative):

> `APP_VERSION` / `GIT_SHA` / `BUILD_ID` — Surfaced in every log line and in `/v1/version`. unset → field becomes `null` in the response. `/v1/version.git_sha` reads `GIT_SHA` first, then falls back to **`RENDER_GIT_COMMIT`** (the variable Render automatically injects for every Git-repo-backed deploy). `BUILD_ID` has no Render auto-injection equivalent and remains `null` unless explicitly set.

### 5.5 Deploy / smoke expectations

- Local validation: clean 3.11 venv, `pip install -r requirements.txt -r requirements-dev.txt`, `pip check`, `from app.main import app` returns `IMPORT OK`, the new `tests/test_version_endpoint.py` passes, full pytest sweep remains at 1525-passing baseline (now +N for the new module).
- **No deploy is part of Patch 11B-b8-b.**
- The **next** Render deploy (whenever that happens, by separate operator decision) will populate `/v1/version.git_sha` from Render's `RENDER_GIT_COMMIT` auto-injection — no Render dashboard env-var change needed.
- A follow-up post-deploy smoke artefact (analogous to `2026-06-08_render_deploy_smoke_cd9d966.md`) will record the populated `git_sha` once a deploy occurs.

---

## 6. Risk and rollback

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Render changes its auto-injected env var name in the future. | very low — `RENDER_GIT_COMMIT` is a long-standing public variable | low | `GIT_SHA` remains the first-precedence source, so an operator override always wins. Bump the fallback in a small future patch if Render renames. |
| R2 | `RENDER_GIT_COMMIT` leaks something secret. | none — it is a public commit SHA from a public-or-private Git repo, identical in shape to what `/v1/version` already attempted to surface; no token, no credential, no PII | low | n/a |
| R3 | The `or` short-circuit treats an explicitly empty `GIT_SHA` as "fall through". | low | low | Documented as intended behaviour; an operator who sets `GIT_SHA=""` evidently wants the fallback. |
| R4 | A non-Render runtime that sets neither var sees `null` (the current state). | medium | low — behaviour-preserving | This is the intentional fallback; nothing regresses. |
| R5 | The new test module asserts behaviour that a future refactor changes. | low | low | The test is small and explicit; future refactors must justify the change. |

### 6.1 Rollback

**Mechanism:** `git revert` the Patch 11B-b8-b commit restores the prior one-line `git_sha` read, the unchanged `env.md` text, and removes the new test module. **No Render-side or workflow-side configuration change required.**

**Window of exposure:** zero. The patch does not include a deploy; the first Render deploy after the patch is a separate operator decision.

---

## 7. Stop-condition impact

| Operational gate | Status after this design patch |
|---|---|
| Dependency / CVE audit (CI pip-audit) | ✅ PASS for the post-Alembic 34-package locked scanned dependency set (run `#5` against `de966a9`). |
| Dependency-file reproducibility | ✅ Closed by Patch 11B-b2-b. |
| Docker base-image digest pin | ✅ Closed by Patch 11B-b3-b. |
| GitHub Actions SHA pinning | ✅ Closed by Patch 11B-b4-b. |
| Stale retention workflow removal | ✅ Closed by Patch 11B-b5-b. |
| Alembic dead-weight removal | ✅ Closed by Patch 11B-b6-b. |
| First Render rebuild under post-remediation stack | ✅ Live at `cd9d966` + smoke PASS (Patch 11B-b6-d). |
| **`/v1/version` build metadata** | ⏳ **Open.** This patch records the design. **Patch 11B-b8-b is what actually closes it.** |
| Dockerfile explicit `--require-hashes` flag | ⏳ Open — now eligible to flip (design posture H4 condition met). |
| Optional `httpx<2` deprecation hygiene | ⏳ Open — optional **Patch 11B-b7**. |
| `github-actions` Dependabot SHA-refresh cadence | ⏳ Open — additive hygiene. |
| Base-image digest refresh cadence | ⏳ Open — operational hygiene item. |
| Render deploy of the post-metadata-fix stack | ⏳ Held until Patch 11B-b8-b lands and is operator-validated locally. |
| Tenant Isolation Smoke #191 rate-limit | ⏳ Open — separate follow-up. |
| Legal / commercial pack per Addendum v1.3 | ⏳ Open — founder track. |

This patch is an **observability improvement** for future production smoke. It does **not change security posture, dependency posture, RLS, tenant isolation, or governance behaviour**. It does **not authorise paid pilot or real clinic data**. **Live Workspace generation remains production-off**.

---

## 8. Non-actions in this patch

The following were **explicitly not done** in Patch 11B-b8-a:

- ❌ No `app/main.py` change.
- ❌ No test file added or modified.
- ❌ No `requirements.in` / `requirements.txt` / `requirements-dev.txt` change.
- ❌ No Dockerfile change.
- ❌ No GitHub Actions change.
- ❌ No migration change.
- ❌ No migrations run.
- ❌ No `env.md` change. (Documentation correction is held for Patch 11B-b8-b.)
- ❌ No other runbook change.
- ❌ No database query or mutation.
- ❌ No production endpoint call in this patch. (The triggering observation references the smoke executed under Patch 11B-b6-d; no new HTTP call is made by this design patch.)
- ❌ No Render API call.
- ❌ No Render setting change.
- ❌ No deploy.
- ❌ No frontend touch.
- ❌ No live Workspace generation enabled.
- ❌ No secret value read, printed, stored, or pasted.
- ❌ No commit. No push. (Per scope.)
- ❌ No compliance / certification / regulator-approval / RCVS-approval claim.
- ❌ No paid-pilot or real-clinic-data authorisation.

What this patch **did** do: located `/v1/version` in `app/main.py:410-418`, confirmed it already reads `GIT_SHA` and `BUILD_ID` (so the prod nulls reflect unset env vars, not missing code), confirmed `docs/operations/env.md:56` carries an empirically-false claim about Render auto-injecting `GIT_SHA`, confirmed zero tests exist for `/v1/version`, assessed five implementation options against safety / Render compatibility / image reproducibility / secret-leak risk / testability / deploy-smoke usefulness / operational simplicity, **recommended Option B** (in-code fallback to `RENDER_GIT_COMMIT` for `git_sha`, no Render setting change needed), recorded the exact file plan / test matrix / `env.md` correction / risk / rollback / stop-condition implications for the implementation patch, and updated the operations README.
