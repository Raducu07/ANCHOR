# ANCHOR Retention Workflow Decision — 2026-06-07

> **Decision / design only.** This artefact inventories the stale scheduled retention-prune GitHub Actions workflow (`.github/workflows/anchor-retention-prune.yml`) and records the recommended treatment ahead of implementation Patch 11B-b5-b. **No workflow changed.** No endpoint called. No dependency changed. No Dockerfile changed. No application code changed. No tests changed. No migrations changed. No migrations run. No database queried or mutated. No Render setting changed. No deploy issued. No secret read, printed, or stored. Not compliance certification. Not a regulator endorsement. Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

---

## 1. Purpose and scope

The Patch 11B-b1 inventory ([`2026-06-07_dependency_reproducibility_inventory.md`](./2026-06-07_dependency_reproducibility_inventory.md) §7) flagged `anchor-retention-prune.yml` as broken — daily-scheduled, targets a non-existent endpoint, runs with a real admin bearer. The Patch 11B-b4-a design ([`2026-06-07_github_actions_sha_pin_design.md`](./2026-06-07_github_actions_sha_pin_design.md) §2) reconfirmed it has zero `uses:` refs and explicitly held it for Patch **11B-b5**. The Patch 11B-b4-b implementation ([`2026-06-07_github_actions_sha_pin_implementation.md`](./2026-06-07_github_actions_sha_pin_implementation.md)) left it byte-identical.

This patch is the **decision step** that precedes implementation patch **11B-b5-b**. Purpose:

- Re-inventory the workflow under HEAD `55c1acc`.
- Confirm the actual backend retention surface (endpoint path, runbook posture).
- Assess operational risk of leaving the workflow as-is.
- Pick a treatment (delete / disable / repair / leave) for 11B-b5-b.

- Decision / design only.
- No workflow changed.
- No endpoint called.
- No dependency changed.
- No Dockerfile changed.
- No app / test / migration / frontend change.
- No DB queried or mutated.
- No Render change.
- No deploy.
- Not compliance certification.
- Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

Out of scope (held for later patches): `alembic` removal (Patch 11B-b6), optional `httpx<2` hygiene (Patch 11B-b7), Dockerfile explicit `--require-hashes` flag flip, any deploy decision.

---

## 2. Current workflow inventory

File: `.github/workflows/anchor-retention-prune.yml` at HEAD `55c1acc` (byte-identical to the file recorded by Patches 11B-b1, 11B-b4-a, and 11B-b4-b).

| Property | Value |
|---|---|
| File | `.github/workflows/anchor-retention-prune.yml` |
| Workflow name | `Anchor Retention Prune` |
| Triggers | `schedule: cron: "15 3 * * *"` (daily at 03:15 UTC); `workflow_dispatch: {}` |
| Schedule | **Daily 03:15 UTC** — fires automatically every day |
| Manual dispatch | Yes (`workflow_dispatch`) |
| Runner | `ubuntu-latest` (timeout 5 min) |
| Permissions block | not declared |
| Concurrency block | not declared |
| Secrets referenced (by name only) | `secrets.ANCHOR_BASE`, `secrets.ANCHOR_ADMIN_TOKEN` |
| Step name | `Call retention prune endpoint` |
| Endpoint targeted | `${ANCHOR_BASE}/v1/admin/retention/prune?days=90` |
| HTTP method | `POST` (via `curl -X POST … --fail`) |
| Request body | **None** (no `-d` payload; the call passes `days=90` only as a query-string parameter) |
| Auth header | `Authorization: Bearer ${ANCHOR_ADMIN_TOKEN}` |
| `Content-Type` header | `application/json` (set, but no body sent) |
| `curl --fail` | Yes — propagates HTTP ≥ 400 as non-zero exit (workflow turns red) |
| Success handling | `echo "Retention prune completed"` (only on `curl` exit 0) |
| Failure handling | Implicit (`set -e` + `curl --fail` ⇒ step fails ⇒ workflow run is red in the Actions tab) |
| `uses:` refs | **None** — pure `curl` script |
| SHA-pin status | **N/A** (nothing to pin) |
| Known issue | Targets `/v1/admin/retention/prune?days=90`. **That endpoint does not exist** in the codebase (see §3.1). |
| Calls production? | **Yes** — `${ANCHOR_BASE}` is the production base; `${ANCHOR_ADMIN_TOKEN}` is a real admin bearer. |
| Currently scheduled? | **Yes — fires daily.** |

---

## 3. Actual backend / runbook state

### 3.1 Endpoint inventory

Read-only `grep` across `app/` confirms exactly one prune endpoint exists.

| Probe | Result |
|---|---|
| `@router.post("/prune")` in `app/admin_intake.py` line 530 | ✅ present |
| Router prefix at `app/admin_intake.py:17` | `APIRouter(prefix="/v1/admin/intake", tags=["admin"])` |
| Composed route | **`POST /v1/admin/intake/prune`** |
| `POST /v1/admin/retention/prune` defined anywhere under `app/`? | ❌ **No matches** for `retention/prune` in any source file. The only matches across the repo are in `.github/workflows/anchor-retention-prune.yml` (the workflow itself), `docs/operations/intake_retention.md` (the runbook, naming the document), and prior audit artefacts that already flagged the mismatch (Patches 11B-b1, 11B-b4-a). |
| `POST /v1/admin/intake/prune` covered by tests? | ✅ `tests/test_admin_intake_prune.py` exists. |

**Conclusion:** the workflow's target path `/v1/admin/retention/prune` is **not a real endpoint**. The actual production retention endpoint is `POST /v1/admin/intake/prune`, defined at `app/admin_intake.py:530` and gated by `require_admin` (platform admin token via `X-ANCHOR-ADMIN-TOKEN` or `Authorization: Bearer …`).

### 3.2 Admin auth expectations

Per `app/admin_intake.py:531-535` and `docs/operations/intake_retention.md §3`:

| Property | Required value |
|---|---|
| Auth | platform admin token via header `X-ANCHOR-ADMIN-TOKEN` **or** `Authorization: Bearer <token>` |
| Default mode in prod | `db` (DB-backed token; legacy env-token mode discouraged) |
| Body shape | JSON: `{"kind": "demo|start|chat|all", "older_than_days": <int 1..3650>, "dry_run": <bool>, "confirm"?: "I-UNDERSTAND"}` |
| Extra fields | rejected (`extra: "forbid"` on the Pydantic model — any unknown field returns 422) |
| Query-string `?days=…` form | **not supported** — the request must carry a JSON body |

The workflow's `?days=90` query-string is **doubly wrong** — wrong path *and* wrong API shape. Even if the path were corrected, the body would still be missing (`POST` with no `-d` payload), which would 422 on the real endpoint.

### 3.3 Runbook posture

`docs/operations/intake_retention.md §3` records the operational doctrine for retention pruning:

| Runbook field | Value |
|---|---|
| Default mode | **Dry-run** (`dry_run: true`) |
| Destructive mode | Requires `dry_run: false` **and** `confirm: "I-UNDERSTAND"` exactly |
| Per-call hard cap | **50 000 rows** across selected kinds (409 if exceeded — refuses BEFORE any DELETE) |
| Scheduler / cron | **None. Pruning is operator-driven by design. There is no scheduled prune today.** |
| Pre-run checklist | Backup/restore drill must be PASS; production health check; deployed SHA captured; admin token from private source; no active incident; no dependent workflow on rows about to age off; reviewed dry-run; recorded founder approval for destructive runs |
| Dry-run + destructive run evidence | Captured in `§7` / `§9` per-run sub-sections; first production dry-run (`§7 Dry-run — 2026-06-07`) passed, all eligible counts zero, **no destructive prune executed** |
| Founder approval | required for every destructive call (`§5` pre-run checklist) |
| `I-UNDERSTAND` confirm literal | required for every destructive call (`§3`, `§8`) |
| Teardown / secret hygiene | `§11` — clear `$Env:ANCHOR_ADMIN_TOKEN` after every run; do not retain row content; record only counts/statuses/`X-Request-ID`/decision |
| Cadence | monthly dry-run pre-pilot; destructive monthly-or-quarterly post first destructive |

The runbook **explicitly states there is no scheduled prune today**. A daily-cron workflow exists in `.github/workflows/` that contradicts the runbook — but the workflow doesn't actually do anything destructive because its target endpoint doesn't exist. The workflow merely **fails 404 every day at 03:15 UTC with a real admin bearer in the request headers**.

---

## 4. Risk assessment

### 4.1 What the workflow does today

The workflow fires `POST https://anchor-api-prod.onrender.com/v1/admin/retention/prune?days=90` with header `Authorization: Bearer <real ANCHOR_ADMIN_TOKEN>` every day at 03:15 UTC. The actual ANCHOR backend has no such route, so FastAPI's router returns **404 Not Found** before any handler runs. `curl --fail` propagates the 404 as exit code 22; `set -e` aborts the step; the workflow run goes red. The Actions tab shows a red `Anchor Retention Prune` daily.

### 4.2 Risk summary

| # | Risk | Likelihood | Impact | Notes |
|---|---|---|---|---|
| R1 | **Operational noise.** A red workflow fires daily. Real failures lose signal when the Actions tab is permanently red on this workflow. | high (already happening) | low — alert fatigue, not data loss | Recommended: delete or disable. |
| R2 | **Admin bearer transmitted daily over the wire.** Every cron firing sends a real admin token to production in an `Authorization: Bearer` header. TLS terminates at Render; the token is masked in CI logs by GitHub Actions' default secret masking; but the surface area is non-zero. | high (every day) | low (TLS + masking) but non-zero | Either delete (token never sent) or disable schedule (token only sent on manual dispatch). |
| R3 | **Mismatch with the operational doctrine in `intake_retention.md §3`.** The runbook records the source of truth as operator-driven; a scheduled workflow contradicts that without going through the runbook's pre-run checklist, dry-run discipline, founder approval, evidence capture, or `I-UNDERSTAND` confirm literal. | high (every day the workflow exists) | medium — contradicts evidence-backed posture | Recommended: delete; preserve the runbook as the only retention path. |
| R4 | **Accidental destructive run** if the workflow is "fixed" naively. Someone reading the failing cron could "repair" it by repointing the URL at `/v1/admin/intake/prune` and adding `kind=all&older_than_days=90` to the query string — which would still fail on the new endpoint (wrong shape: missing JSON body, missing `dry_run`/`confirm`), but the next "fix" attempt could add a body. **A daily scheduled destructive prune with no founder approval, no recorded dry-run, no `I-UNDERSTAND` discipline, and no evidence capture would violate the runbook on every call.** | medium — the repair temptation exists every time someone sees the red workflow | high — bypasses every documented safety control | Recommended: delete; reintroduction must go through `§7` future-criteria. |
| R5 | **False confidence.** A future reader of `.github/workflows/` could conclude "ANCHOR has scheduled retention pruning" without realising the workflow has never actually pruned anything. | medium | medium — misleads readers | Recommended: delete; documentation is the single source of truth. |
| R6 | **Silent vs noisy failure mode.** Today the workflow fails noisily (404 + red). If `ANCHOR_BASE` or `ANCHOR_ADMIN_TOKEN` secrets were ever rotated wrong, the failure mode would still be noisy — but the noise is unrelated to retention work and competes with real signal. | high | low | Recommended: delete; remove the noise. |
| R7 | **Open operational gates.** Until the broader operational stack is closed (paid pilot blocked, real clinic data blocked), a scheduled production-mutating job has no business firing at all. | high | medium | Recommended: delete; reintroduce only with a fresh design after the operational gates are cleared. |

### 4.3 Net assessment

The current workflow has **no upside** (its target endpoint doesn't exist; it has never successfully pruned anything; the runbook records the only valid retention path as operator-driven) and **non-trivial downside** (daily bearer transmission, daily red noise, future-repair-temptation, runbook contradiction). It should not remain scheduled.

---

## 5. Options assessed

| Option | Description | Safety | Operational simplicity | Risk of accidental production mutation | Alignment with runbook | CI / noise impact | Future reintroduction path | Solo-operator practicality |
|---|---|---|---|---|---|---|---|---|
| **A** | **Delete** `.github/workflows/anchor-retention-prune.yml` entirely in Patch 11B-b5-b. | highest — no bearer transmitted, no scheduled call | high — single file deletion, no replacement | none — workflow no longer exists | full alignment — `§3` says "no scheduled prune today" | red workflow disappears from Actions tab | reintroduce later only via a fresh workflow file with the §7 future criteria recorded against it | high |
| **B** | **Disable schedule, keep `workflow_dispatch`** by removing the `schedule:` block but leaving the rest of the file. | medium — bearer still transmitted on manual dispatch; broken target endpoint still present | medium — the file remains and still calls a non-existent endpoint; future operator might trust it and dispatch it manually | low (a manual run still 404s) | partial alignment — removes the cron but leaves a misleading manual control | red workflow stops daily-failing | reintroduce by editing the same file (which carries the runbook contradiction in its history) | medium |
| **C** | **Repair** the target endpoint to `/v1/admin/intake/prune`, keep the daily schedule. | low — daily destructive call against production with no dry-run, no founder approval, no `I-UNDERSTAND`, no evidence template | low — complex change touching scheduling + endpoint + body shape | **high** — would actually delete rows daily against production | **none** — directly contradicts `intake_retention.md §3` ("no scheduled prune today") and `§5` pre-run checklist | red disappears, replaced by a daily destructive job no one approved | n/a — would have to be torn down to align with runbook | low |
| **D** | **Repair** to `/v1/admin/intake/prune` **and** make it manual-only (`workflow_dispatch:` only, dry-run-only by default). | medium — bearer transmitted on manual dispatch; manual control duplicates the runbook's PowerShell flow without the evidence template | medium — adds a second way to call the endpoint that doesn't capture evidence; the PowerShell runbook flow already exists and is the supported path | low | partial — the runbook is still the source of truth; the workflow becomes a redundant call surface | red disappears | n/a — duplicates the runbook | low |
| **E** | **Leave unchanged**, document as known broken, accept daily red. | low — daily bearer transmission, daily noise, future-repair-temptation, runbook contradiction | high (no change) | none — workflow still 404s | n/a — contradicts the runbook | red workflow continues daily-failing | n/a | n/a — accumulates technical debt |

**Recommendation: Option A — delete the workflow entirely.**

Reasons:

- **Aligns with the runbook.** `intake_retention.md §3` is the source of truth: "Scheduler / cron: **None.** Pruning is operator-driven by design." The workflow contradicts this; deletion removes the contradiction.
- **Eliminates the daily bearer transmission and the daily red noise.** Both have zero upside (no successful prune has ever happened).
- **Removes the future-repair-temptation in R4.** A file that doesn't exist can't be naively "fixed" into a daily destructive prune.
- **Preserves manual retention pruning** — the runbook (`§6`–`§11`) is the active control and remains untouched.
- **Smallest possible diff** — single file deletion, single artefact creation, single README update.
- **Reintroduction is cheap** — if scheduled pruning is ever wanted, a new workflow with explicit dry-run-first semantics and a documented founder-approval gate can be added later (see §7 below).

Options B and D would leave a manual control that duplicates the runbook without adding value; Option C would actively contradict the runbook's safety controls; Option E does nothing.

---

## 6. Recommended Patch 11B-b5-b

### 6.1 Implementation shape

**Delete** `.github/workflows/anchor-retention-prune.yml`. Single-file deletion, no replacement.

### 6.2 Files that change in 11B-b5-b

| File | Action |
|---|---|
| `.github/workflows/anchor-retention-prune.yml` | **deleted** |
| `docs/operations/security_audits/2026-06-07_retention_workflow_implementation.md` (or similar dated artefact for the implementation patch) | **new** — records the deletion |
| `docs/operations/README.md` | **modified** — append index entry for the implementation artefact |

No other files change. No application code change, no `Dockerfile` change, no other workflow change, no dependency change, no test change, no migration change. **The retention runbook `docs/operations/intake_retention.md` already records the operator-driven posture and does not need modification.**

### 6.3 Validation steps for 11B-b5-b

1. `git diff --check` — clean.
2. `git status --short` — exactly the three entries above (one deletion, one modification, one new file).
3. `Get-ChildItem .github\workflows -File` — confirm only three workflow files remain (`anchor-rate-limit-ci.yml`, `dependency-audit.yml`, `isolation-smoke.yml`).
4. `Select-String -Path .github\workflows\*.yml -Pattern "retention/prune|intake/prune"` — should return zero matches.
5. **Post-commit/push:** confirm the daily red `Anchor Retention Prune` run on 2026-06-08 03:15 UTC does **not** fire. The workflow file is gone, so GitHub Actions has nothing to schedule.
6. Normal push workflows (`Anchor Rate Limit CI`, `Tenant Isolation Smoke Test`) must still go green on the commit.
7. `Anchor Dependency Audit` remains `workflow_dispatch:` only and must not auto-run.

### 6.4 Post-push GitHub Actions expectation

After the deletion lands:

- The `Anchor Retention Prune` workflow entry should disappear from the Actions tab (GitHub Actions removes workflows whose YAML files no longer exist on the default branch).
- No further scheduled run will appear.
- Manual `workflow_dispatch` is unavailable for the deleted workflow (the dropdown entry is gone).

If the operator later wants scheduled retention, see §7.

---

## 7. Future reintroduction criteria

Scheduled retention pruning can be reintroduced later **only when all** of the following are met:

1. **Correct endpoint.** A new workflow must target `POST /v1/admin/intake/prune` with a JSON body, **not** the legacy `?days=N` query-string form. The body must match the Pydantic model (`{"kind": …, "older_than_days": …, "dry_run": …, "confirm"?: "I-UNDERSTAND"}`) and the `extra: "forbid"` strictness.
2. **Dry-run-first semantics are explicit.** The first scheduled mode must be `dry_run: true`. Destructive scheduled runs require an additional gate (see 3).
3. **Destructive action requires an intentional gate.** A scheduled destructive prune must not be possible without an explicit founder-recorded approval — e.g. a separate workflow that is `workflow_dispatch:` only with an `inputs:` confirmation field, or a feature flag the operator flips for the day, or any other explicit gate. **`confirm: "I-UNDERSTAND"` must not be hardcoded into a scheduled YAML file.**
4. **Evidence capture is documented.** A scheduled prune must write evidence comparable to `intake_retention.md §7` / `§9`: kind, cutoff, counts, deleted, response status, `X-Request-ID`, decision (PASS/FAIL/INCONCLUSIVE), founder-approval reference for destructive runs. The capture path can be a GitHub Actions job artifact, an audit-event row, or both.
5. **Rate-limit and admin-auth expectations confirmed.** Before the first scheduled run, the operator must confirm that the admin-bearer used by the workflow does not interact with the `Tenant Isolation Smoke Test #191` rate-limit follow-up, and that the bearer mode in production (`ANCHOR_ADMIN_MODE=db`) supports the workflow's token source.
6. **First scheduled run is monitored.** The first scheduled firing is operator-monitored in real time and the evidence path is verified before the schedule is allowed to fire unattended.

Until all six are recorded against a fresh workflow with its own evidence artefact, scheduled retention does not return.

---

## 8. Stop-condition impact

| Operational gate | Status after this decision patch |
|---|---|
| Dependency / CVE audit (CI pip-audit) | ✅ PASS for the locked scanned dependency set ([`2026-06-07_post_lockfile_ci_audit.md`](./2026-06-07_post_lockfile_ci_audit.md), run `#4` against `32e9b94`). |
| Dependency-file reproducibility | ✅ Closed by Patch 11B-b2-b. |
| Docker base-image digest pin | ✅ Closed by Patch 11B-b3-b. |
| GitHub Actions SHA pinning | ✅ Closed at the file layer by Patch 11B-b4-b. |
| **Retention workflow treatment** | ⏳ **Open.** This patch records the decision (delete). **Patch 11B-b5-b is what actually closes it.** |
| Dockerfile explicit `--require-hashes` flag | ⏳ Open — deferred. |
| `alembic` dead-weight removal | ⏳ Open — held for **Patch 11B-b6**. |
| Optional `httpx<2` deprecation hygiene | ⏳ Open — optional **Patch 11B-b7**. |
| `github-actions` Dependabot SHA-refresh cadence | ⏳ Open — additive hygiene, separate follow-up. |
| Render deploy of post-Starlette + lockfile + digest + Actions-SHA stack | ⏳ Open — operator decision. Reproducibility-first sequence still recommended (retention workflow delete → alembic removal → deploy). |
| Tenant Isolation Smoke #191 rate-limit | ⏳ Open — separate follow-up. |
| Legal / commercial pack per Addendum v1.3 | ⏳ Open — founder track. |

Deleting the stale workflow **improves operational safety** (removes daily bearer transmission, removes runbook contradiction, removes future-repair-temptation) but **does not complete all operational gates** — `alembic` removal and the deploy decision remain ahead. **Dependency / CVE audit remains PASS** for the locked scanned set. **Docker base digest pin is complete.** **GitHub Actions SHA pin is complete.** **No deploy decision made by this patch.** **Paid pilot / real clinic data remains blocked** by the standing operational gates.

---

## 9. Non-actions in this patch

The following were **explicitly not done** in Patch 11B-b5-a:

- ❌ No workflow change. (`anchor-retention-prune.yml` is byte-identical to the file at HEAD `55c1acc`.)
- ❌ No workflow deletion. (Implementation deletion is **held for Patch 11B-b5-b**.)
- ❌ No workflow disable.
- ❌ No workflow repair / endpoint rewrite.
- ❌ No `intake_retention.md` change. (The runbook already records the operator-driven posture and is unchanged.)
- ❌ No other workflow change.
- ❌ No dependency change. `requirements.in`, `requirements.txt`, `requirements-dev.txt` byte-identical.
- ❌ No Dockerfile change.
- ❌ No application code change.
- ❌ No test change.
- ❌ No migration change.
- ❌ No migrations run.
- ❌ No database query or mutation.
- ❌ No Render setting change.
- ❌ No deploy.
- ❌ No frontend touch.
- ❌ No production endpoint call. (Did not invoke `/v1/admin/intake/prune` or `/v1/admin/retention/prune`; both probes were code/doc reads only.)
- ❌ No secret value read, printed, stored, or pasted. (Secret names appear by name only — `secrets.ANCHOR_BASE`, `secrets.ANCHOR_ADMIN_TOKEN` — never values.)
- ❌ No commit. No push. (Per scope.)
- ❌ No compliance / certification / regulator-approval claim.
- ❌ No paid-pilot or real-clinic-data authorisation.

What this patch **did** do: re-inventoried `.github/workflows/anchor-retention-prune.yml` at HEAD `55c1acc`; confirmed the actual backend retention endpoint (`POST /v1/admin/intake/prune` in `app/admin_intake.py:530`) and that the workflow's target path (`/v1/admin/retention/prune`) is not defined anywhere in the codebase; reconfirmed the runbook's "no scheduled prune today" doctrine in `intake_retention.md §3`; assessed five treatment options against safety, alignment with the runbook, and operational simplicity; **recommended Option A (delete)** for Patch 11B-b5-b; recorded reintroduction criteria so future scheduled retention does not regress on the doctrine the deletion closes; and updated the operations README.
