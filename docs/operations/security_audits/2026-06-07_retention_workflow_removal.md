# ANCHOR Retention Workflow Removal — 2026-06-07

> **Implementation artefact for Patch 11B-b5-b.** Deletes the stale scheduled retention-prune GitHub Actions workflow. **Workflow removal only.** No replacement scheduled workflow added. No endpoint called. No dependency changed. No Dockerfile changed. No application code changed. No tests changed. No migrations changed. No migrations run. No database queried or mutated. No Render setting changed. No deploy issued. No secret read, printed, or stored. Not compliance certification. Not a regulator endorsement. Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

---

## 1. Purpose and scope

The Patch 11B-b5-a decision artefact ([`2026-06-07_retention_workflow_decision.md`](./2026-06-07_retention_workflow_decision.md)) recommended **Option A — delete** `.github/workflows/anchor-retention-prune.yml`. This implementation patch applies that decision.

- This artefact records deletion of the stale retention-prune GitHub Actions workflow.
- Workflow removal only.
- **No replacement scheduled workflow added.**
- No endpoint called.
- No dependency changed.
- No Dockerfile changed.
- No app / test / migration / frontend change.
- No DB queried or mutated.
- No Render change.
- No deploy.
- Not compliance certification.
- Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

**Out of scope** (held for later patches): `alembic` dead-weight removal (Patch **11B-b6**), optional `httpx<2` deprecation hygiene (Patch **11B-b7**), Dockerfile explicit `--require-hashes` flag flip, future `github-actions` Dependabot configuration, any deploy decision.

---

## 2. Source decision

Reference: [`2026-06-07_retention_workflow_decision.md`](./2026-06-07_retention_workflow_decision.md) (Patch 11B-b5-a).

Summary of the decision rationale (re-confirmed at HEAD `d88e559`):

- The stale workflow targeted **non-existent** `POST /v1/admin/retention/prune?days=90`.
- The actual backend retention endpoint is **`POST /v1/admin/intake/prune`** (`app/admin_intake.py:530`; router prefix `/v1/admin/intake` at `app/admin_intake.py:17`).
- The actual endpoint expects a **JSON body** (`{"kind", "older_than_days", "dry_run", "confirm"?}`) with `extra: "forbid"`, **not** a query-string `?days=N` form.
- The operator runbook `docs/operations/intake_retention.md §3` records: **"Scheduler / cron: None. Pruning is operator-driven by design. There is no scheduled prune today."** The workflow directly contradicted that doctrine.
- The workflow's only real-world behaviour was to fail 404 daily while transmitting a real `ANCHOR_ADMIN_TOKEN` bearer to production over TLS.
- Five treatment options were assessed (delete / disable / repair + schedule / repair + manual-only / leave). Deletion was recommended because every alternative left a misleading or contradictory control surface.

---

## 3. Change made

### 3.1 Deletion

| File | Action |
|---|---|
| `.github/workflows/anchor-retention-prune.yml` | **deleted** (`git rm`) |

No replacement scheduled workflow added. No file modified inside `.github/workflows/`.

### 3.2 Remaining workflows

Three workflow files remain under `.github/workflows/`:

| File | Workflow name | Triggers (unchanged) |
|---|---|---|
| `anchor-rate-limit-ci.yml` | `Anchor Rate Limit CI` | `push: branches:[main]`, `pull_request`, `workflow_dispatch` |
| `dependency-audit.yml` | `Anchor Dependency Audit (pip-audit)` | `workflow_dispatch:` only (restored in Patch 11B-b2-c) |
| `isolation-smoke.yml` | `Tenant Isolation Smoke Test` | `push: branches:[main]`, `pull_request: branches:[main]`, `workflow_dispatch` |

All three remain byte-identical to the post-Patch-11B-b4-b state. Their SHA-pinned `uses:` refs (Patch 11B-b4-b) are unchanged.

The `intake_retention.md` operator runbook is **unchanged** — it already records the operator-driven posture as the active retention control.

---

## 4. Validation

| # | Check | Command | Result |
|---|---|---|---|
| 1 | Whitespace lint | `git diff --check` | **Clean.** No whitespace errors. |
| 2 | Workflow directory listing | `Get-ChildItem .github\workflows -File` | Three files: `anchor-rate-limit-ci.yml`, `dependency-audit.yml`, `isolation-smoke.yml`. The deleted file is gone. |
| 3 | No remaining workflow references to retention paths | `Select-String -Path .github\workflows\*.yml -Pattern "retention/prune\|intake/prune"` | **0 matches.** No workflow references either retention endpoint. |
| 4 | Only legitimate remaining `ANCHOR_*` secret refs are in `isolation-smoke.yml` | `Select-String -Path .github\workflows\*.yml -Pattern "ANCHOR_ADMIN_TOKEN\|ANCHOR_BASE"` | Two matches, both in `isolation-smoke.yml:28-29` (its existing smoke-test secret references; out of scope for this patch — left untouched). |
| 5 | Git status reflects the single deletion + the two doc files | `git status --short` | `D .github/workflows/anchor-retention-prune.yml`; `M docs/operations/README.md`; `?? docs/operations/security_audits/2026-06-07_retention_workflow_removal.md`. No other files changed. |
| 6 | Untouched workflow diff | `git diff -- .github/workflows/anchor-rate-limit-ci.yml .github/workflows/dependency-audit.yml .github/workflows/isolation-smoke.yml` | empty diff |

### 4.1 Post-commit/push validation (operator follow-up)

After commit and push the operator should confirm:

- **`Anchor Retention Prune` no longer appears in the Actions tab** for new runs. The workflow file is gone from the default branch, so GitHub Actions has nothing to schedule. The next 03:15 UTC cron should not fire.
- **`Anchor Rate Limit CI`** turns **green** on the new push (the pinned `actions/checkout@<sha>` + pinned `actions/setup-python@<sha>` execute unchanged).
- **`Tenant Isolation Smoke Test`** turns **green** on the new push (the pinned `actions/checkout@<sha>` executes unchanged; production smoke runs unchanged; the `secrets.ANCHOR_*` references in this workflow are unrelated to the retention workflow's deletion).
- **`Anchor Dependency Audit (pip-audit)`** remains manual-only and **must not auto-run**. (Trigger is `workflow_dispatch:` only since Patch 11B-b2-c.)

### 4.2 No local validation needed

Workflow deletion has no effect on local Python paths, `pip check`, or the application import path. There is nothing to regress at the language layer.

---

## 5. Operational effect

- **Scheduled retention pruning is no longer present.** No GitHub Actions workflow on the default branch fires a retention call on any cadence.
- **Manual retention pruning remains governed by `docs/operations/intake_retention.md`.** That runbook (`§3` endpoint summary; `§5` pre-run checklist; `§6` dry-run procedure; `§7` dry-run evidence template; `§8` destructive procedure; `§9` destructive evidence template; `§10` failure-mode playbook; `§11` teardown/secret hygiene; `§12` cadence) is the single source of truth.
- **Destructive prune still requires the documented operator procedure:** founder approval recorded against the exact `kind` + `older_than_days`, a reviewed dry-run, the exact `I-UNDERSTAND` confirm literal, the 50 000-row hard cap (409 before any DELETE), and evidence captured per the `§9` template.
- **No production data was touched by this patch.** No HTTP request was issued; the patch only edits the repository.
- **Daily admin-bearer transmission has stopped.** The deleted workflow was the only daily-scheduled production-touching surface; deletion eliminates the daily `Authorization: Bearer …` call.
- **Daily red noise has stopped.** The Actions tab will no longer carry a permanently-red `Anchor Retention Prune` run.

---

## 6. Future reintroduction criteria

Scheduled retention pruning may be reintroduced **only** when **all** of the following are recorded against a fresh workflow with its own evidence artefact:

1. **Correct endpoint** — `POST /v1/admin/intake/prune` with a JSON body (`{"kind", "older_than_days", "dry_run", "confirm"?}`) matching the Pydantic schema; never the `?days=N` query-string form; never the legacy `/v1/admin/retention/prune` path.
2. **Dry-run-first behaviour** — the scheduled call must default to `dry_run: true`; destructive runs require a separate intentional gate.
3. **Explicit destructive-action gate** — `confirm: "I-UNDERSTAND"` must not be hardcoded into a scheduled YAML file. A destructive scheduled prune requires a per-firing intentional gate (e.g. a `workflow_dispatch` with an explicit `inputs:` confirmation, a feature flag the operator flips for the day, or another explicit operator-side control).
4. **Evidence capture** — the workflow must write evidence comparable to `intake_retention.md §7` / `§9`: kind, cutoff, counts, deleted, response status, `X-Request-ID`, decision (PASS / FAIL / INCONCLUSIVE), founder-approval reference for destructive runs. Capture path can be a GitHub Actions job artifact, an audit-event row, or both.
5. **Confirmed admin auth and rate-limit behaviour** — before the first scheduled firing the operator must confirm the admin-bearer source (`ANCHOR_ADMIN_MODE=db` in prod), confirm the workflow's call does not interact with the open `Tenant Isolation Smoke #191` rate-limit follow-up, and confirm the canonical header form (`X-ANCHOR-ADMIN-TOKEN` or `Authorization: Bearer`).
6. **Monitored first run** — the first scheduled firing must be operator-monitored in real time and the evidence path verified before unattended scheduling is enabled.
7. **A new design artefact** — recorded under `docs/operations/security_audits/<date>_…` with the recommendation explicitly traced through criteria 1–6 above.

Until all seven are in place against a fresh workflow, scheduled retention does not return.

---

## 7. Stop-condition impact

| Operational gate | Status after this patch |
|---|---|
| Dependency / CVE audit (CI pip-audit) | ✅ PASS for the locked scanned dependency set ([`2026-06-07_post_lockfile_ci_audit.md`](./2026-06-07_post_lockfile_ci_audit.md), run `#4` against `32e9b94`). |
| Dependency-file reproducibility | ✅ Closed by Patch 11B-b2-b. |
| Docker base-image digest pin | ✅ Closed by Patch 11B-b3-b. |
| GitHub Actions SHA pinning | ✅ Closed at the file layer by Patch 11B-b4-b. |
| **Retention workflow treatment** | ✅ **Closed by this patch.** Stale workflow deleted; manual operator runbook is the single retention control. |
| Dockerfile explicit `--require-hashes` flag | ⏳ Open — deferred. |
| `alembic` dead-weight removal | ⏳ Open — held for **Patch 11B-b6**. |
| Optional `httpx<2` deprecation hygiene | ⏳ Open — optional **Patch 11B-b7**. |
| `github-actions` Dependabot SHA-refresh cadence | ⏳ Open — additive hygiene, separate follow-up. |
| Base-image digest refresh cadence | ⏳ Open — operational hygiene item. |
| Render deploy of post-Starlette + lockfile + digest + Actions-SHA + retention-cleanup stack | ⏳ Open — operator decision. Reproducibility-first sequence still recommended (`alembic` removal → deploy). |
| Tenant Isolation Smoke #191 rate-limit | ⏳ Open — separate follow-up. |
| Legal / commercial pack per Addendum v1.3 | ⏳ Open — founder track. |

**Operational safety improves** by removing a stale scheduled production-touching workflow. **Reproducibility / operational resilience track still has remaining work** (`alembic` removal, optional `httpx<2` hygiene, the deferred Dockerfile flag, base-image refresh cadence, Dependabot config). **Dependency / CVE audit remains PASS** for the locked scanned set. **Docker base digest pin is complete.** **GitHub Actions SHA pin is complete.** **No deploy decision made by this patch.** **Paid pilot / real clinic data remains blocked** by the standing operational gates.

---

## 8. Non-actions in this patch

The following were **explicitly not done** in Patch 11B-b5-b:

- ❌ No replacement scheduled workflow added.
- ❌ No repair of the deleted workflow.
- ❌ No edit to `anchor-rate-limit-ci.yml`.
- ❌ No edit to `dependency-audit.yml`.
- ❌ No edit to `isolation-smoke.yml`.
- ❌ No `intake_retention.md` change. (The runbook is already correct; it documents the operator-driven posture that this patch leaves as the single retention control.)
- ❌ No dependency change. `requirements.in`, `requirements.txt`, `requirements-dev.txt` byte-identical.
- ❌ No Dockerfile change.
- ❌ No `alembic` removal.
- ❌ No application code change.
- ❌ No test change.
- ❌ No migration change.
- ❌ No migrations run.
- ❌ No database query or mutation.
- ❌ No Render setting change.
- ❌ No deploy.
- ❌ No frontend touch.
- ❌ No production endpoint call. (Did not invoke `/v1/admin/intake/prune`, the deleted workflow's `/v1/admin/retention/prune` path, or any other ANCHOR production route.)
- ❌ No GitHub secret revoked or rotated. (`secrets.ANCHOR_BASE` and `secrets.ANCHOR_ADMIN_TOKEN` continue to exist in repository secrets and are still legitimately referenced by `isolation-smoke.yml`. Removing them from repository secrets — if the operator chooses to — is a separate, optional follow-up; it is not in this patch's scope.)
- ❌ No secret value read, printed, stored, or pasted.
- ❌ No commit. No push. (Per scope.)
- ❌ No compliance / certification / regulator-approval claim.
- ❌ No paid-pilot or real-clinic-data authorisation.

What this patch **did** do: deleted `.github/workflows/anchor-retention-prune.yml`; verified the three remaining workflow files are byte-identical and contain no references to retention/intake prune paths; recorded the deletion, post-deletion validation, operational effect, and reintroduction criteria; and updated the operations README.
