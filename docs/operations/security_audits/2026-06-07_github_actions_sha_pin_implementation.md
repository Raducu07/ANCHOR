# ANCHOR GitHub Actions SHA Pin Implementation — 2026-06-07

> **Implementation artefact for Patch 11B-b4-b.** Pins every actionable `uses:` reference in the three non-retention ANCHOR workflows to the immutable commit SHAs resolved by Patch 11B-b4-a. **Workflow action pin only.** No dependency change. No Dockerfile change. No application code change. No tests changed. No migrations changed. No migrations run. No production endpoint called manually. No database queried or mutated. No Render setting changed. No deploy issued. No secret read, printed, or stored. Not compliance certification. Not a regulator endorsement. Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

---

## 1. Purpose and scope

- This artefact records pinning GitHub Actions `uses:` refs to immutable commit SHAs.
- Workflow action pin only.
- No dependency change.
- No Dockerfile change.
- No app / test / migration / frontend change.
- No production endpoint called manually.
- No DB queried or mutated.
- No Render change.
- No deploy.
- Not compliance certification.
- Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

The Patch 11B-b1 inventory ([`2026-06-07_dependency_reproducibility_inventory.md`](./2026-06-07_dependency_reproducibility_inventory.md) §6) recorded that all four ANCHOR workflows referenced third-party actions by mutable semver tag. The design patch ([`2026-06-07_github_actions_sha_pin_design.md`](./2026-06-07_github_actions_sha_pin_design.md), Patch 11B-b4-a) resolved each tag to an immutable commit SHA via anonymous `git ls-remote`. This implementation patch applies those SHAs.

**Out of scope** (held for later patches):

- `anchor-retention-prune.yml` fix-or-delete — Patch **11B-b5** (the file has no `uses:` refs, so it is not touched by this patch).
- `alembic` dead-weight removal — Patch **11B-b6**.
- Optional `httpx<2` deprecation hygiene — Patch **11B-b7**.
- Explicit Dockerfile `--require-hashes` flag flip — deferred.
- `.github/dependabot.yml` for `github-actions` ecosystem SHA-refresh cadence — additive hygiene, not in this scope.
- Any deploy decision.

---

## 2. Source design

Reference: [`2026-06-07_github_actions_sha_pin_design.md`](./2026-06-07_github_actions_sha_pin_design.md) (Patch 11B-b4-a).

Resolved SHAs applied unchanged from the design:

| Action | Tag (before) | Resolved commit SHA (after) |
|---|---|---|
| `actions/checkout` | `v4` | **`34e114876b0b11c390a56381ad16ebd13914f8d5`** |
| `actions/setup-python` | `v5` | **`a26af69be951a213d495a4c3e4e4022e16d87065`** |

Source: anonymous `git ls-remote https://github.com/actions/<repo>.git refs/tags/<tag> refs/tags/<tag>^{}` against the public GitHub mirrors. No credentialed call, no GitHub API token, no GitHub secret read. Both tags are lightweight (single ref returned, no `^{}` dereference).

---

## 3. Change made

### 3.1 Per-file change table

| Workflow file | Line | Old ref | New ref | Count |
|---|---|---|---|---|
| `.github/workflows/anchor-rate-limit-ci.yml` | 20 | `uses: actions/checkout@v4` | `uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4 resolved 2026-06-07` | 1 |
| `.github/workflows/anchor-rate-limit-ci.yml` | 23 | `uses: actions/setup-python@v5` | `uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5 resolved 2026-06-07` | 1 |
| `.github/workflows/dependency-audit.yml` | 21 | `uses: actions/checkout@v4` | `uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4 resolved 2026-06-07` | 1 |
| `.github/workflows/dependency-audit.yml` | 24 | `uses: actions/setup-python@v5` | `uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5 resolved 2026-06-07` | 1 |
| `.github/workflows/isolation-smoke.yml` | 23 | `uses: actions/checkout@v4` | `uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4 resolved 2026-06-07` | 1 |
| **Total** | | | | **5** |

### 3.2 Per-workflow summary

| Workflow file | Result |
|---|---|
| `anchor-rate-limit-ci.yml` | `checkout` + `setup-python` **pinned** (2 refs). |
| `dependency-audit.yml` | `checkout` + `setup-python` **pinned** (2 refs). |
| `isolation-smoke.yml` | `checkout` **pinned** (1 ref). |
| `anchor-retention-prune.yml` | **Unchanged.** The file has no `uses:` refs (pure `curl` script); fix-or-delete remains held for Patch 11B-b5. |

`git diff` confirms only those five `uses:` lines changed. **No trigger changes.** **No secret changes.** **No job-step or command changes.** **No workflow name changes.** All other workflow content is byte-identical to the pre-patch state.

The trailing `# v<N> resolved 2026-06-07` comment is recorded on every pinned line so future readers (and `grep`) can see the human-readable tag plus the resolution date without re-deriving via `git ls-remote`. The comment does not change execution behaviour — GitHub Actions resolves the SHA literally.

---

## 4. Validation

| # | Check | Command | Result |
|---|---|---|---|
| 1 | Whitespace lint | `git diff --check` | **Clean.** No whitespace errors. |
| 2 | No remaining mutable tag refs | `Select-String -Path .github\workflows\*.yml -Pattern "actions/checkout@v4|actions/setup-python@v5" -CaseSensitive:$false` | **No matches.** All five legacy tag-pinned refs are gone. |
| 3 | Diff scope | `git diff -- .github/workflows/` | Exactly 5 line changes across 3 files; no other workflow line changed. |
| 4 | Retention workflow untouched | `git diff -- .github/workflows/anchor-retention-prune.yml` | **No diff.** File byte-identical to pre-patch. |

### 4.1 Post-commit/push validation (operator follow-up)

The real validation of SHA-pinned actions is their successful execution on GitHub-hosted runners. After commit and push, confirm:

- `Anchor Rate Limit CI` — must turn **green** on the new commit (push trigger). Exercises both pinned actions: `actions/checkout@<sha>` and `actions/setup-python@<sha>`.
- `Tenant Isolation Smoke Test` — must turn **green** on the new commit (push trigger). Exercises the pinned `actions/checkout@<sha>` on a `windows-latest` runner.
- `Anchor Dependency Audit (pip-audit)` — **must not auto-run** on push. The workflow's only trigger is `workflow_dispatch:` (restored in Patch 11B-b2-c). If desired, the operator can manually dispatch it to confirm the pinned `setup-python` and `checkout` SHAs work on `ubuntu-latest`; this is **optional**.

A green run on either push-triggered workflow is direct evidence that the SHA-pinned `actions/checkout@34e1148…` is fetchable and executes correctly on GitHub-hosted runners.

### 4.2 No local validation needed

Pinning workflow action refs has **no effect** on local Python install paths, `pip check`, or `from app.main import app` — those touch zero workflow code. The post-commit GitHub Actions runs are the only meaningful validation surface.

---

## 5. Risk and rollback

### 5.1 Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Pinned actions will **not** automatically receive upstream fixes — including security advisories that ship in a future `v4` / `v5` patch release. | medium (this is **by design** under SHA pinning) | medium | Maintain a refresh cadence (manual re-probe via `git ls-remote`, or add a `.github/dependabot.yml` for the `github-actions` ecosystem as an additive follow-up hygiene patch). |
| R2 | A reviewer or future workflow author copies a stale SHA without re-probing. | medium (human factors) | low | Every pinned line carries `# v<N> resolved 2026-06-07` — staleness is immediately legible. |
| R3 | The pinned SHA is force-pushed or retracted from the action's public repo. | very low — GitHub does not garbage-collect referenced commits in active public repos | high (workflow fails closed) | Rollback to tag form via `git revert`, or repoint to the new maintainer-recommended SHA. |
| R4 | Render's CI smoke runs (the `Tenant Isolation Smoke Test`) call production with `secrets.ANCHOR_*` after the SHA change. | n/a — the SHA change only affects how the runner fetches the repo; it does not affect the smoke script's behaviour | n/a | Existing rate-limit interaction (the `#191` issue) is separate and remains a documented open item, untouched by this patch. |

### 5.2 Maintenance

Future action refresh = re-run `git ls-remote https://github.com/actions/<repo>.git refs/tags/<tag>` and bump the SHA + comment date in a dedicated patch with its own evidence artefact. Optional automation: add `.github/dependabot.yml` configuring the `github-actions` ecosystem updater so Dependabot raises PRs whenever the major-version tags move forward.

### 5.3 Rollback

**Mechanism:** `git revert` of the Patch 11B-b4-b commit restores the `@v4` / `@v5` tag form. Workflows resume executing against the maintainer's current `v4` / `v5` head. **No GitHub-side or Render-side configuration change required.**

**Window of exposure:** zero — Patch 11B-b4-b does not include a deploy. The first push under the new SHAs is what exercises them; if either workflow fails on the next push, the operator can `git revert` immediately.

---

## 6. Stop-condition impact

| Operational gate | Status after this patch |
|---|---|
| Dependency / CVE audit (CI pip-audit) | ✅ PASS for the locked scanned dependency set ([`2026-06-07_post_lockfile_ci_audit.md`](./2026-06-07_post_lockfile_ci_audit.md), run `#4` against `32e9b94`). |
| Dependency-file reproducibility | ✅ Closed by Patch 11B-b2-b. |
| Docker base-image digest pin | ✅ Closed at the file layer by Patch 11B-b3-b ([`2026-06-07_docker_base_digest_pin.md`](./2026-06-07_docker_base_digest_pin.md)). |
| **GitHub Actions SHA pinning** | ✅ **Closed at the file layer by this patch.** Real validation is the first successful push run after commit. |
| Dockerfile explicit `--require-hashes` flag | ⏳ Open — deferred. |
| `anchor-retention-prune.yml` fix-or-delete | ⏳ Open — held for **Patch 11B-b5**. The retention workflow has no `uses:` refs and was not touched by this patch. |
| `alembic` dead-weight removal | ⏳ Open — held for **Patch 11B-b6**. |
| Optional `httpx<2` deprecation hygiene | ⏳ Open — optional **Patch 11B-b7**. |
| `github-actions` Dependabot SHA-refresh cadence | ⏳ Open — additive hygiene, separate follow-up. |
| Render deploy of post-Starlette + lockfile + digest + Actions-SHA stack | ⏳ Open — operator decision. Reproducibility-first sequence still recommended (retention fix-or-delete → alembic removal → deploy). |
| Tenant Isolation Smoke #191 rate-limit | ⏳ Open — separate follow-up. |
| Legal / commercial pack per Addendum v1.3 | ⏳ Open — founder track. |

GitHub Actions reproducibility improves materially: every action ref in the three actively-pinning-eligible workflows is now resolved to an immutable commit SHA. **Reproducibility gate is not fully closed** until the retention workflow is fixed-or-deleted, `alembic` is removed, and a Render deploy validates the stack end-to-end. **Dependency / CVE audit remains PASS** for the locked scanned set. **Docker base-image digest pin is complete.** **No deploy decision made by this patch.** **Paid pilot / real clinic data remains blocked** by the standing operational gates.

---

## 7. Non-actions in this patch

The following were **explicitly not done** in Patch 11B-b4-b:

- ❌ No `.github/workflows/anchor-retention-prune.yml` change. (The file has no `uses:` refs; fix-or-delete held for Patch 11B-b5.)
- ❌ No `.github/dependabot.yml` added.
- ❌ No trigger change on any workflow.
- ❌ No secret reference change on any workflow.
- ❌ No job-step or command change on any workflow other than the five `uses:` lines.
- ❌ No workflow name change.
- ❌ No new workflow added.
- ❌ No workflow removed.
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
- ❌ No production endpoint call **manually**. (`isolation-smoke.yml` continues to call production on push as it did before; that is unchanged behaviour and is not a "manual" call by the operator.)
- ❌ No credentialed GitHub API call. (`git ls-remote` was the only network call used during Patch 11B-b4-a; this implementation patch does not need to re-run it.)
- ❌ No secret value read, printed, stored, or pasted.
- ❌ No commit. No push. (Per scope.)
- ❌ No compliance / certification / regulator-approval claim.
- ❌ No paid-pilot or real-clinic-data authorisation.

What this patch **did** do: changed exactly five `uses:` lines across three workflow files (`anchor-rate-limit-ci.yml`, `dependency-audit.yml`, `isolation-smoke.yml`) to pin `actions/checkout` and `actions/setup-python` to the immutable commit SHAs resolved in Patch 11B-b4-a; left `anchor-retention-prune.yml` untouched; validated the diff is clean and that no mutable-tag refs remain in `.github/workflows/`; and updated the operations README.
