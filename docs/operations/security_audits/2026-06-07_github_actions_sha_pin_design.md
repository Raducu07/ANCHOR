# ANCHOR GitHub Actions SHA Pinning Design — 2026-06-07

> **Design-only artefact.** This artefact inventories GitHub Actions reproducibility and designs the SHA-pinning implementation for Patch 11B-b4-b. **No workflow changed.** No dependency changed. No Dockerfile changed. No application code changed. No tests changed. No migrations changed. No migrations run. No production endpoint called. No database queried or mutated. No Render setting changed. No deploy issued. No secret read, printed, or stored. Not compliance certification. Not a regulator endorsement. Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

---

## 1. Purpose and scope

The Patch 11B-b1 inventory ([`2026-06-07_dependency_reproducibility_inventory.md`](./2026-06-07_dependency_reproducibility_inventory.md) §6) recorded that all four ANCHOR GitHub Actions workflows reference third-party actions by mutable semver tag (`@v4`, `@v5`) rather than by immutable commit SHA. That means the action maintainer can re-point the tag at any time; the next workflow run silently executes a different commit.

This patch is the **design step** that precedes the implementation patch (**11B-b4-b**). Purpose:

- Re-inventory `uses:` references across all four workflows under the current HEAD (`f0d931d`).
- Resolve each action tag to its current immutable commit SHA via read-only public-GitHub lookups.
- Decide the implementation shape: which files to edit, which refs to replace, how to handle the broken `anchor-retention-prune.yml`.
- Record risk and rollback.

This patch is **design only.** No workflow changed. No SHA applied. **Out of scope** (held for later patches):

- Any workflow edit (Patch **11B-b4-b**).
- `anchor-retention-prune.yml` fix-or-delete (Patch **11B-b5**).
- `alembic` dead-weight removal (Patch **11B-b6**).
- Optional `httpx<2` hygiene (Patch **11B-b7**).
- Dockerfile explicit `--require-hashes` flag flip (deferred).
- Any deploy decision.

---

## 2. Current workflow inventory

Four workflow files under `.github/workflows/` at HEAD `f0d931d`.

| # | Workflow file | Workflow name | Triggers | Runner | Action refs (`uses:`) | Tag/SHA status | Secrets used | Calls production? | Known issue | Recommended treatment |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `anchor-rate-limit-ci.yml` | `Anchor Rate Limit CI` | `push: branches:[main]`, `pull_request`, `workflow_dispatch` | `ubuntu-latest` | `actions/checkout@v4` (line 20); `actions/setup-python@v5` (line 23) | **Tag-pinned (mutable)** | None (`RATE_LIMIT_SECRET: "ci-test-secret"` is a hardcoded CI literal, not a GitHub secret) | No — runs deterministic local pytest only | None | **Pin both refs to SHA in Patch 11B-b4-b.** |
| 2 | `anchor-retention-prune.yml` | `Anchor Retention Prune` | `schedule: cron: "15 3 * * *"` (daily 03:15 UTC), `workflow_dispatch` | `ubuntu-latest` | **None** — uses raw `curl`; no `uses:` lines | n/a | `secrets.ANCHOR_BASE`, `secrets.ANCHOR_ADMIN_TOKEN` | **YES** — `curl -X POST "${ANCHOR_BASE}/v1/admin/retention/prune?days=90"` with admin bearer token | **BROKEN.** Endpoint `/v1/admin/retention/prune` does not exist (actual endpoint is `/v1/admin/intake/prune`). Fires daily with a real admin token. | **Nothing to pin** (no action refs). Hold for Patch **11B-b5** (fix-or-delete; recommended delete). |
| 3 | `dependency-audit.yml` | `Anchor Dependency Audit (pip-audit)` | `workflow_dispatch:` only (restored in Patch 11B-b2-c) | `ubuntu-latest` | `actions/checkout@v4` (line 21); `actions/setup-python@v5` (line 24) | **Tag-pinned (mutable)** | None | No — talks only to PyPI / OSV | None | **Pin both refs to SHA in Patch 11B-b4-b.** |
| 4 | `isolation-smoke.yml` | `Tenant Isolation Smoke Test` | `push: branches:[main]`, `pull_request: branches:[main]`, `workflow_dispatch` | `windows-latest` | `actions/checkout@v4` (line 23) | **Tag-pinned (mutable)** | `secrets.ANCHOR_BASE`, `secrets.ANCHOR_ADMIN_TOKEN`, `secrets.ANCHOR_TEST_PASSWORD` | **YES** — runs `scripts\anchor-smoke-isolation.ps1` against production on every push/PR to main. Working; known separate `#191` rate-limit interaction noted in earlier audits. | None for the action-pinning scope of this patch | **Pin `checkout` ref to SHA in Patch 11B-b4-b.** (Only one `uses:` line.) |

### 2.1 Aggregate `uses:` count

| Action | Occurrences | Files |
|---|---|---|
| `actions/checkout@v4` | 3 | `anchor-rate-limit-ci.yml`, `dependency-audit.yml`, `isolation-smoke.yml` |
| `actions/setup-python@v5` | 2 | `anchor-rate-limit-ci.yml`, `dependency-audit.yml` |
| **Total `uses:` lines to pin** | **5** | across 3 workflow files |

`anchor-retention-prune.yml` has **no action refs at all** — it is a pure `curl` invocation. There is nothing to SHA-pin in that file. Its broken-target problem is independent of this patch and is held for Patch 11B-b5.

### 2.2 Other ANCHOR-internal action references

`grep` for `uses:` across `.github/workflows/*.yml` returned exactly the five lines above. No reusable workflow calls (`uses: ./.github/workflows/...`), no `uses: docker://`, no third-party actions other than the two `actions/*` officials.

---

## 3. Action tag resolution

Both action tags resolved via read-only `git ls-remote` against the official public-GitHub mirrors. No GitHub API token used. No GitHub secret read. No credentialed call.

| Action | Current tag in workflow | Resolved commit SHA | Tag form | Command used |
|---|---|---|---|---|
| `actions/checkout` | `v4` | **`34e114876b0b11c390a56381ad16ebd13914f8d5`** | Lightweight (only `refs/tags/v4` returned; no `refs/tags/v4^{}` dereferenced ref — the tag points directly at the commit) | `git ls-remote https://github.com/actions/checkout.git refs/tags/v4 refs/tags/v4^{}` |
| `actions/setup-python` | `v5` | **`a26af69be951a213d495a4c3e4e4022e16d87065`** | Lightweight (same shape — single ref returned) | `git ls-remote https://github.com/actions/setup-python.git refs/tags/v5 refs/tags/v5^{}` |

Notes:

- Both `v4` and `v5` are **major-version** pointer tags that the action maintainers move forward as minor/patch releases ship. They are intentionally mutable; that is exactly why SHA pinning matters.
- The resolved SHAs above are what those tags pointed at **at the moment of this probe** (`f0d931d` baseline, 2026-06-07).
- Lightweight tags mean the tag and the commit share the same hash space; there is no separate tag object to dereference. The SHA returned for `refs/tags/vN` is the commit SHA directly.

---

## 4. Implementation options assessed

| Option | Description | Security / reproducibility | Operational risk | Diff size | Readability / maintenance | Interaction with broken retention workflow | CI validates? | Solo-operator practicality |
|---|---|---|---|---|---|---|---|---|
| **A** | Pin all `uses:` refs in all workflows in one patch (every applicable file edited). | high — closes the mutable-tag dimension across the whole repo in one go | low — workflows continue to work identically; just resolved to a fixed commit | small (5 lines across 3 files) | needs a trailing comment per line mapping SHA → human-readable tag so the file stays grep-able | none — `anchor-retention-prune.yml` has no `uses:` lines, so this option does not touch it | yes — `Anchor Rate Limit CI` and `Tenant Isolation Smoke Test` re-run on push and exercise both pinned actions | high |
| **B** | Pin only the three workflows that have `uses:` refs (excluding the broken retention workflow, which has no `uses:` lines anyway). | identical to A in practice | identical to A | identical to A | identical to A | none — A and B are the **same set of edits** because retention has nothing to pin | identical to A | identical to A |
| **C** | Fix-or-delete `anchor-retention-prune.yml` first (Patch 11B-b5), then pin remaining workflows. | unchanged for the SHA-pin work itself, but front-loads an unrelated patch | low | small | low risk of conflating two independent concerns | proper ordering — but blocks the SHA pin behind the retention decision | yes | medium — adds a patch ordering dependency for no SHA-pin-side benefit |
| **D** | Keep tags but add monitoring only (e.g. a Dependabot config for `github-actions` that surfaces tag-target drift). | partial — drift is *visible* but not *prevented* between Dependabot scans | low | small | adds a `.github/dependabot.yml` (new file) | independent | yes (Dependabot runs out-of-band) | medium — useful **alongside** A/B, not as a replacement |

**Recommendation: Option A (identical to Option B in this codebase).** The retention workflow has nothing to pin, so "pin everything actionable" and "pin only the non-broken workflows" produce the same five-line diff. Option D (Dependabot for `github-actions`) is a useful future addition to handle SHA refresh cadence, but it's an *additive* hygiene patch — not a replacement for pinning.

---

## 5. Recommended Patch 11B-b4-b

### 5.1 Files to edit

Three files:

- `.github/workflows/anchor-rate-limit-ci.yml`
- `.github/workflows/dependency-audit.yml`
- `.github/workflows/isolation-smoke.yml`

### 5.2 Exact refs to replace

Each `uses:` line gets the SHA inlined, with a trailing comment that records the human-readable tag and the resolution date so future readers can refresh without re-deriving the tag.

| File | Line | Before | After |
|---|---|---|---|
| `anchor-rate-limit-ci.yml` | 20 | `uses: actions/checkout@v4` | `uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4 (resolved 2026-06-07)` |
| `anchor-rate-limit-ci.yml` | 23 | `uses: actions/setup-python@v5` | `uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5 (resolved 2026-06-07)` |
| `dependency-audit.yml` | 21 | `uses: actions/checkout@v4` | `uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4 (resolved 2026-06-07)` |
| `dependency-audit.yml` | 24 | `uses: actions/setup-python@v5` | `uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5 (resolved 2026-06-07)` |
| `isolation-smoke.yml` | 23 | `uses: actions/checkout@v4` | `uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4 (resolved 2026-06-07)` |

### 5.3 Include comments mapping SHAs back to tags?

**Yes.** Trailing comment format: `# v<N> (resolved YYYY-MM-DD)`. Reasons:

- A bare SHA is opaque; the comment lets a future reader (or `grep`) confirm intent without `git ls-remote`-ing every line.
- Dating the resolution makes a future refresh-cadence patch trivially auditable.
- The comment does not alter execution behaviour — GitHub Actions still resolves the SHA literally.

### 5.4 Treatment of `anchor-retention-prune.yml`

**Leave it alone in Patch 11B-b4-b.** The workflow has no `uses:` lines, so there is nothing to SHA-pin. Its fix-or-delete decision is held for **Patch 11B-b5** (recommended: delete, per [`2026-06-07_dependency_reproducibility_inventory.md`](./2026-06-07_dependency_reproducibility_inventory.md) §7.4). Pinning is logically independent of that decision.

### 5.5 Validation steps for Patch 11B-b4-b

After the edits, the implementation patch should:

1. `git diff --check` — confirm no whitespace errors.
2. `git diff -- .github/workflows/` — visually confirm exactly five `uses:` lines changed across three files; no other workflow line changed.
3. Run the same `py -3.11` venv install + `pip check` + `from app.main import app` regression as in Patches 11B-b2-b / 11B-b3-b — purely as a "did we accidentally break the repo" check; the SHA pin does not touch any Python path.
4. **Post-commit/push:** confirm `Anchor Rate Limit CI` and `Tenant Isolation Smoke Test` turn green on the new commit. Both push-triggered workflows exercise the pinned `checkout` (and, for rate-limit-ci, the pinned `setup-python`) action. A green run is direct evidence the SHA-pinned actions executed correctly.
5. `Anchor Dependency Audit` should **not** re-fire on push (its temporary trigger was removed in Patch 11B-b2-c). It can be optionally `workflow_dispatch`-triggered after push to confirm the pinned action refs work there too; this is **not** required.

---

## 6. Risk and rollback

### 6.1 Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | The resolved SHA happens to be a bad commit that the action maintainer later supersedes for a security fix. | low — the SHAs above are what `v4` / `v5` point at *right now*, which is by definition the maintainer's current recommended commit | medium | Refresh cadence (manual re-probe + Dependabot for `github-actions`, see R4). |
| R2 | A future workflow author copies the pattern from one of these files and pastes a stale SHA into a new workflow without re-probing. | medium (human factors) | low | The trailing `# v<N> (resolved YYYY-MM-DD)` comment makes staleness immediately legible. |
| R3 | The pinned SHA is removed from the action's repo (force-push, retracted release). | very low — GitHub does not garbage-collect referenced commits in active public repos | high (workflow fails closed) | Rollback to tag form via `git revert`. |
| R4 | Pinned action SHAs silently rot — security advisories or breaking changes ship that the pin masks. | medium (this is **by design** under SHA pinning) | medium | Add `.github/dependabot.yml` configuring the `github-actions` ecosystem updater as a follow-up hygiene patch (not in 11B-b4-b scope). Until then, the operator manually re-probes when an `actions/*` security advisory lands. |
| R5 | The five-line diff is conflated with another workflow change in the same patch and a reviewer misses an unrelated edit. | low — Patch 11B-b4-b will touch only these five lines | low | Patch 11B-b4-b is scoped to the exact five-line set in §5.2; any deviation requires its own patch. |

### 6.2 Rollback

**Mechanism:** `git revert` the Patch 11B-b4-b commit restores `@v4` / `@v5` tag references. Workflows continue to execute against the maintainer's current `v4` / `v5` head. **No GitHub-side or Render-side configuration change required.**

**Refresh path:** for a deliberate refresh (e.g. when a new `actions/checkout` patch release lands), re-run `git ls-remote https://github.com/actions/checkout.git refs/tags/v4` and bump the SHA + comment date in a dedicated patch with its own evidence artefact.

---

## 7. Stop-condition impact

| Operational gate | Status after this design patch |
|---|---|
| Dependency / CVE audit (CI pip-audit) | ✅ PASS for the locked scanned dependency set ([`2026-06-07_post_lockfile_ci_audit.md`](./2026-06-07_post_lockfile_ci_audit.md), run `#4` against `32e9b94`). |
| Dependency-file reproducibility | ✅ Closed by Patch 11B-b2-b. |
| Docker base-image digest pin | ✅ Closed at the file layer by Patch 11B-b3-b ([`2026-06-07_docker_base_digest_pin.md`](./2026-06-07_docker_base_digest_pin.md)). |
| **GitHub Actions SHA pinning** | ⏳ **Open.** This patch identifies and resolves the SHAs. **Patch 11B-b4-b is what actually closes it** (five-line edit across three files). |
| Dockerfile explicit `--require-hashes` flag | ⏳ Open — held for a one-step follow-up after the first successful Render rebuild under the lockfile. |
| `anchor-retention-prune.yml` fix-or-delete | ⏳ Open — held for **Patch 11B-b5**. Logically independent of SHA pinning. |
| `alembic` dead-weight removal | ⏳ Open — held for **Patch 11B-b6**. |
| Optional `httpx<2` deprecation hygiene | ⏳ Open — optional **Patch 11B-b7**. |
| `github-actions` Dependabot SHA-refresh cadence | ⏳ Open — additive hygiene, separate follow-up. |
| Render deploy of post-Starlette + lockfile + digest stack | ⏳ Open — operator decision. Reproducibility-first sequence still recommended (Actions SHAs → retention fix-or-delete → alembic removal → deploy). |
| Tenant Isolation Smoke #191 rate-limit | ⏳ Open — separate follow-up. |
| Legal / commercial pack per Addendum v1.3 | ⏳ Open — founder track. |

Reproducibility gate is **not fully closed** until the workflows are actually pinned and the remaining follow-ups complete. Dependency / CVE audit remains PASS for the locked scanned set. Docker base-image digest pin is complete at the file layer. **No deploy decision made by this patch.** **Paid pilot / real clinic data remains blocked** by the standing operational gates.

---

## 8. Non-actions in this patch

The following were **explicitly not done** in Patch 11B-b4-a:

- ❌ No GitHub Actions workflow change. (No `uses:` line changed. No new workflow added. No workflow removed.)
- ❌ No Dependabot config added.
- ❌ No `anchor-retention-prune.yml` fix or deletion.
- ❌ No dependency change. `requirements.in`, `requirements.txt`, `requirements-dev.txt` byte-identical to the post-Patch-11B-b2-c state.
- ❌ No Dockerfile change.
- ❌ No application code change.
- ❌ No test change.
- ❌ No migration change.
- ❌ No migrations run.
- ❌ No database query or mutation.
- ❌ No Render setting change.
- ❌ No deploy.
- ❌ No frontend touch.
- ❌ No production endpoint call.
- ❌ No GitHub API call requiring credentials. (`git ls-remote` against `https://github.com/actions/checkout.git` and `https://github.com/actions/setup-python.git` is anonymous read-only access to public repos and does not pass any credential.)
- ❌ No secret value read, printed, stored, or pasted.
- ❌ No commit. No push. (Per scope.)
- ❌ No compliance / certification / regulator-approval claim.
- ❌ No paid-pilot or real-clinic-data authorisation.

What this patch **did** do: re-inventoried `uses:` references across all four ANCHOR workflows; resolved both action tags (`actions/checkout@v4`, `actions/setup-python@v5`) to immutable commit SHAs via anonymous `git ls-remote`; recommended a five-line Patch 11B-b4-b across three files with trailing `# v<N> (resolved YYYY-MM-DD)` comments; explicitly left `anchor-retention-prune.yml` alone (no `uses:` lines; held for Patch 11B-b5); and updated the operations README.
