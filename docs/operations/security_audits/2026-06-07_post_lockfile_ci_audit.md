# ANCHOR Post-Lockfile CI pip-audit Result — 2026-06-07

> **Audit evidence only.** This artefact records the CI dependency audit result after Patch 11B-b2-b introduced the hashed `pip-tools` lockfile. No dependency changed in this patch. No Dockerfile change. No application code change. No tests changed. No migrations changed. No production endpoint called. No database queried or mutated. No Render setting changed. No deploy issued. Not compliance certification. Not a regulator endorsement. Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

---

## 1. Purpose and scope

This artefact records the CI dependency audit result for the hashed `pip-tools` lockfile introduced by Patch 11B-b2-b ([`2026-06-07_lockfile_implementation.md`](./2026-06-07_lockfile_implementation.md)). The prior CI audit ([`2026-06-07_post_starlette_ci_audit.md`](./2026-06-07_post_starlette_ci_audit.md), run `#3`) reported PASS for the **pre-lockfile** scanned dependency set against commit `bfec5a0`. The lockfile patch changed dependency resolution mechanics (added full transitive pins and hashes), so a fresh CI audit was needed to confirm the locked set still passes.

- Audit evidence only.
- No dependency changed in this patch.
- No Dockerfile changed.
- No application code changed.
- No tests changed.
- No migrations changed.
- No production endpoint called.
- No DB queried or mutated.
- No Render change.
- No deploy.
- Not compliance certification.
- Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

---

## 2. Source run

| Property | Value |
|---|---|
| Workflow | `Anchor Dependency Audit (pip-audit)` |
| Workflow file | `.github/workflows/dependency-audit.yml` |
| Run title | `Trigger post-lockfile dependency audit` |
| Run number | `#4` |
| Commit scanned | `32e9b94` (local HEAD at the time of the run; the operator's prompt referenced `32e0b94`, a transcription variant of the same commit) |
| Branch | `main` |
| Trigger | Temporary path-filtered `push` trigger used **only** to fire this single post-lockfile audit (added to `on:` for one run, removed in this patch — see §6) |
| Runner | GitHub-hosted (`ubuntu-latest`) |
| Python | `3.11` (via `actions/setup-python@v5`, matches the Render runtime base) |
| Job | `pip-audit -r requirements.txt` |
| Command | `python -m pip_audit -r requirements.txt` |
| Result | **PASS** |
| Exit code | `0` (inferred from successful job status — GitHub Actions marks the job green only when every step exits `0`; the `pip-audit` step is the final step) |
| Evidence | GitHub Actions page shows the dependency audit run `#4` succeeded against commit `32e9b94`. Exact `pip-audit` stdout text was not captured into this artefact at run time. |

---

## 3. Result wording

**CI pip-audit job succeeded; no findings were reported in the successful workflow status evidence available to the operator.** The exact `pip-audit` stdout line (e.g. `No known vulnerabilities found`) was not captured into this artefact at run time — the recorded evidence is the green job status against commit `32e9b94`. The `Run pip-audit against requirements.txt` step is the final step in the job; a green job status therefore implies `pip-audit` returned exit code `0`, which for `pip-audit` means **no vulnerabilities were reported for the scanned set**.

Phrased conservatively for the audit record:

> **No known vulnerabilities were reported by CI pip-audit for the locked dependency set scanned at commit `32e9b94`.**

Caveats:

- This is **not** a guarantee that no vulnerabilities exist.
- This records only the dependency set and advisory data available to `pip-audit` at the time of the run (PyPI advisory DB + OSV).
- The result applies to the **hashed compiled `requirements.txt`** introduced by Patch 11B-b2-b — i.e. the full transitive closure with SHA256 hashes, not just the direct deps.

---

## 4. Dependency state relevant to the pass

Patch 11B-b2-b shipped these changes; this audit confirms the locked set is clean for them:

- `requirements.in` added as the human-edited **direct runtime input** (nine deps, every one pinned).
- `requirements.txt` **regenerated** as a `pip-tools` compiled lockfile with **full transitive pins** and **SHA256 hashes** for every distribution (747 lines).
- `requirements-dev.txt` added for tooling/test dependencies (`pip-tools==7.5.3`, `pytest==9.0.3`, `httpx==0.28.1`); **not installed in the Render image**.
- **Dockerfile still installs `requirements.txt`** unchanged (`pip install --no-cache-dir -r requirements.txt`).
- **Dockerfile was not changed.**
- **Explicit Dockerfile `--require-hashes` flag remains deferred** (design posture H4 — held for a one-step follow-up after the first successful Render build under the lockfile).
- The fully hashed `requirements.txt` causes `pip install -r requirements.txt` to **enter hash-checking mode automatically** and verify every wheel/sdist against the recorded SHA256 hash at install time, both locally and on the Render builder.

The PASS therefore covers a **stricter** dependency set than the prior CI audit covered: pip-audit is now reading pinned transitive packages (e.g. `starlette==1.2.1`, `anyio==4.13.0`, `pydantic-core==2.18.4`, `httpcore==1.0.9`) directly from the lockfile, rather than the resolver's at-build-time choice.

---

## 5. Relationship to prior artefacts

- [`2026-06-07_dependency_reproducibility_inventory.md`](./2026-06-07_dependency_reproducibility_inventory.md) — Patch 11B-b1 inventory that opened the reproducibility gate this lockfile work closes.
- [`2026-06-07_lockfile_strategy_design.md`](./2026-06-07_lockfile_strategy_design.md) — Patch 11B-b2-a design (Layout A + hash posture H4) implemented by 11B-b2-b.
- [`2026-06-07_lockfile_implementation.md`](./2026-06-07_lockfile_implementation.md) — Patch 11B-b2-b implementation that produced the lockfile this audit scans.
- [`2026-06-07_post_starlette_ci_audit.md`](./2026-06-07_post_starlette_ci_audit.md) — prior CI audit (`#3` against `bfec5a0`) recording PASS for the **pre-lockfile** scanned set.

Status:

- **Prior CVE state was PASS** for the pre-lockfile scanned set (Patch 11D-c).
- The lockfile implementation **changed dependency resolution mechanics** — transitive deps moved from "resolver-at-build-time" to "pinned with hashes in the lockfile".
- This artefact records **PASS after the lockfile implementation** — the change in mechanics did not surface new findings.

---

## 6. Workflow cleanup

- The temporary path-filtered `push` trigger (`push: paths: [".github/workflows/dependency-audit.yml"]`) was added to `.github/workflows/dependency-audit.yml` for the express purpose of firing run `#4`. It has now served that purpose.
- **In this patch, the temporary trigger was removed.** `.github/workflows/dependency-audit.yml` is restored to **manual `workflow_dispatch` only**.
- No schedule trigger.
- No `pull_request` trigger.
- Not promoted to a required gate.
- No change to any other workflow.

This matches the workflow's posture after every prior temporary push-trigger use (Patches 11D-a `#2`, 11D-c `#3`); the operator continues to dispatch this workflow manually when an audit is wanted.

---

## 7. Stop-condition impact

| Operational gate | Status after this patch |
|---|---|
| **Dependency / CVE audit (CI pip-audit)** | ✅ **PASS** for the **locked** scanned dependency set (run `#4` against `32e9b94`). |
| **Reproducibility — dependency file layer** | ✅ Closed by Patch 11B-b2-b. Improved materially through the hashed transitive lockfile; install-time hash verification is in effect on both the operator workstation and the Render builder. |
| Dockerfile explicit `--require-hashes` flag | ⏳ Open — held for a one-step follow-up after the first successful Render rebuild under the lockfile (design posture H4). Per-wheel hash verification is already in effect against today's fully-hashed lockfile; the deferred flag's only added effect is to refuse a file that contains any un-hashed entries. |
| Docker base-image digest pin | ⏳ Open — held for **Patch 11B-b3**. |
| GitHub Actions SHA pinning | ⏳ Open — held for **Patch 11B-b4**. |
| `anchor-retention-prune.yml` fix-or-delete | ⏳ Open — held for **Patch 11B-b5**. |
| `alembic` dead-weight removal | ⏳ Open — held for **Patch 11B-b6** (requires re-confirmation of the zero-import proof). |
| Optional `httpx<2` deprecation hygiene | ⏳ Open — optional **Patch 11B-b7**. |
| Render deploy of post-Starlette + lockfile stack | ⏳ Open — operator decision. Reproducibility-first sequence still recommended (lockfile → Docker digest → Actions SHAs → retention fix-or-delete → alembic removal → deploy). |
| Tenant Isolation Smoke #191 rate-limit | ⏳ Open — separate follow-up. |
| Legal / commercial pack per Addendum v1.3 | ⏳ Open — founder track. |

Reproducibility gate is **not fully closed** until each of the listed follow-ups is completed.

**No paid pilot / real-clinic-data authorisation** until **all** standing operational stop conditions are cleared. **No deploy decision is made by this patch.**

---

## 8. Recommended next steps

1. **Commit and push** this evidence/cleanup patch.
2. **Check normal push workflows** turn green on the new commit (Tenant Isolation Smoke Test, Anchor Rate Limit CI). The dependency-audit workflow itself should **not** re-fire under push (the temporary trigger is now removed).
3. **Then proceed to Patch 11B-b3 or 11B-b4** depending on the chosen order:
   - **Patch 11B-b3** — pin the Docker base image by digest (`python:3.11-slim@sha256:<digest>`); supply-chain hardening, narrow Dockerfile change.
   - **Patch 11B-b4** — pin every `actions/*` reference in all four workflows by commit SHA; supply-chain hardening, narrow `.github/workflows/*` change.
   Either order is acceptable; both are independent of each other and of the remaining patches.
4. **Continue to hold Render deploy** unless the founder chooses a deploy-first path with a production smoke check; the reproducibility-first sequence (11B-b3 → 11B-b4 → 11B-b5 → 11B-b6 → deploy) remains the recommended order.

---

## 9. Non-actions in this patch

The following were **explicitly not done** in Patch 11B-b2-c:

- ❌ No dependency changed.
- ❌ No `requirements.in` change.
- ❌ No `requirements.txt` change.
- ❌ No `requirements-dev.txt` change.
- ❌ No Dockerfile change.
- ❌ No GitHub Actions change **beyond** removing the temporary `push: paths:` trigger from `dependency-audit.yml`.
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
- ❌ No compliance / certification / regulator-approval claim.
- ❌ No paid-pilot or real-clinic-data authorisation.

What this patch **did** do: removed the temporary path-filtered `push` trigger from `.github/workflows/dependency-audit.yml` to restore it to manual `workflow_dispatch`-only, recorded the post-lockfile CI `pip-audit` PASS result for run `#4` against commit `32e9b94`, and updated the operations README to reference this artefact.
