# ANCHOR Docker Base Digest Pin — 2026-06-07

> **Implementation artefact for Patch 11B-b3-b.** Pins the Dockerfile base image to the digest identified in Patch 11B-b3-a. **Dockerfile base image pin only.** No dependency change. No requirements file change. No GitHub Actions change. No application code change. No tests changed. No migrations changed. No migrations run. No production endpoint called. No database queried or mutated. No Render setting changed. No deploy issued. No Docker install. No secret read, printed, or stored. Not compliance certification. Not a regulator endorsement. Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

---

## 1. Purpose and scope

The Patch 11B-b1 inventory ([`2026-06-07_dependency_reproducibility_inventory.md`](./2026-06-07_dependency_reproducibility_inventory.md) §5) recorded that the Dockerfile base was tag-pinned only (`python:3.11-slim`), allowing upstream re-tags to silently change what Render builds. The probe patch ([`2026-06-07_docker_base_digest_probe.md`](./2026-06-07_docker_base_digest_probe.md)) identified the canonical Docker Hub digest for that tag via the Docker Registry HTTP API. This implementation patch applies the recommended one-line pin.

- This artefact records pinning the Docker base image to a digest.
- Dockerfile base image pin only.
- No dependency change.
- No requirements file change.
- No GitHub Actions change.
- No app / test / migration / frontend change.
- No production endpoint called.
- No DB queried or mutated.
- No Render change.
- No deploy.
- Not compliance certification.
- Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

**Out of scope (held for later patches):**

- Explicit Dockerfile `--require-hashes` flag (deferred — design posture H4; per-wheel hash verification already in effect via the fully-hashed `requirements.txt`).
- GitHub Actions SHA pinning (Patch **11B-b4**).
- `anchor-retention-prune.yml` fix-or-delete (Patch **11B-b5**).
- `alembic` dead-weight removal (Patch **11B-b6**).
- Optional `httpx<2` hygiene (Patch **11B-b7**).
- Any deploy decision.

---

## 2. Source probe

Reference: [`2026-06-07_docker_base_digest_probe.md`](./2026-06-07_docker_base_digest_probe.md) (Patch 11B-b3-a).

| Field | Value |
|---|---|
| Image tag | `python:3.11-slim` |
| Probe method | Docker Registry HTTP API (anonymous-pull bearer from `auth.docker.io`; manifest from `registry-1.docker.io`); no Docker install, no production touch, no secret |
| `Content-Type` returned | `application/vnd.oci.image.index.v1+json` (multi-arch image index) |
| **Multi-arch index digest used in this patch** | **`sha256:a3ab0b966bc4e91546a033e22093cb840908979487a9fc0e6e38295747e49ac0`** |
| `linux/amd64` platform manifest digest (recorded for reference only) | `sha256:67e6a6053f28db54c173ad84a4bf88fdd4e338793dc09672e87ee38e3b1b378c` |

### 2.1 Why the multi-arch index digest

- Matches what `docker pull python:3.11-slim` resolves at this point in time — the digest most operators, audit tooling, and Dependabot's `docker` ecosystem updater expect to see.
- Standard `FROM image:tag@sha256:<digest>` pattern; widely supported by Docker, BuildKit, and Render's builder.
- Render's builder is `linux/amd64`; at pull time it resolves the index to the same `linux/amd64` sub-manifest (`sha256:67e6a605…378c`) recorded as the forensic backstop in §2 above.
- The human-readable tag (`3.11-slim`) is retained alongside the digest as documentation; Docker treats the digest as authoritative when both are present.

The platform-specific `linux/amd64` digest is **not** used in the Dockerfile; it is kept in this artefact only as a forensic backstop in case a future deploy ever surfaces an unexpected platform mismatch and the operator needs to re-pin tighter.

---

## 3. Change made

### Exact `Dockerfile` change

Before:

```dockerfile
FROM python:3.11-slim
```

After:

```dockerfile
FROM python:3.11-slim@sha256:a3ab0b966bc4e91546a033e22093cb840908979487a9fc0e6e38295747e49ac0
```

`git diff` confirms a **single-line change** to line 1. **No other Dockerfile line changed.** `WORKDIR`, `COPY`, `RUN pip install --no-cache-dir -r requirements.txt`, `ENV`, and `CMD` lines are byte-identical to the pre-patch state.

The explicit `--require-hashes` flag was **not added** in this patch (held for a one-step follow-up after the first successful Render rebuild under the lockfile, as designed in [`2026-06-07_lockfile_strategy_design.md`](./2026-06-07_lockfile_strategy_design.md) §4.2). Note that per-wheel hash verification is already in effect against the fully-hashed `requirements.txt` produced by Patch 11B-b2-b — `pip install -r requirements.txt` enters hash-checking mode automatically because every entry in that file carries hashes. The deferred flag's only added effect is to refuse a file that contains any un-hashed entries.

---

## 4. Validation

**Docker is not installed locally** (confirmed in the Patch 11B-b3-a probe: `Get-Command docker` → `CommandNotFoundException`). **No local Docker build was attempted.** The Dockerfile syntax itself (`FROM image:tag@sha256:<digest>`) is well-formed and is the canonical pattern Docker, BuildKit, and Render's builder all accept.

Local validation focused on the only behaviour the Dockerfile actually executes at build time — the `pip install -r requirements.txt` step — confirming the lockfile install path is still clean. (Pinning the base image has no functional effect at the pip layer; this validation is a regression check, not a digest verification.)

| # | Step | Command (paraphrased) | Result |
|---|---|---|---|
| 1 | Confirm Python 3.11 available | `py -3.11 --version` | `Python 3.11.9` |
| 2 | Create fresh 3.11 venv | `py -3.11 -m venv .venv-dockerpin-check` | venv created |
| 3 | Upgrade pip inside venv | `python -m pip install --upgrade pip` (`--trusted-host pypi.org files.pythonhosted.org` as the workstation-local TLS workaround documented in earlier audits) | `pip-26.1.2` |
| 4 | Install hashed lockfile | `python -m pip install -r requirements.txt` | **all 36 wheels installed; hashes verified by pip** (per-wheel SHA256 check against the recorded hash) |
| 5 | `pip check` | `python -m pip check` | **`No broken requirements found.`** |
| 6 | App import | `python -c "from app.main import app; print('IMPORT OK')"` (with stub `DATABASE_URL`, `RATE_LIMIT_ENABLED=0`, stub `ADMIN_BEARER_TOKEN`, stub `ADMIN_AUTH_PEPPER`) | **`IMPORT OK`** |
| 7 | Cleanup | `Remove-Item -Recurse -Force .\.venv-dockerpin-check` | removed |

**Normal GitHub Actions push workflows must be checked after commit/push** — `Tenant Isolation Smoke Test` and `Anchor Rate Limit CI` should turn green on the new commit. The `Anchor Dependency Audit` workflow should **not** re-fire under push (its temporary trigger was removed in Patch 11B-b2-c).

**Render deploy is still held.** The first Render build under the digest-pinned Dockerfile is a separate operator decision; the reproducibility-first sequence (lockfile → digest → Actions SHAs → retention fix-or-delete → alembic removal → deploy) remains the recommended order.

---

## 5. Risk and rollback

### 5.1 Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | The pinned digest becomes unavailable in the Docker Hub registry (Docker Hub retention/policy change for an official image). | very low — Docker Hub does not garbage-collect by-digest references for the official `library/python` repo | high (Render build fails closed) | Re-probe `python:3.11-slim` (Patch 11B-b3-a method), record the new digest, bump the Dockerfile in a follow-up patch. The human-readable tag (`3.11-slim`) is retained as a fallback reference. |
| R2 | Pinned image stops receiving upstream security updates until intentionally refreshed. | medium — this is **by design** under digest pinning | medium | The next time a Python or Debian-base security advisory is relevant, the operator re-probes and bumps the digest as a deliberate maintenance patch with its own evidence artefact. A periodic refresh cadence for base-image digests is an open operational hygiene item, out of scope for this patch. |
| R3 | Render's builder refuses `FROM image:tag@sha256:<index-digest>` syntax. | very low — this is standard Docker syntax, supported by every modern Docker / BuildKit / OCI builder | medium | Rollback path: `git revert` the Patch 11B-b3-b commit restores the tag-only `FROM` line. |
| R4 | Digest pinned to the multi-arch index resolves at pull time to an `amd64` sub-manifest that doesn't match the recorded forensic backstop (`sha256:67e6a605…378c`). | very low — the sub-manifest is part of the same OCI index and is content-addressable | low | The forensic backstop in §2 is the platform-specific digest captured at the same instant as the index digest; any mismatch on Render would indicate index corruption (extremely unlikely) and would surface as a build failure. |
| R5 | Local validation (Python 3.11 venv) doesn't exercise the Docker layer at all. | always | low | The first Render build under the new Dockerfile is the real validation. The operator should monitor that build (separate decision, out of scope for this patch). |

### 5.2 Rollback

**Mechanism:** `git revert` the Patch 11B-b3-b commit restores `FROM python:3.11-slim` (tag-only, no digest). Render rebuilds using whatever the tag currently points at. **No Render setting change required.**

Alternative: update to a newer recorded digest after a fresh probe (re-run Patch 11B-b3-a method) — a deliberate refresh patch with its own evidence artefact.

**Window of exposure:** the moment between landing this patch and the next Render deploy is **zero** because this patch does **not** include a deploy. The first Render deploy under the digest-pinned Dockerfile is a separate operator decision.

---

## 6. Stop-condition impact

| Operational gate | Status after this patch |
|---|---|
| Dependency / CVE audit (CI pip-audit) | ✅ PASS for the locked scanned dependency set ([`2026-06-07_post_lockfile_ci_audit.md`](./2026-06-07_post_lockfile_ci_audit.md), run `#4` against `32e9b94`). |
| Dependency-file reproducibility | ✅ Closed by Patch 11B-b2-b. |
| **Docker base-image digest pin** | ✅ **Closed at the file layer by this patch.** Validated by Render's first successful build under the new Dockerfile remains a follow-up; rollback is `git revert`. |
| Dockerfile explicit `--require-hashes` flag | ⏳ Open — held for a one-step follow-up after the first successful Render rebuild under the lockfile (design posture H4). |
| GitHub Actions SHA pinning | ⏳ Open — held for **Patch 11B-b4**. |
| `anchor-retention-prune.yml` fix-or-delete | ⏳ Open — held for **Patch 11B-b5**. |
| `alembic` dead-weight removal | ⏳ Open — held for **Patch 11B-b6** (re-proof of zero imports required first). |
| Optional `httpx<2` deprecation hygiene | ⏳ Open — optional **Patch 11B-b7**. |
| Render deploy of post-Starlette + lockfile + digest stack | ⏳ Open — operator decision. Reproducibility-first sequence still recommended (digest → Actions SHAs → retention fix-or-delete → alembic removal → deploy). |
| Base-image digest refresh cadence | ⏳ Open — operational hygiene item; out of scope for this patch. |
| Tenant Isolation Smoke #191 rate-limit | ⏳ Open — separate follow-up. |
| Legal / commercial pack per Addendum v1.3 | ⏳ Open — founder track. |

Docker reproducibility improves materially: the base image is now pinned to an immutable content-addressable digest, removing upstream re-tag drift. **Reproducibility gate is not fully closed** until the remaining follow-ups (Actions SHAs, retention workflow, alembic, deploy) are completed. **No deploy decision made by this patch.** **Paid pilot / real clinic data remains blocked** by the standing operational gates.

---

## 7. Non-actions in this patch

The following were **explicitly not done** in Patch 11B-b3-b:

- ❌ No dependency change. `requirements.in`, `requirements.txt`, `requirements-dev.txt` byte-identical to the post-Patch-11B-b2-c state.
- ❌ No `--require-hashes` flag added to the Dockerfile.
- ❌ No other Dockerfile line changed. `WORKDIR`, `COPY`, `RUN pip install`, `ENV`, `CMD` byte-identical.
- ❌ No GitHub Actions change.
- ❌ No `anchor-retention-prune.yml` fix or deletion.
- ❌ No `alembic` removal.
- ❌ No `httpx` change.
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
- ❌ No Docker install.
- ❌ No `docker pull`, no `docker build`, no `docker inspect`. (Local Docker is unavailable; the first real Docker build under the pinned digest is whatever runs on Render after a future deploy.)
- ❌ No secret value read, printed, stored, or pasted.
- ❌ No commit. No push. (Per scope.)
- ❌ No compliance / certification / regulator-approval claim.
- ❌ No paid-pilot or real-clinic-data authorisation.

What this patch **did** do: changed exactly one Dockerfile line (the `FROM` line) to pin the base image to the multi-arch index digest identified by the Patch 11B-b3-a probe, validated that the lockfile install path remains clean in a fresh Python 3.11 venv (`pip install -r requirements.txt` with hash verification, `pip check` clean, `from app.main import app` returns `IMPORT OK`), and updated the operations README.
