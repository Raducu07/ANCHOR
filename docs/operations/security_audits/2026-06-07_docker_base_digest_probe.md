# ANCHOR Docker Base Digest Probe — 2026-06-07

> **Probe / design only.** This artefact probes how to pin the Docker base image by digest in advance of Patch 11B-b3-b (the implementation patch). **No Dockerfile change.** No dependency change. No workflow change. No application code change. No tests changed. No migrations changed. No migrations run. No production endpoint called. No database queried or mutated. No Render setting changed. No deploy issued. No secret read, printed, or stored. Not compliance certification. Not a regulator endorsement. Not a claim that ANCHOR is secure, compliant, certified, or vulnerability-free.

---

## 1. Purpose and scope

The Patch 11B-b1 inventory ([`2026-06-07_dependency_reproducibility_inventory.md`](./2026-06-07_dependency_reproducibility_inventory.md) §5.1) recorded that ANCHOR's Dockerfile pins its base by **tag** (`python:3.11-slim`), not by **digest** — meaning upstream can re-tag the same `python:3.11-slim` label to point at a different image at any time, silently changing what Render builds. The recommended remediation (Patches **11B-b3**) is to pin the `FROM` line by SHA256 digest.

This probe patch is the design step that precedes the implementation patch (11B-b3-b). Purpose:

- Identify a **safe, reproducible** method to obtain the correct digest, given Docker is not available locally.
- Decide whether to pin to the **multi-arch index** digest or a **platform-specific** manifest digest.
- Record the digest values found so Patch 11B-b3-b can apply them without re-probing.
- Decide whether Patch 11B-b3-b can land directly or needs a CI confirmation step first.

Out of scope (held for later patches):

- Any Dockerfile edit (Patch **11B-b3-b**).
- Dockerfile `--require-hashes` flag flip (separate deferred follow-up, design posture H4).
- GitHub Actions SHA pinning (Patch **11B-b4**).
- `anchor-retention-prune.yml` fix-or-delete (Patch **11B-b5**).
- `alembic` removal (Patch **11B-b6**).
- Any deploy decision.

---

## 2. Current Dockerfile state

`Dockerfile` at HEAD `a13a2b4` (12 lines):

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

CMD sh -c "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"
```

Findings:

- **Current `FROM` line:** `FROM python:3.11-slim` (tag, no digest).
- **Base image digest-pinned?** No.
- **Dependency install path:** `pip install --no-cache-dir -r requirements.txt`.
- **Uses `requirements.txt`?** Yes — reads the **hashed compiled lockfile** introduced by Patch 11B-b2-b ([`2026-06-07_lockfile_implementation.md`](./2026-06-07_lockfile_implementation.md)). `pip` enters hash-checking mode automatically because every entry in that file carries hashes.
- **`--require-hashes` present?** No (deferred; per-wheel verification already in effect via the fully-hashed lockfile — see the §5.2 hash posture note in the lockfile implementation artefact).
- **What changes in Patch 11B-b3-b:** **only** the `FROM` line — `FROM python:3.11-slim` → `FROM python:3.11-slim@sha256:<digest>` (digest values listed in §5–§6 below). No other Dockerfile line changes.

---

## 3. Local Docker availability

Probe command: `Get-Command docker -ErrorAction SilentlyContinue; docker --version`.

Result: **Docker is not installed locally.** PowerShell reports `CommandNotFoundException: The term 'docker' is not recognized as the name of a cmdlet, function, script file, or operable program.` `docker --version` returns the same `CommandNotFoundException`; `docker info` cannot be attempted.

This rules out Options D (local `docker pull` + `docker inspect`) without first installing Docker — which is explicitly out of scope (the prompt says "Do not install Docker"). The probe therefore proceeds with **Option A** (Docker Registry HTTP API), which is a read-only HTTPS call to `auth.docker.io` and `registry-1.docker.io` and touches **no ANCHOR / Render / production / DB / GitHub-secret surface**.

---

## 4. Digest discovery options assessed

| Option | Method | Accuracy | Reproducibility | Scope creep | Workflow change needed? | Local tooling needed? | Touches production? | Solo-operator suitability |
|---|---|---|---|---|---|---|---|---|
| **A** | Docker Registry HTTP API query for `library/python:3.11-slim` (token from `auth.docker.io`, manifest from `registry-1.docker.io`) | high — registry returns canonical `Docker-Content-Digest` header and the multi-arch index | high — pure HTTPS, repeatable from any machine | none | no | only PowerShell (`Invoke-RestMethod` / `Invoke-WebRequest`) — already on this workstation | no | high |
| **B** | GitHub Actions probe — new tiny workflow that runs `docker buildx imagetools inspect python:3.11-slim` on an Ubuntu runner | high — uses the same Docker tooling Render would | high (assuming the workflow itself is reproducible) | **moderate** — requires a new workflow file or a temporary edit + cleanup, mirrors the pattern used for the dependency-audit workflow | yes | none locally | no | medium — adds GitHub Actions churn for a value Option A already returns cleanly |
| **C** | Operator looks up digest on Docker Hub web UI (`hub.docker.com/_/python/tags`) | medium — human-readable but copy/paste-error prone | low | none | no | none | no | medium — works but isn't auditable; the artefact would record a digest with no captured tool output |
| **D** | Install Docker locally and run `docker pull python:3.11-slim`, then `docker inspect --format='{{index .RepoDigests 0}}' python:3.11-slim` | high | high | **high** — explicitly out of scope (prompt: "Do not install Docker") | no | requires Docker Desktop / Docker Engine install | no | **rules out** by scope |
| **E** | Defer the digest pin until evidence is available from a Render deploy (i.e. take the digest Render reports after a successful build) | medium — Render does not surface base-image digest in a first-class way; would require a Render-side `docker inspect` step or scraping build logs | low | high — couples the digest pin to a deploy decision the founder hasn't yet made | no | none | yes (would require either a deploy or an introspection of Render build logs) | low |

**Recommended:** **Option A** — Docker Registry HTTP API.

- Returns the canonical digest header (`Docker-Content-Digest`) that the official tooling (`docker pull`, `docker buildx imagetools inspect`) uses internally.
- Requires no Docker install, no new workflow, no production touch, no secret access.
- Result is reproducible from any machine with network access to Docker Hub.

Option B would be a reasonable backstop if Option A produced an ambiguous result. Option C is acceptable as a manual cross-check by the operator if desired. Options D and E are not pursued in this patch.

---

## 5. Registry probe result

**Probe executed via Option A.** All HTTPS; no credentials; no secrets read; no ANCHOR/Render/production/DB/GitHub surface touched.

### 5.1 Probe details

| Field | Value |
|---|---|
| Auth endpoint | `https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull` |
| Bearer token | obtained (anonymous pull scope only) — **not stored**, used only as an `Authorization` header for the manifest request |
| Manifest endpoint | `https://registry-1.docker.io/v2/library/python/manifests/3.11-slim` |
| Accept header | `application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json` |
| HTTP status | `200 OK` |
| `Content-Type` returned | `application/vnd.oci.image.index.v1+json` (i.e. an **OCI image index**, a.k.a. multi-arch manifest list) |
| `Docker-Content-Digest` returned | **`sha256:a3ab0b966bc4e91546a033e22093cb840908979487a9fc0e6e38295747e49ac0`** |
| Manifest body size | 46,569 bytes (16 platform sub-manifests + signature entries) |
| Temp file `python-3.11-slim-manifest.tmp.json` | **removed** at end of probe (`Test-Path` returns `False`). |

### 5.2 Is the digest an index or platform-specific manifest?

The returned `Content-Type` is `application/vnd.oci.image.index.v1+json` — i.e. a **multi-arch image index** (manifest list). The digest `sha256:a3ab0b966bc4e91546a033e22093cb840908979487a9fc0e6e38295747e49ac0` is therefore the **index digest** (not platform-specific). This is the same digest value that `docker pull python:3.11-slim` would echo as the resolved digest.

### 5.3 `linux/amd64` platform-specific manifest digest

The OCI index lists 16 sub-manifests across `linux/amd64`, `linux/arm/v5`, `linux/arm/v7`, `linux/arm64/v8`, `linux/386`, `linux/ppc64le`, `linux/riscv64`, `linux/s390x`, plus eight `unknown/unknown` attestation entries.

The single sub-manifest matching **`linux/amd64`** (which is the architecture Render's Docker runners use for Python web services) is:

| Field | Value |
|---|---|
| Platform | `linux/amd64` |
| Manifest mediaType | `application/vnd.oci.image.manifest.v1+json` |
| Manifest size | 1,746 bytes |
| **Platform-specific manifest digest** | **`sha256:67e6a6053f28db54c173ad84a4bf88fdd4e338793dc09672e87ee38e3b1b378c`** |

### 5.4 Which digest belongs in the Dockerfile?

Two correct answers exist; they differ in strictness:

- **Index digest** (`sha256:a3ab0b966bc4e91546a033e22093cb840908979487a9fc0e6e38295747e49ac0`) — pins the **multi-arch manifest**. The Docker runtime/builder will pick the appropriate sub-manifest at pull time based on the build platform. This is the digest value `docker pull python:3.11-slim` returns, and the form most documentation and tools (e.g. Dependabot's `docker` ecosystem updater) expect. It is the standard pattern.
- **Platform-specific manifest digest** (`sha256:67e6a6053f28db54c173ad84a4bf88fdd4e338793dc09672e87ee38e3b1b378c`) — pins **only the linux/amd64 sub-image**. Strictly tighter: removes the index-level indirection. Render's builder will fetch this exact manifest unconditionally; if Render ever changed the build runner architecture (extremely unlikely for ANCHOR's Python service), the build would fail closed rather than silently switch.

Both digests are recorded here so that Patch 11B-b3-b (and any future rollback / forensic work) can use either without re-probing.

---

## 6. Digest pin recommendation

### Classification: **`DIGEST PIN TARGET IDENTIFIED`**

The registry probe returned a clean, canonical digest result via the official Docker Registry HTTP API. No tooling ambiguity, no failure class, no missing platform manifest. Both the multi-arch index digest **and** the `linux/amd64` platform-specific manifest digest are recorded above.

### Recommended Patch 11B-b3-b implementation shape

- **Single-line change** in `Dockerfile`:
  - `FROM python:3.11-slim` →
  - `FROM python:3.11-slim@sha256:a3ab0b966bc4e91546a033e22093cb840908979487a9fc0e6e38295747e49ac0`
- Use the **multi-arch index digest** (`sha256:a3ab0b96…49ac0`). Reasons:
  - Matches what `docker pull python:3.11-slim` resolves at this point in time — the digest most operators, audit tooling, and Dependabot's `docker` ecosystem updater expect to see.
  - The Render builder is linux/amd64; the index digest will resolve to the `linux/amd64` sub-manifest (`sha256:67e6a605…378c`) at pull time on Render exactly as it would locally.
  - Tag (`3.11-slim`) is retained alongside the digest as the human-readable label; Docker treats the digest as authoritative when both are present.
- **No other Dockerfile changes.** `COPY`, `RUN pip install`, `CMD`, `WORKDIR`, `ENV` lines remain identical.
- **Explicit `--require-hashes` flag remains deferred** (Patch H4 follow-up); per-wheel hash verification is already in effect via the fully-hashed `requirements.txt`.
- **The platform-specific `linux/amd64` digest (`sha256:67e6a605…378c`) is recorded here as forensic evidence** — Patch 11B-b3-b does not need to use it, but it's available if a future deploy ever surfaces an unexpected platform mismatch.
- **No CI probe step is required first.** The registry probe was unambiguous; the implementation patch can land directly. (If the operator prefers a belt-and-braces approach, a one-shot GitHub Actions `docker buildx imagetools inspect python:3.11-slim@sha256:a3ab0b96…49ac0` run can be fired to confirm Docker tooling accepts the digest before edit; this is **optional** and not part of the recommended path.)

---

## 7. Risk and rollback

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Upstream `python:3.11-slim` is re-tagged after this probe but before Patch 11B-b3-b lands; the recorded digest still exists in the registry but is no longer what the tag points at. | medium (re-tags happen on every Python security release) | **low — the digest pin is *meant* to be sticky.** That's the entire point. The recorded digest is intentional. | None needed. If a security fix later requires a refresh, re-probe and bump in a new patch with its own evidence. |
| R2 | Docker Hub registry is unreachable on the day Patch 11B-b3-b lands. | low | low | The Dockerfile edit itself does **not** require registry access; only the probe does, and the probe is already complete. The operator can apply the edit offline. The first Render build under the new Dockerfile is when registry access becomes load-bearing again. |
| R3 | Render's builder refuses `FROM image@sha256:<index-digest>` syntax (highly unlikely — this is standard Docker syntax). | very low | medium | Optional CI probe (`docker buildx imagetools inspect`) before edit; or rollback by `git revert` of the Patch 11B-b3-b commit. |
| R4 | The digest pin masks an upstream Python security patch from rolling in automatically. | medium (this is by design under digest pinning) | medium | Documented stop condition: digest pinning **requires** a periodic refresh cadence. This will be addressed when the cadence is documented (separate operational hygiene item; out of scope for the lockfile / digest sequence). |
| R5 | Pulled digest mismatches Render's regional registry cache. | very low | low | Digest mismatch would fail the build closed; rollback is `git revert`. |

**Rollback path:** `git revert` the Patch 11B-b3-b commit restores `FROM python:3.11-slim` (no digest). Render rebuilds against whatever the tag currently points at. No Render setting change needed.

---

## 8. Stop-condition impact

| Operational gate | Status after this probe patch |
|---|---|
| Dependency / CVE audit (CI pip-audit) | ✅ PASS for the locked scanned dependency set ([`2026-06-07_post_lockfile_ci_audit.md`](./2026-06-07_post_lockfile_ci_audit.md), run `#4` against `32e9b94`). |
| Dependency-file reproducibility | ✅ Closed by Patch 11B-b2-b. |
| **Docker base-image digest pin** | ⏳ **Open.** This patch identifies the digest. **Patch 11B-b3-b is what actually closes it** (one-line Dockerfile edit). |
| Dockerfile explicit `--require-hashes` flag | ⏳ Open — held for a one-step follow-up after the first successful Render rebuild under the lockfile (design posture H4). |
| GitHub Actions SHA pinning | ⏳ Open — held for **Patch 11B-b4**. |
| `anchor-retention-prune.yml` fix-or-delete | ⏳ Open — held for **Patch 11B-b5**. |
| `alembic` dead-weight removal | ⏳ Open — held for **Patch 11B-b6**. |
| Optional `httpx<2` deprecation hygiene | ⏳ Open — optional **Patch 11B-b7**. |
| Render deploy of post-Starlette + lockfile + digest stack | ⏳ Open — operator decision. Reproducibility-first sequence still recommended (lockfile → digest → Actions SHAs → retention fix-or-delete → alembic removal → deploy). |
| Tenant Isolation Smoke #191 rate-limit | ⏳ Open — separate follow-up. |
| Legal / commercial pack per Addendum v1.3 | ⏳ Open — founder track. |

Reproducibility gate **remains open** until the Dockerfile is actually pinned and validated by a successful Render rebuild. Dependency / CVE audit remains PASS for the locked scanned set. **No deploy decision made by this patch.** **Paid pilot / real clinic data remains blocked** by the standing operational gates above.

---

## 9. Non-actions in this patch

The following were **explicitly not done** in Patch 11B-b3-a:

- ❌ No Dockerfile change. (No `FROM` edit. No `--require-hashes` flag added.)
- ❌ No dependency change. `requirements.in`, `requirements.txt`, `requirements-dev.txt` byte-identical to the post-Patch-11B-b2-c state.
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
- ❌ No Docker install.
- ❌ No `docker pull`, no `docker buildx`, no `docker inspect`.
- ❌ No GitHub Actions workflow added or triggered.
- ❌ No secret value read, printed, stored, or pasted. (The anonymous-pull bearer token from `auth.docker.io` is not a secret — it is granted to any unauthenticated caller on request for public-image scopes — and was used only in-memory as an HTTP header on the manifest request, not written to disk.)
- ❌ No commit. No push. (Per scope.)
- ❌ No compliance / certification / regulator-approval claim.
- ❌ No paid-pilot or real-clinic-data authorisation.

What this patch **did** do: probed the official Docker Hub registry over HTTPS to obtain the canonical multi-arch index digest and the `linux/amd64` platform-specific manifest digest for `python:3.11-slim`, recorded both, recommended the implementation shape for Patch 11B-b3-b (one-line `FROM` edit pinning to the index digest), and updated the operations README.
