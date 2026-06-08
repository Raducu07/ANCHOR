# ANCHOR Render Deploy Smoke — 2026-06-08 — cd9d966

> **Documentation only.** This artefact records the controlled Render deploy and production smoke after the dependency / reproducibility remediation chain. **No code changed.** No dependency changed. No Dockerfile changed. No workflow changed. No migration changed. No migrations run. No database queried or mutated. No Render setting changed. **No deploy performed by this documentation patch.** No frontend touch. No secret read, printed, or stored. Not compliance certification. Not a regulator endorsement. Not a claim that ANCHOR is secure, compliant, certified, vulnerability-free, RCVS-approved, or regulator-endorsed.

---

## 1. Purpose and scope

This artefact records the **first Render deploy of `anchor-api-prod` after the Patch 11B-b series remediation chain** and the production smoke executed against the resulting build. The remediation chain closed the dependency / reproducibility track at the file layer; Render rebuild + smoke is the first validation of that stack end-to-end.

- Documentation only.
- No code changed.
- No dependency changed.
- No Dockerfile changed.
- No workflow changed.
- No migration changed.
- No DB queried or mutated.
- No Render setting changed.
- **No deploy performed by this documentation patch.** The deploy event recorded below was an operator-initiated Render dashboard action **prior to** this patch; this patch only captures the evidence.
- Not compliance certification.
- Not a claim that ANCHOR is secure, compliant, certified, vulnerability-free, RCVS-approved, or regulator-endorsed.

---

## 2. Deploy event

| Property | Value |
|---|---|
| Service | `anchor-api-prod` |
| Platform | Render |
| Branch | `main` |
| Commit deployed | **`cd9d966`** |
| Commit title | `Record post-Alembic dependency audit result` |
| Render event observed | `Deploy live for cd9d966` |
| Deploy time observed | June 8, 2026 — approximately 5:04 PM local dashboard time (per operator screenshot/note; not independently re-verified by this artefact) |
| Deploy initiation | **Manual** from Render dashboard |
| Render env var change | **None** |
| Render setting change | **None** |
| Live Workspace generation enabled | **No** — remains production-off |

---

## 3. Remediation stack covered by this deploy

This is the first Render deploy that exercises the full Patch 11B-b series chain. Stack covered:

- **PyJWT remediation** — `PyJWT==2.13.0` (Patch 11C, `2026-06-07_pyjwt_remediation.md`).
- **Starlette remediation via compound FastAPI / Pydantic bump** — `fastapi==0.133.1`, `pydantic[email]==2.7.4`; resolves Starlette to `1.2.1` above the `1.0.1` `PYSEC-2026-161` fix threshold (Patch 11D-b, `2026-06-07_fastapi_starlette_remediation.md`).
- **Hashed compiled lockfile** — `requirements.in` source of truth + `pip-tools`-compiled `requirements.txt` with SHA256 hashes; `pip install` auto-enters hash-checking mode (Patch 11B-b2-b, `2026-06-07_lockfile_implementation.md`).
- **Post-lockfile CI pip-audit PASS** — run `#4` against `32e9b94` (Patch 11B-b2-c, `2026-06-07_post_lockfile_ci_audit.md`).
- **Docker base-image digest pin** — `python:3.11-slim@sha256:a3ab0b966bc4e91546a033e22093cb840908979487a9fc0e6e38295747e49ac0` (Patch 11B-b3-b, `2026-06-07_docker_base_digest_pin.md`).
- **GitHub Actions SHA pin** — five `uses:` lines across three workflows pinned to immutable commit SHAs (Patch 11B-b4-b, `2026-06-07_github_actions_sha_pin_implementation.md`).
- **Stale retention workflow removal** — `.github/workflows/anchor-retention-prune.yml` deleted; manual `intake_retention.md` runbook remains the active control (Patch 11B-b5-b, `2026-06-07_retention_workflow_removal.md`).
- **Alembic / Mako / MarkupSafe removal** — three packages dropped from the runtime install set; lockfile reduced to 34 packages (Patch 11B-b6-b, `2026-06-07_alembic_removal.md`).
- **Post-Alembic CI pip-audit PASS** — run `#5` against `de966a9`, `No known vulnerabilities found` reported by the `Run pip-audit against requirements.txt` step (Patch 11B-b6-c, `2026-06-07_post_alembic_ci_audit.md`).

---

## 4. Production smoke result

Smoke executed from operator PowerShell against `https://anchor-api-prod.onrender.com` after Render reported `Deploy live for cd9d966`. Three read-only endpoints only; no authenticated path; no write endpoint.

| Check | Expected | Observed | Result |
|---|---:|---:|---|
| `GET /health` | `200` | `200 {"status":"ok"}` | PASS |
| `GET /v1/version` | `200` | `200 {"name":"ANCHOR API","env":"prod","git_sha":null,"build":null...` | PASS with metadata observation |
| unauthenticated `GET /v1/portal/dashboard` | `401` | `401` | PASS |

- The protected dashboard returning **401 unauthenticated** is the **expected** access-control smoke result — confirms `require_clinic` / clinic JWT enforcement remains in force on the protected portal route after the dependency stack change.
- No authenticated clinic or user data was requested.
- No write endpoint was called.
- No secret value was inspected, printed, or stored during the smoke.

---

## 5. Version metadata observation

- `GET /v1/version` returned `env=prod` (correct), but **`git_sha=null`** and **`build=null`**.
- Render dashboard separately showed `Deploy live for cd9d966` — i.e. the deployed commit is known from the Render side, just not surfaced through the API's own `/v1/version` response.
- **This is not a smoke failure.** Liveness, env identification, and route protection all work; the missing fields are observability metadata, not health signals.
- **Observability improvement candidate:** wire build SHA / revision metadata into the runtime environment (e.g. a Render-build-time env var populated from the deployed commit, surfaced via the existing `/v1/version` handler). A small, dedicated optional patch — out of scope here.

---

## 6. Stop-condition impact

| Operational gate | Status after this deploy + smoke |
|---|---|
| Dependency / CVE audit (CI pip-audit) | ✅ PASS for the post-Alembic 34-package locked scanned dependency set (run `#5` against `de966a9`). |
| Dependency-file reproducibility | ✅ Closed by Patch 11B-b2-b; preserved by Patch 11B-b6-b. |
| Docker base-image digest pin | ✅ Closed by Patch 11B-b3-b. |
| GitHub Actions SHA pinning | ✅ Closed at the file layer by Patch 11B-b4-b. |
| Stale retention workflow removal | ✅ Closed by Patch 11B-b5-b. |
| Alembic dead-weight removal | ✅ Closed by Patch 11B-b6-b. |
| **First Render rebuild under the post-remediation stack** | ✅ **Live and smoke-PASS at `cd9d966`** (this artefact). |
| `/v1/version` build metadata (`git_sha`, `build`) | ⏳ Open — observability gap; optional follow-up patch. |
| Dockerfile explicit `--require-hashes` flag | ⏳ Open — now eligible to flip (design posture H4 condition met: "first successful Render build under the lockfile" has occurred). Optional one-line follow-up. |
| Optional `httpx<2` / Starlette TestClient deprecation hygiene | ⏳ Open — optional Patch 11B-b7. |
| `github-actions` Dependabot SHA-refresh cadence | ⏳ Open — additive hygiene, separate follow-up. |
| Base-image digest refresh cadence | ⏳ Open — operational hygiene item. |
| Tenant Isolation Smoke #191 rate-limit | ⏳ Open — separate follow-up. |
| Backup/restore drill cadence | ✅ First drill complete (`backup_restore.md §11`, 2026-06-07 PASS); cadence is the ongoing operational discipline. |
| Intake retention dry-run cadence | ✅ First dry-run complete (`intake_retention.md §7 Dry-run — 2026-06-07`, all zero counts); cadence is monthly pre-pilot. |
| Incident-response runbook + first tabletop | ✅ Runbook in place + first tabletop drill executed 2026-06-07 (`incident_response.md §16`). |
| Live Workspace generation in production | 🚫 Production-off; remains gated by the local/staging safety gate and the hard-refusal harness on the live path (per `CLAUDE.md`). |
| **Paid pilot / real clinic data** | ❌ **Not authorised** by this deploy. Standing gates remain: legal / commercial pack per Addendum v1.3, full operational evidence packaging, founder decision. |
| Legal / commercial pack per Addendum v1.3 | ⏳ Open — founder track. |

The deployed backend passed the minimal production smoke gate after the remediation chain. **This does not authorise paid pilot, real clinic data, or sales push.** Live Workspace generation **remains production-off**.

---

## 7. Recommended next steps

The reproducibility-first sequence is now complete and validated end-to-end by a live Render deploy + smoke. Open follow-ups are independent and can be tackled in any order (or deferred):

1. **Build metadata patch for `/v1/version`** — wire `git_sha` and `build` from Render's build-time environment so `/v1/version` returns the deployed commit. Small, observability-only change; no doctrine implication.
2. **Optional `httpx<2` / Starlette TestClient deprecation hygiene** — Patch 11B-b7. Addresses the persistent single-warning seen in every test run since Patch 11D-b. Pure dev/test hygiene.
3. **Optional explicit Dockerfile `--require-hashes` flag** — now eligible to flip (design posture H4 condition met: first successful Render build under the lockfile has occurred). Single-line Dockerfile edit; per-wheel hash verification is already in effect via the fully-hashed lockfile, so the flag's only added effect is to refuse a future un-hashed entry.
4. **Legal / commercial pack work** per Addendum v1.3 — founder track; the hard precondition for any paid pilot / real clinic data conversation.
5. **Continue operational evidence packaging** — second backup/restore drill, second intake-retention dry-run, additional tabletop scenarios on `incident_response.md §16`, base-image digest refresh cadence document, `.github/dependabot.yml` for the `github-actions` ecosystem.

The next decision is the operator's: which of these (if any) to pick up next, or whether to pause the engineering track and shift to the legal / commercial track.

---

## 8. Non-actions

The following were **explicitly not done** in Patch 11B-b6-d:

- ❌ No code change.
- ❌ No dependency change.
- ❌ No Dockerfile change.
- ❌ No GitHub Actions workflow change.
- ❌ No `requirements.in` / `requirements.txt` / `requirements-dev.txt` change.
- ❌ No migration change.
- ❌ No migrations run.
- ❌ No database query or mutation.
- ❌ No production write endpoint called. (Only the three read-only smoke endpoints in §4 were called, **before** this documentation patch.)
- ❌ No additional production endpoint called beyond the three smoke endpoints already recorded.
- ❌ No authenticated clinic / user data retrieved.
- ❌ No Render setting change.
- ❌ No Render API call.
- ❌ No deploy from this documentation patch. (The `cd9d966` deploy was an operator-initiated Render dashboard action prior to this patch.)
- ❌ No frontend touch.
- ❌ No live Workspace generation enabled.
- ❌ No secret value read, printed, stored, or pasted.
- ❌ No commit. No push. (Per scope.)
- ❌ No compliance / certification / regulator-approval / RCVS-approval claim.
- ❌ No paid-pilot or real-clinic-data authorisation.

What this patch **did** do: recorded the operator-initiated Render deploy of commit `cd9d966` to `anchor-api-prod` and the three-endpoint read-only production smoke (`GET /health` → 200; `GET /v1/version` → 200 with `git_sha`/`build` null observation; unauthenticated `GET /v1/portal/dashboard` → 401), tied the deploy to the remediation chain it exercises end-to-end, recorded the build-metadata observability gap as a follow-up candidate (not a failure), and updated the operations README.
