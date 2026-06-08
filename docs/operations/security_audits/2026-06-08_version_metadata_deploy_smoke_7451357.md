# ANCHOR Version Metadata Deploy Smoke — 2026-06-08 — 7451357

> **Documentation only.** This artefact records the controlled Render deploy and production smoke after implementing the `/v1/version` git metadata fallback (Patch 11B-b8-b). **No code changed in this patch.** No test changed in this patch. No dependency changed. No Dockerfile changed. No workflow changed. No migration changed. No migrations run. No database queried or mutated. No Render setting changed. **No deploy performed by this documentation patch.** No frontend touch. No secret read, printed, or stored. Not compliance certification. Not a regulator endorsement. Not a claim that ANCHOR is secure, compliant, certified, vulnerability-free, RCVS-approved, or regulator-endorsed.

---

## 1. Purpose and scope

This artefact records the **second Render deploy of `anchor-api-prod` after the observability follow-up** (Patch 11B-b8-b, the `/v1/version.git_sha` fallback to Render's `RENDER_GIT_COMMIT`) and the production smoke executed against the resulting build. The previous post-remediation deploy smoke ([`2026-06-08_render_deploy_smoke_cd9d966.md`](./2026-06-08_render_deploy_smoke_cd9d966.md)) recorded the gap — `git_sha=null` — that this deploy is intended to close.

- Documentation only.
- No code changed in this patch.
- No test changed in this patch.
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
| Commit deployed | **`7451357`** |
| Commit title | `Implement version metadata fallback` |
| Render event observed | `Deploy live for 7451357` |
| Deploy time observed | June 8, 2026 — approximately 5:42 PM local dashboard time |
| Deploy initiation | **Manual** from Render dashboard |
| Render env var change | **None** — `RENDER_GIT_COMMIT` is auto-injected by Render for every Git-repo-backed deploy; no operator-side env-var setup was required |
| Render setting change | **None** |
| Live Workspace generation enabled | **No** — remains production-off |

---

## 3. Implementation being validated

Patch 11B-b8-b ([`2026-06-08_version_metadata_implementation.md`](./2026-06-08_version_metadata_implementation.md)):

- `/v1/version.git_sha` now reads **explicit `GIT_SHA` first**.
- If `GIT_SHA` is absent, it **falls back to Render's `RENDER_GIT_COMMIT`** (auto-injected for every Git-repo-backed Render service).
- **`BUILD_ID` behaviour remains unchanged** — `null` unless an operator explicitly sets `BUILD_ID` in Render env vars (Render has no auto-injected equivalent).
- **Response schema remains stable** — same five keys (`name`, `env`, `git_sha`, `build`, `now_utc`), same types, no new fields.

This deploy validates that **Render's `RENDER_GIT_COMMIT` is actually available to the running service** and that the fallback short-circuit selects it correctly when `GIT_SHA` is unset.

---

## 4. Production smoke result

Smoke executed from operator PowerShell against `https://anchor-api-prod.onrender.com` after Render reported `Deploy live for 7451357`. Three read-only endpoints only; no authenticated path; no write endpoint.

| Check | Expected | Observed | Result |
|---|---:|---:|---|
| `GET /health` | `200` | `200 {"status":"ok"}` | PASS |
| `GET /v1/version` | `200`, `env=prod`, non-null `git_sha` | `200`, `env=prod`, `git_sha=7451357c6430be2105a490cbbb7fcb11db024d0c`, `build=null/blank`, `now_utc=2026-06-08T16:42:30.842331+00:00` | **PASS** |
| unauthenticated `GET /v1/portal/dashboard` | `401` | `401` | PASS |

- The **protected dashboard returning 401 unauthenticated** is the **expected** access-control smoke result — confirms clinic-JWT enforcement remains in force on the protected portal route.
- The returned **`git_sha=7451357c6430be2105a490cbbb7fcb11db024d0c`** is the full 40-character commit SHA whose short form (`7451357`) matches the Render dashboard's deployed-commit display. The fallback chain (`GIT_SHA` → `RENDER_GIT_COMMIT`) is therefore producing the correct deployed-commit value via the `RENDER_GIT_COMMIT` path.
- **`build` remaining null/blank is expected** because `BUILD_ID` was not explicitly configured in Render env vars; Render has no auto-injection equivalent for that field. Honest reporting, not a regression.
- No authenticated clinic or user data was requested. No write endpoint was called. No secret value was inspected, printed, or stored during the smoke.

---

## 5. Version metadata observation

- **Previous smoke for `cd9d966`** ([`2026-06-08_render_deploy_smoke_cd9d966.md`](./2026-06-08_render_deploy_smoke_cd9d966.md)) recorded `git_sha=null` — an observability gap, with the Render dashboard as the only source of truth for the deployed commit.
- **After `7451357`,** `/v1/version.git_sha` is populated with the **full Render Git commit SHA** (`7451357c6430be2105a490cbbb7fcb11db024d0c`), matching what the Render dashboard separately shows as the deployed commit.
- **This closes the build metadata observability gap** identified as an open follow-up candidate in the `cd9d966` smoke artefact.
- **`build` remains optional explicit metadata** — operators who want a build-id field populated can set `BUILD_ID` explicitly in Render env vars; there is no Render-side auto-injection for it. The existing operational evidence templates (`intake_retention.md §7` / `§9`, `backup_restore.md`, future deploy-log captures) can now meaningfully record the deployed git SHA per `env.md §13`.

---

## 6. Stop-condition impact

| Operational gate | Status after this deploy + smoke |
|---|---|
| Dependency / CVE audit (CI pip-audit) | ✅ PASS for the post-Alembic 34-package locked scanned dependency set (run `#5` against `de966a9`). |
| Dependency-file reproducibility | ✅ Closed by Patch 11B-b2-b. |
| Docker base-image digest pin | ✅ Closed by Patch 11B-b3-b. |
| GitHub Actions SHA pinning | ✅ Closed by Patch 11B-b4-b. |
| Stale retention workflow removal | ✅ Closed by Patch 11B-b5-b. |
| Alembic dead-weight removal | ✅ Closed by Patch 11B-b6-b. |
| First Render rebuild under post-remediation stack | ✅ Live + smoke-PASS at `cd9d966` (Patch 11B-b6-d). |
| **`/v1/version` build metadata** | ✅ **Closed at the production layer by this deploy + smoke.** `git_sha` now populated from `RENDER_GIT_COMMIT` fallback. |
| Dockerfile explicit `--require-hashes` flag | ⏳ Open — eligible to flip (design posture H4 condition met). |
| Optional `httpx<2` deprecation hygiene | ⏳ Open — optional Patch 11B-b7. |
| `github-actions` Dependabot SHA-refresh cadence | ⏳ Open — additive hygiene, separate follow-up. |
| Base-image digest refresh cadence | ⏳ Open — operational hygiene item. |
| Tenant Isolation Smoke #191 rate-limit | ⏳ Open — separate follow-up. |
| Live Workspace generation in production | 🚫 Production-off; remains gated by the local/staging safety gate and the hard-refusal harness on the live path (per `CLAUDE.md`). |
| **Paid pilot / real clinic data** | ❌ **Not authorised** by this deploy. Standing gates remain: legal / commercial pack per Addendum v1.3, full operational evidence packaging, founder decision. |
| Legal / commercial pack per Addendum v1.3 | ⏳ Open — founder track. |

Future production smoke can now verify runtime revision directly via `/v1/version.git_sha` without cross-referencing the Render dashboard. This does **not change security posture, dependency posture, RLS, tenant isolation, or governance behaviour**. This does **not authorise paid pilot, real clinic data, or sales push**. **Live Workspace generation remains production-off**.

---

## 7. Recommended next steps

The reproducibility-first sequence (Patches 11B-b2 → 11B-b6) and the observability follow-up (Patch 11B-b8) are now complete and validated end-to-end by live Render deploys + smokes. Open follow-ups are independent and can be tackled in any order (or deferred):

1. **Optional `httpx<2` / Starlette TestClient deprecation hygiene** — Patch 11B-b7. Addresses the persistent single-warning in every test run since Patch 11D-b. Pure dev/test hygiene.
2. **Optional explicit Dockerfile `--require-hashes` flag** — now eligible to flip (design posture H4 condition met: two successful Render builds under the hashed lockfile have occurred at `cd9d966` and `7451357`). Single-line Dockerfile edit.
3. **Legal / commercial pack work** per Addendum v1.3 — founder track; the hard precondition for any paid pilot / real clinic data conversation.
4. **Continue operational evidence packaging** — second backup/restore drill, second intake-retention dry-run, additional `incident_response.md §16` tabletop scenarios, base-image digest refresh cadence document, `.github/dependabot.yml` for the `github-actions` ecosystem.

These four are independent. Operator decision.

---

## 8. Non-actions in this patch

The following were **explicitly not done** in Patch 11B-b8-c:

- ❌ No code change.
- ❌ No test change.
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
- ❌ No Render env-var change. (The `RENDER_GIT_COMMIT` auto-injection is Render's default behaviour for Git-repo-backed services; no operator-side env-var was set or changed.)
- ❌ No deploy from this documentation patch. (The `7451357` deploy was an operator-initiated Render dashboard action prior to this patch.)
- ❌ No frontend touch.
- ❌ No live Workspace generation enabled.
- ❌ No secret value read, printed, stored, or pasted.
- ❌ No commit. No push. (Per scope.)
- ❌ No compliance / certification / regulator-approval / RCVS-approval claim.
- ❌ No paid-pilot or real-clinic-data authorisation.

What this patch **did** do: recorded the operator-initiated Render deploy of commit `7451357` to `anchor-api-prod` (`Deploy live for 7451357`, ~5:42 PM local on 2026-06-08, manual from dashboard, no env-var or setting change) and the three-endpoint read-only production smoke (`GET /health` → 200; `GET /v1/version` → 200 with `env=prod`, **non-null `git_sha=7451357c6430be2105a490cbbb7fcb11db024d0c`** matching the deployed commit's full SHA, `build=null/blank`, `now_utc=2026-06-08T16:42:30.842331+00:00`; unauthenticated `GET /v1/portal/dashboard` → 401); confirmed the Patch 11B-b8-b `RENDER_GIT_COMMIT` fallback works end-to-end on Render; closed the build metadata observability gap recorded in the `cd9d966` smoke artefact; and updated the operations README.
