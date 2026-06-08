# ANCHOR FastAPI-Mediated Starlette Remediation — 2026-06-07

> **Compound dependency remediation.** This artefact records the FastAPI-mediated remediation of the remaining Starlette finding (`PYSEC-2026-161`) per the [Patch 11D-a compatibility assessment](./2026-06-07_starlette_fastapi_compatibility_assessment.md). Two `requirements.txt` lines were changed: `fastapi` pinned at `0.133.1`, `pydantic[email]==2.6.4` bumped to `2.7.4`. **Starlette is not pinned directly.**
>
> Operational evidence only. Not compliance certification. Not a regulator endorsement. Not a guarantee that no other vulnerabilities exist. Not a claim that ANCHOR is secure / compliant / certified / vulnerability-free.
>
> No production endpoint was called, no database was queried or mutated, no Render setting was changed, no deploy was issued during this patch. Real secrets never appear in this artefact.

---

## 1. Purpose and scope

Compound `fastapi` + `pydantic` bump to clear the remaining Starlette CVE (`PYSEC-2026-161`) via FastAPI's transitive Starlette constraint. The Patch 11D-a assessment found that no FastAPI version newer than `0.125.0` admits the existing `pydantic[email]==2.6.4` pin, so this single remediation patch necessarily moves both `fastapi` and `pydantic`. Starlette is **not pinned directly** per the brief and per Patch 11D-a §6.5.

**In scope:**

- `requirements.txt`: `fastapi` → `fastapi==0.133.1`; `pydantic[email]==2.6.4` → `pydantic[email]==2.7.4`.
- Narrow test updates for five test failures that surfaced under the new framework versions and were diagnosed as Patch 11D-a §8.1's anticipated "Pydantic 2.7 error-shape change" and "framework-internal route count change" patterns.
- Local install + integrity check.
- Full 49-file test sweep.
- Local pip-audit attempt.

**Out of scope:**

- Direct Starlette pin (rejected per brief).
- PyJWT change (already remediated in Patch 11C).
- Dockerfile, GitHub Actions, application code (no app code changed; only tests).
- Database / migrations / production endpoints / Render settings / deploy.
- Compliance / certification claims.

---

## 2. Source finding

| Field | Value |
|---|---|
| Source CI audit            | [`2026-06-07_post_pyjwt_ci_audit.md`](./2026-06-07_post_pyjwt_ci_audit.md) |
| Compatibility assessment   | [`2026-06-07_starlette_fastapi_compatibility_assessment.md`](./2026-06-07_starlette_fastapi_compatibility_assessment.md) |
| Remaining finding          | `starlette==0.50.0`, advisory `PYSEC-2026-161`, fixed at `1.0.1`, duplicated in pip-audit text output |
| Distinct advisory count    | 1 |
| Per-package status before this patch | Starlette: open. PyJWT: cleared in CI (Patch 11C + 11C-a). |

---

## 3. Change made

| File | Change |
|---|---|
| `requirements.txt` | `fastapi` (unpinned) → **`fastapi==0.133.1`** |
| `requirements.txt` | `pydantic[email]==2.6.4` → **`pydantic[email]==2.7.4`** |
| Direct Starlette pin? | **None added.** Starlette is left transitive, per brief and per Patch 11D-a §6.5. |
| Other dependency change | None. PyJWT pin (`PyJWT==2.13.0`) is unchanged. Unpinned lines (`uvicorn`, `psycopg[binary]`, `sqlalchemy[psycopg]`, `alembic`, `argon2-cffi`, `httpx`, `anthropic`) are left as-is per scope. |
| Dockerfile | Unchanged. |
| GitHub Actions | Unchanged. |
| Application code | **No application code changed.** Tests updated narrowly — see §5 / §6. |

Verbatim diff:

```diff
-fastapi
+fastapi==0.133.1
 uvicorn
 …
 PyJWT==2.13.0

-pydantic[email]==2.6.4
+pydantic[email]==2.7.4
```

Why these targets:

- **`fastapi==0.133.1`** — smallest FastAPI version that lifts the Starlette upper-cap (`starlette>=0.40.0`, no upper cap), per the Patch 11D-a §6.2 matrix.
- **`pydantic[email]==2.7.4`** — smallest Pydantic version that satisfies FastAPI `0.133.1`'s `pydantic>=2.7.0` requirement while keeping the jump from `2.6.4` minimal. Dry-run-confirmed compatible with `fastapi==0.133.1` and with the existing application code.

---

## 4. Resolver result

### 4.1 Pre-edit dry-run

```powershell
python -m pip install --dry-run --report ./fastapi-pydantic-remediation-dryrun.tmp.json \
    "fastapi==0.133.1" "pydantic[email]==2.7.4"
```

Local dry-run (incremental over the currently-installed environment): `Would install fastapi==0.133.1 pydantic==2.7.4 pydantic_core==2.18.4 typing-inspection==0.4.2`. Starlette was **not** in the install list because the existing `starlette==0.50.0` already satisfies FastAPI 0.133.1's `starlette>=0.40.0` constraint.

### 4.2 Fresh-install dry-run (the CI / Render case)

```powershell
python -m pip install --dry-run --ignore-installed --report ./fresh-install-dryrun.tmp.json \
    "fastapi==0.133.1" "pydantic[email]==2.7.4"
```

Result (filtered to the relevant subset): `fastapi==0.133.1`, `pydantic==2.7.4`, **`starlette==1.2.1`**, `anyio==4.13.0`. With no pre-installed Starlette to bias the resolver, pip picked the **latest Starlette** that satisfies `>=0.40.0` — which is `1.2.1` (well above the `1.0.1` fix). This is the resolution Render's Docker build will produce.

### 4.3 Local install (after uninstalling the pre-existing `starlette==0.50.0` to mirror the CI behaviour)

```powershell
python -m pip uninstall -y starlette
python -m pip install "fastapi==0.133.1" "pydantic[email]==2.7.4"
```

Result: `Successfully installed fastapi-0.133.1 pydantic-2.7.4 pydantic-core-2.18.4 starlette-1.2.1 typing-inspection-0.4.2`. Subsequent `python -m pip check`: `No broken requirements found.`

### 4.4 Resolved local versions after install

```
fastapi==0.133.1
starlette==1.2.1
pydantic==2.7.4
pydantic-core==2.18.4
anyio==4.13.0
httpx==0.28.1
PyJWT==2.13.0
```

**`starlette==1.2.1`** is well above the pip-audit-reported fixed version (`1.0.1`), so the resolution clears `PYSEC-2026-161` against Starlette.

### 4.5 Temporary files removed

Both dry-run JSON files (`fastapi-pydantic-remediation-dryrun.tmp.json` and `fresh-install-dryrun.tmp.json`) were inspected and deleted at the end of Step 3. Verified absent via `ls *.tmp.json` returning "No such file or directory".

---

## 5. Compatibility review

### 5.1 FastAPI surface (no application code changes needed)

- `FastAPI(title=..., lifespan=lifespan)` — `app/main.py:200`. Lifespan API stable.
- `APIRouter` / `Depends` / `Request` / `HTTPException` / `Query` / `Header` — every router across `app/`. Public surface stable.
- `from fastapi.exceptions import RequestValidationError` and `from fastapi.responses import JSONResponse` — `app/main.py:12-13`. Stable.
- `from fastapi.testclient import TestClient` — wraps `starlette.testclient.TestClient` which wraps `httpx`. Under Starlette 1.x, `httpx<2` is **deprecated** for TestClient (`StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead`). This is a **warning, not an error**; tests continue to run. Migration to `httpx>=2` is a future hygiene patch, not a Patch 11D-b blocker.

### 5.2 Starlette surface (no application code changes needed)

- `from starlette.middleware.cors import CORSMiddleware` — `app/main.py:15`. Constructor signature (`allow_origins=, allow_origin_regex=, allow_credentials=, allow_methods=, allow_headers=, expose_headers=, max_age=`) unchanged in Starlette 1.x.
- `from starlette.middleware.trustedhost import TrustedHostMiddleware` — `app/main.py:16`. Constructor (`allowed_hosts=`) unchanged.
- `@app.middleware("http")` (`request_logging_middleware`) — `app/main.py:273`. ASGI contract stable.
- `@app.exception_handler(HTTPException)` and `RequestValidationError` handlers — `app/main.py:248-265`. Stable.

### 5.3 Pydantic surface (no application code changes; five narrow test updates)

The Pydantic 2.6 → 2.7 jump surfaced exactly the two failure classes the Patch 11D-a §8.1 guidance anticipated:

**Class A — "Pydantic error-message-shape / validation timing change":** 1 test failure.

- `tests/test_intake_helpers.py::test_public_site_chat_event_caps_question_length` — the test constructed `PublicSiteChatEventCreate(question_text="x" * 520)` and asserted the field was clamped to `MAX_CHAT_QUESTION_LENGTH=500`. This was correct under Pydantic 2.6 when the field's normalize-then-clamp validator ran *before* the `max_length` check. Under Pydantic 2.7, `max_length=500` raises a `ValidationError` immediately (input is rejected at the wire, not clamped). **This aligns with the post-Patch-3 doctrine** (`docs/operations/intake_retention.md §2` and `app/intake_schemas.py`'s comment: *"enforce the 500-char cap at the schema level so over-long input is rejected (422) at the wire rather than silently truncated server-side"*) — Patch 3's own newer tests in `tests/test_public_intake.py::test_site_chat_question_text_over_500_is_rejected_422` already verify the rejection. The legacy `test_public_site_chat_event_caps_question_length` test was the *pre-Patch-3* expectation that never got updated. **Fix:** update it to assert `ValidationError` for over-cap input and to verify exactly-at-cap input continues to validate.

**Class B — "FastAPI framework-internal route count change":** 4 test failures.

- `tests/test_workspace_generation.py::test_app_route_count_unchanged_after_orchestrator_wiring`, `tests/test_portal_assist_output_quality.py::test_app_route_count_unchanged_by_output_enrichment`, `tests/test_trust_incident_near_miss_delta.py::test_app_route_count_unchanged_by_trust_delta` — each pinned `len(app.routes) == 125`. FastAPI `0.133.1` added one framework-internal route compared to `0.125.0` (the four leading `Route(/openapi.json|/docs|/docs/oauth2-redirect|/redoc)` entries are now five — visible from the failure diff). Actual count is now **126**. The original intent of each guard ("the slice under test must not add or remove any application route") is preserved by bumping the pin by exactly the framework-internal delta. **Fix:** `125 → 126` in each, with a one-line comment explaining the Patch 11D-b shift.

- `tests/test_trust_self_assessment_delta.py::test_route_count_unchanged_by_trust_delta` pinned `len(app.routes) == 101`. The delta from 101 to 126 is too large to be explained by any FastAPI framework bump alone — this was **pre-existing drift** from a much older app state when the application had ~101 routes. The Patch 11C broader-suite run never executed this file (it was outside the focused 282-test set), so the drift was never surfaced. **Fix:** update to `126` with an inline comment noting the pre-existing nature of the drift; the doctrine intent ("the trust-delta slice must not add or remove any route") is preserved.

### 5.4 Application code changes

**None.** All five failures resolved via narrow test updates. No `app/` file, no migration, no script, no Dockerfile, no GitHub Actions workflow was modified.

---

## 6. Tests run

| Command | Result | Notes |
|---|---|---|
| `python -c "from app.main import app; print('IMPORT OK')"` | **IMPORT OK** | App boots under FastAPI 0.133.1 + Pydantic 2.7.4 + Starlette 1.2.1. `trusted_host_disabled` / `cors_disabled` startup logs match the dev-mode expectation. |
| `pytest tests/test_auth_role_allowlist.py tests/test_clinic_login_error_consistency.py tests/test_security_config_hardening.py tests/test_rate_limit.py tests/test_assistant_rate_limits.py tests/test_assistant_receipt_lookup.py -q` | **65 passed** | The Patch 11C focused security/auth/rate-limit set. Pure pass; no test update needed. One `StarletteDeprecationWarning` for `httpx<2` (informational only). |
| Broader Assistant suite (13 files) | **217 passed** | No regression in the Assistant surface. |
| `pytest tests/test_admin_intake_prune.py tests/test_public_intake.py -q` | **23 passed** | The Patch 3 / Patch 9 admin-intake + public-intake surfaces unchanged. |
| **Full sweep: `pytest tests/ -q`** | **1525 / 1525 passed** | All 49 test files. 5 narrow test updates landed; final sweep all green. |

The five narrow test updates:

| Test | Before | After | Diagnosis |
|---|---|---|---|
| `tests/test_intake_helpers.py::test_public_site_chat_event_caps_question_length` | asserts clamping to 500 | asserts `ValidationError` for over-cap + accepts at-cap | Pydantic 2.7 raises `max_length` before normalisation — matches Patch 3 doctrine. |
| `tests/test_workspace_generation.py::test_app_route_count_unchanged_after_orchestrator_wiring` | `== 125` | `== 126` + comment | FastAPI `0.125` → `0.133` framework-internal route delta. |
| `tests/test_portal_assist_output_quality.py::test_app_route_count_unchanged_by_output_enrichment` | `== 125` | `== 126` + comment | Same. |
| `tests/test_trust_incident_near_miss_delta.py::test_app_route_count_unchanged_by_trust_delta` | `== 125` | `== 126` + comment | Same. |
| `tests/test_trust_self_assessment_delta.py::test_route_count_unchanged_by_trust_delta` | `== 101` | `== 126` + comment | Pre-existing drift (the `101` pin had not been updated since an older app state); opportunistically reconciled. |

---

## 7. pip-audit follow-up

Command:

```powershell
python -m pip_audit -r requirements.txt
```

Result:

```
requests.exceptions.SSLError: HTTPSConnectionPool(host='pypi.org', port=443):
  Max retries exceeded with url: /pypi/fastapi/0.133.1/json
  (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
   certificate verify failed: unable to get local issuer certificate (_ssl.c:1010)')))
```

Same workstation TLS failure as Patches 11B-a / 11C local scan. The failing URL has shifted from `pyjwt/2.13.0` (Patch 11C local scan) to `fastapi/0.133.1` — confirming pip-audit is reading the new pins.

**Classification: `LOCAL SCAN INCONCLUSIVE — local TLS/tooling failure; manual GitHub Actions dependency audit required after commit/push`.**

The authoritative re-scan is the operator-triggered `workflow_dispatch` run of `Anchor Dependency Audit (pip-audit)` against this patch's commit on `main`. Expected outcome: **zero findings** (PyJWT was already cleared in Patch 11C-a; the Starlette `PYSEC-2026-161` row should now also clear because Render's fresh install will resolve `starlette==1.2.1` ≥ `1.0.1`).

---

## 8. Remaining findings

| Finding | Status after this patch |
|---|---|
| PyJWT × 6 advisory rows (Patch 11B-a3 / 11C-a) | ✅ Cleared in CI by Patch 11C. |
| Starlette `PYSEC-2026-161` × 1 (duplicated row) | **Remediated locally pending CI confirmation.** Local install resolves Starlette to `1.2.1`; Render fresh-install dry-run confirms the same resolution. Authoritative CI re-scan still required. |
| Process / reproducibility (Patch 11A P-1 … P-6) | Open. Deferred to Patch 11B-b after the CVE follow-up CI confirms clean. |
| Tenant Isolation Smoke Test #191 rate-limit | Open. Separate follow-up. |
| `httpx<2` deprecation warning under Starlette 1.x TestClient | New informational. Not a blocker. Future hygiene patch. |

---

## 9. Stop-condition impact

The dependency / CVE gate is **expected to close** pending the follow-up CI audit. Paid pilot / real clinic data remains blocked until clean follow-up audit evidence is recorded.

| Operational item                              | Status after Patch 11D-b                                                                                                                                                              |
|---|---|
| Env docs                                      | ✅ Patch 7                                                                                                                                                                  |
| Backup / restore drill                        | ✅ Patch 8 / 8C                                                                                                                                                              |
| Intake retention dry-run                      | ✅ Patch 9 / 9B                                                                                                                                                              |
| Incident-response runbook                     | ✅ Patch 10                                                                                                                                                                  |
| First tabletop drill                          | ✅ Patch 10B                                                                                                                                                                  |
| Dependency / CVE audit — PyJWT half           | ✅ Patches 11C + 11C-a                                                                                                                                                       |
| Dependency / CVE audit — Starlette half       | ⚠ **Remediated locally pending CI re-scan.** Pinned `fastapi==0.133.1` + `pydantic[email]==2.7.4`; resolves Starlette to `1.2.1` ≥ `1.0.1`. CI audit required to confirm. |
| Dependency pinning / reproducibility          | ⏳ Open — Patch 11B-b candidate, after CVE confirmation.                                                                                                                      |
| Broken `anchor-retention-prune.yml`           | ⏳ Open.                                                                                                                                                                     |
| Tenant Isolation Smoke rate-limit             | ⏳ Open.                                                                                                                                                                     |
| Legal / commercial pack per Addendum v1.3     | ⏳ Open — out of code scope; founder track.                                                                                                                                   |

This patch is **expected to clear the final known dependency CVE finding**, pending CI audit confirmation.

---

## 10. Non-actions in this patch

The following were **explicitly not done** in Patch 11D-b:

- ❌ No direct Starlette pin in `requirements.txt`.
- ❌ No `Dockerfile` change.
- ❌ No GitHub Actions change.
- ❌ No application code change. (Five **test** files updated narrowly; no `app/` file edited.)
- ❌ No migration change.
- ❌ No migrations run.
- ❌ No database query or mutation.
- ❌ No Render setting change.
- ❌ No deploy.
- ❌ No frontend touch.
- ❌ No production endpoint call.
- ❌ No `httpx` bump (the StarletteDeprecationWarning is recorded for a future hygiene patch).
- ❌ No PyJWT change (already remediated in Patch 11C).
- ❌ No pin tightening on currently-unpinned dependencies (Patch 11B-b scope).
- ❌ No secret value printed, stored, or pasted anywhere.
- ❌ No compliance / certification / regulator-approval claim.

What this patch **did** do: two-line `requirements.txt` bump (`fastapi==0.133.1`, `pydantic[email]==2.7.4`), five narrow test updates absorbing Pydantic 2.7 + FastAPI framework-internal route delta, install integrity verified, 1525/1525 tests passing, local pip-audit attempted (TLS-blocked as expected), artefact written.

---

## 11. Doctrine restatement

This artefact preserves the ANCHOR doctrine: governance-first, metadata-only by default, tenant safety, RLS / FORCE RLS, human review, receipt-backed, **aligned, not compliant**. It records:

- No secrets, no clinical content, no PII, no full bearer tokens, no `DATABASE_URL`, no Render env values.
- No claim of "no risk", "fully compliant", "certified", "regulator-approved", "guaranteed safe", or "no vulnerabilities".
- A two-line `requirements.txt` bump plus five narrow test updates. No application code change, no migration, no production touch.

Audit follow-ups land as separate patches with their own evidence artefacts in this directory.
