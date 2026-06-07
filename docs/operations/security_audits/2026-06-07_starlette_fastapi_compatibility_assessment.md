# ANCHOR Starlette / FastAPI Compatibility Assessment — 2026-06-07

> **Read-only assessment.** This artefact assesses the remaining Starlette finding (`PYSEC-2026-161`) after the Patch 11C / 11C-a PyJWT remediation. **No remediation is applied in this patch.** Starlette is **not** pinned directly. **No dependency, application code, migration, Dockerfile, GitHub Actions, production endpoint, database, or Render setting is changed.** Real secrets — admin tokens, API keys, `DATABASE_URL`, JWT secret, hash salt, admin pepper, GitHub secrets values — never appear in this artefact.
>
> Operational evidence only. Not compliance certification. Not a regulator endorsement. Not a guarantee that no other vulnerabilities exist. Not a claim that ANCHOR is secure / compliant / certified / vulnerability-free.

---

## 1. Purpose and scope

Assess the **remaining Starlette finding** after Patch 11C / 11C-a cleared the PyJWT half of the CI audit, and **decide whether a FastAPI-mediated remediation path is available**.

**In scope:**

- Reading the current dependency declaration (`requirements.txt`) and the currently-resolved runtime environment.
- Inspecting FastAPI's Starlette and Pydantic constraints across candidate versions to find the smallest bump that lifts the Starlette cap to admit `1.0.1`.
- Summarising the application's FastAPI / Starlette compatibility surface (middleware, exception handlers, response classes, lifespan, TestClient).
- Recording a classification (likely available / not yet / inconclusive) and recommending the Patch 11D-b shape.

**Out of scope:**

- Any dependency change (no Starlette pin, no FastAPI bump, no Pydantic bump, no pin tightening).
- Application code change.
- Migration / Dockerfile / GitHub Actions change.
- Production endpoints / database queries / Render settings / deploy.
- Compliance / certification claims.

---

## 2. Source finding

Per [`2026-06-07_post_pyjwt_ci_audit.md`](./2026-06-07_post_pyjwt_ci_audit.md) §3:

| Package | Scanned version | Advisory | Fixed version reported by pip-audit |
|---|---|---|---|
| `starlette` | `0.50.0` | `PYSEC-2026-161` (duplicated in pip-audit text output) | `1.0.1` |

Distinct advisory count: **1**. The duplicate row is a pip-audit output artefact, not two independent advisories.

---

## 3. Current dependency declaration

`requirements.txt` at the time of this assessment (commit `64dcc7b2dd57`, post-Patch 11C-a):

| Line | Direct? | Pin posture | Relevance to this assessment |
|---|---|---|---|
| `fastapi` | yes | **unpinned** | Drives Starlette via its transitive constraint. The unpinned line means Render's resolver picks whichever FastAPI PyPI offers at build time. |
| `uvicorn` | yes | unpinned | ASGI server. Some FastAPI bumps tighten the `uvicorn` minimum. |
| `psycopg[binary]` | yes | unpinned | Unrelated to this assessment. |
| `sqlalchemy[psycopg]` | yes | unpinned | Unrelated. |
| `alembic` | yes | unpinned (Patch 11A P-6 dead-weight) | Unrelated. |
| `PyJWT==2.13.0` | yes | **pinned** (Patch 11C) | Already remediated. |
| `pydantic[email]==2.6.4` | yes | **pinned** | **Binding constraint for the assessment.** FastAPI ≥ 0.126 requires `pydantic>=2.7.0`. |
| `argon2-cffi` | yes | unpinned | Unrelated. |
| `httpx` | yes (test dep inlined) | unpinned | Unrelated. |
| `anthropic` | yes | unpinned | Unrelated. |
| **`starlette`** | **NO — not declared** | n/a | Transitive of `fastapi`. **Not in `requirements.txt`.** |
| `anyio` | NO — not declared | n/a | Transitive of `starlette`. |

**Key declarations for this assessment:**

- `fastapi` — unpinned.
- `starlette` — not declared (transitive only).
- `pydantic[email]==2.6.4` — pinned.

---

## 4. Current resolved environment

Local probe via `importlib.metadata`:

```
fastapi==0.125.0
starlette==0.50.0
pydantic==2.6.4
uvicorn==0.47.0
anyio==4.13.0
httpx==0.28.1
```

- **Local `starlette==0.50.0` matches the CI finding exactly.** Same vulnerable version.
- **Local `fastapi==0.125.0`** declares its Starlette constraint as `starlette<0.51.0,>=0.40.0`. This **explicit upper cap at `<0.51.0`** is the binding wall: under FastAPI `0.125.0`, no resolver can ever admit Starlette `1.0.1`. The CVE is unreachable via Starlette alone while FastAPI stays at `0.125.0`.
- **Local `pydantic==2.6.4`** matches the `requirements.txt` pin.

---

## 5. Application compatibility surface

FastAPI / Starlette usage inventory across `app/` and `tests/`:

| Surface | Where | Risk under a FastAPI bump |
|---|---|---|
| `FastAPI` app construction with `lifespan=` | `app/main.py:200` (and `lifespan` definition L152–197) | Low. Lifespan API has been stable in FastAPI ≥ 0.93. |
| `APIRouter` (every router) | `app/admin_audit.py`, `app/admin_auth.py`, `app/admin_intake.py`, `app/admin_ops.py`, `app/admin_tokens.py`, `app/assistant.py`, `app/auth_and_rls.py`, `app/client_transparency.py`, `app/db.py`, `app/governance_policy.py`, `app/incident_near_miss.py`, `app/learn_v1.py`, `app/main.py`, and ~20 portal routers | Low. `APIRouter` shape stable since FastAPI ≥ 0.79. |
| `Depends`, `Request`, `HTTPException`, `Query`, `Header` | every router | Low. Public surface; stable. |
| `from fastapi.exceptions import RequestValidationError` | `app/main.py:12` | Low. Public re-export; stable. |
| `from fastapi.responses import JSONResponse` | `app/main.py:13` | Low. |
| `from starlette.middleware.cors import CORSMiddleware` | `app/main.py:15` | **Medium.** Direct Starlette import. Starlette major-version transitions (0.x → 1.x) are the primary risk if the middleware module path or constructor signature changes between versions. The `CORSMiddleware(allow_origins=, allow_origin_regex=, allow_credentials=, allow_methods=, allow_headers=, expose_headers=, max_age=)` signature used at `app/main.py:123-134` has been stable in Starlette 0.x; needs a re-read against Starlette 1.0 changelog. |
| `from starlette.middleware.trustedhost import TrustedHostMiddleware` | `app/main.py:16` | **Medium.** Direct Starlette import. The `TrustedHostMiddleware(allowed_hosts=)` signature used at `app/main.py:104-105` is stable in 0.x. |
| `@app.exception_handler(HTTPException)` / `RequestValidationError` | `app/main.py:248-265` | Low. Exception-handler decorator is stable. |
| `@app.middleware("http")` | `app/main.py:273` (`request_logging_middleware`) | **Medium.** ASGI middleware contract is stable across the 0.x line; needs a re-read against Starlette 1.0. |
| `from fastapi.testclient import TestClient` | `tests/test_admin_intake_prune.py`, `tests/test_assistant_*.py`, `tests/test_public_intake.py`, `tests/test_security_config_hardening.py` (and others) | **Medium.** `TestClient` is a re-export of Starlette's TestClient which in turn wraps `httpx`. Cross-version compatibility between TestClient and `httpx==0.28.1` should be re-verified after any bump. |
| `RequestValidationError` handling | `app/main.py:261-266` | Low. |
| `from contextlib import asynccontextmanager` + `lifespan=lifespan` | `app/main.py:8, 152, 200` | Low. FastAPI lifespan is documented stable. |
| Pydantic v2 models everywhere (≈40 `BaseModel` definitions across `app/`, all using v2 idioms; ConfigDict where needed; M6.6.1 cleanup recorded as held in CLAUDE.md) | every router schema | **High.** A Pydantic 2.6 → 2.7+ bump is part of any FastAPI ≥ 0.126 path. While Pydantic 2.x is supposed to be ABI-compatible across patch lines, the 2.6 → 2.7+ jump touches strict-mode behaviour, `model_validator`, and error message shapes. Any FastAPI bump under §7 must be paired with a careful re-run of the full Assistant / governance test set. |

**Test count: 49 test files.** TestClient is used widely (every Assistant suite, the public-intake suite, the admin-intake-prune suite, the security-config-hardening CORS preflight tests). Any TestClient incompatibility would surface during the standard `pytest` sweep.

---

## 6. Candidate remediation path

### 6.1 PyPI inspection succeeded

`python -m pip index versions fastapi` returned the full FastAPI release list. Latest: **`0.136.3`**. Local TLS path used by `pip-audit` previously failed (Patches 11B-a, 11C local scan), but `pip index` over HTTPS to PyPI's simple index works on this workstation — distinct code path that does not exercise the same TLS verification.

`python -m pip install --dry-run --report ...` against multiple candidate FastAPI versions succeeded and exposed per-version metadata.

### 6.2 Per-version probe results

Probed via `pip install --dry-run` for each candidate, reading `requires_dist` from the resolver report:

| FastAPI version | Starlette constraint | Pydantic constraint | Admits Starlette `1.0.1`? | Admits Pydantic `2.6.4`? |
|---|---|---|---|---|
| `0.125.0` (currently installed) | `<0.51.0,>=0.40.0` | `>=1.7.4,<3.0.0` (with exclusions) | ❌ (capped <0.51) | ✅ |
| `0.126.0` | `<0.51.0,>=0.40.0` | `>=2.7.0` | ❌ (capped <0.51) | ❌ |
| `0.128.8` | `<1.0.0,>=0.40.0` | `>=2.7.0` | ❌ (capped <1.0) | ❌ |
| `0.130.0` | `<1.0.0,>=0.40.0` | `>=2.7.0` | ❌ (capped <1.0) | ❌ |
| `0.132.0` | `<1.0.0,>=0.40.0` | `>=2.7.0` | ❌ (capped <1.0) | ❌ |
| **`0.133.1`** | **`>=0.40.0`** (no upper cap) | `>=2.7.0` | **✅** | ❌ |
| `0.134.0` | `>=0.46.0` | `>=2.7.0` | ✅ | ❌ |
| `0.135.0` | `>=0.46.0` | `>=2.7.0` | ✅ | ❌ |
| `0.136.3` (latest) | `>=0.46.0` | `>=2.9.0` | ✅ | ❌ |

### 6.3 Starlette `1.0.1` standalone

`python -m pip install --dry-run --report ./starlette-101-dryrun.tmp.json "starlette==1.0.1"` succeeded; pip-side resolution shows Starlette `1.0.1` is installable on PyPI. The brief forbids pinning Starlette directly without a founder decision; that path is not pursued here.

### 6.4 Compound-bump implication

**Every FastAPI version that lifts the Starlette cap above `<1.0.0` also requires `pydantic>=2.7.0`.** The smallest FastAPI version that admits Starlette `1.0.1` is **`0.133.1`**, but it carries a `pydantic>=2.7.0` requirement that breaks the current `pydantic[email]==2.6.4` pin.

There is therefore **no single-package FastAPI bump** that satisfies the Starlette CVE without also touching Pydantic.

### 6.5 Direct-Starlette-pin path (rejected)

If `requirements.txt` were to gain `starlette==1.0.1` directly, the resolver under FastAPI `0.125.0` (which caps `<0.51.0`) would reject the install. So even a direct Starlette pin requires the FastAPI bump above — and therefore the Pydantic bump too. Direct Starlette pinning offers no shortcut. The brief's rule against direct Starlette pinning aligns with this conclusion.

---

## 7. Assessment classification

**`FASTAPI-MEDIATED REMEDIATION LIKELY AVAILABLE`** — with a binding caveat.

**Why this classification:**

- PyPI inspection succeeded; FastAPI versions exist that admit Starlette `1.0.1`.
- The smallest such version is `0.133.1` (Starlette constraint `>=0.40.0`, no upper cap).
- Starlette `1.0.1` is installable on PyPI and fixes `PYSEC-2026-161` per pip-audit's reported fixed version.

**Binding caveat (must be acknowledged before Patch 11D-b lands):**

- The FastAPI bump from `0.125.0` to `0.133.1` (or higher) requires a simultaneous **Pydantic bump from `2.6.4` to `≥2.7.0`** (or `≥2.9.0` if going to the latest FastAPI `0.136.3`).
- Pydantic `2.6 → 2.7+` is a *minor* bump within Pydantic 2.x and is ABI-compatible at the public-API level, but introduces strict-mode behaviour refinements, `model_validator` changes, and error-message-shape changes that may affect ANCHOR's ~40 `BaseModel` definitions, several `ConfigDict` usages, and the existing test assertions that match against error strings.
- **This is no longer a single-package remediation. It is a compound (`fastapi` + `pydantic`) bump.**

**This is NOT classified as `NOT YET AVAILABLE`** — a path exists. **Nor `INCONCLUSIVE`** — local tooling answered every question. But the path is materially larger than the Patch 11C PyJWT remediation, and Patch 11D-b must scope accordingly.

---

## 8. Recommended Patch 11D-b

**Recommended shape:** compound dependency bump in two staged sub-patches if the founder prefers smaller landings, or one combined patch if cleaner.

### 8.1 Single-patch shape

Edit only `requirements.txt`:

```diff
-fastapi
+fastapi==0.133.1
 uvicorn
 psycopg[binary]
 sqlalchemy[psycopg]
 alembic
 PyJWT==2.13.0

-pydantic[email]==2.6.4
+pydantic[email]==2.7.4
 argon2-cffi
```

(Exact target versions to be confirmed: `0.133.1` is the smallest FastAPI that lifts the Starlette cap. `2.7.4` is a *candidate* — the smallest Pydantic that satisfies FastAPI `0.133.1`'s `>=2.7.0` while remaining a minimal jump. Operator should re-probe before pinning.)

**Why not Starlette pin:** rejected per the brief and per §6.5 — no resolution improvement and policy-aligned to let FastAPI's transitive resolution drive Starlette.

**Test set to run (cannot guess at compatibility — must verify):**

- App import check (`python -c "from app.main import app; print('IMPORT OK')"`).
- The Patch 11C 282-test set: `tests/test_auth_role_allowlist.py`, `tests/test_clinic_login_error_consistency.py`, `tests/test_security_config_hardening.py`, `tests/test_rate_limit.py`, `tests/test_assistant_rate_limits.py`, `tests/test_assistant_receipt_lookup.py`, and the broader Assistant 13-file suite.
- The wider sweep: `pytest -q tests/` — all 49 test files. Pydantic 2.6 → 2.7 may surface in any `BaseModel`-touching test, not just the JWT path.
- Any failure that traces to a Pydantic-2.7 error-message-shape change should be addressed by **updating the test's expected error string**, not by reverting the Pydantic bump.
- Any failure that traces to a `model_validator` semantics change is a real compatibility break; assess case-by-case and either adjust the model or hold the patch.

**Local install (narrow):**

```powershell
python -m pip install "fastapi==0.133.1" "pydantic[email]==2.7.4"
python -m pip check
```

**Workflow:**

- Trigger `Anchor Dependency Audit (pip-audit)` manually after commit/push.
- Append a new artefact `<YYYY-MM-DD>_post_starlette_ci_audit.md` recording the post-Starlette CI result. Expected outcome: zero advisory rows (PyJWT already cleared; Starlette now ≥ 1.0.1).

### 8.2 Two-patch shape (optional)

If the operator prefers smaller landings to bound blast radius:

- **Patch 11D-b-1**: pin Pydantic to a `2.7+` version (`pydantic[email]==2.7.4`). Verify the full 49-file test set. No FastAPI change.
- **Patch 11D-b-2**: pin FastAPI to `0.133.1`. Verify the full 49-file test set. No Pydantic change in this patch.

The two-patch shape isolates Pydantic-side failures from FastAPI-side failures during validation. If a failure surfaces, it is unambiguously attributable to one bump. Cost: two CI re-scans instead of one.

### 8.3 Risk acceptance path (fallback)

If neither single-patch nor two-patch shape can land cleanly (e.g. tests reveal a real Pydantic incompatibility ANCHOR has no time to address):

- Write a separate `<YYYY-MM-DD>_starlette_risk_acceptance.md` artefact under `docs/operations/security_audits/`.
- Reference `incident_response.md §3` to place the residual risk at a documented severity level.
- Record explicit founder-approved hold, with a re-scan cadence (recommended: every 14 days) and a re-assessment trigger (any new FastAPI release that drops the Pydantic minimum, or any Pydantic 2.x release that addresses ANCHOR's specific compatibility blocker).
- Re-trigger `Anchor Dependency Audit (pip-audit)` at the cadence; append a new artefact each time.

---

## 9. Stop-condition impact

The dependency / CVE gate **remains open**. PyJWT is cleared (Patch 11C + 11C-a). Starlette remains unresolved pending Patch 11D-b or a documented risk-acceptance artefact.

| Operational item                              | Status after Patch 11D-a                                                                                                                                                                                          |
|---|---|
| Env docs                                      | ✅ Patch 7                                                                                                                                                                  |
| Backup / restore drill                        | ✅ Patch 8 / 8C — 2026-06-07 PASS                                                                                                                                            |
| Intake retention dry-run                      | ✅ Patch 9 / 9B — 2026-06-07 PASS, all counts 0                                                                                                                              |
| Incident-response runbook                     | ✅ Patch 10                                                                                                                                                                  |
| First tabletop drill                          | ✅ Patch 10B — 2026-06-07 PASS                                                                                                                                                |
| Dependency / CVE audit — PyJWT half           | ✅ Patch 11C + 11C-a — PyJWT findings cleared in CI; pin `PyJWT==2.13.0`.                                                                                                       |
| Dependency / CVE audit — Starlette half       | ⚠ **FINDINGS — Starlette `PYSEC-2026-161` remains open.** Patch 11D-b shape recommended: compound `fastapi==0.133.1` + `pydantic[email]==2.7.x` bump. Alternative: documented risk acceptance. |
| Dependency pinning / reproducibility          | ⏳ Open — Patch 11B-b candidate, after CVE remediation is complete.                                                                                                          |
| Broken `anchor-retention-prune.yml`           | ⏳ Open.                                                                                                                                                                     |
| Tenant Isolation Smoke rate-limit             | ⏳ Open — separate follow-up.                                                                                                                                                 |
| Legal / commercial pack per Addendum v1.3     | ⏳ Open — out of code scope; founder track.                                                                                                                                   |

**Paid pilot / real clinic data remains blocked** until the Starlette half clears or is formally risk-assessed.

---

## 10. Non-actions in this patch

The following were **explicitly not done** in Patch 11D-a:

- ❌ No `requirements.txt` change.
- ❌ No Starlette pin (direct or transitive).
- ❌ No FastAPI version bump.
- ❌ No Pydantic version bump.
- ❌ No `Dockerfile` change.
- ❌ No GitHub Actions change.
- ❌ No application code change.
- ❌ No migration change.
- ❌ No migrations run.
- ❌ No database query or mutation.
- ❌ No Render setting change.
- ❌ No deploy.
- ❌ No frontend touch.
- ❌ No production endpoint call.
- ❌ No `pip install` against the project environment (only `pip install --dry-run --report` against scratch JSON files, which were inspected and then deleted).
- ❌ No secret value printed, stored, or pasted anywhere.
- ❌ No compliance / certification / regulator-approval claim.

What this patch **did** do: probe FastAPI / Starlette / Pydantic constraints across nine candidate FastAPI versions via dry-run inspection, identify the smallest compound bump (`fastapi==0.133.1` + `pydantic>=2.7.0`) that satisfies the Starlette CVE, and write this assessment artefact recommending Patch 11D-b shape.

---

## 11. Doctrine restatement

This artefact preserves the ANCHOR doctrine: governance-first, metadata-only by default, tenant safety, RLS / FORCE RLS, human review, receipt-backed, **aligned, not compliant**. It records:

- No secrets, no clinical content, no PII, no full bearer tokens, no `DATABASE_URL`, no Render env values.
- No claim of "no risk", "fully compliant", "certified", "regulator-approved", "guaranteed safe", or "no vulnerabilities".
- A read-only assessment. No code, no migration, no dependency change, no production touch.

Audit follow-ups land as separate patches with their own evidence artefacts in this directory.
