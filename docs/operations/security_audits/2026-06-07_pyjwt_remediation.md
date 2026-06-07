# ANCHOR PyJWT Remediation — 2026-06-07

> **Targeted dependency remediation.** This artefact records the bump of `PyJWT` from `2.8.0` to `2.13.0` in response to the six PyJWT advisory rows recorded in [`2026-06-07_pip_audit_ci_findings.md`](./2026-06-07_pip_audit_ci_findings.md). It is **operational evidence only** — not compliance certification, not a regulator endorsement, not a guarantee that no other vulnerabilities exist, not a claim that ANCHOR is secure / compliant / certified / vulnerability-free.
>
> No production endpoint was called, no database was queried or mutated, no Render setting was changed, no deploy was issued, no application code or migration was changed during this patch. Real secrets — admin tokens, API keys, `DATABASE_URL`, JWT secret, hash salt, admin pepper, GitHub secrets values — never appear in this artefact.

---

## 1. Purpose and scope

Targeted remediation of the **PyJWT** findings from the CI pip-audit findings artefact. **PyJWT only.** Starlette / FastAPI remediation is **explicitly deferred** to Patch 11D.

**In scope:**

- Updating the `PyJWT` pin in `requirements.txt` to a version that satisfies all six reported PyJWT advisory fixes.
- Installing the new PyJWT locally and verifying integrity / focused test pass.
- Attempting a local pip-audit re-scan and recording the result.
- Documenting compatibility review of ANCHOR's JWT encode / decode usage against the new PyJWT line.

**Out of scope:**

- Any Starlette / FastAPI bump (deferred to Patch 11D — see [`2026-06-07_pip_audit_ci_findings.md §8`](./2026-06-07_pip_audit_ci_findings.md)).
- Any other dependency change (no pin tightening, no lockfile, no Docker base bump — those carry forward to Patch 11B-b).
- Any GitHub Actions edit.
- Any application code change.
- Calling production endpoints, querying / mutating the database, or changing Render settings.
- Compliance / certification claims of any kind.

---

## 2. Source finding

| Field | Value |
|---|---|
| Source artefact | [`2026-06-07_pip_audit_ci_findings.md`](./2026-06-07_pip_audit_ci_findings.md) |
| Workflow        | `Anchor Dependency Audit (pip-audit) #1` |
| Audited commit  | `87c2ab9` |
| Branch          | `main` |
| Overall result  | **FINDINGS** |

Six PyJWT advisory rows (verbatim from the source artefact):

| # | advisory ID       | fixed version reported by pip-audit |
|---|-------------------|-------------------------------------|
| 1 | `PYSEC-2026-120`  | `2.12.0` |
| 2 | `PYSEC-2025-183`  | (no fixed version shown by pip-audit) |
| 3 | `PYSEC-2026-179`  | `2.13.0` |
| 4 | `PYSEC-2026-175`  | `2.13.0` |
| 5 | `PYSEC-2026-177`  | `2.13.0` |
| 6 | `PYSEC-2026-178`  | `2.13.0` |

---

## 3. Change made

| Aspect | Detail |
|---|---|
| File changed                   | `requirements.txt` |
| Line changed                   | `PyJWT==2.8.0` → `PyJWT==2.13.0` |
| Target version selected        | **`2.13.0`** |
| Why this version               | Highest fixed-version reported by pip-audit across the six PyJWT advisory rows. Pinning to `2.13.0` is sufficient to satisfy rows #1 (`≥2.12.0`) and rows #3 – #6 (`≥2.13.0`). Row #2 (`PYSEC-2025-183`) has no fixed version shown by pip-audit; the resolution is the same — the next CI scan will report whether it remains or has been re-mapped upstream. |
| Other dependency changes       | **None.** No Starlette change. No FastAPI change. No pin tightening on any other line. |
| Application code changes       | **None.** Compatibility review (§4) found PyJWT's 2.x encode / decode API stable across `2.8.0` → `2.13.0` for the surfaces ANCHOR uses. |
| Test changes                   | **None.** Existing focused suites cover the relevant behaviour. |
| Dockerfile changes             | **None.** |
| GitHub Actions changes         | **None.** |
| Migration changes              | **None.** |

Verbatim diff:

```diff
-PyJWT==2.8.0
+PyJWT==2.13.0
```

Single-line change. No surrounding-context modification, no whitespace change.

---

## 4. JWT compatibility review

### 4.1 Files / functions inspected

```
$ grep -rn "import jwt|from jwt|jwt\.(encode|decode)" app/ tests/
app/auth_and_rls.py:12   import jwt
app/auth_and_rls.py:194  return jwt.encode(full, JWT_SECRET, algorithm="HS256")
app/auth_and_rls.py:211  claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], audience=..., issuer=..., leeway=..., options={...})
```

JWT usage is **concentrated in a single application module**: `app/auth_and_rls.py`. Two call sites; no other `app/*.py` module touches `jwt`.

### 4.2 Encode surface (`_make_jwt`, `app/auth_and_rls.py:181-194`)

```python
return jwt.encode(full, JWT_SECRET, algorithm="HS256")
```

Algorithm: HS256 only (no `none`, no `RS*`, no `ES*`). Payload claims: `iss`, `aud`, `iat`, `exp` plus per-call `clinic_id`, `clinic_user_id`, `role`, `sub`. The encode signature `(payload, key, algorithm=)` has been stable in PyJWT 2.x since 2.0.

### 4.3 Decode surface (`_decode_jwt`, `app/auth_and_rls.py:197-233`)

```python
claims = jwt.decode(
    token,
    JWT_SECRET,
    algorithms=["HS256"],
    audience=JWT_AUDIENCE,
    issuer=JWT_ISSUER,
    leeway=JWT_LEEWAY_SEC,
    options={
        "require": ["exp", "iat", "iss", "aud"],
        "verify_signature": True,
        "verify_exp": True,
        "verify_iat": True,
        "verify_iss": True,
        "verify_aud": True,
    },
)
```

Plus catches on `jwt.ExpiredSignatureError` and `jwt.InvalidTokenError`. All of these — the `algorithms=` allow-list (not the deprecated `algorithm=`), the explicit `audience=` / `issuer=` kwargs, the `options={"require": [...], "verify_*": True}` dict shape, and the `ExpiredSignatureError` / `InvalidTokenError` exception hierarchy — have been stable in PyJWT 2.x since 2.0 and are still present in 2.13.0. No known breaking change between 2.8.0 and 2.13.0 affects this code path.

The decode block is also defended by the `Patch 1` startup fail-closed assertion (`assert_hash_salt_for_prod`), the `Patch 4B` admin-mode assertion (`assert_admin_mode_for_prod`), and the strict claim allowlist in `_validate_claims_strict` (`app/auth_and_rls.py:236-267`) — none of which depend on PyJWT internals.

### 4.4 Test coverage of these surfaces

| Suite | Covers |
|---|---|
| `tests/test_auth_role_allowlist.py` | JWT-side role gate via `_normalize_role`; default allowlist (`{admin, owner, practice_manager, staff, reader, readonly}`); rejection of unknown / empty / clinical-decision-shaped roles. |
| `tests/test_clinic_login_error_consistency.py` | Patch 5A login error normalisation (every 401 detail = `invalid_credentials`); exercises the real `clinic_login` handler that ultimately calls `_make_jwt` on success. |
| `tests/test_security_config_hardening.py` | Patch 1 / 4B / 6 startup fail-closed asserts. Indirect coverage of the JWT-secret-required path. |
| `tests/test_assistant_rate_limits.py` | Patch 2 rate-limit decoration on receipt + assistant submit; exercises the request flow that depends on `_decode_jwt` (via the stubbed `require_clinic_user`). |
| `tests/test_assistant_receipt_lookup.py` | Receipt lookup; same path. |
| `tests/test_rate_limit.py` | Limiter primitives; no JWT touch but confirms 429 shape unchanged. |
| Broader `tests/test_assistant_*.py` (13 files, 217 tests) | Assistant policy, run, review, receipt, generation, intelligence, traceability — every route under `Depends(require_clinic_user)` which exercises the JWT decode path under stubs. |

No test had to be added, modified, or skipped for this patch.

### 4.5 Conclusion

**No compatibility break between PyJWT `2.8.0` and `2.13.0` for ANCHOR's JWT usage.** No application code change is required. All 282 focused tests run pass (see §6).

---

## 5. Local install and integrity check

Command:

```powershell
python -m pip install "PyJWT==2.13.0"
```

Result:

```
Successfully uninstalled PyJWT-2.8.0
Successfully installed PyJWT-2.13.0
```

Integrity check:

```powershell
python -m pip check
```

Result:

```
No broken requirements found.
```

Post-install runtime probe:

```powershell
python -c "import jwt; print('PyJWT', jwt.__version__)"
# → PyJWT 2.13.0
```

**No conflicts, no warnings beyond the (cosmetic) "A new release of pip is available" notice.** No other package was installed, upgraded, or uninstalled by this step.

---

## 6. Tests run

| Command | Result | Notes |
|---|---|---|
| `python -c "from app.main import app; print('IMPORT OK')"` | ✅ IMPORT OK | App boots under PyJWT 2.13.0; `trusted_host_disabled` / `cors_disabled` startup logs match the dev-mode expectation. |
| `pytest tests/test_auth_role_allowlist.py -v` | ✅ 11 passed | Role allowlist behaviour unchanged. |
| `pytest tests/test_clinic_login_error_consistency.py -v` | ✅ 5 passed | Patch 5A 401 normalisation holds; login encode path exercised. |
| `pytest tests/test_security_config_hardening.py -v` | ✅ 30 passed | Patch 1 / 4B / 6 startup fail-closed asserts unchanged. |
| `pytest tests/test_rate_limit.py -v` | ✅ 7 passed | Rate-limit primitives unchanged. |
| `pytest tests/test_assistant_rate_limits.py -v` | ✅ 4 passed | Patch 2 receipt + assistant_submit limiters unchanged. |
| `pytest tests/test_assistant_receipt_lookup.py -v` | ✅ 8 passed | Receipt lookup endpoint unchanged. |
| Broader Assistant suite (13 files, listed below) | ✅ 217 passed | No regression in any Assistant surface. |

Combined: **65 focused security/auth/rate-limit + 217 broader Assistant = 282 tests passed, 0 failed, 0 warnings introduced.**

Broader Assistant files run: `test_assistant_contracts.py`, `test_assistant_intelligence.py`, `test_assistant_output_safety.py`, `test_assistant_policy_settings.py`, `test_assistant_policy_traceability.py`, `test_assistant_run_creation.py`, `test_assistant_run_generation.py`, `test_assistant_run_review.py`, `test_assistant_run_traceability.py`, `test_assistant_runs_migration.py`, `test_assistant_runs_pagination.py`, `test_assistant_run_receipts.py`, `test_assistant_usage_limits.py`.

No test was added, modified, or skipped. No application code was modified. No migration was modified.

---

## 7. pip-audit follow-up

Command:

```powershell
python -m pip_audit -r requirements.txt
```

Result: **`LOCAL SCAN INCONCLUSIVE — local TLS/tooling failure; manual GitHub Actions dependency audit required after commit/push`**.

The failing URL has shifted from the Patch 11B-a observation:

```
HTTPSConnectionPool(host='pypi.org', port=443):
  Max retries exceeded with url: /pypi/pyjwt/2.13.0/json
  (Caused by SSLError(SSLCertVerificationError(1,
    '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed:
     unable to get local issuer certificate (_ssl.c:1010)')))
```

The URL now references `pyjwt/2.13.0` rather than the Patch 11B-a / 11B-a3 `pyjwt/2.8.0` — confirming pip-audit is reading the new pin. The failure class is the same (workstation-side TLS verification against PyPI advisory endpoint).

**No PASS / FINDINGS claim is recorded.** The authoritative re-scan is the `Anchor Dependency Audit (pip-audit)` workflow on a fresh CI run after this patch is committed and pushed. The expected outcome there is that the six PyJWT advisory rows clear (with `PYSEC-2025-183` being the only one whose status is uncertain because pip-audit did not report a fixed version) and the two Starlette rows remain (still in scope for Patch 11D).

---

## 8. Remaining findings

| Finding | Status after this patch |
|---|---|
| PyJWT `2.8.0` × 6 advisory rows | **Remediated locally pending CI confirmation.** PyJWT pin is `2.13.0`; the highest pip-audit-reported fixed version is met. Next CI run will give the authoritative answer. |
| Starlette `0.50.0` × 1 advisory (duplicated row in pip-audit output) — `PYSEC-2026-161`, fixed `1.0.1` | **Open. Deferred to Patch 11D** per the source findings artefact §8.2. This patch does not pin Starlette directly and does not touch FastAPI. |
| Process / reproducibility findings P-1 … P-6 (from Patch 11A §7) | Open. Deferred to Patch 11B-b. |
| Tenant Isolation Smoke Test #191 rate-limit response | Open. Separate follow-up per the source findings artefact §5. |

**The CVE gate remains open** until a follow-up CI re-scan confirms the final dependency state and the Starlette half is addressed (or accepted with an explicit risk note).

---

## 9. Stop-condition impact

The dependency / CVE gate **remains active**. This patch reduces the PyJWT portion of the risk pending CI confirmation; it does not clear the overall CVE gate.

| Operational item                              | Status after Patch 11C                                                                                                                                                                |
|---|---|
| Env docs                                      | ✅ Patch 7                                                                                                                                                                  |
| Backup / restore drill                        | ✅ Patch 8 / 8C — 2026-06-07 PASS                                                                                                                                            |
| Intake retention dry-run                      | ✅ Patch 9 / 9B — 2026-06-07 PASS, all counts 0                                                                                                                              |
| Incident-response runbook                     | ✅ Patch 10                                                                                                                                                                  |
| First tabletop drill                          | ✅ Patch 10B — 2026-06-07 PASS                                                                                                                                                |
| Dependency / CVE audit (snapshot)             | ⚠ **FINDINGS — partial remediation.** PyJWT bumped to `2.13.0` (Patch 11C); local scan INCONCLUSIVE (workstation TLS); CI re-scan required. Starlette finding still open. |
| Dependency pinning / reproducibility          | ⏳ Open — Patch 11B-b candidate, after CVE remediation is complete.                                                                                                          |
| Broken `anchor-retention-prune.yml`           | ⏳ Open.                                                                                                                                                                     |
| Tenant Isolation Smoke rate-limit             | ⏳ Open.                                                                                                                                                                     |
| Legal / commercial pack per Addendum v1.3     | ⏳ Open — out of code scope; founder track.                                                                                                                                   |

**Paid pilot / real clinic data remains blocked** until findings are remediated and a clean (or formally risk-assessed) follow-up scan is recorded.

---

## 10. Non-actions in this patch

The following were **explicitly not done** in Patch 11C:

- ❌ No `Dockerfile` change.
- ❌ No GitHub Actions change (the `dependency-audit.yml` `workflow_dispatch`-only posture from Patch 11B-a3 is preserved).
- ❌ No migration change.
- ❌ No migrations run.
- ❌ No database query or mutation.
- ❌ No Render setting change.
- ❌ No deploy.
- ❌ No frontend touch.
- ❌ **No Starlette pin or FastAPI bump.** Starlette / FastAPI remediation is the Patch 11D scope.
- ❌ No application code change.
- ❌ No test change.
- ❌ No pinning of currently-unpinned dependencies.
- ❌ No production endpoint call.
- ❌ No secret value printed, stored, or pasted anywhere.
- ❌ No compliance / certification / regulator-approval claim.

What this patch **did** do: bump one pinned dependency line from `PyJWT==2.8.0` to `PyJWT==2.13.0`, verify install integrity, run 282 focused tests, and record the result.

---

## 11. Doctrine restatement

This artefact preserves the ANCHOR doctrine: governance-first, metadata-only by default, tenant safety, RLS / FORCE RLS, human review, receipt-backed, **aligned, not compliant**. It records:

- No secrets, no clinical content, no PII, no full bearer tokens, no `DATABASE_URL`, no Render env values.
- No claim of "no risk", "fully compliant", "certified", "regulator-approved", "guaranteed safe", or "no vulnerabilities".
- A single one-line change to `requirements.txt`. No code, no migration, no production touch.

Audit follow-ups land as separate patches with their own evidence artefacts in this directory.
