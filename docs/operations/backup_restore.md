# ANCHOR Backup / Restore Drill Runbook

> **Operator-facing runbook.** This document is the procedure for proving that the ANCHOR Render Postgres database is recoverable and that the backend boots cleanly against a restored copy. Drills are operator-driven, time-bounded, and produce evidence captured in §11.
>
> Real secrets — drill or production — must never appear in this document, in logs, in screenshots, in tickets, in PR descriptions, or in commits. Every example is a placeholder.

---

## 1. Purpose and scope

This runbook documents a **restore-to-new** drill for the ANCHOR backend and its Render Postgres database. The drill proves that a Render Postgres backup can be restored into a *new, separate* non-production database and that the ANCHOR FastAPI backend can boot and serve traffic against it.

The drill produces **operational resilience evidence** that satisfies one of the four pre-pilot operational gates referenced in Roadmap v2.6 §234 and Addendum v1.3 §63. It does **not** grant compliance, certification, RCVS approval, regulator endorsement, or guaranteed protection. ANCHOR is aligned to RCVS principles and EU AI Act articles where it can be; it is not compliant with them.

**No restore into production is permitted.** The only acceptable restore mode is "create new database from snapshot" (or PITR equivalent). The Render UI offers both buttons; this runbook uses the safe one.

Out of scope here: the intake retention prune runbook (`docs/operations/intake_retention.md`, planned) and the incident-response runbook (`docs/operations/incident_response.md`, planned). Each will reference this drill as one of its prerequisites.

---

## 2. Doctrine and stop conditions

- **Restore-to-new only.** No restore into the production database, ever. The "Restore" button against production is off-limits.
- **No production DB mutation.** Reads from the Render Dashboard during the §4 inventory only; no writes, no test inserts, no admin endpoint that mutates state on prod.
- **No live Workspace generation in the drill.** `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` is **unset** on the drill service and `ANTHROPIC_API_KEY` is **unset**. Live generation also remains off in production until 2A-C.5E and the hard-refusal boundary are documented as passed.
- **No real clinic data / paid pilot** until: (a) this drill has been executed at least once and evidence captured in §11; (b) the intake retention prune runbook is in place and a controlled destructive run has been executed under founder approval; (c) the incident-response runbook is in place; (d) `docs/operations/env.md` has been adopted as the deploy reference; (e) the legal/commercial pack referenced in Addendum v1.3 is complete.
- **No compliance / certification / RCVS approval / regulator endorsement / guaranteed protection claims** in this runbook, in drill evidence, in PRs that touch this file, or anywhere else.
- **No reuse of production secrets** in the drill. Every credential the drill service uses is freshly generated, drill-only, single-use, and rotated at teardown.
- **No buyer-discovery framing** in any artefact produced by this drill. The "5–10 practice-owner conversations" / "parallel listening cadence" wording was withdrawn in Addendum v1.3 and must not reappear.

---

## 3. What the drill must prove

The drill is a **PASS** if and only if every item below is observed:

- [ ] A Render Postgres backup of the production database exists and is usable (snapshot or PITR).
- [ ] Restore-to-new into a separate Postgres instance succeeds; the drill DB reaches "Available" state in Render.
- [ ] The ANCHOR backend image (same git SHA as production) boots against the restored DB.
- [ ] `GET /health` returns `200 {"status":"ok"}` on the drill service.
- [ ] `GET /v1/version` returns `200` with `env` matching the drill `APP_ENV` and `git_sha` matching the prod-deployed SHA.
- [ ] `GET /v1/portal/dashboard` without `Authorization` returns `401 missing_bearer_token`.
- [ ] `GET /db-check` returns `200 {"db":"ok"}`.
- [ ] Migration checksum verification passes against the restored `schema_migrations` table — boot logs show `migration.scan` with `checksum_column=true` and `verify_checksums=true`, followed by `startup_migrations_ok`, and **no** `migration.checksum.mismatch`.
- [ ] RLS / FORCE RLS posture survives the restore — `scripts/anchor-verify-force-rls.ps1` reports OK on the restored DB using a drill-only admin token.

Any **FAIL** on any item is logged, the drill is marked FAIL or INCONCLUSIVE in §11, and the failure-mode playbook in §13 applies.

---

## 4. Pre-drill Render inventory checklist

These items are **read** in the Render UI and **recorded** in §11 *before* any restore action. None of the actions in this section mutates anything. Do not paste env values into the evidence file; record presence only.

**Render Postgres `anchor-api-prod`** (or current prod DB name):

- [ ] Plan tier: ________________
- [ ] Postgres major.minor version: ________________
- [ ] Region: ________________
- [ ] Backup retention window (days): ________________
- [ ] Most recent snapshot timestamp (UTC) and snapshot identifier (record id only — never connection strings): ________________
- [ ] PITR availability on this plan: yes / no
- [ ] PITR window (if applicable): ________________
- [ ] Team members with restore-issuing permission: ________________
- [ ] Read the "Restore" section in the UI but **do not click Restore against the prod database.** Confirm a "Create new database from snapshot" or PITR-restore-to-new option exists.

**Render Web Service `anchor-api-prod`** (or current prod service name):

- [ ] Service plan / instance size: ________________
- [ ] Region: ________________
- [ ] Auto-deploy branch / current deployed SHA: ________________
- [ ] Health check path (expected `/health`): ________________
- [ ] Start command (expected `uvicorn app.main:app --host 0.0.0.0 --port ${PORT}`): ________________
- [ ] **Required production env vars are set per `docs/operations/env.md §3`.** Tick presence only; do not record values.

**What not to click:**

- ❌ Delete database (prod).
- ❌ Restore (prod) — only "Create new database from snapshot" is permitted, and not in this step.
- ❌ Reset password (prod service env).
- ❌ Promote / failover controls on the Postgres instance.
- ❌ Anything that modifies the live custom domain bindings on the prod service.

Inventory must be complete before §5 begins.

---

## 5. Restore-to-new procedure

**Naming convention** (so the drill is obviously a drill in every dashboard view):

- Drill database: `anchor-restore-drill-YYYYMMDD-HHMM`
- Drill web service: `anchor-restore-drill-svc-YYYYMMDD-HHMM`

Use UTC in the suffix. **Never** name the drill anything that could be confused with prod (no `prod`, `live`, `main`, `release` in the name).

### 5.1 Provision the drill Postgres (5–10 min wall-time)

1. Render Dashboard → Postgres → `anchor-api-prod` → **Snapshots** tab.
2. Pick the most recent snapshot (or a chosen PITR target) recorded in §4.
3. Click **"Create new database from snapshot"** (or the PITR equivalent — *not* the "Restore" button that targets the existing prod DB).
4. Database name: `anchor-restore-drill-YYYYMMDD-HHMM`.
5. Region: **same as prod** (avoids cross-region latency in the smoke).
6. Plan: smallest plan that fits the prod DB size. The drill is short-lived.
7. Wait for the drill DB to reach "Available". Record start/end timestamps in §11.
8. Capture the drill `DATABASE_URL` to a local note for §5.3. **Do not** paste it into any shared channel, the evidence file, or a PR description. The evidence file records its *presence*, not its value.

### 5.2 Provision the drill Web Service (5 min wall-time)

1. Render Dashboard → New → Web Service → Build from Git → ANCHOR repo.
2. **Pin to the same git SHA prod is currently running.** If the drill SHA differs from prod, the migration runner may try to apply migrations the snapshot does not know about, *or* Patch 6 checksum verification may report drift because the drill repo's migration files differ from the snapshot's stored checksums. Both cases invalidate the drill.
3. Service name: `anchor-restore-drill-svc-YYYYMMDD-HHMM`.
4. Region: same as the drill DB.
5. Hostname: use the auto-generated `<drill-name>.onrender.com`. **Do not** attach the prod custom domain.
6. Auto-deploy: **disabled**. A routine `main` push must not silently rebuild the drill service.

---

## 6. Drill environment variables

The drill is deliberately **detached** from production credentials. None of the values below may equal the production value of the same variable. Generate fresh random strings for every drill.

**First pass — `APP_ENV=staging`** (proves the code boots against the restored DB without testing the Patch 1 / 4B / 6 prod-only fail-closed asserts):

| Variable | Drill value (placeholder) | Rationale |
|---|---|---|
| `APP_ENV` | `staging` | Skips prod fail-closed asserts so a fresh deploy with non-prod-default secrets can boot. |
| `DATABASE_URL` | the drill DB connection string from §5.1 | Different from prod by construction. |
| `ANCHOR_JWT_SECRET` | freshly-generated random string ≥ 32 bytes | **Must differ from prod** so a prod-issued JWT cannot authenticate against the drill. |
| `ANCHOR_HASH_SALT` | freshly-generated random string, **not** the default literal | |
| `ANCHOR_ADMIN_PEPPER` | freshly-generated random string, **not** the default literal | Prod admin tokens were hashed with the prod pepper; the drill's hash table cannot validate them. |
| `RATE_LIMIT_ENABLED` | `1` | Keep limits live to mirror prod posture. |
| `RATE_LIMIT_SECRET` | freshly-generated random string | Different from prod. |
| `INVITE_TOKEN_SALT` | freshly-generated random string | Different from prod. |
| `ANCHOR_ADMIN_MODE` | `hybrid` | One-time drill exception. Paired with the next env. Documented as drill-only operator override in §11. |
| `ANCHOR_ADMIN_TOKEN` | freshly-generated string, **drill-only**, never reused | Lets the RLS verify script authenticate without provisioning DB-tier tokens in the drill. |
| `ANCHOR_MIGRATION_VERIFY_CHECKSUMS` | `1` (or unset; the first-pass default with `APP_ENV=staging` is off, so set `1` explicitly to exercise the Patch 6 path) | Verification on. This is the test point for §9. |
| `CORS_ALLOW_ORIGINS` | empty (CORS disabled) or a drill-specific origin | **Must not include the prod portal origin.** |
| `TRUSTED_HOSTS` | the drill `*.onrender.com` hostname only | Must not include the prod hostname. |
| `LOG_LEVEL` | `INFO` | |
| `SERVICE_NAME` | `anchor-restore-drill-YYYYMMDD` | Tags every drill log line. |
| `ANCHOR_JWT_ISSUER` | drill-specific value (e.g. `anchor-drill`) | Belt-and-braces: drill JWTs cannot replay in prod. |
| `ANCHOR_JWT_AUDIENCE` | drill-specific value (e.g. `anchor-drill-portal`) | |
| `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` | **unset** | Live generation off. Do not set the variable at all. |
| `ANTHROPIC_API_KEY` | **unset** | No provider credentials anywhere in the drill. |
| `ANCHOR_RECEIPT_SIGNING_SECRET` / `..._KID` | unset, unless signed-receipt smoke is being tested | Signed-receipt path no-ops cleanly if unset. |

**Second pass — `APP_ENV=prod`** (proves the Patch 1 / 4B / 6 startup asserts pass against the restored DB):

After the first-pass smoke succeeds, flip `APP_ENV` to `prod` on the same drill service and redeploy. No drill DB content changes — only the service restarts. The startup logs should now show every fail-closed assert passing (or the relevant `startup_failed` event if a fresh secret value still hits the default literal, which would be an operator error to fix).

**Reuse of production secrets is forbidden.** If the operator finds themselves wanting to "just paste the prod value", stop and generate a fresh one. The point of the drill is to confirm restore quality, not to recreate prod.

---

## 7. Live-generation and traffic isolation controls

Three independent gates ensure live generation stays off:

1. `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` is **unset** on the drill service.
2. `ANTHROPIC_API_KEY` is **unset** on the drill service. Even if (1) flipped accidentally, the live client would return a safe `503` config error.
3. The drill smoke set in §8 invokes **only read-only endpoints**. `POST /v1/assistant/runs`, `POST /v1/portal/assist`, and any Workspace generation path are never called during a drill.

Five independent gates ensure no production traffic reaches the drill service:

1. Drill uses the auto-generated `*.onrender.com` hostname only.
2. `TRUSTED_HOSTS` on the drill includes only the drill hostname — any request bearing the prod `Host` header is rejected by `TrustedHostMiddleware`.
3. `CORS_ALLOW_ORIGINS` on the drill is empty (CORS disabled) or contains only a drill-specific origin. The prod portal frontend has no way to invoke the drill from a user's browser.
4. Drill uses its own fresh `ANCHOR_JWT_SECRET`, `ANCHOR_ADMIN_PEPPER`, `INVITE_TOKEN_SALT`, and `RATE_LIMIT_SECRET`. No prod-issued JWT, no prod-issued admin token, and no prod-issued invite token can authenticate against the drill.
5. Drill service has auto-deploy disabled (per §5.2). A routine push to `main` does not silently rebuild the drill.

**Do not** announce the drill hostname in any shared channel.

---

## 8. Smoke tests

All commands below are **read-only** from the drill service's perspective. Capture status code, the `X-Request-ID` header, and (where relevant) the `env` / `git_sha` JSON fields into §11. **Do not** capture bearer tokens, the drill DB URL, or env-var values.

### 8.1 Liveness (no auth)

```powershell
$Base = 'https://anchor-restore-drill-svc-YYYYMMDD-HHMM.onrender.com'

# /health → 200 {"status":"ok"}
Invoke-WebRequest -UseBasicParsing -Uri "$Base/health" |
    Select-Object StatusCode, Content
```

### 8.2 Version (no auth)

```powershell
# /v1/version → 200; env="staging" (first pass) or "prod" (second pass);
# git_sha should equal the prod-deployed SHA.
Invoke-WebRequest -UseBasicParsing -Uri "$Base/v1/version" |
    Select-Object StatusCode, Content
```

### 8.3 Protected route without bearer

```powershell
# /v1/portal/dashboard with no Authorization → 401 missing_bearer_token
try {
    Invoke-WebRequest -UseBasicParsing -Uri "$Base/v1/portal/dashboard"
} catch {
    $_.Exception.Response.StatusCode.value__   # expect 401
}
```

### 8.4 DB connectivity (no auth)

```powershell
# /db-check → 200 {"db":"ok"}
Invoke-WebRequest -UseBasicParsing -Uri "$Base/db-check" |
    Select-Object StatusCode, Content
```

### 8.5 RLS / FORCE-RLS posture (admin-token-gated, read-only)

```powershell
# scripts/anchor-verify-force-rls.ps1 hits /v1/admin/ops/rls-self-test and
# asserts ENABLE + FORCE on every clinic-scoped tenant table.
# The admin token is the DRILL-only token from §6, not a prod token.
$Env:DRILL_ADMIN_TOKEN = '<DRILL admin token from §6 — do not log or paste anywhere>'
.\scripts\anchor-verify-force-rls.ps1 -Base $Base -AdminToken $Env:DRILL_ADMIN_TOKEN
# Clear from environment immediately after.
Remove-Item Env:DRILL_ADMIN_TOKEN
```

A PASS here is the strongest single-line evidence that the restore preserved the RLS substrate — the doctrine bedrock under every clinic-scoped surface.

### 8.6 Optional — cross-tenant isolation smoke (`scripts/anchor-smoke-isolation.ps1`)

> **Optional and conditional.** Inspect the script before invoking it for the first time in a drill context.

`scripts/anchor-smoke-isolation.ps1` is a tenant-isolation cross-test that may **provision test clinics in the drill DB** as part of its setup. This *mutates* the drill DB (it does not mutate prod — it talks only to `$Env:ANCHOR_BASE`).

Conditions for use in a drill:

- Run only **after** §8.1–§8.5 have all passed. The point of the basic smoke is to confirm the restored DB is healthy *before* we deliberately write to it.
- **Read the script first.** Confirm that the clinics it provisions are bounded to the drill DB and that nothing escapes to a prod hostname. The script reads `$Env:ANCHOR_BASE`; the operator must set this to the drill hostname only.
- Acceptable only because the drill DB is being deleted in §11. The test-clinic rows it creates never leave the drill DB.
- **Do not** run this script with `$Env:ANCHOR_BASE` set to the prod hostname under any circumstance.

```powershell
# Optional — only after §8.5 PASS and after reading the script.
$Env:ANCHOR_BASE = $Base
$Env:ANCHOR_ADMIN_TOKEN = '<DRILL admin token from §6>'
.\scripts\anchor-smoke-isolation.ps1
Remove-Item Env:ANCHOR_ADMIN_TOKEN
Remove-Item Env:ANCHOR_BASE
```

The result of this optional script does not change the drill's PASS / FAIL state unless §8.5 also failed. It is a deeper read of isolation behaviour, not a gating check.

---

## 9. Migration checksum verification evidence

Open the drill service log in Render Dashboard → drill service → Logs. Filter to the boot window. Confirm:

- A single `migration.scan` event with `checksum_column: true` and `verify_checksums: true`.
- A `startup_migrations_ok` event after the runner completes.
- **No** `migration.checksum.mismatch` event.

Record into §11 the `applied`, `skipped`, `verified`, and `backfilled` counts from the run summary.

**If a `migration.checksum.mismatch` fires:**

1. **Stop the drill.** Do not proceed to §8.
2. **Do not** edit `schema_migrations` on the drill DB. The drill DB is a clone of prod; whatever the drill catches is also present in prod.
3. **Investigate against git history.** Use `git log --follow -- migrations/<file>` to find every historical version of the affected file, and compare each version's stripped SHA-256 to the stored value (which is the value from prod's `schema_migrations.checksum`).
4. **Follow the Patch 6B precedent.** Restore the migration file on the active branch to the historical version whose checksum matches prod, then add a *new* forward migration carrying any desired-but-not-applied changes. Do not edit the existing migration in place.
5. **The drill catching this is itself a valuable outcome** — it surfaces a real doctrine violation before clinic data is involved. Mark the drill INCONCLUSIVE in §11 and link to the remediation PR.

---

## 10. Read-only Render inventory baseline — 2026-06-07

> **Inventory baseline, not a completed restore drill.** The data below was captured by manually inspecting the Render Dashboard. **No Render settings were changed.** No DB query was issued. No Render API was called. No secret value was recorded. The restore drill itself has **not** yet been executed; this section establishes the starting state for the first drill.

### 10.1 Postgres

| Field | Value |
|---|---|
| Database service name | `anchor-postgres-prod` |
| Service ID | `dpg-d60ccuh4tr6s738g7vo0-a` |
| Plan / instance type | Basic-1gb |
| RAM / CPU / storage | 1 GB RAM / 0.5 CPU / 15 GB |
| Status | Available |
| PostgreSQL version | 16 |
| Region | Frankfurt (EU Central) |
| Storage used | 0.71% |
| Storage autoscaling | Enabled |
| High availability | Disabled |
| Database name | `anchor_u0lp` |
| Runtime username | `anchor_app` |
| Backup / PITR available | Yes |
| Recovery window | past 3 days |
| Manual export option visible | Yes |
| Manual export retention | at least 7 days |
| Restore option visible in UI | Yes |
| Inbound IP restrictions | `0.0.0.0/0` (open) |
| PostgreSQL 18 upgrade | available — **not part of the current drill** |

### 10.2 Web service

| Field | Value |
|---|---|
| Service name | `anchor-api-prod` |
| Service ID | `srv-d60dn2f8bdcs73f0r2ig` |
| Runtime | Docker |
| Plan | Starter |
| Region | Frankfurt (EU Central) |
| Repo / branch | `Raducu07/ANCHOR` `main` |
| Dockerfile path | `./Dockerfile` |
| Docker build context | repo root |
| Auto-deploy | Off |
| Render subdomain | Enabled |
| Health check path | `/health` |
| Maintenance mode | Disabled |
| Current live deployed SHA | `f96d1bc` |
| Current live deploy message | *"Restore applied migration and add forward RLS reassertion"* |
| Latest live deploy timestamp | 2026-06-07 10:31 (UTC) |

### 10.3 Workspace / account

| Field | Value |
|---|---|
| Workspace plan | Hobby (legacy) |
| Team members | 1 |
| Founder role | Admin |
| 2FA enforcement | Not enforced |
| Google SSO enforcement | Not enforced |
| HIPAA compliance | Disabled |
| Workspace audit logs | require Pro plan or higher |
| Build pipeline | Starter |
| Notifications | workspace default; failure notifications only |

### 10.4 Env posture — presence / category only

> No secret values were recorded. Items below indicate presence/category as observed in the Render UI.

| Variable | Status |
|---|---|
| `APP_ENV` | `prod` |
| `DATABASE_URL` | present |
| `ANCHOR_HASH_SALT` | present |
| `ANCHOR_JWT_SECRET` | present |
| `ANCHOR_ADMIN_PEPPER` | present |
| `ANCHOR_ADMIN_MODE` | `hybrid` |
| `RATE_LIMIT_SECRET` | present |
| `ANCHOR_MIGRATION_VERIFY_CHECKSUMS` | enabled (`1`) |
| `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` | off (`false` / `0`) |
| `ANTHROPIC_API_KEY` | present |
| `TRUSTED_HOSTS` | present |
| `CORS_ALLOW_ORIGINS` | present |
| Receipt signing vars | present |
| Rate-limit vars | present |
| Ops threshold vars | present |

### 10.5 Inventory notes

- **No secret values were recorded** in this baseline. All env rows record presence / category only.
- **Inventory baseline captured on 2026-06-07.** The first restore-to-new drill was executed on **2026-06-07** and **passed** — see the per-drill evidence in §11 (Drill — 2026-06-07). The next drill is due according to the cadence in §14.
- **No Render settings were changed during inventory.** All actions were read-only UI inspection.
- `ANTHROPIC_API_KEY` is **present**. Per `env.md §9`, presence does not enable live generation; the live path is gated on `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED`, which is observed off. No doctrine violation here; recorded for the trail.

### 10.6 Follow-up hardening items (not changed in this patch)

These are observations from the inventory that are deliberately **not** acted on as part of Patch 8B. Each is captured so the trail explains why it was seen and left alone.

- **Inbound IP restrictions `0.0.0.0/0`.** Render Postgres connections are still authenticated via `DATABASE_URL`, but tightening the inbound allow-list to Render-internal / known-egress only is a defence-in-depth improvement. **Review later** — do not change in this patch. Treat as a Patch X candidate when the Render team's recommended pattern for internal-only Postgres is confirmed.
- **`ANCHOR_ADMIN_MODE=hybrid`.** Per Patch 4B doctrine, `hybrid` is allowed in prod only as an explicit, documented operator override; the steady state is `db` (DB-backed platform admin tokens with per-token revocation and audit linkage). Hybrid is in place today as a bootstrap posture. **Migrate later** to DB-tier admin tokens, then either remove the env value (so the prod default of `db` applies) or set it explicitly to `db`. Do not change in this patch.
- **`ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED=false`/`0`.** Per `env.md §9` and the live-generation doctrine, the canonical "off" posture is **unset** (no env var present). Observed as explicitly `false`/`0`, which is also off (since `is_live_generation_enabled()` only returns `True` for `{1,true,yes,on}` after strip+lower). **Normalise later** to either a single accepted false value (`0`) or unset entirely, for predictability. Do not change in this patch.
- **PostgreSQL 16 → 18 upgrade available.** Render offers the upgrade; it is **not part of the current drill**. Schedule when an upgrade window can be paired with a restore-to-new drill so the upgraded version is exercised before any prod cutover. Do not upgrade in this patch.
- **2FA / Google SSO not enforced at workspace level.** Workspace plan limits this; recorded for awareness, not changed here.
- **High availability disabled on Postgres.** Acceptable for current pre-pilot posture; revisit when paid pilot / real clinic data is on the horizon. Recorded for awareness.

---

## 11. Evidence template

Copy this template into a new sub-section the day of the drill. Fill placeholders only — never real values.

```markdown
### Drill — <YYYY-MM-DD>

| Field | Value |
|---|---|
| Drill date (UTC) | <YYYY-MM-DD HH:MM> |
| Operator | <name> |
| Prod git SHA in use | <40-char-sha> |
| Prod DB plan / tier at time of drill | <tier> |
| Snapshot timestamp (UTC) | <YYYY-MM-DD HH:MM> |
| Snapshot id (record id only — never connection strings) | <render-snapshot-id> |
| Drill DB name | anchor-restore-drill-YYYYMMDD-HHMM |
| Drill DB plan | <tier> |
| Drill DB available-at timestamp | <YYYY-MM-DD HH:MM> |
| Drill service name | anchor-restore-drill-svc-YYYYMMDD-HHMM |
| Drill service first-pass APP_ENV | staging |
| Drill service second-pass APP_ENV | prod |

#### Smoke results

| Step | Endpoint / action | Status code | X-Request-ID | Pass? |
|---|---|---|---|---|
| 8.1 | GET /health | <code> | <req-id> | ☐ |
| 8.2 first pass | GET /v1/version (env=staging) | <code> | <req-id> | ☐ |
| 8.2 second pass | GET /v1/version (env=prod) | <code> | <req-id> | ☐ |
| 8.3 | GET /v1/portal/dashboard no bearer | <code expected 401> | <req-id> | ☐ |
| 8.4 | GET /db-check | <code> | <req-id> | ☐ |
| 8.5 | scripts/anchor-verify-force-rls.ps1 | <pass/fail> | n/a | ☐ |
| 8.6 (optional) | scripts/anchor-smoke-isolation.ps1 | <pass/fail/skipped> | n/a | ☐ |

#### Migration checksum result

| Field | Value |
|---|---|
| migration.scan checksum_column | true / false |
| migration.scan verify_checksums | true / false |
| applied count | <n> |
| skipped count | <n> |
| verified count | <n> |
| backfilled count | <n> |
| migration.checksum.mismatch observed? | yes / no |

#### Teardown confirmation

| Step | Action | Done? |
|---|---|---|
| 12.1 | Drill web service deleted | ☐ |
| 12.2 | Drill DB deleted | ☐ |
| 12.3 | Local notes containing drill secrets shredded | ☐ |
| 12.4 | Render Dashboard screenshot showing absence of drill DB and service | ☐ |

#### Decision

- ☐ **PASS** — all gating checks in §3 passed; evidence retained; next drill scheduled for <date>.
- ☐ **FAIL** — gating check(s) failed: <which>. Remediation owner: <name>. Re-drill scheduled for <date>.
- ☐ **INCONCLUSIVE** — drill caught a real issue requiring remediation before next attempt: <issue>. Linked PR: <url>.

#### Notes

<short free-form note — no secrets, no clinic identifiers>
```

### Drill — 2026-06-07

> **First restore-to-new drill — PASS.** No production database was overwritten and no production service was changed. No secret values are recorded below.

| Field | Value |
|---|---|
| Drill date (UTC) | 2026-06-07 |
| Operator | RGG |
| Source production DB | `anchor-postgres-prod` |
| Source DB recovery path | Render point-in-time recovery / restore-to-new |
| Drill DB name | `anchor-restore-drill-20260607-1055` |
| Drill DB internal name | `anchor_u0lp_0nvl` |
| Drill DB service ID | `dpg-d8ikveeq1p3s73erhef0-a` |
| Drill DB instance type | Free |
| Drill DB region | Frankfurt |
| Drill service name | `anchor-restore-drill-svc-20260607-1055` |
| Drill service URL | `https://anchor-restore-drill-svc-20260607-1055.onrender.com` |
| Drill service ID | `srv-d8iljcs8aovs738eib7g` |
| Drill service runtime | Docker |
| Drill deployed git SHA | `54c63db` |
| Drill deployed commit message | *"Record Render backup restore inventory baseline"* |
| Drill service first-pass `APP_ENV` | `staging` |
| Drill service second-pass `APP_ENV` | `prod` |
| Production DB overwritten? | **No** |
| Production service changed? | **No** |

#### Smoke results — first pass (`APP_ENV=staging`)

| Step | Endpoint / action | Status code | Pass? |
|---|---|---|---|
| 8.1 | `GET /health` | 200 `{"status":"ok"}` | ✅ |
| 8.2 | `GET /v1/version` | 200, `env=staging` | ✅ |
| 8.3 | `GET /v1/portal/dashboard` no bearer | 401 | ✅ |
| 8.4 | `GET /db-check` | 200 `{"db":"ok"}` | ✅ |

First-pass result: **PASS**

#### RLS / FORCE-RLS verification — `scripts/anchor-verify-force-rls.ps1`

| Policy / table | RLS enabled | FORCE RLS | Pass? |
|---|---|---|---|
| `rls_clinics` | True | True | ✅ |
| `rls_clinic_users` | True | True | ✅ |
| `governance_events` | True | True | ✅ |
| `rls_ops_metrics_events` | True | True | ✅ |
| `rls_clinic_policies` | True | True | ✅ |
| `rls_clinic_policy_state` | True | True | ✅ |
| `rls_clinic_privacy_profile` | True | True | ✅ |
| `rls_admin_audit_events` | True | True | ✅ |

RLS / FORCE-RLS verification result: **PASS** — the legacy seven-table set (Patch 4A `10014`) plus the admin-audit-events overlay (Patch 5B `10015`) are intact end-to-end across snapshot → restore-to-new → boot.

#### Smoke results — second pass (`APP_ENV=prod`)

| Step | Endpoint / action | Status code | Pass? |
|---|---|---|---|
| 8.1 | `GET /health` | 200 `{"status":"ok"}` | ✅ |
| 8.2 | `GET /v1/version` | 200, `env=prod` | ✅ |
| 8.3 | `GET /v1/portal/dashboard` no bearer | 401 | ✅ |
| 8.4 | `GET /db-check` | 200 `{"db":"ok"}` | ✅ |

Second-pass result: **PASS** — Patch 1 / 4B / 6 prod-mode startup fail-closed asserts all passed against the restored database with drill-only non-default secrets.

#### Migration checksum result

| Field | Value |
|---|---|
| `migration.scan` event present | yes |
| `db_name` observed | `anchor_u0lp_0nvl` |
| `db_user` observed | `anchor_app` |
| `checksum_column` | true |
| `verify_checksums` | true |
| `startup_migrations_ok` event present | yes |
| `migration.checksum.mismatch` observed | **no** (not present in the inspected boot logs) |

Migration checksum result: **PASS** — Patch 6 verification ran on the restored `schema_migrations` table and reported no mismatch. Patch 6B's restoration of `10010_force_rls_all_tenant_tables.sql` is therefore corroborated end-to-end against a fresh restore.

#### Teardown confirmation

| Step | Action | Done? |
|---|---|---|
| 12.1 | Drill web service deleted | ✅ |
| 12.2 | Drill DB deleted | ✅ |
| 12.3 | Local notes containing drill secrets shredded | ✅ |
| 12.4 | Production service / database untouched | ✅ |

#### Decision

- ✅ **PASS** — every gating check in §3 was observed. Evidence retained in this sub-section. Next drill scheduled per §14 cadence (quarterly pre-pilot — target ~2026-09-07).

#### Notes

- Initial drill service deploy failed because the drill `DATABASE_URL` was malformed. Corrected by pasting the full **Internal Database URL** from the restored drill database into the drill service env. The malformed value was never the production value; both the malformed and corrected values are drill-only and were shredded at teardown per §12.3.
- `CORS_ALLOW_ORIGINS` was left blank/absent on the drill service because no browser / frontend access was exercised during the drill. The smoke set uses server-side `Invoke-WebRequest` calls only.
- `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` were intentionally **unset** on the drill service. No provider credentials in the drill scope.
- `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` remained `false`. The drill never exercised any Workspace generation path. Doctrine preserved.
- `scripts/anchor-smoke-isolation.ps1` was **not** run. It remains optional per §8.6 because it may mutate the drill DB by provisioning test clinics — and the basic gating set in §8.1–§8.5 was sufficient for this drill. Future drills may run it once §8.5 has cleared.
- All drill credentials (drill `DATABASE_URL`, drill `ANCHOR_JWT_SECRET`, drill `ANCHOR_HASH_SALT`, drill `ANCHOR_ADMIN_PEPPER`, drill `RATE_LIMIT_SECRET`, drill `INVITE_TOKEN_SALT`, drill `ANCHOR_ADMIN_TOKEN`) were freshly generated for the drill, never reused from production, and shredded at teardown. None appear in this evidence sub-section.

---

## 12. Teardown procedure

Order matters: web service first (so it doesn't briefly point at a deleted DB and emit noisy errors), then Postgres.

### 12.1 Delete the drill web service

1. Render Dashboard → drill service → Settings → Delete Service.
2. Confirm the name matches `anchor-restore-drill-svc-YYYYMMDD-HHMM`.
3. Click Delete.
4. Capture a dashboard screenshot showing the absent service for §11.

### 12.2 Delete the drill Postgres database

1. Render Dashboard → drill DB → Settings → Delete Database.
2. Confirm the name matches `anchor-restore-drill-YYYYMMDD-HHMM`.
3. Click Delete.
4. Capture a dashboard screenshot showing the absent database for §11.

### 12.3 Shred local notes containing drill secrets

Delete the local files / clipboard entries containing:

- The drill `DATABASE_URL`.
- The drill `ANCHOR_JWT_SECRET`.
- The drill `ANCHOR_HASH_SALT`.
- The drill `ANCHOR_ADMIN_PEPPER`.
- The drill `RATE_LIMIT_SECRET`.
- The drill `INVITE_TOKEN_SALT`.
- The drill `ANCHOR_ADMIN_TOKEN`.

None of these may be retained, archived, or pasted into any persistent store after teardown.

### 12.4 What evidence to retain

In the per-drill §11 evidence sub-section:

- This runbook reference and the timestamps captured.
- The smoke results table (status codes and request ids only).
- The migration checksum result table (counts only).
- Teardown confirmation screenshots (Render dashboard chrome only — no env values visible).
- The decision (PASS / FAIL / INCONCLUSIVE) and the next-drill date.

### 12.5 What must NOT be retained

- The drill `DATABASE_URL`.
- The drill `ANCHOR_ADMIN_TOKEN`.
- The drill `ANCHOR_JWT_SECRET`.
- The drill `ANCHOR_ADMIN_PEPPER`.
- The drill `ANCHOR_HASH_SALT`.
- The drill `RATE_LIMIT_SECRET`.
- The drill `INVITE_TOKEN_SALT`.
- Any other env value used by the drill service.
- The pairing of snapshot id and timestamps that could let a reviewer infer prod data volume.

If any of these were captured into a note during the drill, the note is shredded in §12.3 and replaced with `<recorded-locally-then-rotated>` in the evidence file.

---

## 13. Failure-mode playbook

### 13.1 Snapshot restore fails

- **Do not retry** the restore against the prod database under any circumstance.
- Capture the Render error message into §11 (verbatim, no secrets).
- Escalate to Render support.
- Mark the drill INCONCLUSIVE in §11 and reschedule.

### 13.2 Drill service boot fails

- Read the drill service `Logs` in Render Dashboard.
- Look for `startup_failed` events. Likely causes, in order of probability:
  - One of the Patch 1 / 4B / 6 prod fail-closed asserts fired (only on the second pass with `APP_ENV=prod`). A drill env value still equals the default literal (`anchor-default-salt`, `anchor-admin-pepper-default`, `env` mode, unknown checksum-verify value). Fix the env value and redeploy.
  - `DATABASE_URL` is wrong. The first pass with `APP_ENV=staging` will still raise on import in this case.
  - Migration runner fault. Check for `migration.failed` events with the offending filename. Do not edit `schema_migrations`; investigate the file in git.
- If the boot failure is on `APP_ENV=staging`, the drill DB itself is suspect. If the failure is only on `APP_ENV=prod`, it is an env-value problem on the drill service.

### 13.3 Migration checksum mismatch

See §9 "If a `migration.checksum.mismatch` fires". The drill is paused, the issue is investigated against git history per the Patch 6B precedent, and a remediation PR is opened before any re-drill.

### 13.4 RLS self-test fails

- A `FAIL` from `scripts/anchor-verify-force-rls.ps1` against the drill means either (a) the restore was incomplete and the RLS metadata did not survive, or (b) the migration runner partially applied during the drill boot and left tables in an intermediate state.
- **Do not** attempt to "fix" the drill DB by issuing `ALTER TABLE … FORCE ROW LEVEL SECURITY` manually. The drill DB is being deleted; the fix needed is in the runner / migrations, not in the drill DB.
- Escalate to founder. Mark drill FAIL in §11. Investigate against the migration runner and the legacy / 2026-series RLS migrations (`10014`, `10015`, `10017`).

### 13.5 Protected route returns 500 instead of 401

- Indicates that `require_clinic_user` raised on missing context rather than returning the documented 401 — usually a downstream code-path bug.
- Capture the response body's `request_id`, the `X-Request-ID` header, and the drill service log line at that request_id.
- Mark drill FAIL in §11. Open a remediation issue against the auth path.

### 13.6 Drill service accidentally receives production traffic

- The five gates in §7 should make this impossible. If it happens anyway:
  1. **Immediately delete the drill web service** (§12.1). The drill DB can wait.
  2. Capture log lines showing the offending Host header / referer.
  3. Mark drill INCONCLUSIVE in §11.
  4. Diagnose how the gate failed (mis-set `TRUSTED_HOSTS`, accidental custom-domain bind, etc.) before re-drilling.
- The drill service does not have prod's `ANCHOR_JWT_SECRET` or prod's `ANCHOR_ADMIN_PEPPER`, so no prod-issued credential could have authenticated against it. The contamination is therefore traffic-only, not credential-leak.

### 13.7 Drill credentials leaked

- Treat as an S1 incident. Open the (planned) `docs/operations/incident_response.md` runbook for the formal flow; until that ships, the immediate actions are:
  1. Disable the drill service so the leaked credentials cannot be used.
  2. Delete the drill DB.
  3. Confirm in the audit that no prod credential was ever in the drill scope (per §6 — drill credentials are always freshly generated and drill-only).
  4. Document the leak vector in §11 and in a separate retrospective.
- Because drill credentials are single-use and rotated at teardown, a leak windows out at the drill duration — typically under two hours. The risk is still real and must be tracked.

---

## 14. Cadence

- **Before the first paid pilot / first real clinic data:** at least one PASS drill within 30 days of pilot kickoff. Re-drill required if more than 90 days have elapsed.
- **Quarterly** between pilots, while no real clinic data is in production.
- **Monthly** during any period of active real clinic data, or after a material change to the migration runner (`app/migrate.py`), to migrations `10000`–`10017` or any future RLS / schema migration, or to the production Postgres plan (instance resize, version upgrade, region change).
- **Always after** a major incident, an executed prune destructive run, or a doctrine-relevant patch (e.g. a future Patch X that changes RLS posture).

Operator schedules the next drill in the §11 evidence sub-section as part of every completed drill.

---

## 15. Related docs

- [`env.md`](./env.md) — Environment variable reference used by §4 and §6.
- `intake_retention.md` — Operator runbook for `POST /v1/admin/intake/prune`. **Planned**, not yet written. Will reference this drill as one of its prerequisites.
- `incident_response.md` — Severity ladder, contact flow, first-15-minutes checklist, containment actions, postmortem template. **Planned**, not yet written. Will reference §13 above for backup/restore-specific failure modes.
- `../canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md` §234 — strategic source of the "tested restore" requirement.
- `../canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md` §63 — operational gate enumeration.
