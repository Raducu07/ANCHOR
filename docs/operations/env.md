# ANCHOR Backend Environment Variables

> **Operator reference. Values live in Render (the deployment secret store), not in git.**
> Every example in this document is a placeholder. Real secrets must never appear in this file, in logs, in screenshots, in tickets, in PR descriptions, or in commits.

## 1. Purpose and scope

This document is the source of truth for **which** environment variables the ANCHOR backend reads, **where** in the code they take effect, and **what failure mode** a misconfiguration causes. It is an operator/reviewer reference, not a configuration file.

This document does not grant compliance, certification, RCVS approval, regulator endorsement, or guaranteed protection. ANCHOR is aligned to RCVS principles and EU AI Act articles where it can be; it is not compliant with them.

Out of scope here: backup/restore procedure, intake retention prune procedure, incident response runbook. Those will live in separate files under `docs/operations/`.

## 2. Production rules

| Rule | Why |
|---|---|
| `APP_ENV` **must** be `prod` in production. | Every startup fail-closed assert is gated on `get_app_env() == "prod"`. Without it, the prod safety net is silently off. |
| No real secret values in logs, docs, screenshots, tickets, commits, or PR descriptions. | This document, the canonical docs, and the test suite all use placeholders. Treat secrets as if they were patient identifiers — they never appear in any artefact under version control. |
| Prefer DB-backed admin tokens (`POST /v1/admin/tokens`) over env admin tokens. | Env tokens cannot be revoked without a redeploy and carry no per-token audit linkage. Patch 4B refuses `ANCHOR_ADMIN_MODE=env` in production. |
| Live Workspace generation stays off. | `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` must remain unset (or `0`/`false`) until the 2A-C.5E local/staging safety gate is documented as passed. The hard-refusal boundary (no diagnosis / no prescribing / no treatment-planning) must be proven on the live path before enablement. |
| Migration checksum verification on in prod after Patch 6B. | `ANCHOR_MIGRATION_VERIFY_CHECKSUMS` must be `1` (or unset — the prod default is on). It was temporarily set to `0` during the Patch 6 incident; flip it back as soon as the restored migration content is deployed. |
| `CORS_ALLOW_ORIGINS` and `TRUSTED_HOSTS` are explicit allow-lists. | No wildcards alongside `CORS_ALLOW_CREDENTIALS=true`; the startup config check refuses that combination outright. |

## 3. Required in production — startup fail-closed

These variables must be set in prod. A missing or default value causes the FastAPI process to refuse to start (logged as `startup_failed` with `error_type=RuntimeError`).

| Variable | Purpose | Required shape (placeholder) | Failure mode | Enforced in |
|---|---|---|---|---|
| `APP_ENV` | Selects production policy. Must be `prod`. | `prod` | All other fail-closed asserts no-op when this is anything else. | `app/anchor_logging.py::get_app_env` (consumer in every prod assert) |
| `DATABASE_URL` | Postgres connection string. `postgres://` is auto-normalised to `postgresql://`. | `postgresql://<user>:<password>@<host>/<dbname>` | `RuntimeError("DATABASE_URL is not set")` at import time. | `app/db.py::_normalize_database_url` |
| `ANCHOR_JWT_SECRET` | HS256 signing secret for clinic-user JWTs. | non-empty random string ≥ 32 bytes, base64 or hex | `HTTPException(500, "ANCHOR_JWT_SECRET not set")` on every JWT encode/decode. | `app/auth_and_rls.py::_make_jwt`, `_decode_jwt` |
| `ANCHOR_HASH_SALT` *or* `ANCHOR_LOG_SALT` | Salt for SHA-256 hashing of IP/UA in logs and admin audit metadata. One of the two must be set; `ANCHOR_HASH_SALT` is preferred. | non-empty random string, **must not equal** `anchor-default-salt`. | `RuntimeError("ANCHOR_HASH_SALT (or ANCHOR_LOG_SALT) must be set when APP_ENV=prod; default fallback is not permitted in production.")` at lifespan startup. | `app/anchor_logging.py::assert_hash_salt_for_prod` (Patch 1) |
| `ANCHOR_ADMIN_PEPPER` | Pepper for SHA-256 hashing of platform admin tokens at rest. | non-empty random string, **must not equal** `anchor-admin-pepper-default`. | `RuntimeError("ANCHOR_ADMIN_PEPPER must be set when APP_ENV=prod; default fallback is not permitted in production.")` at lifespan startup. | `app/admin_auth.py::assert_admin_pepper_for_prod` (Patch 1) |
| `RATE_LIMIT_SECRET` (when `RATE_LIMIT_ENABLED=1`) | HMAC key for in-memory rate-limit bucket fingerprints (so IP / token plaintext is never used as a bucket key). | non-empty random string | `RuntimeError("RATE_LIMIT_SECRET is required when RATE_LIMIT_ENABLED is on")` at limiter build time. | `app/rate_limit.py::build_limiter` |
| `ANCHOR_ADMIN_MODE` | Controls which admin-token sources are accepted. **Must not be `env` in prod.** Unset/blank resolves to `db` in prod; explicit `hybrid` is the only acceptable temporary operator override. | unset (defaults `db`) or `db` or `hybrid` | `RuntimeError("ANCHOR_ADMIN_MODE='env' is not permitted when APP_ENV=prod; …")` for `env`; `RuntimeError("ANCHOR_ADMIN_MODE=… is not a valid admin mode …")` for any unknown value. | `app/admin_auth.py::assert_admin_mode_for_prod` (Patch 4B) |
| `ANCHOR_MIGRATION_VERIFY_CHECKSUMS` | Controls migration-runner checksum verification. Unknown value in prod is a startup failure. | unset (defaults `1` in prod), `1` / `true` / `yes` / `on`, or `0` / `false` / `no` / `off` (operator override only) | `RuntimeError("ANCHOR_MIGRATION_VERIFY_CHECKSUMS=… is not a recognised boolean. …")` for any other value in prod. | `app/migrate.py::verify_checksums_enabled` (Patch 6) |

Lifespan order (`app/main.py::lifespan`): salt → pepper → admin-mode → migrations. A misconfigured deploy aborts before serving any traffic.

## 4. Required in production — functional but not always startup-fail-closed

These do not raise at startup, but their absence causes functional regressions or weaker security posture.

| Variable | Purpose | Default | Notes |
|---|---|---|---|
| `CORS_ALLOW_ORIGINS` | Comma-separated allow-list of browser origins (portal frontend, etc.). | empty → CORS disabled, log `cors_disabled` | Must be the explicit portal origin list. **Never `*` with credentials.** |
| `CORS_ALLOW_CREDENTIALS` | Whether cookies/auth headers cross CORS boundary. | `false` | If set true with `*` in `CORS_ALLOW_ORIGINS`, startup raises a `RuntimeError`. |
| `CORS_ALLOW_METHODS` | Allowed HTTP methods on CORS. | **Hardcoded** in `app/main.py:118`: `GET, POST, PUT, PATCH, DELETE, OPTIONS`. *Not env-driven today.* | If you need to narrow this, it is a code change. Flagged in §16. |
| `CORS_ALLOW_HEADERS` | Allowed request headers on CORS. | **Hardcoded**: `["*"]`. *Not env-driven today.* | If you need to narrow this, it is a code change. Flagged in §16. |
| `CORS_MAX_AGE` | Preflight cache lifetime, seconds. | **Hardcoded**: `600`. *Not env-driven today.* | Flagged in §16. |
| `CORS_ALLOW_ORIGIN_REGEX` | Implicit — *not* an env var. | Patch 1 gates the localhost regex on `get_app_env() != "prod"`. | No env action needed; documented for completeness. |
| `TRUSTED_HOSTS` | Comma-separated list for Starlette's TrustedHostMiddleware. | empty → TrustedHost disabled, log `trusted_host_disabled` | Must include the prod Render origin (e.g. `anchor-api-prod.onrender.com`) and any custom domain in use. |
| `SERVICE_NAME` / `APP_NAME` | Service label embedded in every structured log line. | `anchor` | Set to a deploy-specific value (e.g. `anchor-api-prod`) for log grep clarity. |
| `APP_VERSION` / `GIT_SHA` / `BUILD_ID` | Surfaced in every log line and in `/v1/version`. | unset → field becomes `null` in the `/v1/version` response. | `/v1/version.git_sha` reads explicit `GIT_SHA` first, then falls back to Render's Git metadata variable `RENDER_GIT_COMMIT` (auto-injected for every Git-repo-backed Render service). If both are absent, `git_sha` remains `null`. `BUILD_ID` remains optional explicit app metadata — Render has no auto-injected equivalent, so it stays `null` unless explicitly set. **Do not store secrets in any of these variables**; the commit SHA is non-secret build metadata only. |
| `LOG_LEVEL` | Standard Python logging level. | `INFO` | Use `INFO` in prod. `DEBUG` is a forensic-only setting. |
| `DB_POOL_SIZE` | SQLAlchemy pool size. | `5` | Tune to Render Postgres plan. |
| `DB_MAX_OVERFLOW` | SQLAlchemy max overflow connections. | `10` | Tune to Render Postgres plan. |

## 5. Authentication and JWT tuning

| Variable | Purpose | Default | Recommended prod posture |
|---|---|---|---|
| `ANCHOR_JWT_ISSUER` | `iss` claim and decode-side issuer check. | `anchor` | Set explicitly per environment (e.g. `anchor-prod`) so a staging token cannot replay in prod. |
| `ANCHOR_JWT_AUDIENCE` | `aud` claim and decode-side audience check. | `anchor-portal` | Same — set explicitly per environment. |
| `ANCHOR_JWT_TTL_SEC` | Token lifetime, seconds. | `86400` (24 h) | Acceptable for the current portal flow. Reduce only if a refresh flow ships. |
| `ANCHOR_JWT_LEEWAY_SEC` | Clock-skew tolerance, seconds. | `30` | Leave as default unless Render clock skew is observed. |
| `ANCHOR_JWT_MAX_TOKEN_LEN` | Defensive cap on bearer-token length before decode. | `8192` | Leave as default. |
| `ANCHOR_AUTH_STRICT_DB_CHECK` | When `1`, every protected route re-validates the user against `clinic_users` (active_status, role) per request. | `1` (on) | **Keep on in prod.** Off would let an orphan token survive a clinic-user disable. |
| `ANCHOR_ROLE_ALLOWLIST` | Comma-separated allow-list of accepted JWT `role` values. | `admin,staff,reader,readonly,owner,practice_manager` | Override only if narrowing. Validated server-side. |
| `INVITE_TOKEN_SALT` | Salt mixed into the SHA-256 hash of invite tokens at storage. | **Has a default literal** (`anchor-invite-salt`). *Should be explicitly set in prod.* | This is the same shape risk Patch 1 addressed for `ANCHOR_HASH_SALT` and `ANCHOR_ADMIN_PEPPER`. There is no startup fail-closed assert today; set a non-default value via Render env. A follow-up patch may add a `assert_invite_salt_for_prod` mirror. |

## 6. Admin tokens and bootstrap mode

`ANCHOR_ADMIN_MODE` controls which admin-token sources `require_admin` accepts:

| Mode | DB tokens accepted? | Env tokens accepted? | Allowed in prod? |
|---|---|---|---|
| `db` | yes | no | **Yes — production steady state.** Default when env is unset. |
| `hybrid` | yes | yes | Yes, but only as an *explicit operator override* during a documented bootstrap window. Should not be the steady state. |
| `env` | no | yes | **No — refused at startup in prod** by `assert_admin_mode_for_prod` (Patch 4B). |

**Bootstrap-only env tokens:**

- `ANCHOR_ADMIN_TOKEN` — single bearer token.
- `ANCHOR_ADMIN_TOKENS` — comma-separated set of bearer tokens.

These are intended for first-clinic bootstrap or emergency re-entry. They have no `platform_admin_tokens` row, so:

- they cannot be revoked via `POST /v1/admin/tokens/{id}/disable`;
- `write_admin_audit_event` records `admin_token_id=None` for them, so they have weaker per-token audit linkage.

**Recommended steady state:** issue DB-backed tokens via `POST /v1/admin/tokens`, transition the operator to a DB token, then **rotate or remove the env admin token entirely**. After transition, set `ANCHOR_ADMIN_MODE=db` (or remove the env so it defaults to `db` in prod).

Rotation note: when rotating from env to DB, do not leave the env value in place "just in case". Either remove it or keep it disabled and tracked in a private rotation log; do not paste plaintext into shared channels.

## 7. Rate limits

`RATE_LIMIT_ENABLED` controls the in-memory fixed-window limiter. **Keep on in prod.**

| Variable | Purpose | Default |
|---|---|---|
| `RATE_LIMIT_ENABLED` | Master switch. Truthy values: `1`, `true`, `yes`. | `1` (on) |
| `RATE_LIMIT_SECRET` | HMAC key for limiter bucket fingerprints (so raw IP / token never becomes a bucket key). | required when `RATE_LIMIT_ENABLED=1` — startup raises otherwise |

**Per-group windows and limits.** All values read by `app/rate_limit.py::rules_from_env`. Defaults below are read from the same module:

| Group | Endpoint(s) | Window default | Limit default | Window env | Limit env |
|---|---|---|---|---|---|
| `auth` | `POST /v1/clinic/auth/login` (and legacy alias) | 60 s | 10 | `RL_AUTH_WINDOW_S` | `RL_AUTH_LIMIT` |
| `invite` | `POST /v1/clinic/auth/invite/accept` | 300 s | 10 | `RL_INVITE_WINDOW_S` | `RL_INVITE_LIMIT` |
| `receipt` | `GET /v1/assistant/runs/{run_id}/receipt`, `GET /v1/assistant/receipts/{identifier}` | 60 s | 30 | `RL_RECEIPT_WINDOW_S` | `RL_RECEIPT_LIMIT` |
| `export` | `GET /v1/portal/export.csv` | 300 s | 5 | `RL_EXPORT_WINDOW_S` | `RL_EXPORT_LIMIT` |
| `assistant_submit` | `POST /v1/assistant/runs`, `POST /v1/portal/assist` | 60 s | 10 | `RL_ASSISTANT_SUBMIT_WINDOW_S` | `RL_ASSISTANT_SUBMIT_LIMIT` |
| `public_intake` | `POST /v1/public/demo-request`, `POST /v1/public/start-request`, `POST /v1/public/site-chat/log` | 60 s | 5 | `RL_PUBLIC_INTAKE_WINDOW_S` | `RL_PUBLIC_INTAKE_LIMIT` |
| `admin` | every `/v1/admin/*` endpoint (token-fingerprinted bucket) | 60 s | 60 | `RL_ADMIN_WINDOW_S` | `RL_ADMIN_LIMIT` |
| `admin_bootstrap` | `POST /v1/admin/bootstrap/clinic` | 3600 s | 10 | `RL_ADMIN_BOOTSTRAP_WINDOW_S` | `RL_ADMIN_BOOTSTRAP_LIMIT` |

Keys: `auth`, `invite`, `public_intake` are per-IP (`enforce_ip`). `receipt`, `export`, `assistant_submit` are per `(clinic_id, clinic_user_id)` (`enforce_authed`). `admin`, `admin_bootstrap` are per admin-token fingerprint (`enforce_admin_token` / `enforce_admin_token_group`).

Exceeded budget → `HTTP 429` with `Retry-After` header and `detail: "rate_limited"`.

## 8. Export and receipt controls

| Variable | Purpose | Default | Notes |
|---|---|---|---|
| `ANCHOR_EXPORT_MAX_WINDOW_DAYS` | Maximum window for `/v1/portal/export.csv`. | `31` | Tightening reduces the metadata blast radius of a single export. |
| `ANCHOR_EXPORT_MAX_ROWS` | Hard cap on rows per export. | `20000` | Combined with the window cap, sets the export's worst-case shape. |
| `ANCHOR_RECEIPT_SIGNING_SECRET` | HMAC secret for signed receipt artefacts read in `app/portal_read.py`. | empty (signing disabled if absent) | Set when the signed-receipt feature is in active use. Not currently part of the startup fail-closed set. |
| `ANCHOR_RECEIPT_SIGNING_KID` | Key id tag carried alongside signed receipts. | `v1` | Rotate together with the signing secret. |

## 9. Workspace / Assistant / provider env vars

> **DANGER:** the variable in the next row is the single most consequential operational flag in the system.

| Variable | Purpose | Default | Doctrine |
|---|---|---|---|
| `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` | When truthy, the Workspace orchestrator routes eligible `client_comm` requests to the live Anthropic provider rather than the deterministic builder. | unset / falsy → **production-off** | **Must remain unset (or `0`/`false`) in production** until the 2A-C.5E local/staging safety gate is documented as passed AND the hard-refusal boundary (no diagnosis / no prescribing / no treatment-planning) is proven on the live path. Flipping this on makes Anthropic a production subprocessor; flag any change that would activate it. |
| `ANTHROPIC_API_KEY` | Provider credential. Read by `app/assistant_anthropic_client.py`. | unset → live path returns a safe `503` | **Presence does not imply enablement.** Live generation is gated by the flag above; the API key alone is not enough. Treat as a high-sensitivity secret. |
| `ANCHOR_ASSISTANT_MODEL` | Provider model id used by the live path when enabled. | `claude-sonnet-4-20250514` | Change only via a deliberate version review. |
| `ANCHOR_ASSISTANT_MAX_TOKENS` | Hard cap on tokens per live generation when enabled. | `1000` | Lower is safer; higher costs more. |

No `OPENAI_*` env vars are present in the current code. No other provider client is wired. Vendor-neutrality is a future direction; ANCHOR is structurally compatible with future vendor-neutral generation, not vendor-neutral today.

## 10. Public intake and notifications

Public intake (`/v1/public/demo-request`, `/v1/public/start-request`, `/v1/public/site-chat/log`) stores public contact PII and visitor free text in `demo_requests`, `start_requests`, and `public_site_chat_events`. **This data is outside the clinic-governance metadata-only perimeter** — it is pre-clinic marketing intake, governed by UK-GDPR. The clinic-data metadata-only doctrine continues to apply to every clinic-scoped surface.

| Variable | Purpose | Default | Notes |
|---|---|---|---|
| `RL_PUBLIC_INTAKE_WINDOW_S` / `RL_PUBLIC_INTAKE_LIMIT` | Per-IP rate limit applied before honeypot and DB write on every public intake endpoint. | `60 s` / `5` | See §7. |
| `ANCHOR_INTAKE_NOTIFICATION_WEBHOOK_URL` | Internal-notification webhook fired after a successful intake persist. | unset → notification stubbed (logged `intake.notification.stubbed`) | **Webhook payload includes raw record fields** (name, email, phone, message) by current design. Point this at a trusted internal queue only. |
| `ANCHOR_INTAKE_ACK_WEBHOOK_URL` | Acknowledgement webhook for the visitor (carries `recipient_email`). | unset → ack stubbed | Same trust posture as the notification webhook. |

**Retention is operational.** `POST /v1/admin/intake/prune` is admin-token gated, dry-run by default, requires `"I-UNDERSTAND"` to delete, and caps destructive runs at 50 000 rows per call. There is **no scheduled prune today**; the operator runs it. Recommended operator-side defaults: 365 days for `demo`/`start`, 90 days for `chat`. These will be documented in `docs/operations/intake_retention.md`.

## 11. Migration verification

`ANCHOR_MIGRATION_VERIFY_CHECKSUMS` (Patch 6) controls the migration runner's checksum verification step.

| Resolved value | Behaviour |
|---|---|
| `1`, `true`, `yes`, `on` (case- and whitespace-tolerant) | Verification on. |
| `0`, `false`, `no`, `off` | Verification off. |
| unset/blank in prod | Defaults to on. |
| unset/blank in non-prod | Defaults to off (so a developer iterating on a draft migration is not blocked). |
| unknown value in prod | **Startup raises `RuntimeError`.** |
| unknown value in non-prod | Defaults to off (defensive). |

**What a checksum mismatch means.** On every boot the runner computes the SHA-256 of every applied migration's on-disk content (stripped) and compares it to the checksum captured when the migration was first applied. A mismatch means the file has been edited after application, which is a doctrine violation (*"Existing migrations are never retroactively edited"*). The runner refuses to start and logs `migration.checksum.mismatch` with the stored vs expected sha256 (metadata only — no SQL body).

**Correct response to a mismatch:**

1. **Do not** edit `schema_migrations` to make the error go away.
2. Inspect git history for the affected migration. The originally applied content (the version whose SHA-256 matches the stored value) is the source of truth.
3. **Restore** the migration file on the branch to its applied content.
4. If the desired-but-not-applied changes are still wanted, add them as a **new** migration with a higher number. Doctrine: existing migrations are never retroactively edited.
5. Re-enable verification (`ANCHOR_MIGRATION_VERIFY_CHECKSUMS=1` or remove the override) only after the restore is deployed.

Patch 6B is the precedent. Migration `10010_force_rls_all_tenant_tables.sql` was edited in place in March 2026; Patch 6 surfaced the violation; Patch 6B restored the file to its applied content and added `10017_force_rls_idempotent_reassertion.sql` to carry forward the safer wrapping. This is the template for any future occurrence — it is not an admission of compliance with anything.

## 12. Example Render environment checklist

Mark each item with **set** / **unset** / **present** / **absent** in your deploy log. **Do not write actual values into the log.**

Required (fail-closed):

- [ ] `APP_ENV` = `prod`
- [ ] `DATABASE_URL` present
- [ ] `ANCHOR_JWT_SECRET` present, non-default
- [ ] `ANCHOR_HASH_SALT` present, non-default *(or `ANCHOR_LOG_SALT` set as fallback)*
- [ ] `ANCHOR_ADMIN_PEPPER` present, non-default
- [ ] `RATE_LIMIT_SECRET` present *(required while `RATE_LIMIT_ENABLED` is on, which is the default)*
- [ ] `ANCHOR_ADMIN_MODE` unset *(→ `db` in prod)* OR explicitly `db` OR explicitly `hybrid` with a documented operator override note
- [ ] `ANCHOR_MIGRATION_VERIFY_CHECKSUMS` unset *(→ on in prod)* OR explicitly `1`

Bootstrap discipline:

- [ ] `ANCHOR_ADMIN_TOKEN` / `ANCHOR_ADMIN_TOKENS`: absent in steady state. If present, log the bootstrap reason and the rotation timeline.
- [ ] Admin mode is **not** left at `hybrid` long term.

Functional posture:

- [ ] `CORS_ALLOW_ORIGINS` set to the explicit portal allow-list, no `*`.
- [ ] `CORS_ALLOW_CREDENTIALS` set deliberately (true/false). If true, `CORS_ALLOW_ORIGINS` has no `*`.
- [ ] `TRUSTED_HOSTS` includes the Render hostname and any custom domain in use.
- [ ] `LOG_LEVEL` = `INFO`.

Danger:

- [ ] `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` is **unset** (or `0`/`false`).
- [ ] `ANTHROPIC_API_KEY` is unset unless the live path is being prepared in a non-prod environment. *Presence alone does not enable live generation.*

JWT tuning:

- [ ] `ANCHOR_JWT_ISSUER` set explicitly (e.g. `anchor-prod`).
- [ ] `ANCHOR_JWT_AUDIENCE` set explicitly (e.g. `anchor-portal-prod`).

Invite hygiene:

- [ ] `INVITE_TOKEN_SALT` set explicitly (not the default literal `anchor-invite-salt`).

Receipts / exports (optional):

- [ ] `ANCHOR_RECEIPT_SIGNING_SECRET` / `ANCHOR_RECEIPT_SIGNING_KID` set if signed receipts are in use.
- [ ] `ANCHOR_EXPORT_MAX_WINDOW_DAYS` / `ANCHOR_EXPORT_MAX_ROWS` left at defaults unless a deliberate tightening is needed.

Intake notifications (optional):

- [ ] `ANCHOR_INTAKE_NOTIFICATION_WEBHOOK_URL`, `ANCHOR_INTAKE_ACK_WEBHOOK_URL` point at trusted internal queues only (webhook payloads include raw contact PII by current design).

## 13. Operational smoke after env changes

After every env change, run the safe smoke set from a workstation. These are read-only and return no clinic data. Founder uses PowerShell:

```powershell
# 1) Liveness (no auth) — should return 200
Invoke-WebRequest -UseBasicParsing `
  -Uri 'https://anchor-api-prod.onrender.com/health' |
  Select-Object StatusCode, Content

# 2) Version + env (no auth) — should return 200 with env=prod
Invoke-WebRequest -UseBasicParsing `
  -Uri 'https://anchor-api-prod.onrender.com/v1/version' |
  Select-Object StatusCode, Content

# 3) Protected route without bearer — should return 401 missing_bearer_token
try {
    Invoke-WebRequest -UseBasicParsing `
        -Uri 'https://anchor-api-prod.onrender.com/v1/portal/dashboard'
} catch {
    $_.Exception.Response.StatusCode.value__   # expect 401
}
```

Capture into the deploy log: status codes, the `X-Request-ID` header from each response, and the `env`/`git_sha` fields from `/v1/version`. **Do not paste real bearer tokens into the deploy log or anywhere else.**

When credentials are available, the two PowerShell scripts under `scripts/` cover deeper checks:

- `scripts/anchor-verify-force-rls.ps1 -Base <prod-base> -AdminToken <DB-tier admin token>` — confirms `ENABLE`/`FORCE` posture on tenant tables.
- `scripts/anchor-smoke-isolation.ps1` — cross-tenant smoke. Requires `ANCHOR_BASE` and `ANCHOR_ADMIN_TOKEN`.

Both are read-only. The admin token must be a DB-backed token (per `ANCHOR_ADMIN_MODE=db` in prod).

## 14. Stop conditions

- **Do not deploy** if any required prod secret in §3 is missing or equal to its default literal. The startup asserts will fail and the deploy will not serve traffic, but catch it earlier in the deploy log.
- **Do not leave `ANCHOR_MIGRATION_VERIFY_CHECKSUMS=0`** as a steady-state setting. It is acceptable only as an emergency recovery flag during an active checksum-mismatch incident, and must be removed (or set back to `1`) as soon as the offending migration has been restored.
- **Do not enable live Workspace generation in production.** The 2A-C.5E safety gate and the hard-refusal boundary must be documented as passed before `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` is set in prod.
- **Do not use env admin tokens as a steady state.** Bootstrap-only. Transition to DB-backed tokens and set `ANCHOR_ADMIN_MODE=db` (or remove the override so the prod default of `db` applies).
- **Do not print secret values** in deploy logs, screenshots, tickets, commits, PR descriptions, support emails, or anywhere else they could surface later.
- **Do not introduce buyer-discovery framing.** Addendum v1.3 has withdrawn that wording.
- **Do not make compliance / certification / RCVS approval / regulator endorsement / guaranteed protection claims** in any prod string, log, doc, or marketing surface. ANCHOR is aligned, not compliant.
- **Do not proceed to paid pilots or real clinic data** until: backup/restore drill is complete and documented in `docs/operations/backup_restore.md`; intake retention prune procedure has been dry-run and at least one controlled destructive run has been executed under founder approval; `docs/operations/incident_response.md` is in place; and the legal/commercial pack referenced in Addendum v1.3 is complete.

## 15. Doctrine pointers

Operative canon (read these for non-env questions):

- `docs/canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md`
- `docs/canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md`
- `docs/canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md`

This document does not duplicate doctrine. It documents env vars; doctrine lives in the canonical set.

## 16. Known uncertainties for a later doc/code audit

These items are flagged here because they affect operator confidence today; none of them are addressed in Patch 7.

- **CORS methods/headers/max-age are hardcoded in `app/main.py`**, not env-driven. The Patch 7 brief asked them to be documented as env vars; they are documented here as hardcoded values. If env-driven tuning is desired, that is a future code change.
- **`INVITE_TOKEN_SALT` defaults to a known literal (`anchor-invite-salt`)** in `app/auth_and_rls.py`. Patch 1 closed the equivalent gap for `ANCHOR_HASH_SALT` and `ANCHOR_ADMIN_PEPPER`; the invite salt should follow with a `assert_invite_salt_for_prod` mirror in a follow-up patch.
- **Receipt signing env vars** (`ANCHOR_RECEIPT_SIGNING_SECRET`, `ANCHOR_RECEIPT_SIGNING_KID`) are present in `app/portal_read.py` but the live status of the signed-receipt feature has not been re-confirmed in 2A-D.2; treat as "set if in use, absent otherwise" until a follow-up audit.
- **No `OPENAI_*` env vars are present in code** as of this writing. Vendor-neutral live generation is a future direction, not a present-tense capability. Do not document a vendor as supported until the code wires it.
