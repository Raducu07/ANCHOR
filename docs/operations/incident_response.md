# ANCHOR Incident Response Runbook

> **Operator-facing runbook.** This document defines how the ANCHOR operator triages, contains, and recovers from operational, security, privacy, governance, availability, migration, and AI-governance incidents on the ANCHOR backend and its operational infrastructure.
>
> Real secrets — admin tokens, JWT secrets, `DATABASE_URL`, API keys, raw clinical or client content, full bearer tokens, cookies, peppered hashes — must never appear in this document, in incident notes, in screenshots, in tickets, in commits, in PR descriptions, or in any external communication.

---

## 1. Purpose and scope

This runbook is the procedural authority for incident response on the **ANCHOR backend / operational infrastructure**. It covers:

- **Triage** — classifying severity and scope.
- **Containment** — stopping the bleed, preserving evidence.
- **Evidence capture** — what to record, what never to record.
- **Escalation** — when to page, when to involve legal / counsel, when to consider regulatory or user notification (always after legal review).
- **Recovery** — service restoration and verification.
- **Post-incident review** — blameless write-up, preventive actions, follow-up.

This runbook is **not**:

- Legal advice.
- A compliance certification, RCVS approval, regulator endorsement, or guaranteed-protection statement.
- A substitute for professional legal, security, or clinical advice.
- An authorisation by itself for any production mutation. Production changes require the operator-in-the-loop decisions documented inside.

**Out of scope:**

- Clinical decision-making guidance, direct veterinary advice, or any clinical determination.
- Regulatory notification determinations without legal review.
- Frontend feature implementation.
- Live-generation enablement.
- Destructive database actions except under explicit incident containment approval recorded in the §10 post-incident review.

---

## 2. Doctrine and stop conditions

ANCHOR doctrine applies to incident response with the same force as to feature work:

- **Governance-first, metadata-only by default.** Incident notes must contain metadata only — hashes, request IDs, status codes, timestamps. **Never raw prompts, outputs, transcripts, clinical content, or client/patient identifiers.**
- **Tenant safety + RLS / FORCE RLS.** Incident response itself must not violate tenant isolation; do not run cross-tenant queries to "investigate" without explicit incident-commander approval and a documented read-only justification.
- **Human-review based.** No automated remediation. Every production change during an incident is operator-in-the-loop with the decision logged in §10 / §11.
- **Receipt-backed.** Where the `admin.intake.prune*` audit events, the `migration.*` log events, the `http.request.*` and `startup_*` events already capture the trail, point to those events rather than reconstructing them in prose.
- **Aligned, not compliant.** No compliance / certification / RCVS-approval / regulator-endorsement / guaranteed-protection claim in any incident artefact, comm, or post-mortem.
- **No raw clinical content** should be copied into incident notes — ever. If you find raw content already present in logs or tickets, treat that surface as in-scope of the incident and contain the *surface*, not the content.
- **No secrets** in tickets, chat, screenshots, GitHub, docs, or runbooks. The §7 list of "never capture" is doctrine, not preference.
- **Live Workspace generation remains production-off.** No incident response unblocks live generation. The reverse is true: any incident touching the live-generation path is per-se SEV-1+ (§8.7).
- **No paid pilot / real clinic data** until: env docs (✅ Patch 7), backup/restore drill (✅ Patch 8 / 8C — drill 2026-06-07 PASS), intake retention dry-run (✅ Patch 9 / 9B — dry-run 2026-06-07 PASS, all counts 0), incident-response runbook (✅ this patch), and the legal/commercial pack per Addendum v1.3 are complete. This runbook does not satisfy the legal/commercial gate by itself.
- **Incident response evidence is operational evidence only.** It is not a compliance claim about ANCHOR or any clinic.

---

## 3. Incident severity ladder

| Sev | Definition | Examples | Immediate response target | Escalation requirement | Evidence requirement | Production changes allowed? |
|---|---|---|---|---|---|---|
| **SEV-0** | **Critical trust / safety / tenant-isolation incident.** Cross-tenant data exposure suspected or confirmed; RLS / FORCE RLS failure; raw clinical content surfaces in any unintended place; live generation produced or exposed clinical content. | Cross-tenant data exposure suspected; RLS or FORCE RLS verified broken on a clinic-scoped table; raw clinical content found in logs / receipts / exports; live-generation gate flipped on with raw content surfaced; restored DB used to serve real clinic traffic. | Begin containment within **15 minutes**. Stop other work. | **Page founder + halt all deploys + freeze risky env changes.** Legal review queued as soon as scope is known. | Full §10 post-incident review **required**. §11 evidence log started in the first 15 minutes. | **Only containment-grade changes**, recorded live in §11, with incident-commander approval. |
| **SEV-1** | **Security, privacy, production outage, migration-integrity, live-generation-boundary incident.** No confirmed cross-tenant exposure but a real risk vector. | Admin token suspected exposed; production API outage; migration checksum mismatch in prod; accidental live-generation enablement without confirmed clinical-content exposure; provider API key suspected exposed; unauthorised admin endpoint access attempt; backup restore failure during the drill cadence. | Begin containment within **1 hour**. | Page founder. Consider legal review once scope is known. | Full §10 post-incident review **required**. §11 evidence log started promptly. | **Containment + rollback** with operator decision logged in §11. |
| **SEV-2** | **Degraded production function or process anomaly with no data exposure suspected.** | Failed deploy that rolled back cleanly; repeated public-intake abuse without confirmed data loss; admin / API misuse caught by rate limits; malformed CORS / Trusted Host change that the operator can revert; non-prod migration checksum mismatch. | Begin within **4 hours** during business hours; next business day otherwise. | Founder informed. | §11 evidence log started. §10 review optional unless founder requests one. | **Reversible production changes** with operator decision logged. |
| **SEV-3** | **Minor issue, documentation gap, non-production incident, near miss.** | A docs link 404s. A test in CI flapped. A near-miss during the prune dry-run. A self-found typo in this runbook. | Within **next business day**. | None unless pattern emerges. | Lightweight note; §11 log only if useful for trend analysis. | Normal change process. |

**Severity-class examples carried in §8 containment playbooks** (one playbook per class, named after the example):

- **§8.1** Production API outage (SEV-1 typical).
- **§8.2** Database connectivity / restore failure (SEV-1; SEV-0 if restore corrupted into prod — but doctrine forbids that path).
- **§8.3** Migration checksum mismatch (SEV-1 in prod; SEV-2 in non-prod).
- **§8.4** Tenant isolation / RLS / FORCE RLS failure (**SEV-0**).
- **§8.5** Admin token exposure or misuse (SEV-1; SEV-0 with confirmed misuse).
- **§8.6** Public intake PII exposure / abuse (SEV-1 if exposure confirmed; SEV-2 if abuse only).
- **§8.7** Live Workspace generation accidentally enabled (SEV-1; **SEV-0** if raw clinic content surfaced).
- **§8.8** Provider / API key exposure (SEV-1).
- **§8.9** Authentication / login anomaly (SEV-2; SEV-1 if patterned).
- **§8.10** CORS / Trusted Host misconfiguration (SEV-1 in prod outage; SEV-2 otherwise).
- **§8.11** Public trust / receipt evidence error (SEV-1 if external; SEV-2 if internal-only).

**Promotion rules.** Promote up one level if (a) real clinic data is potentially involved, (b) tenant boundary is potentially involved, (c) live generation is potentially involved, (d) raw content is potentially involved, or (e) the operator is uncertain. **Never demote** without a documented justification signed off in §10.

---

## 4. First 15 minutes checklist

Work this list top-to-bottom. **Do not delete evidence. Do not paste secrets.** Use the §11 evidence log from row one.

1. **Stop and classify** — read §3 honestly. If unsure, classify upward.
2. **Do not delete evidence** — no log filter that excludes the noisy line, no `git reset`, no "tidy" config edit.
3. **Do not paste secrets** anywhere — chat, ticket, log, screenshot, runbook, browser bar, search engine.
4. **Record UTC time, operator, service, environment, suspected trigger** in §11 row 1.
5. **Confirm production vs non-production.** If non-prod, much of §8 still applies but post-incident review may be lighter.
6. **Confirm whether real clinic data / public PII / credentials / tenant boundary may be involved.** If yes → promote severity per §3.
7. **Preserve logs and request IDs** where safe. Render log tab open; capture key lines verbatim into §11 with secrets redacted. Capture `X-Request-ID` from any client-side error response.
8. **Freeze risky changes** — disable Render auto-deploy (already off per `backup_restore.md §10.2`); pause any in-flight PR; do not run the prune endpoint mid-incident (see `intake_retention.md §10.9`).
9. **Disable live-generation if relevant** — see §8.7. If the incident is anywhere near the Workspace path, unset `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` first.
10. **If active exposure suspected, contain first, diagnose second.** Diagnostic curiosity does not justify a second authenticated request that confirms the leak.
11. **Decide whether to page / escalate.** §3 dictates by severity; in solo-founder mode, "page" means stop other work and dedicate to this incident.
12. **Start the §11 incident evidence record.** Every subsequent action gets one row. No row is "too small".

Notes on this checklist:

- **No commands that mutate production** appear here. Every command an operator might run is in §8 under the relevant containment playbook with the explicit "is this reversible?" call-out.
- **PowerShell-safe** posture: when running smoke checks for triage, use the `Invoke-WebRequest` / `Invoke-RestMethod` form from `env.md §13` against public read-only endpoints (`/health`, `/v1/version`, `/db-check`). These do not require credentials and do not mutate state.

---

## 5. Incident roles and responsibilities

### 5.1 Solo-operator mode (current)

| Role | Who | Notes |
|---|---|---|
| Incident lead / commander | Founder / operator | Owns the decision tree end-to-end. |
| Scribe / evidence owner | Founder / operator | Same person. Discipline = consistent §11 rows. |
| Technical responder | Founder / operator (or named contractor) | One responder; no parallel mutators. |
| Legal / commercial reviewer | External counsel (when scope warrants) | Called in by founder after triage; never bypassed. |
| Communications owner | Founder | Internal first; external only after legal review. |

### 5.2 Multi-operator mode (future)

| Role | Notes |
|---|---|
| Incident commander | Owns decisions; controls the room. |
| Technical lead | Owns the mitigation; reports to the commander. |
| Evidence scribe | Owns §11 entries verbatim; protects evidence. |
| Communications owner | Owns internal status; coordinates with legal/commercial reviewer for external. |
| Legal / privacy reviewer | Required for SEV-0 / SEV-1 with potential data exposure or notification implications. |

### 5.3 Standing rules (both modes)

- **One person owns the incident record** at any given moment. Handovers are explicit and timestamped in §11.
- **One person owns production changes** at any given moment. Handovers are explicit and timestamped in §11.
- **No parallel uncoordinated changes.** If a second person wants to act, the incident lead must approve the change inline in §11 first.
- The incident lead may not also paste secrets, take destructive action without a second pair of eyes (where any second pair exists), or close the incident without §10 sign-off.

---

## 6. Communication rules

### 6.1 Order of operations

1. **Internal first.** Operator → founder (solo: self-brief in writing in §11). Capture facts before any external word.
2. **Legal / commercial review** before any external communication that could imply notification, liability, or doctrine-relevant assertions.
3. **Public / client / regulator communications** only after facts are confirmed and legal review has signed off.

### 6.2 Tone and certainty

- **Never overstate certainty.** "Investigating" is honest; "fully contained" is a claim that must be earned.
- **Use factual status language.** Approved phrases: *"investigating"*, *"contained"*, *"no evidence observed at this time"*, *"confirmed"*, *"not yet confirmed"*, *"under review with counsel"*, *"will update when more is known"*.
- **No claims of compliance, certification, RCVS approval, regulator endorsement, or guaranteed safety.** Ever. Including in private comms.

### 6.3 Safe wording examples

- *"We are investigating an operational issue affecting ANCHOR service availability. We will update when more is known."*
- *"We have contained the issue and are reviewing logs for impact. At this stage, we have not observed evidence of cross-tenant data exposure."*
- *"ANCHOR is governance and readiness infrastructure; this update is an operational incident notice, not a compliance statement."*
- *"We are reviewing the scope of the issue with counsel before any further external communication."*

### 6.4 Wording to avoid

- ❌ *"No risk."*
- ❌ *"Fully compliant."*
- ❌ *"Guaranteed no exposure."*
- ❌ *"Regulator approved."*
- ❌ *"Clinically safe."*
- ❌ *"No issue."* — before evidence supports it.
- ❌ Any version of *"This proves ANCHOR is …"* in an incident comm. ANCHOR is aligned, not compliant; that doctrine line holds under stress.

### 6.5 Content rules

- **No secrets, no raw clinical content, no raw client content, no `DATABASE_URL`, no admin tokens, no unredacted personal data** in any communication, internal or external. If the only way to make a point is to quote a value, you are doing it wrong; quote the metadata (status code, request_id, hashed identifier) instead.
- **If user, client, regulator, or insurer notification may be needed, pause for legal/commercial review.** This runbook does not authorise notification by itself.

---

## 7. Evidence capture rules

### 7.1 Capture (with secrets redacted)

| Item | Notes |
|---|---|
| UTC timestamps | Always UTC, ISO-8601 where possible (e.g. `2026-06-07T14:39:55Z`). |
| Service name | E.g. `anchor-api-prod`, `anchor-postgres-prod`. |
| Environment | `prod` / `staging` / drill (`anchor-restore-drill-svc-…`). |
| Deploy SHA | Read from `/v1/version` or Render Dashboard. |
| Endpoint / path affected | `/v1/portal/dashboard`, `/v1/admin/intake/prune`, etc. |
| Status codes | 401 / 403 / 409 / 422 / 5xx. |
| Error message class | `error_type` from logs, truncated to the first 240 chars per existing log convention. |
| Request ID | `X-Request-ID` header from a response, or `request_id` field from log JSON. |
| Hashed IP / User-Agent | Already hashed at the edge per `app/anchor_logging.py::hash_with_salt`. Use the hash, never the raw. |
| Render deploy ID | If available — operational identifier, not a credential. |
| Migration filename / checksum mismatch | The filename and the stored-vs-expected SHA-256 from the `migration.checksum.mismatch` log event. SHA-256 hex is metadata. |
| Admin audit event type | `admin.intake.prune.rejected_cap`, `admin.auth`, etc. — log keys only. |
| Screenshot with secrets redacted | Render dashboard chrome only; black out env values, tokens, connection strings, full URLs that contain credentials. |
| Commands run | Operator's PowerShell history excerpt, with secret placeholders substituted (see §11 secret-safe column). |
| Actions taken and operator | Always name the operator and the time. |

### 7.2 Never capture

| Item | Reason |
|---|---|
| Admin tokens (any form) | Credential. Disable / rotate; record token ID only if DB-backed. |
| JWT secrets, hash salts, admin pepper, rate-limit secret, invite-token salt | Credentials. Rotate; never paste. |
| `DATABASE_URL` (full or fragment with credentials) | Credential. Reference by service name only. |
| Provider API keys (`ANTHROPIC_API_KEY`, any other) | Credential. Revoke at provider; rotate Render env. |
| Database passwords | Credential. |
| Raw prompts, raw model outputs, raw transcripts | Doctrine violation if pasted; metadata-only. |
| Raw clinical records, patient identifiers, client identifiers | Doctrine violation; per ANCHOR doctrine these are not stored by the system. |
| Raw public-intake message content | Unless legally required to retain a verbatim copy *and* that copy is held in a separately-secured store. Default: do not copy into the incident doc. |
| Full bearer tokens, cookies | Credential. |
| Render env values | Treat all as secret-shaped unless `env.md §4` lists them as functional defaults. |

If a value cannot fit any of the §7.1 rows without violating §7.2, **it does not go in the evidence record**. Reword to record the *fact* (e.g. "admin token used was DB-backed token ID `<uuid>`") rather than the *value*.

---

## 8. Containment playbooks by incident class

Each sub-section is structured: **trigger → severity → first containment action → verification → preserve → escalate**. None of the recommended commands mutates production state unless explicitly flagged.

### 8.1 Production API outage

- **Triggers:** `/health` returns non-200; multiple endpoint requests timeout; Render dashboard shows the service down or deploy failed.
- **Severity:** SEV-1 (SEV-0 if outage is tied to data corruption or tenant-isolation regression).
- **First containment:**
  1. Check `/health`, `/v1/version`, `/db-check` from a known-good network using the §13 smoke set in `env.md`.
  2. Check Render Dashboard → Deploys for the most recent deploy status. Confirm the SHA matches §10.2 baseline expectation.
  3. If a recent deploy is the trigger, consider **rollback via Render Deploy History** to the previous known-good SHA. Auto-deploy is off (`backup_restore.md §10.2`), so the rollback is an explicit operator action.
- **Do not** edit code "live" in Render's editor; do not push a fix-forward in the middle of an outage without an operator-in-the-loop decision logged in §11.
- **Verification:** smoke set returns 200 / 200 / 200 (`/health`, `/v1/version`, `/db-check`), `/v1/portal/dashboard` without bearer returns 401.
- **Preserve:** boot logs (`startup_failed`, `startup_migrations_ok`), the failing deploy ID, any `migration.*` log event from the failing boot.
- **Escalate:** founder if SEV-1 has lasted >15 min; legal review if exposure surfaces during the outage.

### 8.2 Database connectivity / restore failure

- **Triggers:** `/db-check` returns 500; Render Postgres shows degraded / unavailable; a backup-restore drill (`backup_restore.md`) fails.
- **Severity:** SEV-1. **Never SEV-0 by accidental restore-into-prod — that path is doctrinally forbidden.**
- **First containment:**
  1. Confirm via `/db-check` and Render Postgres dashboard.
  2. **Do not restore into production.** The only acceptable restore mode is restore-to-new (`backup_restore.md §5`).
  3. If a restore is needed for forensic investigation, follow `backup_restore.md §5` to provision a clone and a drill service; do not point the prod service at the clone.
  4. Preserve the production DB connection string and config unchanged unless the incident commander explicitly approves a config change with the change captured in §11.
- **Verification:** `/db-check` returns 200; Render Postgres status returns Available.
- **Preserve:** Render Postgres dashboard screenshots (chrome only — no env values visible), `db_check` log lines, any `migration.*` events.
- **Escalate:** if the production DB is suspected unrecoverable, this is a SEV-0 by promotion; involve legal review immediately, as the implications cross tenant safety and regulatory readiness expectations.

### 8.3 Migration checksum mismatch

- **Triggers:** Boot log shows `migration.checksum.mismatch` per `app/migrate.py::_verify_existing_checksum`. The Patch 6 / 6B precedent (the `10010_force_rls_all_tenant_tables.sql` mismatch on 2026-06-07) is the canonical example.
- **Severity:** **SEV-1 in production**; SEV-2 in non-production (drill / local).
- **First containment:**
  1. **Do not edit `schema_migrations` as a first response.** Editing the table to silence the mismatch is the wrong direction; it removes the only signal Patch 6 was designed to surface.
  2. **Do not permanently disable checksum verification.** A temporary `ANCHOR_MIGRATION_VERIFY_CHECKSUMS=0` is acceptable only as a documented emergency operator escape hatch, with the override recorded in §11 and a removal commitment in §10. (`env.md §14` and `env.md §11` codify this.)
  3. Investigate git history for the named migration file (`git log --follow -- migrations/<file>` and `git show <commit>:migrations/<file>` per Patch 6 / 6B precedent).
  4. **Doctrine-aligned remediation:** restore the historically-applied migration content on the branch to the version whose stripped SHA-256 matches the stored value, **and** add a *new* forward migration carrying any desired changes. Do not retroactively edit the existing migration in place. See Patch 6B as canonical precedent.
- **Verification:** Next boot logs show no `migration.checksum.mismatch`; the run summary's `verified` / `backfilled` counts are sane.
- **Preserve:** the `migration.checksum.mismatch` log line (filename + stored sha256 + expected sha256 — all metadata), the git history snippet, the PR that restores the file.
- **Escalate:** founder; legal review only if the affected migration touches RLS / tenant safety and the restored content reveals a doctrine-relevant drift.

### 8.4 Tenant isolation / RLS / FORCE RLS failure

- **Triggers:** `scripts/anchor-verify-force-rls.ps1` reports any RLS or FORCE column as `False` on a clinic-scoped table; a clinic user observes another clinic's data; a test in `tests/test_*_rls*.py` newly fails in CI; the `admin.intake.prune*` audit log shows cross-clinic effects.
- **Severity:** **SEV-0.**
- **First containment:**
  1. **Freeze deploys.** Render auto-deploy is off; confirm.
  2. **Consider stopping affected endpoints** if the leak vector is identified and bounded (e.g. one router can be removed from `app/main.py` via a follow-up emergency deploy gated by §10 incident-commander approval). Stopping the *whole* service is acceptable; stopping only the leaking router is preferable when possible.
  3. **Run read-only verification scripts only if safe.** `anchor-verify-force-rls.ps1` is read-only and admin-token-gated.
  4. **Do not query tenant data manually** unless the incident commander explicitly approves a read-only justification recorded in §11. Curiosity is not a justification.
  5. **Preserve the RLS / FORCE posture** by capturing the script output (table-by-table RLS / FORCE state).
- **Verification:** Patch 4A `10014` + Patch 5B `10015` + Patch 6B `10017` RLS posture confirmed back to the baseline matching `backup_restore.md §11 Drill — 2026-06-07` table.
- **Preserve:** RLS verification output, request IDs of cross-tenant requests if known, hashed IP/UA only (already hashed at the edge).
- **Escalate:** **Legal / privacy review queued immediately**, as cross-tenant exposure may trigger notification obligations. Treat the incident as SEV-0 until proven otherwise; do not de-escalate without §10 review.

### 8.5 Admin token exposure or misuse

- **Triggers:** Admin token observed in a screenshot / log / chat / commit / search result; unexpected `admin.auth` events for endpoints the operator did not invoke; `platform_admin_audit_events` shows actions the operator did not perform.
- **Severity:** SEV-1; **SEV-0 if misuse is confirmed against clinic-scoped data**.
- **First containment:**
  1. **If the token is DB-backed:** call `POST /v1/admin/tokens/{id}/disable` immediately. Record token ID (a UUID — not a credential) in §11.
  2. **If the token is env-source** (legacy `ANCHOR_ADMIN_TOKEN(S)` — see `env.md §6`): rotate the Render env secret and redeploy. The token cannot be DB-disabled because it has no `platform_admin_tokens` row.
  3. **Prefer DB-backed admin tokens** going forward — the Patch 4B prod default is `ANCHOR_ADMIN_MODE=db`. If `hybrid` is still in place per the `backup_restore.md §10.4` inventory baseline, plan the migration to DB-only mode as a §10.6 follow-up.
  4. Check `platform_admin_audit_events` for the token's recent activity. Record event types (`admin.intake.prune`, `admin.tokens.create`, etc.), times, and routes.
  5. **Do not paste the token** into evidence. Record the token ID only, and only if DB-backed. For env-source tokens, record only "env-source admin token" — no value, no name.
- **Verification:** disabled token returns 401 on next use. Subsequent `admin.auth` events on the same token-source are absent.
- **Preserve:** the disabled-token row, the audit-event timeline, any `X-Request-ID` headers from affected calls.
- **Escalate:** founder for SEV-1; legal review if misuse against clinic-scoped data is confirmed (SEV-0).

### 8.6 Public intake PII exposure / abuse

- **Triggers:** A `demo_requests` / `start_requests` / `public_site_chat_events` row surfaces in an unintended place; rate-limit `public_intake` (per `env.md §7`, default 5 req / 60 s per IP) is repeatedly tripped; honeypot rejections spike.
- **Severity:** **SEV-1 if exposure is confirmed**; SEV-2 if abuse only (no exposure).
- **First containment:**
  1. **Use the data boundary doctrine from `intake_retention.md §2`**: public intake holds public-contact PII and visitor free text, outside the clinic-governance metadata-only perimeter, but UK-GDPR territory.
  2. Confirm the rate-limit posture (`env.md §7 public_intake` defaults / Render env overrides).
  3. **Do not copy raw messages into the incident doc.** Capture counts and timestamps only. If a specific row is in scope, capture the row's `id` (UUID — not a credential, not content) and let the admin list view show the operator the content out-of-band, where it stays.
  4. **Admin list views only when required.** `GET /v1/admin/intake/requests` and `GET /v1/admin/intake/chat-events` are admin-token-gated and read-only. Do not paginate further than needed.
  5. **Retention prune is not an emergency response** — `intake_retention.md` is the procedure, and the dry-run-before-destructive rule still applies. A destructive prune mid-incident requires both founder approval *and* a fresh dry-run; do not skip steps.
  6. **For sustained abuse**, follow-up options are CAPTCHA / WAF / rate-limit-tuning — these are *patches*, not emergency improvisations, unless the abuse is severe enough to threaten service availability (then promote to SEV-1).
- **Verification:** `public_intake` 429 rate confirms rate-limit damping is engaging; no further unintended-surface appearance of the row.
- **Preserve:** rate-limit log lines (`http.request.rate_limited`), row UUIDs of in-scope rows, hashed IP / UA, `X-Request-ID` headers.
- **Escalate:** legal review if exposure is confirmed; founder for all PII incidents.

### 8.7 Live Workspace generation accidentally enabled

- **Triggers:** `/v1/version` or boot logs indicate `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` truthy; `workspace_generation.is_live_generation_enabled()` reports True in any log event; a Workspace response carries a `model_provider` / `model_name` from a live provider instead of `deterministic_fallback`; Anthropic billing surfaces unexpected usage.
- **Severity:** SEV-1; **SEV-0 if raw clinic data was processed by the live path or unsafe output exposure is suspected**.
- **First containment:**
  1. **Immediately set `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED=false` or unset** in the affected Render service env. Per `env.md §9`, the canonical "off" posture is unset; either form is acceptable as immediate containment, but the post-incident normalisation should align to unset.
  2. **Remove the provider API key** (`ANTHROPIC_API_KEY`) from the affected environment if necessary to prevent re-enablement. Per `env.md §9`, presence of the key alone does not enable live generation, but during containment the belt-and-braces is correct.
  3. **Redeploy / restart** the service. Confirm boot logs do not show the live flag truthy.
  4. **Confirm deterministic fallback** is being served by checking a Workspace request (admin-driven, not from a real clinic user) returns a `generation_source` of `deterministic_*`.
  5. **Check no raw content was persisted.** The Workspace path is metadata-only by doctrine; the database tables it touches store `*_sha256` hashes, not raw text. Confirm via spot-read of one `assistant_runs` row's columns (admin-token-gated, read-only); record the column names verified, not the values.
  6. **Preserve logs and governance metadata.** Whatever the live path produced is captured in `assistant_runs` and `assistant_run_receipts` as metadata; this is exactly the governance trail the doctrine was designed to preserve.
- **Verification:** `/v1/version` no longer reports the flag truthy; spot-check Workspace requests return deterministic source; `ANTHROPIC_API_KEY` absent in env (if removed for containment).
- **Preserve:** the env-flag change timeline, the affected boot logs, the `assistant_runs` row IDs touched by the live path (UUIDs — not content), any provider billing screenshot with key / org IDs redacted.
- **Escalate:** founder immediately; legal review if any chance the live path processed real clinic data; provider-side check (Anthropic dashboard) for usage telemetry. The accidental enablement is itself a doctrine-relevant event regardless of whether data was exposed.

### 8.8 Provider / API key exposure

- **Triggers:** Key string appears in a commit / screenshot / log / search result / chat; unexpected provider charges; provider sends a security notification.
- **Severity:** SEV-1.
- **First containment:**
  1. **Revoke the provider key at the provider dashboard** (Anthropic Console → Settings → API Keys → Revoke). Do this before rotating in Render.
  2. **Remove / rotate the Render env var** (`ANTHROPIC_API_KEY`) and redeploy.
  3. **Check whether live generation was enabled** during the exposure window (`ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` history in Render env audit if available; otherwise the live flag in boot logs at deploys within the window). If yes → see §8.7 in parallel.
  4. **Check billing / usage** at the provider dashboard for any unexpected calls during the exposure window. Capture the calls' timestamps and counts (not content) into §11.
  5. **Do not paste the key anywhere.** Record provider name and key id (Anthropic key fingerprint or last-4 if shown — not the full key) only.
- **Verification:** provider dashboard shows the key revoked; the new key is in Render env and the service has redeployed; spot-call (if live generation was supposed to be enabled, which per current doctrine it should not be) confirms the new key is in use.
- **Preserve:** provider revocation timestamp, Render env-change timestamp, billing screenshot with org/account identifiers redacted.
- **Escalate:** founder for any provider exposure; legal review if billing or scope suggests external misuse.

### 8.9 Authentication / login anomaly

- **Triggers:** Spike of 401s on `/v1/clinic/auth/login`; spike of 429s on `auth` rate-limit group; user reports inconsistent error strings; observed differential between unknown-slug and bad-password (which Patch 5A normalised to `invalid_credentials`).
- **Severity:** SEV-2; **SEV-1 if patterned (credential stuffing / enumeration)**.
- **First containment:**
  1. Check auth endpoint status via `env.md §13` smoke set against `/health` and `/v1/version`.
  2. **Check the login error string remains normalised** per Patch 5A — every 401 detail should be exactly `invalid_credentials`. A regression here would be a doctrine drift, not just a UX bug.
  3. Check `auth` rate-limit group (`env.md §7` defaults: 60s window / 10 req per IP) is engaging. Look for `http.request.rate_limited` log events with `rule: "auth"`.
  4. **Do not reveal whether a clinic slug or email exists** in any operator response to users during the incident — Patch 5A is the normalised baseline.
  5. Preserve `X-Request-ID` values from affected attempts (operator-reported and from logs).
- **Verification:** Rate-limit damps the attempt rate; no enumeration-shape responses observed.
- **Preserve:** auth log lines (timestamps, hashed IPs, status codes only — no email, no slug), rate-limit events.
- **Escalate:** SEV-1 if a sustained pattern suggests targeted attack; founder for SEV-1; legal review only if credential-stuffing crosses into confirmed unauthorised access.

### 8.10 CORS / Trusted Host misconfiguration

- **Triggers:** `/health` reachable directly but the portal frontend can't call the API; CORS preflight failures in browser dev tools; `trusted_host_enabled` / `cors_disabled` log events at boot don't match expectation; an env change to `CORS_ALLOW_ORIGINS` / `TRUSTED_HOSTS` was just made.
- **Severity:** **SEV-1 if production outage results**; SEV-2 otherwise.
- **First containment:**
  1. Confirm `/health` is directly reachable from a known-good network using the §13 smoke set.
  2. Confirm production portal origin against `env.md §4` and the deploy log's `cors_enabled` event (which lists `allow_origins`).
  3. Check `trusted_host_enabled` / `cors_disabled` / `cors_enabled` boot log events.
  4. **Do not** use wildcard CORS (`*`) in production. The startup config check explicitly refuses `*` with `CORS_ALLOW_CREDENTIALS=true` (raises `RuntimeError` per `app/main.py::_configure_edge_middlewares`).
  5. **If a recent env change caused the outage, revert it via Render env and redeploy.** Auto-deploy is off; the redeploy is an explicit operator action.
- **Verification:** Portal can call the API; preflights succeed; boot logs show `cors_enabled` with the expected origin list.
- **Preserve:** the env-change history, boot log lines, browser dev-tools network tab screenshot with secrets redacted.
- **Escalate:** founder; legal review only if the misconfiguration window allowed unintended-origin authenticated calls.

### 8.11 Public trust / receipt evidence error

- **Triggers:** A receipt / trust-pack surface displays inconsistent governance metadata to a clinic user; a published transparency surface shows a stale policy version; an external review surfaces a mismatch between the displayed governance state and the underlying data.
- **Severity:** **SEV-1 if external (client / clinic) is affected**; SEV-2 if internal-only.
- **First containment:**
  1. **Freeze affected public / external use** of the surface (e.g. don't share the URL further; if a published transparency profile is wrong, retract or correct via the existing publish/retire flow, not by editing rows).
  2. **Do not alter metadata rows manually.** The `clinic_governance_events`, `assistant_runs`, `assistant_run_receipts`, `policy_attestations`, `clinic_self_assessments`, `clinic_client_transparency_profiles` tables are governance evidence. Manual edits destroy that evidence.
  3. **Capture affected receipt IDs / policy version IDs / profile IDs only.** Not content.
  4. **Correct via code/data migration only after review.** Any data fix must come through a new migration with the doctrine-aligned review (Patch 6B precedent), not a hot-edit.
- **Verification:** Affected receipt / surface now shows correct or retracted state; governance evidence trail is intact in the underlying tables.
- **Preserve:** the receipt / profile IDs, the displayed-vs-expected discrepancy described in metadata, the affected user / clinic identifier as a hash if needed.
- **Escalate:** founder; legal review if the incorrect display reached an external party in a way that could imply liability or attestation failure.

---

## 9. Recovery checklist

Use this before closing the incident in §12.

- [ ] **Service health confirmed.** `/health` → 200 `{"status":"ok"}`.
- [ ] **Protected route returns 401 unauthenticated.** `/v1/portal/dashboard` no bearer → 401.
- [ ] **`/db-check` returns 200** if DB was involved.
- [ ] **Migration checksum verification passes** if migrations were involved. Boot logs show `migration.scan` with `checksum_column: true`, `verify_checksums: true`, `startup_migrations_ok` present, no `migration.checksum.mismatch`. `ANCHOR_MIGRATION_VERIFY_CHECKSUMS` is not stuck at `0` outside the incident window.
- [ ] **RLS / FORCE RLS posture confirmed** if tenant safety was involved (via `scripts/anchor-verify-force-rls.ps1` against the production service using a fresh DB-tier admin token).
- [ ] **Live-generation flag off** if relevant. `/v1/version` or boot logs show the flag unset / falsy.
- [ ] **Admin token rotated / disabled** if relevant. `platform_admin_tokens` shows the old token disabled; the new token is in use.
- [ ] **Provider key rotated** if relevant.
- [ ] **Evidence record complete.** §11 log has every action timestamped; §10 review filled where required by severity.
- [ ] **No secret values were stored** in incident notes, screenshots, tickets, or commits. Reviewed §7.2 list line by line.
- [ ] **Follow-up issues created** with owners and due dates. Logged in §10 *Preventive actions*.

---

## 10. Post-incident review template

Copy this block into a new sub-section after the incident. Fill placeholders only — never real secrets, never raw content.

```markdown
### Incident — <YYYY-MM-DD>-<short-slug>

| Field | Value |
|---|---|
| Incident ID                   | <YYYY-MM-DD-NNN> |
| Date / time UTC               | <YYYY-MM-DD HH:MM> |
| Severity                      | SEV-0 / SEV-1 / SEV-2 / SEV-3 |
| Operator / incident lead      | <name> |
| Summary                       | <one-sentence factual description> |
| Impact                        | <users affected, services degraded, durations; or "no observed impact"> |
| What happened                 | <factual sequence — no speculation> |
| Detection source              | <alert / log event / user report / smoke check / drill / patch> |
| Timeline (UTC)                | bulleted list of timestamps + actions |
| Root cause                    | <single sentence; "unknown" is acceptable if uncertain> |
| Contributing factors          | <process, tooling, doctrine drift, env config, etc.> |
| Containment actions           | <bulleted list — link to §11 evidence rows> |
| Recovery actions              | <bulleted list — link to §9 checklist completion> |
| Evidence captured             | <link / location of §11 evidence rows; never paste secrets> |
| Data / secrets involved?      | yes / no / unknown — <if yes, what class — no values> |
| Tenant boundary involved?     | yes / no / unknown |
| Live generation involved?     | yes / no / unknown |
| User / client notification needed? | yes / no / unknown — <decision and legal-review reference if yes> |
| Legal / privacy review needed?| yes / no / unknown — <decision and reviewer if yes> |
| Preventive actions            | bulleted list — what doctrine, code, doc, or process change prevents recurrence |
| Owner                         | <name per preventive action> |
| Due date                      | <YYYY-MM-DD per preventive action> |
| Final status                  | Closed / Open with follow-ups |
| Sign-off                      | <operator name, date>; <founder name, date> for SEV-0 / SEV-1 |
```

---

## 11. Incident evidence log template

Copy this block into the same incident sub-section. Fill rows in time order, top-to-bottom, as the incident unfolds. **Append-only**. Never edit a prior row except to add a follow-up cross-reference.

```markdown
#### Incident evidence log

| UTC time | Actor | Action / observation | Evidence reference | Secret-safe? | Follow-up |
|---|---|---|---|---|---|
| <HH:MM> | <name> | <one-line factual statement> | <log line / link / screenshot id> | yes / no | <link or §10 row> |
```

Rules:

- **Every row is timestamped and named.** Even when the operator is the only person on shift.
- **Secret-safe column is non-negotiable.** If a row says `no`, fix the row before closing the incident, by reworking the entry so the underlying credential is referenced indirectly (ID / metadata) instead of directly.
- **Append-only.** A row that turns out to be wrong stays, with a follow-up row correcting it.
- **No raw clinical, client, or PII content** in any row.
- **No tokens, no `DATABASE_URL`, no API keys, no JWT secrets** in any row.

---

## 12. Incident closure criteria

An incident may be closed only when **all** of the following are true:

- [ ] **Service restored** or risk **contained** (containment can be a permanent block, e.g. live-generation flag unset and provider key removed).
- [ ] **No active exposure** — no ongoing leak vector.
- [ ] **Evidence record complete** — §10 post-incident review filled for SEV-0 / SEV-1; §11 evidence log complete and append-only across the incident window.
- [ ] **Secrets rotated** if any were exposed or suspected exposed during the incident.
- [ ] **Customer / user communication decided.** For SEV-0 / SEV-1 with potential external impact, the decision is recorded after legal review per §6.
- [ ] **Follow-up tasks logged** with owners and due dates in §10 *Preventive actions*.
- [ ] **Post-incident review completed for SEV-0 / SEV-1.** SEV-2 / SEV-3 reviews are optional unless founder requests.
- [ ] **Founder sign-off recorded** for SEV-0 / SEV-1.
- [ ] **Stop-condition impact reassessed.** If the incident touched any of the §2 stop conditions (live generation, tenant safety, metadata-only, paid-pilot prerequisites), explicitly state whether the relevant operational gate is still considered closed. If not, the closure rolls forward to the gate being re-met.

---

## 13. Cadence and drills

### 13.1 Runbook review cadence

- **Quarterly pre-pilot** — operator re-reads this runbook, walks the §3 ladder, confirms the §4 checklist still maps to current code, updates §8 sub-sections after any patch that changes a containment surface.
- **Monthly during real-clinic-data / paid-pilot periods.**
- **After every SEV-0 / SEV-1** — the post-incident review will surface preventive actions; the runbook should incorporate any process-shape change immediately.
- **After any patch** that changes severity-relevant surfaces (auth, RLS, migrations, prune, live-generation gate, env asserts, rate-limit groups).

### 13.2 Tabletop incident drills

At least one tabletop drill must be performed **before paid pilot / real clinic data**. Suggested scenarios (one per drill cycle until covered):

1. **Migration checksum mismatch.** Re-create the Patch 6 / 6B narrative as a tabletop. Walk §8.3 end-to-end, including the §10 review. Confirm the operator can find git history and identify the "restore + forward migration" remediation pattern without prompting.
2. **Admin token exposure.** Simulate a screenshot of a deploy log containing an admin token; walk §8.5 including DB token disable, env-source rotation, and `platform_admin_audit_events` review.
3. **Accidental live-generation flag enablement.** Simulate a Render env-change tab showing `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED=true`; walk §8.7 including provider-key removal and deterministic-fallback confirmation.
4. **Public intake PII abuse.** Simulate a `public_intake` rate-limit spike with honeypot rejections; walk §8.6 including the rule that the prune endpoint is not an emergency response.
5. **Tenant isolation alarm.** Simulate `anchor-verify-force-rls.ps1` reporting one table as `FORCE=False`; walk §8.4 including the "freeze deploys, contain first, diagnose second" discipline.
6. **Production API outage.** Simulate `/health` returning 503; walk §8.1 including rollback via Render deploy history.

**No tabletop drill has been completed yet.** This runbook does not pre-credit any drill as done.

### 13.3 Drill evidence

Each tabletop drill produces a §10 post-incident review with `Severity: tabletop` and a §11 evidence log. Drill evidence is appended to this file (or split into `docs/operations/security_audits/` if the file grows past comfort). The drill's `Owner` is the operator; the drill's `Final status` is `Closed (tabletop)`.

---

## 14. Current status and first-use plan

- **Runbook created as Patch 10**, 2026-06-07.
- **No real incident has been simulated or executed** during the creation of this runbook. No production endpoint was called. No database was queried or mutated. No Render setting was changed.
- **First tabletop drill is pending.** Recommended first scenario: §13.2 #1 (migration checksum mismatch), because the Patch 6 / 6B incident already provides a real precedent the operator can walk without invention.
- **This runbook closes the incident-response documentation gate** for the 2A-D.2 operational resilience track. Live operational confidence should be increased by completing at least one tabletop drill before paid pilot / real clinic data.
- **Remaining operational gates for paid pilot / real clinic data:**
  - Env docs (✅ Patch 7).
  - Backup / restore drill (✅ Patch 8 / 8C — drill 2026-06-07 PASS).
  - Intake retention dry-run (✅ Patch 9 / 9B — dry-run 2026-06-07 PASS, all counts 0).
  - Incident-response runbook (✅ this patch).
  - **Legal / commercial pack per Addendum v1.3** (still pending).
- **First tabletop drill is also pending** and is the suggested next operational action; it is not gated on the legal pack.

---

## 15. Related docs

- [`env.md`](./env.md) — Backend environment variable reference. The §3 / §4 / §6 / §7 / §9 / §11 / §13 / §14 categories are the operator's quick lookup during triage.
- [`backup_restore.md`](./backup_restore.md) — Render Postgres restore-to-new drill runbook. §8.2 references this runbook for the only acceptable restore path.
- [`intake_retention.md`](./intake_retention.md) — Public intake retention dry-run / destructive prune runbook. §8.6 references this runbook for the public-intake data boundary.
- `security_audits/` — Append-only directory of dated audit / CVE-scan artefacts. **Planned**, not yet present.
- `../canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md` §234 — strategic source of the "operational resilience" RC gate (breach runbook).
- `../canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md` §63 — operational gate enumeration.
- `../canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md` §86 / §99 / §140 / §153 — readiness-map themes touching breach response, retention, and audit posture. None of these constitute compliance certification.
