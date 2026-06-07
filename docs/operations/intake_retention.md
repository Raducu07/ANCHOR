# ANCHOR Public Intake Retention Runbook

> **Operator-facing runbook.** This document is the procedure for retention pruning of the **public intake** tables (`demo_requests`, `start_requests`, `public_site_chat_events`) via the admin-token-gated `POST /v1/admin/intake/prune` endpoint.
>
> Real secrets — production admin tokens, drill credentials, any other env value — must never appear in this document, in logs, in screenshots, in tickets, in PR descriptions, or in commits. Every example is a placeholder.

---

## 1. Purpose and scope

This runbook covers retention pruning of the three **public intake** tables on the ANCHOR backend:

- `demo_requests` — entries from the "Request a demo" form on the marketing site.
- `start_requests` — entries from the "Start with ANCHOR" form on the marketing site.
- `public_site_chat_events` — visitor question-and-answer events from the marketing-site chat widget.

It exists so an operator can **age public-contact PII and visitor free text** out of the system on a controlled, evidence-backed cadence — reducing the standing data-protection blast radius. It is **operational-resilience / data-minimisation evidence**, not compliance certification.

**Out of scope here:**

- Clinic-governance metadata (`clinic_governance_events`, `assistant_runs`, `assistant_run_receipts`, `admin_audit_events`, `clinic_policy_versions`, `policy_attestations`, `clinic_self_assessments`, `clinic_self_assessment_answers`, `clinic_client_transparency_profiles`, `client_transparency_public_versions`, `learning_completions`, `cpd_exports`, `ai_incident_near_miss_records`). These tables are clinic-scoped, governed by RLS / FORCE RLS, and managed under the clinic-governance metadata-only doctrine. They are **not touched** by `POST /v1/admin/intake/prune` and **not addressed** by this runbook.
- Raw clinical, patient, or client content. None of that is stored anywhere in ANCHOR by doctrine.
- Backup / restore — see [`backup_restore.md`](./backup_restore.md).
- Incident response — see (planned) `incident_response.md`.

---

## 2. Data boundary and doctrine

- **Public intake is outside the clinic-governance metadata-only perimeter.** The three tables in §1 hold public contact PII (`full_name`, `work_email`, `phone`, `message`, `clinic_name`) and visitor free text (`question_text`, `question_text_redacted`). They are pre-clinic marketing data, governed by UK-GDPR considerations. The clinic-data metadata-only doctrine continues to apply to every clinic-scoped surface — none of which is affected by this runbook.
- **Even though public intake is outside the clinic-governance perimeter, it must remain:**
  - **rate-limited** (per `env.md §7` group `public_intake`, defaults 5 req / 60 s per IP, applied before honeypot and DB write);
  - **admin-gated** (every read / mutate path is platform-admin-token-gated);
  - **retention-aware** (this runbook);
  - **evidence-captured** (every prune call writes an `admin.intake.prune*` row to `platform_admin_audit_events`; this runbook additionally captures operator-side decisions).
- **No claims** of GDPR compliance, RCVS approval, certification, regulator endorsement, or guaranteed protection are made in this runbook or in any artefact it produces. ANCHOR is aligned to RCVS principles and EU AI Act articles where it can be; it is not compliant with them.
- **No real clinic data / paid pilot** until: backup/restore drill complete (✅ first drill executed 2026-06-07 — see `backup_restore.md §11`), retention prune procedure documented and a first **dry-run** executed (✅ first production dry-run executed 2026-06-07 and passed — see §7 *Dry-run — 2026-06-07*; no destructive prune executed; destructive prune not required at this time because all eligible counts were zero), incident-response runbook in place (planned), `env.md` adopted as the deploy reference (✅), and the legal/commercial pack referenced in Addendum v1.3 complete.

---

## 3. Endpoint summary

`POST /v1/admin/intake/prune` — defined in `app/admin_intake.py`. Behavioural contract:

| Property | Value |
|---|---|
| Auth | `require_admin` — platform admin token (header `X-ANCHOR-ADMIN-TOKEN` or `Authorization: Bearer …`). Per `env.md §6`, prod default mode is `db`. |
| Audit | Every call writes one row to `platform_admin_audit_events` — `admin.intake.prune` on success, `admin.intake.prune.rejected_cap` if the 409 cap fires, `admin.intake.prune.error` on 500. |
| Default mode | **Dry-run** (`dry_run: true`). |
| Destructive mode | Requires `dry_run: false` **and** `confirm: "I-UNDERSTAND"` exactly. |
| Per-call hard cap | **50 000 rows** total across selected kinds. If the combined count exceeds the cap, the endpoint returns `409 intake_prune_rows_exceed_cap` **before** any DELETE is issued. |
| Allowed `kind` values | `demo`, `start`, `chat`, `all` — internal allowlist mapping in code; `kind` is never interpolated into SQL. |
| `older_than_days` bounds | 1 ≤ value ≤ 3650 (≈ 10 years). Pydantic-enforced. |
| Scheduler / cron | **None.** Pruning is operator-driven by design. There is no scheduled prune today. |

### Request body shape

**Dry run (default):**

```json
{
  "kind": "demo|start|chat|all",
  "older_than_days": <int 1..3650>,
  "dry_run": true
}
```

**Destructive run (requires explicit confirm literal):**

```json
{
  "kind": "demo|start|chat|all",
  "older_than_days": <int 1..3650>,
  "dry_run": false,
  "confirm": "I-UNDERSTAND"
}
```

`extra: "forbid"` on the request model means any unknown field is rejected at the wire with 422.

### Response shape

```json
{
  "status": "ok",
  "outcome": "dry_run" | "deleted",
  "kind": "demo|start|chat|all",
  "older_than_days": <int>,
  "cutoff_utc": "<ISO-8601 UTC timestamp>",
  "dry_run": <bool>,
  "counts":  { "demo": <int>, "start": <int>, "chat": <int> },   // only kinds in scope
  "deleted": { "demo": <int>, "start": <int>, "chat": <int> },   // empty on dry runs
  "cap": 50000
}
```

> **No real admin tokens, no real cookie values, and no `DATABASE_URL` fragments may appear anywhere in operator notes, evidence files, or screenshots taken during this procedure.**

---

## 4. Recommended retention defaults

These are **operational defaults** for the first dry-run, not legal advice. They reflect the typical signal-to-storage ratio for each table at this stage of the project. Founder can adjust before the first destructive run; shorter retention may be appropriate before any paid pilot / real clinic data starts flowing.

| Kind | Recommended `older_than_days` | Rationale |
|---|---|---|
| `chat` | **90** | `public_site_chat_events` is the highest-volume / lowest-signal table; visitors type whatever they like into the chat box. Shorter retention closes the raw-text exposure faster. |
| `demo` | **365** | `demo_requests` is the warm-lead funnel; useful for follow-up over a full sales cycle. |
| `start` | **365** | `start_requests` is the strong-intent funnel; same reasoning. |

**These defaults are starting points, not policy.** Document the chosen values per drill in §7 (dry-run evidence) and §9 (destructive evidence) so future operators can see the decision trail.

---

## 5. Pre-run checklist

Tick each item **before** sending the first request. Both dry-run and destructive runs use this checklist; the destructive-run additional rows are flagged.

- [ ] **Backup/restore drill has passed within the cadence in `backup_restore.md §14`.** Most recent PASS recorded in `backup_restore.md §11`.
- [ ] **Production service is healthy.** `GET /health → 200`, `GET /v1/version → 200 env=prod` (see `env.md §13`).
- [ ] **Current deployed SHA noted** for the evidence file (read from `/v1/version` `git_sha` field).
- [ ] **Admin token is available from a private source.** Token is DB-backed per Patch 4B prod default (`ANCHOR_ADMIN_MODE=db`). Never paste the token into shared channels.
- [ ] **No active incident.** If `incident_response.md` (planned) is being followed, do not run prune mid-incident.
- [ ] **No support, sales, or export dependency on the rows about to be pruned.** Check whether anyone is mid-workflow on a row that might be aged off; in particular, any in-flight sales pipeline against `demo_requests` / `start_requests`.
- [ ] **Operator has re-read §3** — request shape, response shape, 50 000-row cap, confirm literal.
- [ ] **Dry-run has been executed and reviewed** before any destructive call. (Required for destructive run.)
- [ ] **Founder approval has been obtained** for the destructive run, with the exact `kind` and `older_than_days` to be applied. Record in §9 evidence. (Required for destructive run.)

---

## 6. Dry-run procedure

Dry-run calls run `SELECT COUNT(*) … WHERE created_at < :cutoff` per selected table. **No DELETE is issued.** The endpoint rolls the transaction back and returns counts plus the resolved `cutoff_utc`.

### Setup (PowerShell — founder uses PowerShell)

```powershell
# Public production base — already in env.md.
$Base = 'https://anchor-api-prod.onrender.com'

# Admin token. Paste once from a private source. Do not log, screenshot,
# print, or paste anywhere persistent. Cleared in §11.
$Env:ANCHOR_ADMIN_TOKEN = '<admin token from secure source — never echo>'

# Reusable header hash. The endpoint accepts both the canonical
# X-ANCHOR-ADMIN-TOKEN header and Authorization: Bearer <token>; the
# X-ANCHOR-ADMIN-TOKEN form is used here.
$Headers = @{
    'X-ANCHOR-ADMIN-TOKEN' = $Env:ANCHOR_ADMIN_TOKEN
    'Content-Type'         = 'application/json'
}
```

### Recommended first dry runs (per-kind)

Run each in turn; record the response into the §7 evidence template. Per-kind dry runs are recommended **before** any `all` call — they isolate the volume each table contributes.

```powershell
# 1) Chat — recommended retention 90 days.
$body = @{ kind = 'chat';  older_than_days = 90;  dry_run = $true } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$Base/v1/admin/intake/prune" `
    -Headers $Headers -Body $body | ConvertTo-Json -Depth 4

# 2) Demo — recommended retention 365 days.
$body = @{ kind = 'demo';  older_than_days = 365; dry_run = $true } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$Base/v1/admin/intake/prune" `
    -Headers $Headers -Body $body | ConvertTo-Json -Depth 4

# 3) Start — recommended retention 365 days.
$body = @{ kind = 'start'; older_than_days = 365; dry_run = $true } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$Base/v1/admin/intake/prune" `
    -Headers $Headers -Body $body | ConvertTo-Json -Depth 4
```

### Optional `all` dry run

`kind: "all"` applies one `older_than_days` to every table. The recommended chat retention (90) is shorter than demo/start (365), so the `all` cutoff at 365 days will **under**-report eligible chat rows. The `all` form is useful as a combined sanity check, **not** as the basis for a destructive run.

```powershell
# Optional combined dry run — useful only if you want a single combined view.
$body = @{ kind = 'all'; older_than_days = 365; dry_run = $true } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$Base/v1/admin/intake/prune" `
    -Headers $Headers -Body $body | ConvertTo-Json -Depth 4
```

After every dry-run sequence, **clear the token** per §11.

---

## 7. Dry-run evidence template

Copy this block into a new sub-section the day of the dry-run. Fill placeholders only — never real tokens, never raw row content.

```markdown
### Dry-run — <YYYY-MM-DD>

| Field | Value |
|---|---|
| Dry-run date (UTC)            | <YYYY-MM-DD HH:MM> |
| Operator                      | <name> |
| Endpoint base                 | https://anchor-api-prod.onrender.com |
| Deployed git SHA at call time | <40-char-sha> |
| Backup/restore drill ref      | backup_restore.md §11 Drill — <YYYY-MM-DD> |

| Call | kind  | older_than_days | dry_run | response status | cutoff_utc            | counts                                   | decision         | notes |
|------|-------|-----------------|---------|-----------------|------------------------|-------------------------------------------|------------------|-------|
| 1    | chat  | 90              | true    | 200             | <YYYY-MM-DDTHH:MMZ>    | `{"chat": <n>}`                           | proceed / hold  |       |
| 2    | demo  | 365             | true    | 200             | <YYYY-MM-DDTHH:MMZ>    | `{"demo": <n>}`                           | proceed / hold  |       |
| 3    | start | 365             | true    | 200             | <YYYY-MM-DDTHH:MMZ>    | `{"start": <n>}`                          | proceed / hold  |       |
| 4    | all   | 365             | true    | 200 / skipped   | <YYYY-MM-DDTHH:MMZ>    | `{"demo": <n>, "start": <n>, "chat": <n>}` | sanity-only     |       |

#### Combined view

- Per-kind eligible counts vs the 50 000-row cap: <summary>.
- Any per-kind count > 50 000 alone? <yes/no — if yes, destructive must be split>.

#### Decision

- ☐ **Proceed to destructive** with the same per-kind parameters: <which kinds, which older_than_days, on what date>.
- ☐ **Hold.** Reason: <e.g. founder review pending; cap concern; counts unexpectedly large/small>.
- ☐ **Adjust retention values** before next dry-run. Proposed new value(s): <…>.

#### Notes

<short free-form note — no secrets, no raw row content>
```

### Dry-run — 2026-06-07

> **First production dry-run — PASS.** No destructive prune was executed. **Confirm literal was not used.** All three eligible counts returned **0**, so no destructive call is required at this time. No secret values are recorded below.

| Field | Value |
|---|---|
| Dry-run date (UTC)            | 2026-06-07 |
| Operator                      | RGG |
| Endpoint base                 | `https://anchor-api-prod.onrender.com` |
| Endpoint                      | `POST /v1/admin/intake/prune` |
| Mode                          | `dry_run` only |
| Authentication                | Admin token used privately; **no token recorded** anywhere in this evidence |
| Header used                   | `Authorization: Bearer <admin-token>` (canonical alternative to `X-ANCHOR-ADMIN-TOKEN`) |
| Backup/restore drill ref      | `backup_restore.md §11 Drill — 2026-06-07` (PASS) |
| Destructive prune executed?   | **No** |
| Confirm literal used?         | **No** |
| Rows deleted                  | 0 |

#### Calls executed

| Call | kind  | older_than_days | dry_run | response status | `outcome` | `cutoff_utc`                       | counts             | `cap` | result |
|------|-------|-----------------|---------|-----------------|-----------|-------------------------------------|--------------------|-------|--------|
| 1    | chat  | 90              | true    | 200             | `dry_run` | `2026-03-09T14:39:55.081685+00:00`  | `{"chat": 0}`      | 50000 | ✅ PASS |
| 2    | demo  | 365             | true    | 200             | `dry_run` | `2025-06-07T14:41:33.026176+00:00`  | `{"demo": 0}`      | 50000 | ✅ PASS |
| 3    | start | 365             | true    | 200             | `dry_run` | `2025-06-07T14:41:39.747518+00:00`  | `{"start": 0}`     | 50000 | ✅ PASS |

The optional combined `kind = "all"` sanity check (§6) was **not** executed because the three per-kind counts were already zero. The §11 secret-hygiene teardown was performed at the end of the session.

#### Combined view

- Per-kind eligible counts vs the 50 000-row cap: every count = 0 / 50 000. Cap not in play.
- Any per-kind count > 50 000 alone? **No.** Cap discipline confirmed not triggered.
- Combined eligible total: **0 rows**.

#### Decision

- ☑ **Proceed: no destructive call required at this time.** Per §8, a destructive call is appropriate only when there are eligible rows to delete; with zero counts there is nothing to do. Continue with the §12 monthly dry-run cadence.
- ☐ Hold.
- ☐ Adjust retention values before next dry-run.

#### Notes

- **Header-name correction for the record.** The first three attempts returned `401` because they used the non-canonical header name `X-Admin-Token`. Per `app/admin_auth.py`, the accepted forms are `X-ANCHOR-ADMIN-TOKEN` and `Authorization: Bearer <token>`. The successful calls used the `Authorization: Bearer` form. **No prune logic ran during the 401 attempts** — `require_admin` rejected the requests before reaching the prune handler, and the per-call `admin.intake.prune*` audit events were therefore not written for those failed attempts. Future operators: paste the canonical header name from `env.md §6` and the §6 PowerShell example, not a guessed variant.
- Successful calls used a production admin token held only in the local PowerShell environment for the duration of the session. No token plaintext, no `DATABASE_URL`, no other secret value appears in this evidence sub-section. Per §11, the token was removed from `$Env:ANCHOR_ADMIN_TOKEN` after the session.
- No raw intake row content was inspected or recorded. Only counts, statuses, and `cutoff_utc` strings are captured above.
- Next dry-run due per §12 cadence (monthly pre-pilot — target ~2026-07-07).
- Doctrine preserved end-to-end: public intake remains outside the clinic-governance metadata-only perimeter; admin-token gating held; rate-limit posture unchanged; no destructive action taken; no compliance / certification / regulator-approval claim made.

---

## 8. Destructive prune procedure

> **Read §5 again.** The destructive call requires (a) a reviewed dry-run, (b) founder approval recorded against the exact `kind` + `older_than_days` to be applied, (c) the `confirm` literal exactly `"I-UNDERSTAND"`.

Rules for the destructive run:

1. **Do not run** until a dry-run on the same `kind` + `older_than_days` has been executed and reviewed.
2. **Use the same `kind` and `older_than_days`** values as the reviewed dry-run. Do not change either between dry-run review and destructive call without re-running the dry-run.
3. **Capture the returned `deleted` counts** into §9. If the returned counts differ **materially** from the reviewed dry-run without an obvious explanation (e.g. new intake submissions arrived in the gap), **stop** and investigate before issuing another destructive call.
4. **Stop if `409 intake_prune_rows_exceed_cap`.** The endpoint refuses to delete > 50 000 rows in one call. Split by `kind` or tighten `older_than_days`, then re-dry-run.
5. **Stop if `5xx`.** Capture the request_id from the response (`X-Request-ID` header), record into §9, and follow the relevant entry in §10.
6. **Do not batch multiple different retention changes** in one ambiguous call. One destructive run = one decision = one evidence row. If demo / start / chat have different `older_than_days` values, that is **three separate destructive runs**, not one `all` with mixed semantics.

### PowerShell example

```powershell
$Base = 'https://anchor-api-prod.onrender.com'
$Env:ANCHOR_ADMIN_TOKEN = '<admin token from secure source — never echo>'
$Headers = @{
    'X-ANCHOR-ADMIN-TOKEN' = $Env:ANCHOR_ADMIN_TOKEN
    'Content-Type'         = 'application/json'
}

# Example: chat older than 90 days, after reviewed dry-run + founder approval.
$body = @{
    kind            = 'chat'
    older_than_days = 90
    dry_run         = $false
    confirm         = 'I-UNDERSTAND'
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "$Base/v1/admin/intake/prune" `
    -Headers $Headers -Body $body | ConvertTo-Json -Depth 4

# Clear immediately.
Remove-Item Env:ANCHOR_ADMIN_TOKEN
```

After every destructive run, **clear the token** per §11 and record evidence in §9.

---

## 9. Destructive prune evidence template

Copy this block into a new sub-section the day of the destructive run. Fill placeholders only — never tokens, never raw row content.

```markdown
### Destructive prune — <YYYY-MM-DD>

| Field | Value |
|---|---|
| Run date (UTC)                       | <YYYY-MM-DD HH:MM> |
| Operator                             | <name> |
| Founder approval recorded?           | yes / no — <link / dated note reference> |
| Backup/restore drill reference       | backup_restore.md §11 Drill — <YYYY-MM-DD> |
| Most recent reviewed dry-run         | intake_retention.md §7 Dry-run — <YYYY-MM-DD>, Call <n> |
| Deployed git SHA at call time        | <40-char-sha> |
| kind                                 | demo / start / chat / all |
| older_than_days                      | <int> |
| Dry-run count reviewed               | <int> |
| Destructive deleted count returned   | <int> |
| Response HTTP status                 | 200 / 409 / 5xx |
| `outcome` field returned             | deleted / (none if 409 / 5xx) |
| Audit event expected in platform_admin_audit_events | admin.intake.prune / admin.intake.prune.rejected_cap / admin.intake.prune.error |
| `X-Request-ID` returned              | <req-id> |
| Final decision                       | ☐ PASS ☐ FAIL ☐ INCONCLUSIVE |
| Follow-up actions                    | <link / dated note> |

#### Notes

<short free-form note — no secrets, no raw row content>
```

---

## 10. Failure-mode playbook

### 10.1 `401` / `403` — admin auth failure

- Confirm the token is paired with the correct `X-ANCHOR-ADMIN-TOKEN` header (not an `Authorization: Bearer …` typo).
- Confirm the token has not been disabled — check via `POST /v1/admin/tokens/{id}/disable` history if a DB token, or via env-token rotation log if hybrid is still in use.
- Confirm `ANCHOR_ADMIN_MODE` in prod still permits the source of the token (Patch 4B: prod default `db`).
- **Do not** widen admin mode to "fix" the auth error. Generate a new DB token via the admin endpoint instead.

### 10.2 `422` — validation failure / missing confirm

- Re-read the §3 request shape. `extra: "forbid"` rejects any field name not in the schema.
- For destructive calls: the failure is almost always `confirm` missing or not exactly `"I-UNDERSTAND"`. Do not paste-from-rich-text editors (smart quotes break the equality check).
- For `older_than_days` out of bounds: 1 ≤ value ≤ 3650.

### 10.3 `409 intake_prune_rows_exceed_cap` — cap exceeded

- The endpoint counted > 50 000 eligible rows across the selected `kind`s and refused to delete.
- Audit event `admin.intake.prune.rejected_cap` has been written.
- Split the run: pick the largest-volume `kind` and split it by tightening `older_than_days` to bring the count under 50 000, run a new dry-run, re-confirm, then destructive.
- **Do not** raise the cap. The 50 000 ceiling is doctrine (Patch 3) to prevent a misconfigured cutoff from locking a table.

### 10.4 `5xx` — server error

- Capture the `X-Request-ID` from the response header.
- Read Render logs for `admin.intake.prune_failed` with the same request_id.
- The endpoint's exception handler logs `error_type` and `error_message[:240]` only — no secret values surface.
- If the error is transient, do not retry blindly. Re-run a dry-run first.
- If the error reproduces, treat as an incident (see planned `incident_response.md`) and stop the procedure.

### 10.5 Eligible count unexpectedly **high**

- Compare against the prior dry-run from the same kind / older_than_days. A jump usually means a sudden influx of intake (e.g. marketing campaign) or a clock skew on the previous run.
- Re-run the dry-run before any destructive call.
- If still unexpectedly high, **do not** flip to destructive. Pause, get a second opinion, document.

### 10.6 Eligible count unexpectedly **zero**

- Compare against the previous run. A zero result on a kind with prior non-zero volume usually means a recent destructive run already cleared the eligible set, or the cutoff is wrong.
- Re-read the §6 examples; confirm `older_than_days` is sane.
- Do not assume "nothing to do"; confirm by spot-checking a single recent row's `created_at` against the cutoff. (Read-only inspection only — no DELETE.)

### 10.7 Operator pasted the wrong base URL

- Symptoms: 404 (path not found on a non-ANCHOR host) or a TLS/certificate error.
- Verify `$Base` matches the prod hostname recorded in `env.md §13` and `backup_restore.md §10.2`.
- **Never** point the prune endpoint at a drill hostname — the drill DB is a clone of production and pruning it both wastes the clone and risks confusing the operator about whether prod was touched.
- After a wrong-base attempt, clear the token immediately, then re-run dry-run carefully.

### 10.8 Admin token exposed

- Treat as an S1 incident (see planned `incident_response.md`).
- Immediately disable the exposed token via `POST /v1/admin/tokens/{id}/disable`. If the token is an env-source token (legacy / bootstrap), rotate `ANCHOR_ADMIN_TOKEN(S)` in Render and redeploy.
- Audit `platform_admin_audit_events` for any actions taken under the exposed token between issue and revoke.
- Record the exposure vector in the §9 notes and in the (future) incident-response postmortem.

### 10.9 Production incident during the run

- **Stop the prune sequence immediately.**
- If a destructive call is in flight, let it complete (do not kill the HTTP connection mid-DELETE — the endpoint commits per call and partial state is harder to reason about than a completed call).
- Capture the request_id and counts returned so far.
- Hand off to the incident-response runbook (planned).
- Do not resume prune until the incident is closed and a fresh dry-run has been run.

---

## 11. Teardown / secret hygiene

After every dry-run **and** every destructive run:

```powershell
Remove-Item Env:ANCHOR_ADMIN_TOKEN -ErrorAction SilentlyContinue
Get-History | Where-Object { $_.CommandLine -match 'ANCHOR_ADMIN_TOKEN' } | ForEach-Object {
    Clear-History -Id $_.Id
}
```

Discipline:

- **Remove** the admin token from the shell environment. Verify via `Get-Item Env:ANCHOR_ADMIN_TOKEN` returning nothing.
- **Do not** store the admin token in the evidence file, in screenshots, in tickets, in PR descriptions, in support emails, in browser bookmarks, or in clipboard managers that persist.
- **Do not** retain raw intake row content. The audit event log line in `platform_admin_audit_events` already captures kind, cutoff, counts, and outcome — those are the only operator-side identifiers needed in §7 / §9.
- **Retain** in evidence: dates, operator name, cutoff timestamp, counts, status codes, `X-Request-ID`, decision (PASS / FAIL / INCONCLUSIVE), founder-approval reference for destructive runs.
- **Shred** any local note containing the token, the request body with token in plaintext, or the destructive run's response body if it accidentally captured the bearer.

If at any point the token was committed, pasted into a shared channel, or otherwise exposed: §10.8.

---

## 12. Cadence

- **Dry-run monthly** before the first paid pilot or first real clinic data. The first dry-run is the next planned action after this runbook is committed (see §13).
- **Destructive prune monthly or quarterly** after the first destructive run, depending on row volume and founder preference. Lighter volume → quarterly is fine; heavier volume → monthly.
- **Always review (dry-run at minimum) after** any of:
  - Public-site / marketing changes that alter intake volume.
  - Changes to `app/intake_notifications.py` or webhook env values.
  - Changes to `app/intake_schemas.py` field caps or `app/public_intake.py` handler logic.
  - Changes to `app/admin_intake.py` (the prune endpoint itself).
  - Changes to the `public_intake` rate-limit group defaults in `env.md §7`.
  - A backup/restore drill that surfaced a finding affecting public intake.

---

## 13. First-run plan

**Status as of 2026-06-07: complete.** The first production dry-run was executed on **2026-06-07** and **passed** — see §7 *Dry-run — 2026-06-07*. **No destructive prune was executed**, and **destructive prune is not required at this time** because all three eligible counts (`chat`, `demo`, `start`) returned **0**.

The historical first-run plan is retained below for the next operator's reference. The next planned action is now a follow-up dry-run on the §12 cadence (monthly pre-pilot), not a destructive call.

Original first-run sequence (executed on 2026-06-07):

1. `kind = "chat"`,  `older_than_days = 90`,  `dry_run = true`.  → executed, count `0`, PASS.
2. `kind = "demo"`,  `older_than_days = 365`, `dry_run = true`.  → executed, count `0`, PASS.
3. `kind = "start"`, `older_than_days = 365`, `dry_run = true`.  → executed, count `0`, PASS.

Optional follow-up (sanity check only) — `kind = "all"`, `older_than_days = 365`, `dry_run = true` — was not executed for this first run because the three per-kind counts were already zero. Future operators may include or skip the `all` call by the same logic.

**No destructive call** has been issued. Per §8, a destructive call must not be initiated from the same operator session as a dry-run, must be preceded by a fresh dry-run with the same `kind` + `older_than_days`, and requires recorded founder approval. None of those conditions is in play because there are no rows eligible to delete.

---

## 14. Related docs

- [`env.md`](./env.md) — Backend environment variable reference. See §6 (admin tokens), §7 (rate limits, `public_intake` group), §10 (public intake + notifications).
- [`backup_restore.md`](./backup_restore.md) — Restore-to-new drill runbook. The first PASS drill (`§11 Drill — 2026-06-07`) is the prerequisite for the first destructive prune.
- `incident_response.md` — **Planned**, not yet written. Will own the S1 / token-exposure / mid-run-incident flow referenced in §10.4, §10.8, §10.9.
- `../canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md` §234 — strategic source of the "operational resilience" RC gate.
- `../canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md` §63 — operational gate enumeration.
