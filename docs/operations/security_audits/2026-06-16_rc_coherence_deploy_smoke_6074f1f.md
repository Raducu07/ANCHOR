# ANCHOR RC Coherence Deploy Smoke — 6074f1f

> **Operational evidence artefact** for a backend runtime deploy smoke. It is **not** a migration note, **not** legal approval, **not** pilot authorisation, and **not** final RC sign-off. Documentation only — no code, dependency, deploy, DB, Render, or secret change is made by this note.

## 1. Status and purpose

This artefact records the Render **production** deploy smoke for backend commit `6074f1f`, the first RC coherence patch (Assistant receipt Trust Pack aggregate + `output_blocked` run-status filter acceptance). Its purpose is to capture, as standing evidence, that the deployed runtime is healthy, reports the expected revision, and keeps protected routes protected after the change. It authorises nothing.

## 2. Deployed commit

| Field | Value |
|---|---|
| Short SHA | `6074f1f` |
| Full SHA | `6074f1f38447e0f447f89046b12cf4542c148868` |
| Commit message | `Add assistant receipt Trust Pack aggregate` |
| Branch | `main` |
| Environment | Render production (`anchor-api-prod`) |

## 3. Patch summary

- Assistant receipt Trust Pack evidence now uses real `assistant_run_receipts` aggregate counts (total, recent-window, by review state, most-recent timestamp) instead of governance-event counts.
- The aggregate is **metadata-only / counts-only**.
- **No** raw prompt, draft, output, hash values, clinical content, client data, or patient data is exposed.
- `output_blocked` is now accepted as an assistant run-status filter (`GET /v1/assistant/runs?run_status=output_blocked`), consistent with the other run statuses.
- **No** migration or schema change.
- **No** frontend change.

## 4. Production smoke results

Read-only smoke from operator PowerShell. No authenticated path called; no write endpoint called; no secret inspected.

- **`GET /health`**
  - status: `200`
  - response: `{"status":"ok"}`

- **`GET /v1/version`**
  - status: `200`
  - response: `{"name":"ANCHOR API","env":"prod","git_sha":"6074f1f38447e0f447f89046b12cf4542c148868","build":null,"now_utc":"2026-06-16T06:32:09.496661+00:00"}`

- **`GET /v1/portal/dashboard`** (unauthenticated)
  - status: `401`
  - result: expected protected-route response (clinic-JWT enforcement intact)

## 5. Interpretation

- **Deploy smoke PASS.**
- Runtime revision verified by `/v1/version.git_sha` = `6074f1f38447e0f447f89046b12cf4542c148868`, matching the deployed commit.
- `env=prod` confirmed; `build` is null as expected (no `BUILD_ID` set — Render has no auto-injection equivalent; honest reporting).
- Protected dashboard route remains protected (unauthenticated `401`).
- No env changes, migrations, destructive actions, or live-generation activation were performed.

## 6. Standing blocks preserved

- No paid pilot authorised.
- No real clinic data authorised.
- No billing or Stripe activation.
- No live Workspace generation activation.
- No Anthropic production subprocessor activation.
- No connector / runtime ingestion activation.
- No solicitor-approved / final legal status.

ANCHOR remains **aligned, not compliant** — not RCVS-approved, not regulator-endorsed, not certified. This smoke records runtime health and revision only; it is not a security, compliance, or readiness guarantee.

## 7. Next follow-up

The next RC-coherence follow-up should be **frontend-only** (`anchor-portal`):

- Fix any `Content hash: None` rendering by showing a safe placeholder (e.g. "—" / "No output generated") for null `output_sha256` values — the backend correctly returns `null` for runs with no model output; the literal "None" is a frontend display artefact. Do not fabricate or backfill a hash.
- Clarify sealed-receipt snapshot labelling so a receipt is not mistaken for the current mutable run review state (a receipt is a frozen snapshot sealed at review time; the live run can be re-reviewed afterward).
