# ANCHOR 2A-D.1 Security Seed Follow-ups — Documentation Note

> **Status: documentation-only sanitised operations note. Not a full audit. Not a remediation patch.**
>
> Internal documentation-only artefact recording two operational/security follow-up findings surfaced during the private provider/controller mapping work, so they are tracked in the security-audits lane rather than lost in private notes. **Not** a penetration test, secret scan, dependency scan, or legal advice. Contains **no** secret values, endpoint URL values, tokens, or credentials — env var **names** only. It changes no code, configuration, or deployment, and **authorises no gated activity**.
>
> ANCHOR is **aligned, not compliant**. Live Workspace generation **remains production-off**. Paid pilots and real clinic data **remain blocked**.

---

## 1. Title

**2A-D.1 Security Seed Follow-ups — Documentation Note** — 2026-06-25

## 2. Status / purpose

- Documentation-only; sanitised operations note.
- Not a full audit; not a remediation patch.
- Records two follow-up findings (Render Postgres inbound IP posture; intake notification/acknowledgement webhook outbound PII path) plus standing operational watch items.
- Authorises no gated activity.
- Includes no secrets or env values (env var names only).
- Companion to the broader [`2026-06-22_2a_d_1_security_audit_result.md`](./2026-06-22_2a_d_1_security_audit_result.md) (which records 2A-D.1 as **PARTIAL**). This note does not change that status; it seeds two named follow-ups for future, separately-authorised hardening briefs.

## 3. Source basis

Inspected read-only: `CLAUDE.md`; `docs/operations/backup_restore.md`; `docs/operations/env.md`; `app/db.py`; `app/intake_notifications.py`; existing `docs/operations/security_audits/` notes (house style); `docs/operations/README.md` (index pattern). Render posture facts in Finding A are **operator-supplied dashboard facts**. No privileged review was used as a source. No secret values were inspected: `DATABASE_URL`, webhook URL values, tokens, and credentials were **not** read or printed.

## 4. Finding A — Render Postgres inbound IP restrictions

**Operator-supplied dashboard facts.** Render Postgres service `anchor-postgres-prod`; region Frankfurt (EU Central); high availability disabled; backup/PITR available with a recovery window past 3 days; inbound IP restrictions recorded as `0.0.0.0/0` (open everywhere).

**Repo corroboration (read-only).**
- `docs/operations/backup_restore.md` already records the open inbound posture (`Inbound IP restrictions | 0.0.0.0/0 (open)`) and already flags tightening the inbound allow-list to Render-internal / known-egress only as a **future hardening / review-later candidate** — so this finding is already seeded in-repo, not novel.
- The same runbook shows the restore-drill service connecting via Render's **Internal Database URL** form, confirming an internal/private connection string exists and was used at least for the drill.
- `app/db.py` reads `DATABASE_URL` and only normalises the scheme; it is **endpoint-agnostic** and cannot reveal internal-vs-public. The value was not read.

**Internal vs public endpoint — cannot be confirmed from the repo.** Whether the production web service connects over Render's internal endpoint or a public endpoint depends on which `DATABASE_URL` form is set in the Render dashboard. This requires **Render dashboard confirmation** and must not be inferred by reading the secret.

**Independent of which form the app uses:** an inbound allow-list of `0.0.0.0/0` means the database's public endpoint is reachable from any source IP. Connections remain authenticated (credentials in `DATABASE_URL`) and TLS-capable, so this is a **defence-in-depth / attack-surface** item, not an unauthenticated-database situation.

**Conditional severity (must remain conditional):**
- If the production app uses a **public DB endpoint + open inbound allow-list** → **priority hardening item**.
- If the production app uses an **internal/private endpoint** → **lower practical risk, but still a defence-in-depth dashboard posture item** (closing the open public inbound allow-list remains worthwhile even if unused).
- **Current status: requires Render dashboard confirmation before final severity can be set.**

## 5. Finding B — Intake notification / acknowledgement webhook outbound PII path

**Code path.** `app/intake_notifications.py`. Env var **names** only: `ANCHOR_INTAKE_NOTIFICATION_WEBHOOK_URL`, `ANCHOR_INTAKE_ACK_WEBHOOK_URL`. Values were not read.

**Inactive by default (confirmed).** When the relevant env var is unset/blank, the code logs `intake.notification.stubbed` (`reason="webhook_not_configured"`), makes **no outbound call**, and returns status `stubbed`. With both unset, the overall status is `stubbed`.

**Personal data if enabled.** If a webhook is configured, the notification payload embeds the full public-intake record (e.g. name, email, phone, message, clinic name); the acknowledgement payload additionally carries the submitter's recipient email. This is **public-intake contact PII** transmitted outbound. `docs/operations/env.md` §10 corroborates ("webhook payload includes raw record fields … point this at a trusted internal queue only").

**HTTPS-only gap.** The delivery helper posts to the configured URL without validating the scheme, so a misconfigured non-HTTPS target could transmit contact PII without transport encryption. There is also no outbound authentication or payload signing on the request.

**Operator-configured target.** The destination is whatever URL the operator places in the env var; it is not pinned to a named provider in code. Before enablement, the target should be identified, confirmed as a trusted internal queue (or a documented external endpoint), and **listed in the subprocessor / data-flow record** if external. This is **not** transactional email — it is a generic outbound webhook.

**Future hardening candidate (not performed here):** enforce an `https://`-only scheme check before any POST; optionally add a host allow-list and/or request signing; and require founder approval before either webhook env var is set in production.

## 6. Additional watch items

- **High availability disabled** on `anchor-postgres-prod` — an **operational-resilience watch item, not a blocker** in the current pre-pilot posture; revisit before any real-clinic-data readiness step.
- **Render log retention and backup/PITR retention** — **provider-managed / dashboard-confirmable**; not set in the repo. The exact backup-retention window is Render-managed and outside ANCHOR's direct control (consistent with the R2 retention note's "do not over-promise deletion within the backup window").
- **Live Workspace generation remains off** (`ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` gated off).
- **Anthropic credentials may be present, but production processing remains off** while live generation is disabled; not an active clinic-data subprocessor today.
- **Stripe / billing / connectors remain not implemented / gated.**

## 7. Recommended future hardening actions (future — not performed)

> Candidates for separate, explicitly-scoped hardening briefs. None is authorised or performed by this note.

- Confirm internal-vs-public production DB endpoint in the Render dashboard (presence/form only — do not read the secret value).
- Tighten the Postgres inbound allow-list from `0.0.0.0/0` to Render-internal / known-egress ranges if appropriate.
- Prefer the internal `DATABASE_URL` form for the app where available/appropriate.
- Add `https://`-only validation for the intake webhook URLs before any enablement.
- Consider a host allow-list and/or request signing for the webhooks.
- Require founder approval and provider/subprocessor listing before enabling any outbound webhook target.
- Revisit HA before real-clinic-data / pilot readiness.

## 8. What this note does not do

- Does not change code.
- Does not change Render settings.
- Does not enable webhooks.
- Does not inspect secrets or env values.
- Does not authorise external use, clinic access, paid pilots, real clinic data, billing/Stripe, Anthropic production processing, live generation, connectors, or runtime ingestion.
- Does not close 2A-D.1 fully.

## 9. Conclusion

The two findings are now tracked in the security-audits lane. **2A-D.1 remains PARTIAL / materially tightened** — these follow-ups should be handled only under separate explicit hardening briefs, and the standing hard stops (solicitor review pending; legal/commercial pack not final; live generation production-off; paid pilots and real clinic data blocked) remain in force.

## 10. Cross-references

- [`2026-06-22_2a_d_1_security_audit_result.md`](./2026-06-22_2a_d_1_security_audit_result.md) — 2A-D.1 security audit result (PARTIAL).
- [`../backup_restore.md`](../backup_restore.md) — Render Postgres restore drill; records the open inbound posture and the review-later hardening candidate.
- [`../env.md`](../env.md) — env var reference (§9 provider/live-generation flags; §10 intake notification webhook design).
- [`../2026-06-22_r2_retention_memory_consent_note_v1.md`](../2026-06-22_r2_retention_memory_consent_note_v1.md) — clinic-governance retention posture (backup deletion lag caveat).
