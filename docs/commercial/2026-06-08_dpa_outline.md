# ANCHOR DPA Outline v1 — 2026-06-08

## 1. Purpose and status

- This document is an **internal founder / solicitor-preparation outline** for a future ANCHOR Data Processing Agreement.
- **It is not legal advice.**
- **It is not a final DPA.**
- **It is not a contract.**
- **It is not ready to send to clinics.**
- It must be reviewed and drafted by an appropriate solicitor / legal adviser before any version of it is used externally.
- **It does not authorise paid pilots.**
- **It does not authorise real clinic data.**
- It does not make ANCHOR compliant, certified, RCVS-approved, regulator-endorsed, or commercially ready by itself.

---

## 2. Relationship to existing readiness documents

References:

- [`2026-06-08_legal_commercial_pack_outline.md`](./2026-06-08_legal_commercial_pack_outline.md) — defines the **commercial documents** required before pilot.
- [`2026-06-08_privacy_data_boundary_outline.md`](./2026-06-08_privacy_data_boundary_outline.md) — defines **intended data categories and hard boundaries**.
- [`../operations/2026-06-08_founder_status_summary.md`](../operations/2026-06-08_founder_status_summary.md) — plain-English founder status note.
- [`../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md`](../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md) — operational evidence checkpoint.

Status:

- The legal/commercial pack outline defines the **commercial documents** required before pilot.
- The privacy/data-boundary outline defines **intended data categories and hard boundaries**.
- **This DPA outline converts those boundaries into a solicitor-preparation structure.**
- **It must not be treated as the final legal position.**

---

## 3. Role model to be legally confirmed

The **controller / processor** roles below are **working assumptions for solicitor review**, not the final legal position. They must not be used externally until confirmed by solicitor.

| Relationship | Likely role to assess | Reason / context | Status |
|---|---|---|---|
| Clinic / veterinary practice | Likely **controller** for clinic / user / client / patient-related personal data submitted via ANCHOR | The clinic decides why and how data about its staff, clients, and patients is processed. | Working assumption — **solicitor confirmation required** |
| ANCHOR operating entity | Likely **processor** for clinic-submitted personal data; likely **controller** for its own business / account / admin data (named-admin contact details, billing if applicable) | ANCHOR provides governance infrastructure on behalf of the clinic; also runs its own business. Dual role is common but must be confirmed. | Working assumption — **solicitor confirmation required** |
| Render (hosting provider) | Sub-processor of ANCHOR | Render hosts `anchor-api-prod` and its Postgres; Render's own terms / DPA / region apply. | **Confirm Render DPA + region + transfer basis** |
| Render Postgres (database provider) | Sub-processor of ANCHOR | Same as Render — same legal entity / same DPA. | **Confirm with Render's terms** |
| GitHub (source control / CI) | **Not a clinic-data sub-processor.** GitHub stores source code and CI metadata only. | No clinic data is committed to or processed through GitHub. | **Confirm this remains true in the DPA wording** |
| AI provider (Anthropic) | **Not active for clinic data today** — only relevant if and when live Workspace generation is enabled in production. If activated, would be a sub-processor of ANCHOR. | Live Workspace generation remains production-off. | **Not active.** If live generation is later enabled, DPA + sub-processor list must be updated **before** that change ships. |
| Payment provider (Stripe or other) | Would be controller for payment-card data and sub-processor for invoicing metadata | Not implemented today. | **Future / not active.** Must be added to the sub-processor list and DPA before activation. |
| Transactional email provider | Would be sub-processor for transactional email metadata if implemented for clinic comms | Not implemented today for clinic data. | **Future / not active.** Must be added to the sub-processor list and DPA before activation. |

**Note for solicitor:** the working assumption "clinic is controller, ANCHOR is processor on clinic-submitted data; ANCHOR is controller on its own business/account data" reflects how ANCHOR is **intended** to operate under the metadata-only doctrine — it is not the final legal position and must not be used externally until reviewed.

---

## 4. Processing purposes

Potential processing purposes (must be reflected in the future Schedule 2):

- Account creation and authentication.
- Clinic / tenant membership management.
- Governance event and receipt metadata.
- Policy acknowledgement and attestation evidence.
- Learn / CPD completion evidence.
- Trust Pack / Trust posture evidence.
- Self-assessment responses.
- Client-facing transparency metadata.
- Incident / near-miss metadata.
- Public intake contact / request handling (`demo_requests`, `start_requests`, `public_site_chat_events`).
- Operational telemetry, rate limiting, auditability, and abuse prevention.
- Exports requested by authorised users.
- Support and incident handling.

**ANCHOR must not be positioned as processing data for diagnosis, prescribing, treatment recommendation, triage, or autonomous clinical decision-making.** Per `CLAUDE.md` doctrine: ANCHOR is governance infrastructure, not clinical decision-making AI.

---

## 5. Categories of data

| Data category | Examples | Boundary | Pilot status |
|---|---|---|---|
| Clinic / tenant identifiers | Tenant UUID, clinic slug | Metadata-only; tenant-scoped via RLS / FORCE RLS | Outline only |
| User account identifiers | Username, named-admin identifier | Hashed password; JWT session metadata; no clinical content | Outline only |
| Role / permission metadata | Role labels, permission grants | Metadata-only | Outline only |
| Policy acknowledgement metadata | Policy version ID, attestation timestamp, named-staff acknowledgement | Metadata-only; no clinical content | Outline only |
| Governance event metadata | Who, when, mode, origin, review state, risk class, policy version, receipt ID | **Metadata-only — no raw prompts, outputs, drafts, transcripts, or clinical content** | Outline only |
| Receipt IDs | UUID-shaped governance receipt identifiers | Metadata-only | Outline only |
| Timestamps | UTC timestamps on every governance event | Metadata-only | Outline only |
| Risk / PII / governance classification metadata | Risk class labels, PII-handling class labels | Metadata-only; classification, not content | Outline only |
| Learn / CPD completion metadata | Module completion records, named-staff completions | Completion metadata only; not proof of competence; not certified CPD | Outline only |
| Trust Pack / self-assessment evidence | Dated evidence artefact references, RCVS self-assessment responses | Metadata + curated references; no raw clinical content | Outline only |
| Incident / near-miss metadata | Category, severity, workflow context, timestamps, status, reviewer/action metadata | **No unnecessary raw clinical content; no unnecessary personal data** | Outline only |
| Public intake contact / request data | Public-contact PII submitted via marketing-site forms; visitor free-text chat events | Bounded, rate-limited, admin-gated; `intake_retention.md` runbook applies (dry-run-first prune, 50 000-row hard cap, founder-approval-gated destructive runs, exact `I-UNDERSTAND` confirm literal) | Outline only — public intake only, not clinic operational data |
| Workspace source material **(if ever entered)** | Source content entered into governed work surface | Standing posture: **not stored**; local/session context per implementation | Outline only; **future change requiring separate approval** to store |
| Workspace governed output **(if ever generated)** | Output of a governed Workspace run | Receipt + review-state metadata; no raw output content stored by default | Outline only; live generation **production-off** |
| Support / contact data | Named-admin contact details for support routing | Metadata-only | Outline only |
| Payment / invoicing metadata **(if later enabled)** | Clinic billing contact, invoice line metadata | **Payment-card data must never enter ANCHOR's own data store** — would live with payment provider | **Future / not active** |

Clear boundary language preserved: **metadata-only by default; no unnecessary clinical / source content; no paid pilot / real clinic data yet; live Workspace generation production-off.**

---

## 6. Data subject categories

Potential categories (must be legally reviewed before external DPA use):

- **Clinic staff / users** of ANCHOR.
- **Practice owners / managers / administrators.**
- **Public website / intake requesters** (people who submit the marketing-site contact forms or chat widget).
- **Clients / animal owners** — only if data is submitted contrary to or within an explicitly approved future boundary; today this is prohibited.
- **Veterinary patients** are not legal data subjects in the same way as humans, but patient-identifying information may identify clients or staff (e.g. "Mrs Smith's dog") and must be bounded carefully.
- **ANCHOR founder / admin / support contacts** (internal).

Data subject categories must be legally reviewed before external DPA use; the lines between "human data subject", "patient identifier that becomes a human identifier", and "non-personal animal-only data" need solicitor handling.

---

## 7. Special category / sensitive data boundary

- ANCHOR **should not receive special-category or highly sensitive personal data by default.**
- ANCHOR **should not receive emergency triage content, raw consultation transcripts/audio, full medical histories, diagnostic images, lab reports, or unrestricted clinical free text before explicit approval.**
- If users submit personal or sensitive data accidentally, the **incident-response and retention procedures may apply** (`incident_response.md`, `intake_retention.md`).
- Any future acceptance of sensitive data requires **separate legal, security, operational, and founder approval** with a dedicated dated decision artefact.

---

## 8. Processing instructions

Outline what the future DPA's binding instructions should say (solicitor-drafted required):

- Process data **only on documented clinic instructions**.
- Process **only for permitted ANCHOR governance purposes** (per §4).
- **Do not use data for clinical decision-making.**
- **Do not use data for model training** unless explicitly agreed in a future reviewed document with separate founder authorisation.
- **Do not sell data.**
- **Do not use data outside the agreed purpose.**
- **Follow retention / deletion procedures** as set out in §12.
- **Maintain appropriate technical and organisational measures** as set out in §11.
- **Assist with reasonable data-subject / controller requests** where applicable (per §14).

**All wording above is for solicitor drafting.** This outline does not draft legal clauses.

---

## 9. Subprocessors

| Subprocessor / system | Current status | Purpose | Data boundary | Review needed |
|---|---|---|---|---|
| **Render** | **Active** | Hosting infrastructure for `anchor-api-prod` | Hosts the ANCHOR backend; runtime image is digest-pinned (`python:3.11-slim@sha256:a3ab0b96…49ac0`); runtime deps hash-pinned (34-package lockfile, CI `pip-audit` PASS) | Confirm Render DPA + region + transfer basis |
| **Render Postgres** | **Active** | Application database | Stores everything in §5; tenant isolation via RLS / FORCE RLS; backup/restore drill complete (`backup_restore.md §11`, PASS 2026-06-07) | Confirm Render's database DPA terms |
| **GitHub** | Active for source control / CI **only** | Source code, workflows, CI artefacts | **Not a clinic-data store.** No clinic data is committed to or processed through GitHub. | Confirm wording explicitly excludes clinic data |
| **Anthropic** | **Not active for clinic data today** | Only relevant **if and when** live Workspace generation / provider integration is enabled in production. | Live Workspace generation **production-off**; no clinic data is currently processed through Anthropic. | **Do not claim Anthropic is processing clinic data while live Workspace generation is production-off.** Update DPA + sub-processor list **before** any live-generation activation in production. |
| **Transactional email provider** | **Future / not active** | Would handle transactional email if implemented for clinic comms | Not implemented today | Must be added to sub-processor list and DPA before activation |
| **Payment provider (Stripe or other)** | **Future / not active** | Would handle pilot/clinic payment if implemented | Payment-card data must never enter ANCHOR's own data store | Must be added to sub-processor list and DPA before activation |

State:

- **Final subprocessor list must be confirmed before pilots.**
- **Region, transfer, DPA links, and security terms** must be reviewed by solicitor.
- **Do not claim Anthropic is processing clinic data** while live Workspace generation is production-off.
- **Do not claim payment / email subprocessors are active** unless actually implemented.

---

## 10. International transfers

- Render, GitHub, future AI providers, and future payment / email providers **may involve international transfer considerations** depending on region selection and provider posture.
- **UK GDPR / GDPR transfer basis must be reviewed by solicitor.** (Standard Contractual Clauses, UK IDTA, addendums, adequacy decisions — solicitor scope.)
- **No external transfer wording should be published before legal review.**
- **Sub-processor regions and legal terms must be confirmed** as part of the §9 review.
- Where a transfer mechanism is needed, the solicitor must drive the choice; this outline must not pre-empt it.

---

## 11. Security measures summary

Reference operational evidence **without overclaiming**:

- **Hard multi-tenancy / RLS posture** — every tenant table enables RLS + FORCE RLS; request-scoped tenant context via `current_setting('app.clinic_id')`.
- **Metadata-only default** — `CLAUDE.md` doctrine; no raw prompts, outputs, drafts, transcripts, or clinical content stored.
- **Hashed dependency lockfile** — `requirements.txt` is fully hashed; `pip install` auto-enters hash-checking mode (per-wheel SHA256 verified at install on workstation + Render).
- **Dependency / CVE CI audit PASS** for the locked scanned set — `2026-06-07_post_alembic_ci_audit.md` (CI run `#5` against `de966a9`, `No known vulnerabilities found` for the 34-package set).
- **Docker base digest pin** — `python:3.11-slim@sha256:a3ab0b96…49ac0` (Patch 11B-b3-b).
- **GitHub Actions SHA pinning** — `actions/checkout` + `actions/setup-python` SHA-pinned across the remaining `.github/workflows/*.yml`.
- **Production smoke tests** — `2026-06-08_render_deploy_smoke_cd9d966.md` + `2026-06-08_version_metadata_deploy_smoke_7451357.md`.
- **`/v1/version.git_sha` runtime revision evidence** — populated in production via `RENDER_GIT_COMMIT` fallback (Patch 11B-b8-b).
- **Incident-response runbook** — `docs/operations/incident_response.md` (severity ladder, first-15-minutes checklist, evidence capture rules, never-capture list, eleven containment playbooks; first tabletop executed 2026-06-07).
- **Backup / restore runbook** — `docs/operations/backup_restore.md` (Render Postgres restore-to-new drill; first PASS drill 2026-06-07).
- **Intake-retention runbook** — `docs/operations/intake_retention.md` (dry-run-first, founder-approval-gated destructive, 50 000-row cap, `I-UNDERSTAND` literal).

State:

- These are **evidence of operational controls, not a guarantee of security or compliance.**
- The dependency / CVE CI PASS records the absence of *known* vulnerabilities for the scanned set at the time of scan; it is not a security certification.
- The **final security schedule** (Schedule 4 in §19) must be solicitor / commercial reviewed.

---

## 12. Retention and deletion

References:

- `docs/operations/intake_retention.md` — public intake retention runbook.
- `docs/operations/backup_restore.md` — Render Postgres restore-to-new drill runbook.

State:

- **Retention must be defined per data category** — different §5 zones have different appropriate windows; a single global retention promise would misrepresent the codebase.
- **Public intake retention controls exist and are dry-run-first** (`POST /v1/admin/intake/prune` with `dry_run: true` by default; per-call 50 000-row hard cap; 409 before any DELETE if cap exceeded).
- **Destructive retention requires founder approval** and the **exact confirmation phrase `I-UNDERSTAND`** (per `intake_retention.md §5` pre-run checklist and `§8` destructive procedure).
- **Backup / restore implications must be understood before deletion promises are made** — restore-to-new drill is operator-driven; cadence applies; backup retention windows are governed by Render's posture, not by clinic-facing promises.
- **Deletion evidence and exit procedures must be defined before pilots** (see §16).
- **No deletion promise should exceed tested / runbook-backed capability.**

---

## 13. Incident / breach handling

Reference: `docs/operations/incident_response.md` — severity ladder (SEV-0 to SEV-3), first-15-minutes checklist, evidence capture rules (with explicit never-capture list), eleven per-class containment playbooks, recovery checklist, post-incident review template, evidence log template, closure criteria, cadence, tabletop scenarios. First tabletop drill (migration checksum mismatch) completed 2026-06-07 (PASS).

Outline for the future DPA's incident / breach handling:

- **Incident notification route.**
- **Severity classification** (mapped to the runbook's SEV-0 → SEV-3 ladder).
- **Evidence capture rules** (what is captured; explicit never-capture list inherited from the runbook — no secrets, no raw clinical content, no full bearer tokens, no `DATABASE_URL`).
- **Privacy / security incident handling** under the appropriate runbook containment playbook.
- **Controller assistance duties**, if applicable, in line with ANCHOR's likely processor role.
- **Notification timing** to be **legally drafted** by solicitor.
- **What not to capture** — explicit list per the runbook's never-capture rules.
- **Post-incident review** per `incident_response.md` template.
- **Founder / legal escalation** path on SEV-0 / SEV-1.

**Legal breach-notification obligations must be solicitor-reviewed** before any external DPA wording is committed.

---

## 14. Data subject rights / clinic assistance

Outline:

- How ANCHOR may assist the clinic with **access, deletion, correction, restriction, portability, objection** requests where applicable.
- **Limits** because ANCHOR is metadata-first and may **not store the raw content** a data-subject request would otherwise target — assistance is bounded by what ANCHOR actually holds.
- **Identity verification and authorisation** needed through the clinic / admin route; ANCHOR will not respond to data-subject requests directly without clinic involvement.
- **Response timelines** to be solicitor-drafted (UK GDPR's one-month baseline, with permitted extensions).
- **No external promise** until the process is reviewed.

---

## 15. Audit / information rights

Outline:

- **Reasonable information requests** by the clinic / controller, with timing and scope to be solicitor-drafted.
- **Security / operational posture summary** provided on request (the Security and Operational Posture Summary in the Legal & Commercial Pack Outline §3).
- **Evidence pack boundaries** — what evidence can be shared without breaching other clinics' tenant isolation, without leaking secrets, and without overclaiming.
- **No unrestricted system access** for clinics / controllers.
- **No disclosure of secrets, tenant data, or other clinics' data.**
- **Audit process to be solicitor-drafted** — including notice periods, frequency caps, and cost.

---

## 16. Return / deletion at pilot exit

Outline:

- **Export of metadata / evidence** where available (governance event metadata, receipts, attestations, Learn/CPD completion records, Trust Pack evidence — role-gated formats).
- **Deletion / pruning process according to runbook** (`intake_retention.md` for public-intake-shaped data; equivalent runbook for clinic-governance metadata must be drafted before promises are made externally).
- **Backup-retention limitations** — Render-managed backups have their own retention window outside ANCHOR's direct control; external deletion wording must be consistent with that.
- **Written confirmation / evidence** of deletion on exit, dated.
- **No destruction outside the approved process** — the runbook's dry-run-first / founder-approval / `I-UNDERSTAND` discipline applies.
- **Solicitor drafting required** for the binding clauses; this outline does not draft them.

---

## 17. AI provider / live generation boundary

- **Live Workspace generation remains production-off.**
- **No real clinic data should be sent to an AI provider in production under current status.**
- **If live generation is enabled later, DPA + sub-processor list + privacy wording must be updated first** — this is a hard precondition.
- **AI provider terms, region, training / data-use settings, logging, retention, and incident process must be reviewed** before any change.
- **Human review remains mandatory** for any AI output touching a clinical-or-near-clinical context.
- **ANCHOR must not be positioned as clinical decision-making AI** — in any external surface, any DPA clause, any sub-processor disclosure, any sales conversation.

The moment live generation is enabled in production, Anthropic becomes an active sub-processor; the §9 sub-processor table and the binding DPA must be updated **before** that change ships.

---

## 18. Clinic obligations

The future DPA should require the clinic to:

- **Use ANCHOR only for permitted governance purposes** (per §4).
- **Not upload unnecessary personal / client / patient data.**
- **Not upload emergency triage or full clinical records.**
- **Not upload secrets / API keys / passwords.**
- **Maintain authorised user access** within their tenant (named admin manages users).
- **Perform human review** of any AI output touching a clinical-or-near-clinical context.
- **Report incidents promptly** through the agreed Incident and Support route.
- **Comply with the clinic's own legal / professional obligations** (RCVS code, UK GDPR controller duties, professional indemnity, etc.).
- **Not use ANCHOR as an EHR / PMS, ambient scribe, diagnostic / treatment tool, or substitute for professional judgement.**

---

## 19. DPA schedule placeholders

All schedules are **placeholders for solicitor drafting**. This outline does not draft schedule content.

- **Schedule 1: Subject matter and duration.**
- **Schedule 2: Nature and purpose of processing** (mapped from §4).
- **Schedule 3: Categories of personal data and data subjects** (mapped from §5 and §6).
- **Schedule 4: Technical and organisational measures** (mapped from §11; must not overclaim).
- **Schedule 5: Subprocessors** (mapped from §9; must reflect live posture at signing).
- **Schedule 6: Retention and deletion** (mapped from §12; must not exceed runbook-backed capability).
- **Schedule 7: Incident notification and support** (mapped from §13; timings solicitor-drafted).
- **Schedule 8: Exit assistance** (mapped from §16).

---

## 20. Founder DPA approval checklist

To be ticked in writing before any DPA is shared with a clinic:

- [ ] Controller / processor role confirmed by solicitor.
- [ ] Processing purposes reviewed.
- [ ] Data categories reviewed.
- [ ] Data subject categories reviewed.
- [ ] Special-category data boundary reviewed.
- [ ] Subprocessor list confirmed.
- [ ] International transfer position confirmed.
- [ ] Technical / organisational measures schedule reviewed.
- [ ] Retention / deletion schedule reviewed.
- [ ] Incident / breach notification wording reviewed.
- [ ] Data subject assistance process reviewed.
- [ ] Exit / deletion process reviewed.
- [ ] AI provider / live-generation boundary reviewed.
- [ ] Clinic obligations reviewed.
- [ ] Founder explicitly approves DPA before any pilot (dated signed note).

Any unticked box is a hard stop.

---

## 21. Hard stop conditions

- **No real clinic data** before DPA reviewed and approved.
- **No paid pilot** before the legal / commercial pack is reviewed.
- **No live Workspace generation in production.**
- **No AI provider processing of real clinic data** unless DPA / sub-processor / privacy position is updated first.
- **No client / patient-identifiable data** without explicit approval.
- **No clinical decision-making positioning** in any external surface.
- **No compliance / certification / RCVS / regulator-endorsement claims.**
- **No deletion promises beyond tested / runbook-backed capabilities.**
- **No destructive retention outside the approved runbook.**
- **No external DPA wording before solicitor review.**

These mirror and reaffirm the operational hard stops in `docs/operations/2026-06-08_founder_status_summary.md §4`, the legal/commercial pack outline §12, and the privacy/data-boundary outline §20.

---

## 22. Non-actions in this patch

- ❌ No code change.
- ❌ No test change.
- ❌ No dependency change.
- ❌ No Dockerfile change.
- ❌ No GitHub Actions workflow change.
- ❌ No migration change.
- ❌ No migrations run.
- ❌ No database query or mutation.
- ❌ No production endpoint call.
- ❌ No Render API call.
- ❌ No Render setting change.
- ❌ No deploy.
- ❌ No frontend change.
- ❌ No secret access.
- ❌ **No legal document finalised.** Every section is outline / solicitor-prep only.
- ❌ **No DPA approved.**
- ❌ **No pilot authorised.**
- ❌ **No real clinic data authorised.**
- ❌ No sub-processor added or activated.
- ❌ No commitment, claim, or representation made to any clinic, advisor, or regulator on the strength of this outline.
- ❌ No commit. No push. (Per scope.)

What this outline **did** do: defined the solicitor-preparation structure for ANCHOR's future DPA; recorded the working controller/processor role model (clinic likely controller, ANCHOR likely processor on clinic-submitted data + controller on its own business/account data — all subject to solicitor confirmation); enumerated processing purposes, data categories, data subject categories, special-category boundary; mapped processing instructions, sub-processor list (Render + Render Postgres active; GitHub not a clinic-data store; Anthropic / payment / email future-or-gated), international-transfer review requirement, security measures (with explicit "evidence not guarantee" framing), retention / deletion / incident / data-subject rights / audit / exit posture; reaffirmed the AI provider / live-generation boundary; listed clinic obligations and DPA schedule placeholders; recorded the founder DPA approval checklist and hard stops.
