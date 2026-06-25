# ANCHOR Privacy & Data Boundary Outline v1 — 2026-06-08

## 1. Purpose and status

- This document is an **internal founder / solicitor-preparation outline**.
- It defines the **intended** privacy and data-boundary posture **before** pilots or real clinic data.
- **It is not legal advice.**
- **It is not a final Privacy Notice.**
- **It is not a DPA.**
- **It is not Terms of Service.**
- **It is not ready to send to clinics.**
- It must be reviewed by an appropriate solicitor / legal adviser before any version of it is used externally.
- **It does not authorise paid pilots.**
- **It does not authorise real clinic data.**
- It does not make ANCHOR compliant, certified, RCVS-approved, regulator-endorsed, or commercially ready by itself.

---

## 2. Core data-boundary principle

- ANCHOR is **governance, trust, learning, intelligence, and accountability infrastructure** for safe AI use in veterinary clinics.
- ANCHOR is **not clinical decision-making AI.**
- ANCHOR is **not an EHR / PMS.**
- ANCHOR is **not an ambient scribe.**
- ANCHOR is **not a diagnostic, prescribing, triage, or treatment-recommendation system.**
- **Metadata-only governance accountability is the default posture.**
- The default target is to record **governance facts** about AI use, review, policy, learning, incidents, transparency, and trust evidence — **not clinical content**.
- **Human professional review remains mandatory** for any AI output that touches a clinical-or-near-clinical context.

Every section below sits inside this principle. Any product change that would expand the boundary requires a separate explicit decision (see §17).

---

## 3. Current product data zones

Outline — must be confirmed against implementation and solicitor review before external use.

| Zone | Current purpose | Intended data type | Content boundary | Pilot status |
|---|---|---|---|---|
| Authentication / user account | Sign-in for named clinic admins/users | Username, hashed password, role, JWT session metadata | No clinical content; no patient/client identifiers | Outline only; no paid pilot |
| Clinic / tenant membership | RLS / FORCE RLS tenant scoping | Tenant identifier, named-admin assignment | No clinical content; tenant-scoped via `current_setting('app.clinic_id')` | Outline only; no paid pilot |
| Governance events / receipts | Auditable record of governed interactions | Event metadata (who, when, mode, review state, risk class, policy version, receipt ID, hashes) | **Metadata-only**; no raw prompts, outputs, drafts, transcripts, or clinical content | Outline only; no paid pilot |
| Dashboard / operational telemetry | Operator reliability + auditability | Log lines, request IDs, rate-limit counters, structured logs | Hashed identifier-shaped fields (IPs, user-agents) at write time; no raw clinical content | Outline only; no paid pilot |
| Policies / acknowledgements / attestations | Policy library + staff attestation | Policy version metadata, attestation timestamps, named staff acknowledgement | No clinical content | Outline only; no paid pilot |
| Learn / CPD evidence | CPD-Recordable AI Literacy | Module completion metadata, timestamps, named-staff completion records | Completion metadata only; not proof of competence; not certified CPD | Outline only; no paid pilot |
| Trust Pack / Trust posture | Readiness evidence packaging | Dated evidence artefacts referencing other zones | Metadata + curated evidence references; no raw clinical content | Outline only; no paid pilot |
| Self-assessment | Internal governance readiness | RCVS self-assessment responses + dated evidence | Internal governance metadata; no raw clinical content | Outline only; no paid pilot |
| Client-facing transparency layer | Clinic's public statement about its AI use / governance | Curated transparency profile + published version metadata | Clinic-published transparency text; **no secrets, no raw prompts, no source material, no unnecessary client/patient identifiers** | Outline only; no paid pilot |
| Incident / near-miss logging | Governance incident / near-miss metadata | Category, severity, workflow context, timestamps, status, reviewer/action metadata | **No unnecessary raw clinical content; no unnecessary personal data** | Outline only; no paid pilot |
| Intake / public request flow (`demo_requests`, `start_requests`, `public_site_chat_events`) | Marketing-site intake | Public-contact PII explicitly submitted via intake forms + visitor free-text chat events | Bounded, rate-limited, admin-gated; retention runbook (`intake_retention.md`) applies; dry-run-first prune | Outline only; **public intake only — not clinic operational data** |
| Workspace source material | Governed work surface | Local/session context per implementation; standing posture is not to store unnecessary source content | **No unnecessary source content stored**; governance receipts store metadata, not source content | Outline only; no paid pilot |
| Workspace governed output | Governed work surface | Receipt + review-state metadata | Metadata-only by default | Outline only; no paid pilot |
| Live Workspace generation | Workspace live integration on Anthropic API | n/a in production | **Production-off.** Anthropic becomes a subprocessor the moment live generation is enabled in production. | **Not enabled. Hard stop.** |
| Assistant / provider integration | Governed Assistant evidence loop | Metadata receipts and governance events | Metadata-only; no raw provider content stored | Outline only; no paid pilot; live path gated |
| Exports | Operator/clinic export of evidence | Role-gated exports of governance metadata | Role-gated; no secret values; no raw clinical content | Outline only; no paid pilot |

---

## 4. What ANCHOR may collect by default

Outline — must be confirmed against implementation and legal advice before external use.

- Clinic identifier / tenant identifier.
- User identifier / role.
- Policy acknowledgement metadata.
- Governance event metadata (who initiated, when, mode, origin, review state, risk classification, policy version, receipt ID).
- Receipt identifiers.
- Timestamps (UTC).
- Review status / reviewer metadata.
- Risk / PII / governance classification metadata.
- Incident / near-miss category / severity / status metadata.
- Learn / CPD completion metadata.
- Trust Pack evidence metadata.
- Self-assessment responses (internal governance readiness).
- Operational telemetry needed for reliability / rate limits / auditability (hashed identifier-shaped fields at write time; never raw IPs/user-agents).
- **Public-intake contact data only** if explicitly submitted through the intake route (`demo_requests`, `start_requests`, `public_site_chat_events`), governed by the `intake_retention.md` runbook.

This list is an outline. Final wording must be confirmed against the codebase and solicitor-reviewed before external use.

---

## 5. What ANCHOR should not collect by default

- Unnecessary client personal data.
- Unnecessary animal patient clinical history.
- Full medical / veterinary records.
- Diagnostic images / lab reports unless explicitly authorised later under a separately approved process.
- Financial / payment-card data **inside ANCHOR itself** (any payment processor will be a separate subprocessor, not part of the ANCHOR data store).
- Special-category or highly sensitive personal data unless legally reviewed and explicitly authorised.
- Emergency triage data.
- Raw consultation transcripts / ambient audio.
- Unrestricted free-text clinical content.
- Passwords, tokens, API keys, or secrets in user-submitted material.

A clinic submitting any of the above (e.g. pasting a full record into a free-text field) is **out of policy** under the Acceptable Use Policy and triggers the data-boundary response in §15.

---

## 6. Metadata-only governance meaning

- "Metadata-only" does **not** mean "no data."
- It means ANCHOR records **governance / accountability facts** rather than **raw clinical / source content** wherever possible.

**Examples of metadata** (recorded by default):

- Who initiated a governed workflow (named user / tenant).
- Which clinic / tenant it belongs to.
- Timestamp (UTC).
- Mode / origin / review state.
- Risk classification.
- PII handling classification.
- Policy version applied.
- Receipt ID.
- Human review status (reviewed / not reviewed / reviewer identity).
- Incident category / severity / status.

**Examples of content that should not be stored by default:**

- Full consultation notes.
- Raw client communication text.
- Patient-identifying source documents.
- Raw AI prompt / output content — unless a future explicitly approved feature requires it **and** legal review is complete **and** the founder has explicitly authorised it.

The doctrine in `CLAUDE.md` line 2 of "Metadata-only by default — never store raw prompts, outputs, drafts, transcripts, or clinical content; hashes only" remains the operative engineering principle.

---

## 7. Workspace data boundary

- Workspace is a **governed work surface**, not a clinical decision-making engine.
- Source material may be entered for review **in local / session context** depending on implementation; the standing posture is **not to store unnecessary source content**.
- Governance receipts and events should store **metadata, not source content**, unless a future approved feature explicitly changes this.
- **Live Workspace generation remains production-off** until the local/staging safety gate **and** the hard-refusal harness (diagnosis / treatment / prescribing) pass on the live path.
- **Do not enable live generation for real clinic data** until separate safety, legal, operational, and founder gates pass.
- Workspace **must not** be positioned as a clinical decision-making engine in any external surface.
- The moment live generation is enabled in production, **Anthropic becomes a subprocessor**; the subprocessor list (see §14) and the DPA must be updated **before** that change ships.

---

## 8. Client-facing transparency layer boundary

- **Purpose:** support clinic transparency about its AI governance, review, and accountability.
- It should **not** expose unnecessary internal data.
- It should **not** expose secrets, raw prompts, raw source material, or unnecessary client / patient identifiers.
- It **must not imply** that ANCHOR certified the clinical correctness of any output.
- It should make **human review visible** where applicable.
- Wording on the published transparency surface is the clinic's responsibility; ANCHOR provides the publishing surface and the governance metadata, not the editorial content's clinical accuracy.

---

## 9. Incident / near-miss data boundary

- Incident logging should prioritise: **category, severity, workflow context, timestamps, status, reviewer / action metadata, governance follow-up**.
- **Avoid unnecessary raw clinical content.**
- **Avoid unnecessary personal data.**
- **High-severity incidents** follow `docs/operations/incident_response.md` (SEV-0 to SEV-3 ladder, first-15-minutes checklist, evidence capture rules with explicit never-capture list, eleven per-class containment playbooks).
- **Any privacy / security incident** must be handled under the incident-response runbook and legal advice where needed; the runbook's "never capture" list is operative.

---

## 10. Learn / CPD data boundary

- Learn / CPD evidence records **completion / acknowledgement metadata**.
- It is **not proof of competence**.
- It is **not certified CPD** unless a future approved process establishes that with the relevant body.
- It should **not** collect unrelated personal data.
- Exports remain **role-gated** as implemented.
- Wording on any clinic-facing surface must not claim CPD certification or regulator endorsement.

---

## 11. Trust Pack / self-assessment boundary

- Trust Pack and posture surfaces are **evidence / readiness surfaces**.
- They **do not create** compliance, certification, RCVS approval, or regulator endorsement.
- Self-assessment (RCVS self-assessment + evidence closure, per `docs/governance/self_assessment/`) is an **internal governance readiness artefact**.
- Responses should avoid unnecessary personal / clinical data.
- Evidence should be **factual and dated**.
- External wording referencing Trust Pack / self-assessment must use **aligned-not-compliant** language; check `docs/canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md §2` first.

---

## 12. Public intake / contact-data boundary

Public intake **exists in the codebase** — three tables (`demo_requests`, `start_requests`, `public_site_chat_events`) covered by `docs/operations/intake_retention.md`.

- Intake data is **deliberately bounded**: public-contact PII explicitly submitted via marketing-site intake forms + visitor free-text chat events. Per-field caps and `extra: "forbid"` on the request schema reject unknown fields at the wire.
- **Retention controls exist**: dry-run-first prune procedure (`POST /v1/admin/intake/prune` with `dry_run: true` by default); per-call 50 000-row hard cap (409 before any DELETE); destructive prune requires exact `confirm: "I-UNDERSTAND"` literal; every call writes an admin audit event.
- **Destructive pruning remains founder-approval-gated** per `intake_retention.md §5` pre-run checklist and `§8` destructive procedure; first dry-run executed 2026-06-07 with zero eligible counts (no destructive prune executed).
- **Public-intake data must not be treated as clinic operational data without separate approval.** It is pre-clinic marketing data, outside the clinic-governance metadata-only perimeter; the clinic-data metadata-only doctrine continues to apply to every clinic-scoped surface.
- Intake is rate-limited (`public_intake` group, defaults 5 req / 60 s per IP, applied before honeypot and DB write) and admin-gated on every read / mutate path.

---

## 13. Retention and deletion boundary

References:

- `docs/operations/intake_retention.md` — public intake retention runbook.
- `docs/operations/backup_restore.md` — Render Postgres restore-to-new drill runbook.
- `docs/operations/incident_response.md` — incident-response runbook, including data-related incident classes.

State:

- **Retention must be defined by data category.** Different zones (§3) have different appropriate retention windows; one global retention promise is misleading.
- **Deletion / pruning must follow the approved runbook.** Today this is `intake_retention.md` for public intake; clinic-governance metadata retention is not yet under a comparable runbook and must not be promised externally until one exists.
- **Destructive retention is not automatic** — operator-driven, dry-run-first, founder-approval-gated for destructive runs, `I-UNDERSTAND` literal required, 50 000-row hard cap, evidence template.
- **Evidence must be captured** for retention actions (per `intake_retention.md §7` / `§9` templates).
- **Backup / restore considerations must be understood** before external deletion promises are made — the restore-to-new drill (`backup_restore.md §11`, PASS 2026-06-07) is operator-driven; cadence applies.
- **External deletion wording must be solicitor-reviewed** before any version reaches a clinic-facing surface.

---

## 14. Subprocessor / hosting boundary

Outline — final subprocessor list must be confirmed before pilots; international transfer / UK GDPR implications require legal review.

| Provider / system | Current role | Data boundary | Status |
|---|---|---|---|
| **Render** | Hosting / backend infrastructure (`anchor-api-prod`) | Hosts the ANCHOR backend and its Postgres database; image is digest-pinned; runtime dependencies hash-pinned | Active subprocessor for the platform. Region selection / international-transfer position requires legal review before pilots. |
| **Render Postgres** | Application database | Stores everything in §3 zones; tenant isolation enforced by RLS / FORCE RLS; backups managed by Render | Active subprocessor. Backup/restore drill complete (`backup_restore.md §11`, PASS 2026-06-07). |
| **GitHub** | Source control + CI/CD | Stores source code, workflows, CI artefacts (logs, audit run output) | **Not a clinic-data store.** No clinic data is committed to or processed through GitHub. |
| **Anthropic** | Only relevant **if and when** live Workspace generation / provider integration is enabled in production | Today: **not active.** Live Workspace generation is production-off. No clinic data is currently processed through Anthropic. | **Not active for clinic data.** If/when live generation is enabled in production, Anthropic becomes a subprocessor and the subprocessor list + DPA must be updated **before** that change ships. |
| Transactional email provider | Not implemented for clinic data today | n/a | **Future / not active.** Must be added to the subprocessor list and DPA before activation. |
| Payment provider (Stripe or other) | Not implemented today | n/a | **Future / not active.** Payment-card data should never enter ANCHOR's own data store; payment-provider integration must be added to the subprocessor list and DPA before activation. |

**External wording must not claim more than this.** No active subprocessor processes clinic operational data beyond Render / Render Postgres today. Final list, region, and international-transfer position require solicitor review before pilots.

---

## 15. User and clinic responsibilities

- Clinics / users **must not upload unnecessary personal data**.
- Clinics / users **remain responsible** for source material they enter.
- **Human review remains mandatory** for any AI output that touches a clinical-or-near-clinical context.
- **ANCHOR does not replace clinical judgement.**
- **Clinic admin should control user access** within their tenant.
- **Clinic must report suspected incidents** through the agreed route (per the Incident and Support Process Statement once finalised; today, the operations runbook is the internal control).
- **Clinic must not use ANCHOR outside permitted use** (Acceptable Use Policy, per §7 of the Legal & Commercial Pack Outline).
- If a clinic submits prohibited data (see §16), the clinic is responsible; ANCHOR's metadata-only posture and the rejection-or-minimisation expectation in §5 / §6 apply.

---

## 16. Prohibited data before pilot approval

Until pilot approval **and** an executed DPA / pack are in place, the following must not be submitted to ANCHOR:

- Real clinic records.
- Client-identifiable material.
- Patient-identifiable clinical histories.
- Emergency triage content.
- Raw consultation transcripts / ambient audio.
- Highly sensitive personal data (special-category data under UK GDPR).
- Payment-card details.
- Credentials / secrets / API keys.
- Third-party copyrighted / proprietary content without permission.
- Any data the clinic is not authorised to share.

This list mirrors and reinforces the Acceptable Use prohibitions in the Legal & Commercial Pack Outline §7.

---

## 17. Future changes requiring separate approval

Each of the following is **out of scope today** and requires its own dated decision artefact, solicitor review where relevant, and explicit founder authorisation:

- Enabling **live Workspace generation in production**.
- Storing **source material**.
- Storing **AI prompt / output content** (beyond hashes).
- Connecting to an **EHR / PMS**.
- Ingesting **ambient audio / transcripts**.
- Adding **provider integrations** (beyond what's already documented as governed and production-off).
- Adding a **payment provider** (Stripe or other).
- **Onboarding real clinic data.**
- **Running paid pilots.**
- Changing **retention / deletion promises**.
- Changing the **subprocessor list**.
- Using data for **model training or analytics beyond governance metadata**.

Each change must update the subprocessor list and the DPA before shipping.

---

## 18. Draft external wording requirements

Do not write final external wording here. The future Privacy Notice / DPA / clinic-facing surfaces must satisfy:

- **Plain English.** No jargon-locked sentences.
- **No overclaiming.** Aligned-not-compliant wording; no compliance, certification, RCVS-approval, or regulator-endorsement claims.
- **Clear distinction** between governance metadata and clinical content.
- **Clear human-review statement** — ANCHOR does not replace professional judgement.
- **Clear support / incident route.**
- **Clear data-protection complaints route (public-source watch item).** Public-source hygiene only, grounded in the Data (Use and Access) Act 2025 (DUAA 2025): controllers should provide a route for data-protection complaints, acknowledge a complaint within 30 days, and investigate without undue delay. Treat as a Privacy Notice / public-contact / controller-side process item for the public-intake and contact surfaces where ANCHOR may act as controller. Public intake stays separate from clinic-governance processing.
- **Clear deletion / retention statement** — backed by the runbook, not by aspirational promises.
- **Clear subprocessor statement** — matching §14 of this outline at time of publication.
- **Solicitor review required** before any version goes to a clinic.

---

## 19. Founder approval checklist

To be ticked in writing before any clinic data boundary is committed externally:

- [ ] Data zones reviewed against implementation.
- [ ] Data categories reviewed.
- [ ] Prohibited data list approved.
- [ ] Retention / deletion position reviewed.
- [ ] Backup / restore implications reviewed.
- [ ] Incident-response route reviewed.
- [ ] Subprocessor list confirmed.
- [ ] International transfer position reviewed.
- [ ] DPA position reviewed.
- [ ] Privacy wording reviewed by solicitor.
- [ ] Live generation remains **off** unless separately approved (and, if approved, only after the local/staging safety gate and hard-refusal harness pass on the live path).
- [ ] Founder explicitly approves any pilot data boundary (dated signed note).

Any unticked box is a hard stop.

---

## 20. Hard stop conditions

- **No real clinic data** until privacy / data boundary **and** DPA are reviewed.
- **No paid pilot** until the legal / commercial pack is reviewed.
- **No live Workspace generation in production.**
- **No client / patient-identifiable data** without explicit approval.
- **No clinical decision-making positioning** in any external surface.
- **No compliance / certification / RCVS / regulator-endorsement claims.**
- **No subprocessor claims** until confirmed (§14 list is the live ceiling).
- **No deletion promises beyond tested / runbook-backed capabilities.**
- **No destructive retention outside the approved runbook** (`intake_retention.md`).

These mirror and reaffirm the operational hard stops in `docs/operations/2026-06-08_founder_status_summary.md §4` and the legal/commercial pack outline §12.

---

## 21. Non-actions in this patch

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
- ❌ **No legal document finalised.** This is an outline; the Privacy Notice, DPA, ToS, Pilot Agreement, AUP, and onboarding checklist remain `Required — not finalised`.
- ❌ **No pilot authorised.**
- ❌ No subprocessor added or activated.
- ❌ No commitment, claim, or representation made to any clinic, advisor, or regulator on the strength of this outline.
- ❌ No commit. No push. (Per scope.)

What this outline **did** do: defined ANCHOR's intended privacy and data-boundary posture before pilots; restated the metadata-only core principle and ANCHOR positioning boundaries; mapped 16 product data zones to their intended types, content boundaries, and current pilot status; enumerated what may and may not be collected by default; clarified the meaning of "metadata-only governance"; defined zone-specific boundaries (Workspace, transparency layer, incident logging, Learn/CPD, Trust Pack/self-assessment, public intake); referenced the existing retention / backup / incident runbooks; outlined the subprocessor / hosting boundary (Render active; Anthropic gated by live-generation production-off); enumerated clinic / user responsibilities, prohibited data before pilot approval, future changes requiring separate approval, and external-wording requirements; recorded the founder approval checklist and hard stop conditions.
