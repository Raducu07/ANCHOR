# ANCHOR Personal Data / Data-Flow Inventory v1 — 2026-06-08

## 1. Purpose and status

- This is an **internal founder / solicitor-preparation inventory**.
- It maps ANCHOR product and operational surfaces that may touch **personal data, staff data, governance metadata, public-intake data, clinic / client / patient-linked data, exports, retention, or sub-processors**.
- It is intended to **reduce solicitor Phase 1 fact-finding time**.
- **It is not legal advice.**
- **It is not a DPIA.**
- **It is not a RoPA.**
- **It is not a final Privacy Notice.**
- **It is not a final DPA schedule.**
- **It is not a final sub-processor schedule.**
- **It does not authorise clinic access, pilots, paid pilots, real clinic data, live Workspace generation, or AI-provider processing of real clinic data.**

---

## 2. Core correction this inventory makes

> **"No real clinic clinical data" does not mean "no personal data."**

- Staff / user accounts, role records, CPD / Learn completions, reviewer attribution, policy acknowledgements, admin actions, exports, public-intake contact details, IP / user-agent metadata (hashed at write time per `CLAUDE.md` doctrine), and audit trails **may be personal data** if they relate to identifiable people.
- **Metadata-only governance reduces content exposure but does not eliminate UK GDPR analysis.**
- The legal question is **surface-specific**: what is ANCHOR processing, for whose purposes, in what role, under what contract, with what retention, and with what sub-processors?

This inventory exists because the prior outlines (privacy/data-boundary, DPA, AUP) correctly recorded the metadata-only doctrine but did not always foreground that **staff-attributable governance metadata is itself personal data** under UK GDPR. The solicitor's Phase 1 review must answer "what is ANCHOR a processor of, by surface?" — not just "does real clinic data exist?"

---

## 3. High-level data-flow map

| Surface | Active status | Data enters from | Data stored? | Data transits? | Sub-processor involved? | Current legal question |
|---|---|---|---|---|---|---|
| Authentication / login / users | Active | Clinic users | Yes (hashed password; JWT session metadata) | Render | Render Postgres | DPA wording for staff identity / authentication processing |
| Clinic / tenant membership | Active | Founder / operator at provisioning | Yes (tenant identifier; named-admin) | Render | Render Postgres | DPA wording for tenant administration |
| Roles and permissions | Active | Clinic admin | Yes | Render | Render Postgres | DPA wording for access control |
| Governance events / receipts | Active | Clinic users via portal | Yes (metadata-only) | Render | Render Postgres | DPA wording for staff-attributable governance metadata |
| Dashboard / operational telemetry | Active | Operator + app instrumentation | Logs + counters; hashed identifier-shaped fields at write time | Render | Render Postgres + Render log capture | DPA wording for operational logs that may identify staff |
| Policies / acknowledgements / attestations | Active | Clinic staff | Yes (named-staff acknowledgement metadata) | Render | Render Postgres | DPA wording for staff acknowledgement records |
| Learn / CPD completions and exports | Active | Clinic staff | Yes (per-user completion metadata; CPD export records) | Render | Render Postgres | **DPA + privacy notice for staff training records** |
| Trust Pack / Trust posture | Active | Clinic governance flow | Yes (curated evidence references) | Render | Render Postgres | DPA wording for clinic-readiness evidence |
| Self-assessment | Active | Clinic admin | Yes (RCVS self-assessment answers + dated evidence) | Render | Render Postgres | DPA wording for internal-governance responses |
| Client-facing transparency layer | Active | Clinic admin (publishes) | Yes (transparency profile + public version metadata) | Render | Render Postgres | Privacy wording for clinic-published surface; clinic editorial responsibility |
| Incident / near-miss logging | Active | Clinic users | Yes (category / severity / context / status metadata; reviewer attribution) | Render | Render Postgres | DPA + privacy wording for incident reporter attribution |
| Public intake (demo / start / public-site chat) | Active | Marketing-site visitors | Yes (`demo_requests`, `start_requests`, `public_site_chat_events`) | Render | Render Postgres | **Privacy Notice for public intake contact data**; retention runbook |
| Workspace source material | Surface only; **no source content stored by default** | Clinic user (local/session context) | No by default | Render (transit only if entered) | Render | Solicitor wording for "what is and isn't stored" |
| Workspace governed output | Active (metadata-only) | Workspace generation | Yes (receipt + review-state metadata) | Render | Render Postgres | DPA wording for governed output metadata |
| Assistant / provider-mediated generation | Code path present; **no real clinic data in production** | n/a today | n/a today (metadata receipts only stored) | Anthropic API only on live path (production-off) | Anthropic (only when enabled) | Documents required before activation |
| **Live Workspace generation** | **Production-off** | n/a | n/a | n/a | n/a (until enabled) | **Hard gate**: DPA + sub-processor + Privacy Notice + Pilot Agreement + AUP + Onboarding all must update before enable |
| Exports / CSV / downloadable evidence | Active (role-gated) | Operator / clinic admin request | Yes (`cpd_exports` table; metadata exports) | Render → role-gated download | Render Postgres | DPA wording for external sharing + retention |
| Admin audit events | Active | Admin actions | Yes (`platform_admin_audit_events`) | Render | Render Postgres | DPA wording for accountability log |
| Backups / restore | Active | Render managed | Yes (Render-managed backups) | Render | Render Postgres + Render backup system | Privacy/DPA wording for backup retention beyond ANCHOR's direct control |
| Retention / prune | Active for public intake (`POST /v1/admin/intake/prune`) | Operator-driven only | n/a (deletes existing rows) | Render | Render Postgres | DPA Schedule 6 wording bounded by runbook capability |
| CI/CD and source control | Active | Founder / operator commits | No clinic data; source code + workflow artefacts | GitHub | GitHub | Sub-processor confirmation: **not a clinic-data store** |
| Render hosting / database | Active | Backend service | Yes (everything in active rows above) | Render | Render (active sub-processor) | Sub-processor schedule + transfer basis + region |
| GitHub | Active for source/CI only | n/a (no clinic data) | No clinic data | n/a (clinic data) | GitHub | Confirm whether GitHub appears in clinic-facing schedules |
| Anthropic / AI provider | **Not active for clinic data** (live generation production-off) | n/a today | n/a today | n/a today | Anthropic (gated) | Documents required before activation |
| Payment provider future | **Not active** | Future | No today | n/a today | Future sub-processor | DPA + privacy update before activation; payment-card data never enters ANCHOR's own store |
| Transactional email future | **Not active** | Future | No today | n/a today | Future sub-processor | DPA + privacy update before activation |

---

## 4. Detailed surface inventory

Where exact table or module names are uncertain, the row says **"needs confirmation"** rather than inventing. Implementation source paths are read-only references for the solicitor; this inventory is not a code audit.

| Surface | Relevant code / docs / tables | Data subjects | Personal data likely? | Content or metadata? | Stored / transit / export | Retention posture | Sub-processor | Solicitor question |
|---|---|---|---|---|---|---|---|---|
| Auth / login / users | `app/auth_and_rls.py`, `app/admin_auth.py`, `app/admin_tokens.py` | Clinic staff; founder / admin | **Yes** — usernames, hashed passwords (argon2), JWT session metadata | Metadata + secret hash | Stored (Postgres) | Aligned with active-account lifecycle | Render Postgres | DPA wording for authentication / session processing; retention of inactive accounts |
| Clinic / tenant membership | `app/portal_bootstrap.py`, `app/portal_me.py`, `clinic_slug_lookup` migration | Clinic admin; clinic | Yes — clinic identifier + named-admin | Metadata | Stored (Postgres) | Tenant lifecycle | Render Postgres | DPA wording for tenant administration |
| Roles and permissions | `app/auth_and_rls.py` (role-checks); needs confirmation re tables | Clinic users | Yes — role assignments per user | Metadata | Stored (Postgres) | Tenant lifecycle | Render Postgres | DPA wording for access control |
| Governance events / receipts | `app/governance.py`, `app/governance_config.py`, `app/assistant.py` (`assistant_runs`, `assistant_run_receipts` tables) | Clinic users; reviewers | **Yes** — initiator user, reviewer attribution, clinic ID, timestamp, risk class, decision metadata | **Metadata only** (no raw prompts / outputs / drafts / transcripts / clinical content per `CLAUDE.md`) | Stored (Postgres); exportable | Aligned with clinic record-keeping; runbook-bounded | Render Postgres | **DPA wording for staff-attributable governance metadata** — this is the central question |
| Dashboard / operational telemetry | `app/portal_dashboard.py`, `app/portal_ops*.py`, `app/anchor_logging.py`, `app/http_metrics.py`, `app/rate_limit.py` | Clinic users; operator | Yes if logs identify users; IP/user-agent **hashed at write time** per doctrine | Metadata | Render logs + Postgres | Operational log retention (Render-managed) | Render | DPA wording for operational logs that may identify staff |
| Policies / acknowledgements / attestations | `app/governance_policy.py`; tables `policy_templates`, `clinic_policy_versions`, `policy_attestations` | Clinic staff | **Yes** — named-staff attestation timestamps + policy version applied | Metadata | Stored (Postgres) | Clinic record-keeping | Render Postgres | DPA wording for staff acknowledgement records |
| Learn / CPD completions and exports | `app/learn_v1.py`, `app/learn_models.py`; tables `learning_modules`, `learning_completions`, `cpd_exports` | Clinic staff | **Yes — staff training records are personal data** | Metadata | Stored (Postgres); CPD export records | Aligned with CPD evidence retention | Render Postgres | **DPA + Privacy Notice for staff training/CPD records — central to Phase 1** |
| Trust Pack / Trust posture | `app/trust_materials.py`, `app/trust_scoring.py`, `app/trust_snapshot.py`, `app/portal_trust.py`, `app/portal_trust_state.py` | Clinic; staff (via attribution) | Yes if includes staff-attributable items | Metadata + curated evidence references | Stored (Postgres) | Clinic record-keeping | Render Postgres | DPA wording for clinic-readiness evidence; external sharing posture |
| Self-assessment | `app/self_assessment.py`; tables `self_assessment_templates`, `self_assessment_questions`, `clinic_self_assessments`, `clinic_self_assessment_answers` | Clinic admin | Yes — admin-attributable responses | Metadata | Stored (Postgres) | Clinic record-keeping | Render Postgres | DPA wording for internal-governance responses |
| Client-facing transparency layer | `app/client_transparency.py`; tables `client_transparency_templates`, `clinic_client_transparency_profiles`, `client_transparency_public_versions` | Clinic admin (publisher); clinic clients (audience) | Yes — clinic admin attribution; **clinic editorial responsibility for what's published** | Metadata + clinic-published transparency text | Stored (Postgres); public version | Clinic-controlled | Render Postgres | Privacy wording for clinic-published surface; clinic editorial responsibility for clinical-correctness implication |
| Incident / near-miss logging | `app/incident_near_miss.py`; table `ai_incident_near_miss_records` | Reporter; reviewer; (potentially) affected staff | **Yes** — category / severity / context / status metadata + reporter / reviewer attribution | Metadata only (per `incident_response.md` never-capture list — no raw clinical content / secrets / `DATABASE_URL`) | Stored (Postgres) | Clinic record-keeping | Render Postgres | DPA + privacy wording for incident reporter attribution; breach-notification timing |
| Public intake / demo / start / public-site chat | `app/public_intake.py`, `app/intake_*.py`, `app/admin_intake.py`, `app/intake_notifications.py`; tables `demo_requests`, `start_requests`, `public_site_chat_events` | Public marketing-site requesters; chat visitors | **Yes — public-contact PII (`full_name`, `work_email`, `phone`, `message`, `clinic_name`) + visitor free text** | Content + metadata | Stored (Postgres); rate-limited; admin-gated read/mutate | `intake_retention.md` runbook: dry-run-first prune, 50 000-row cap, founder-approval-gated destructive runs, `I-UNDERSTAND` literal; default 90/365/365 days | Render Postgres | **Privacy Notice + retention wording for public intake contact data** |
| Workspace source material | `app/workspace_generation.py` (front-door); **no source content stored by default** | Clinic users (local/session) | Yes if entered (depending on implementation in session context); standing posture = **not stored** | Content (if entered) | Render (transit only) | n/a today | Render | Solicitor wording for "what is and isn't stored" by default |
| Workspace governed output | `app/workspace_generation.py`, `app/portal_assistant.py`, `app/portal_assist.py` | Clinic users; reviewer | Yes — receipt + review-state metadata | Metadata only | Stored (Postgres) | Aligned with governance metadata | Render Postgres | DPA wording for governed output metadata |
| Assistant / provider-mediated generation | `app/assistant.py`, `app/assistant_anthropic_client.py`, `app/assistant_prompts.py`, `app/assistant_output_safety.py`, `app/assistant_usage_limits.py`, `app/assistant_intelligence.py`, `app/portal_intelligence.py`, `app/portal_assistant.py`, `app/portal_assist.py` | Clinic users; reviewer | Yes if real clinic / client / patient material is ever transited (today: production-off) | Metadata receipts stored; content **may transit to Anthropic only on live path** | Stored (metadata only) | Aligned with governance metadata | **Anthropic (only when live generation enabled)** | AI-provider DPA terms; sub-processor schedule update; prompt / output / logging / retention / training-data-use wording |
| **Live Workspace generation** | `app/workspace_generation.py` (gated) | n/a today | n/a today | n/a today | n/a today | Anthropic (gated) | **Documents required before activation**: DPA + sub-processor + Privacy Notice + Pilot Agreement + AUP + Onboarding + safety gate + hard-refusal harness PASS |
| Exports / CSV / downloadable evidence | `app/portal_export.py`; `cpd_exports` table | Clinic admin; staff (via attribution) | Yes — may include staff-attributable governance metadata | Metadata | Stored (Postgres) → role-gated download | Aligned with clinic record-keeping | Render Postgres | DPA wording for external sharing and retention/deletion |
| Admin audit events | `app/admin_audit.py`; `platform_admin_audit_events` table | Founder / operator / admin actions | **Yes** — admin identity + action metadata | Metadata | Stored (Postgres) | Accountability lifetime | Render Postgres | DPA wording for accountability log; retention; access |
| Backups / restore | `docs/operations/backup_restore.md` runbook; Render-managed | All data subjects in §3 active rows | Yes (whatever is in DB at backup time) | All categories above | Render-managed backups | Render-controlled retention | Render | **Privacy / DPA wording for backup retention beyond ANCHOR's direct control** |
| Retention / prune | `app/admin_intake.py:530` (`/v1/admin/intake/prune`); `docs/operations/intake_retention.md` | Public-intake requesters (only) | n/a (deletes existing rows; does not introduce new data) | n/a | n/a | Render Postgres | DPA Schedule 6 wording bounded by runbook capability |
| CI / CD and source control | `.github/workflows/*.yml` (3 active); GitHub repo | Founder / operator | No clinic data — source code + workflow artefacts only | n/a | GitHub | GitHub-controlled | **GitHub** | Confirm GitHub does not appear in clinic-facing sub-processor schedules |
| Render hosting | Render dashboard; `Dockerfile` digest-pinned; `requirements.txt` hashed | All active surfaces | Yes — all of §3 | All categories | Render-controlled | Render-controlled | **Render** | Sub-processor schedule + transfer basis + region |
| Render Postgres | Render-managed managed-Postgres add-on | All active surfaces | Yes — all of §3 | All categories | Render-controlled | Render-controlled | **Render Postgres** | Confirm Render's database DPA terms |
| Anthropic | `app/assistant_anthropic_client.py`; production-off | n/a today | n/a today | n/a today | n/a today | **Gated** | **Documents required before activation** |
| Payment provider | **Not implemented** | Future | n/a today | n/a today | n/a today | Future sub-processor | Payment-card data must never enter ANCHOR's own data store |
| Transactional email | **Not implemented for clinic data** | Future | n/a today | n/a today | n/a today | Future sub-processor | DPA + privacy update before activation |

---

## 5. Data-subject categories

- **ANCHOR founder / admin / operator** — internal; admin-audit attribution; support contacts.
- **Clinic owners / directors / managers** — typically named admin; account/contact data.
- **Clinic staff / users** — most personal data is here: account identity, role, attestations, CPD/Learn completions, reviewer attribution on governance events / receipts / incidents.
- **Public-intake requesters** — public-contact PII via marketing-site forms + chat events.
- **Veterinary clients / animal owners** — **only if a future approved boundary admits client-identifiable content**; today **prohibited**.
- **Veterinary patients** — animal records; **may indirectly identify human clients** (Mrs Smith's dog) and must be bounded carefully.
- **Support contacts** — clinic-side contacts for support; founder-side support identifiers.
- **Future billing contacts** — when payment provider is activated.

Data-subject categories must be **legally reviewed** before any external DPA / Privacy Notice wording.

---

## 6. Data categories

| Category | Examples | Current status | Notes for solicitor |
|---|---|---|---|
| Account identity | Username; user UUID | Active | Authentication processing; DPA wording needed |
| Email / contact details | Named-admin email | Active | DPA wording needed |
| Role / membership data | Role label; tenant membership | Active | Access-control processing; DPA wording needed |
| Authentication / session metadata | JWT session; hashed password (argon2) | Active | Secret-hashed; session retention TBC |
| Policy acknowledgement metadata | Policy version + attestation timestamp + named-staff | Active | Staff training/governance record |
| CPD / Learn completion metadata | Module completion records; CPD exports | Active | **Staff training records — personal data** |
| Governance event metadata | Who / when / mode / origin / review state / risk class / receipt ID | Active | Metadata-only; staff attributable |
| Receipt metadata | UUID-shaped receipt identifiers | Active | Metadata-only; staff attributable |
| Reviewer attribution | Named reviewer + review status | Active | Personal data via attribution |
| Incident / near-miss metadata | Category / severity / context / status / reporter / reviewer | Active | Personal data via attribution; never-capture list applies |
| Public-intake contact data | `full_name`, `work_email`, `phone`, `message`, `clinic_name`; visitor free text | Active | **Public PII**; retention-runbook bounded |
| IP / user-agent or hashed technical metadata | Hashed at write time per `CLAUDE.md` doctrine | Active | DPA wording for operational logs |
| Source material | Workspace source content | **Future / gated** | Standing posture: not stored |
| Governed output | Workspace generated output content | **Future / gated** | Standing posture: not stored as raw content; metadata receipt only |
| Client-identifiable data | Patient records; client contact data | **Prohibited unless approved** | Hard gate |
| Patient-linked clinical material | Diagnosis / treatment / lab / imaging | **Prohibited unless approved** | Hard gate |
| Payment data | Card / bank details | **Future / not active**; must never enter ANCHOR's own data store | Lives with future payment provider |
| Support communications | Operator-clinic email / ticket | **Future / limited** | DPA wording needed when active |
| Logs / backups / operational evidence | Render logs; Render backups; runbook evidence | Active | Retention bounded by Render; never-capture list applies to incident evidence |

---

## 7. Current "metadata-only" position

- **Metadata-only means ANCHOR aims to store governance / accountability facts rather than raw source clinical content by default.**
- **It does not mean zero personal data.** Named-staff attributable governance metadata, CPD completion records, attestations, reviewer attribution, and incident reporter attribution are all personal data under UK GDPR even though they're metadata-shaped.
- **It narrows the risk** by reducing raw content storage, by hashing identifier-shaped fields (IPs, user-agents) at write time, and by tenant-isolating via RLS / FORCE RLS.
- **It does not remove the need for privacy / DPA analysis** where metadata relates to identifiable staff / users / requesters.
- **It does not remove the sub-processor question** if content ever transits to an AI provider (Anthropic gated by live-generation production-off).

The solicitor's central question is not "does ANCHOR have clinical content?" — it is **"by surface, what is ANCHOR a processor of, for whose purposes, in what role?"**

---

## 8. Scenario matrix

| Scenario | Personal data? | Real clinic data? | AI-provider processing? | Likely documents needed | Current permission |
|---|---|---|---|---|---|
| Internal founder-only testing with synthetic data | Founder/admin personal data only | No | No | Founder dated note | ✅ Permitted |
| Solicitor review only | Solicitor + founder personal data | No | No | NDA / engagement letter | ✅ Permitted with NDA |
| External synthetic demo with no clinic access | Founder + demo viewer | No | No | AI Governance Boundary Statement; founder dated note | ✅ Permitted with founder approval |
| Clinic access with synthetic data only **but real staff accounts** | **Yes — staff accounts are personal data** | No clinical content | No | **DPA + Privacy Notice + AUP + Pilot Agreement** (staff data is in scope) | **❌ Not authorised today** |
| Learn / CPD use by real clinic staff | **Yes — staff training records are personal data** | No clinical content | No | **DPA + Privacy Notice + AUP + Pilot Agreement; staff-training wording in DPA** | **❌ Not authorised today** |
| Unpaid assisted pilot with no clinical data but real staff users | **Yes — staff accounts + governance metadata** | No clinical content | No | DPA + Privacy Notice + AUP + Pilot Agreement | **❌ Not authorised today** |
| Paid pilot with no clinical data but real staff users | **Yes** | No clinical content | No | DPA + Privacy Notice + AUP + Pilot Agreement + Terms + Order Form + Pricing/VAT | **❌ Not authorised today** |
| Public intake by real requester | **Yes — public PII** | No clinical content | No | **Privacy Notice for public intake; retention runbook**; **already in production but bounded** | ⚠ Bounded today via `intake_retention.md`; Privacy Notice still required |
| Limited real clinic / client / patient data pilot | **Yes** | **Yes — narrow + approved** | No | DPA + Privacy Notice + AUP + Pilot Agreement + special-category boundary + founder approval | **❌ Not authorised today** |
| Live Workspace generation with real clinic data | **Yes** | Yes | Yes (Anthropic) | DPA + Privacy Notice + AUP + Pilot Agreement + Onboarding + Anthropic sub-processor addendum + safety gate + hard-refusal harness | **❌ Hard stop** |
| AI-provider processing of real clinic data | **Yes** | Yes | **Yes** | Same as above | **❌ Hard stop** |
| Full commercial onboarding | **Yes** | Per agreement | Per agreement | Full pack + ToS + Order Form + Pricing/VAT/invoicing + Cancellation/exit | **❌ Not authorised today** |

Be conservative: **real staff accounts and CPD records are personal data**, even where no clinical content is involved.

---

## 9. Sub-processor and transit map

| Service / party | Current role | Data involved | Active today? | Legal question |
|---|---|---|---|---|
| **Render** | Hosting / backend infrastructure (`anchor-api-prod`) | All §3 active surfaces' data | ✅ Active | Sub-processor schedule + transfer basis + region |
| **Render Postgres** | Application database | All §3 active surfaces' data | ✅ Active | Sub-processor; confirm Render's database DPA terms |
| **GitHub** | Source control + CI/CD | Source code + CI artefacts only; **no clinic data** | Active (no clinic data) | Confirm GitHub does not appear in clinic-facing sub-processor schedules |
| **Anthropic / AI provider** | Workspace live generation / governed assistant | n/a today (production-off) | **Gated** | Documents required before activation |
| Payment provider | Future invoicing / commercial | n/a today | **Not active** | DPA + Privacy update before activation; card data never in ANCHOR data store |
| Transactional email provider | Future clinic comms | n/a today | **Not active** | DPA + Privacy update before activation |
| **Solicitor / professional adviser** (if pack sent) | Legal counsel | Tier 1 / Tier 2 pack contents (per dispatch checklist) | Pending dispatch | NDA / engagement letter; confidentiality |
| **Clinic** as controller (working assumption — subject to solicitor confirmation) | Controller of clinic-submitted personal data | Staff / user / clinic data | Pending solicitor confirmation | Confirm controller role |
| **ANCHOR** as processor / controller / both (working assumption — subject to solicitor confirmation) | Processor on clinic-submitted data; controller on its own business / account / admin data | Per role | Pending solicitor confirmation | Confirm dual-role model |

---

## 10. Retention and deletion map

References: `docs/operations/intake_retention.md`; `docs/operations/backup_restore.md`; `docs/operations/incident_response.md`.

| Data surface | Current runbook / evidence | Deletion / prune mechanism | Caveat |
|---|---|---|---|
| Public intake (`demo_requests`, `start_requests`, `public_site_chat_events`) | `intake_retention.md` — dry-run-first; 50 000-row hard cap (409 before any DELETE); founder-approval-gated destructive runs; exact `I-UNDERSTAND` literal; default 90/365/365 days; first PASS dry-run 2026-06-07 | `POST /v1/admin/intake/prune` (admin-gated; audit-logged) | **No automatic prune**; operator-driven |
| Governance metadata (events, receipts, attestations, exports) | No dedicated retention runbook today | Tenant lifecycle; no automatic delete | **Solicitor must confirm** whether a runbook is needed before external promises |
| Receipts / events (`assistant_runs`, `assistant_run_receipts`) | Same as above | Same as above | Same caveat |
| Learn / CPD records (`learning_completions`, `cpd_exports`) | Same as above | Same as above | Same caveat; **staff training records are personal data** |
| Self-assessment (`clinic_self_assessments`, `clinic_self_assessment_answers`) | Same as above | Same as above | Same caveat |
| Incident / near-miss (`ai_incident_near_miss_records`) | `incident_response.md` evidence retention; never-capture list | Tenant lifecycle | Solicitor must confirm |
| Backups | `backup_restore.md` — Render Postgres restore-to-new drill (first PASS 2026-06-07) | **Render-managed retention window**; outside ANCHOR's direct control | **Cannot promise deletion within backup window** without Render-side action |
| Exports | `portal_export.py`; `cpd_exports` table | Tenant lifecycle | Solicitor must confirm external-sharing wording |

**Do not overpromise deletion.** Solicitor must approve wording before any external retention/deletion promise.

---

## 11. Export and external disclosure map

| Output | Could include staff/accountability metadata? | Should be role-gated? | Should avoid raw clinical content? | Solicitor wording needed |
|---|:---:|:---:|:---:|---|
| **CPD exports** | **Yes** — per-staff completion records | ✅ | ✅ (no clinical content stored) | External-sharing wording for staff training records |
| **CSV governance exports** | Yes — governance event metadata | ✅ | ✅ | External-sharing wording; DPA Schedule 6 |
| **Trust Pack evidence** | Yes — clinic-readiness evidence | ✅ | ✅ | "Evidence not guarantee" framing; clinic editorial responsibility |
| **Receipts** | Yes — staff-attributable governance receipts | ✅ | ✅ | DPA wording for receipt-shared cases |
| **Self-assessment evidence** | Yes — admin-attributable responses | ✅ | ✅ | DPA wording |
| **Solicitor pack** (per dispatch checklist) | Founder + operator names; possibly redacted internal evidence | ✅ (founder dispatch approval) | ✅ | NDA / engagement letter; never-send list operative |
| **Future clinic onboarding pack** | Per signed terms | ✅ | ✅ | Solicitor draft per signed Pilot Agreement / DPA |

For each: **solicitor must confirm external-sharing wording** before any clinic-facing version ships.

---

## 12. Highest-priority solicitor questions

1. **Given ANCHOR's metadata-only design, what exactly is ANCHOR a processor of, by surface?** (Authentication; governance receipts; CPD completions; incident logs; public intake; exports — each may have a different role-and-purpose answer.)
2. **Which surfaces make ANCHOR a controller, processor, or both?** (Working assumption: clinic controller for clinic-submitted; ANCHOR processor on clinic-submitted + controller on its own business/account/admin data.)
3. **Does real clinic staff use of Learn / CPD require DPA + Privacy Notice/Addendum before any clinic pilot?**
4. **Does clinic access with real staff accounts require a DPA even if all clinical data is synthetic?**
5. **What wording is needed for staff governance / training records** in the Privacy Notice and DPA?
6. **What wording is needed for public-intake contact data** in the Privacy Notice, given the existing retention runbook?
7. **What is the correct DPA structure for governance metadata, receipts, and CPD records?**
8. **What needs to change before AI-provider processing of real clinic / client / patient content** (DPA / sub-processor schedule / Privacy Notice / Pilot Agreement / AUP / Onboarding / safety gate / hard-refusal harness)?
9. **What sub-processor wording is needed for Render / Render Postgres today?**
10. **What sub-processor wording is needed for Anthropic / provider if live generation is enabled later?**
11. **What deletion / backup limitation wording is safe** given Render-managed backup retention is outside ANCHOR's direct control?
12. **What documents are mandatory before:** synthetic demo, clinic access with real staff accounts, unpaid pilot, paid pilot, real clinic data, live generation?

---

## 13. Impact on existing legal sequence

- The **prior staged sequence remains directionally right**: Pilot Agreement + AUP + DPA + Privacy Notice + Onboarding + Founder Approval.
- The **main correction** is that **"real clinic staff access" and "Learn / CPD completion" create a personal-data question before clinical / client data**.
- Therefore **Phase 1 legal review should not treat personal data as only a later real-clinic-data gate** — staff personal data is in scope **the moment a real clinic is provisioned with real staff accounts**, even on a synthetic-content pilot.
- The **cheapest safe external route may still be synthetic demo**, but **only if it avoids real clinic staff accounts** or is legally covered for staff/account metadata (likely requires at minimum a DPA + AUP).
- **Any live AI-provider processing remains a separate hard gate** (DPA + sub-processor schedule update + Privacy Notice update + Pilot Agreement update + AUP update + Onboarding update + safety gate + hard-refusal harness).

The solicitor pack should therefore lead with: **"what changes the moment a real clinic admin signs up — even before any clinical content is uploaded?"**

---

## 14. Hard stops

- **No clinic access without founder approval record.**
- **No pilot before Pilot Agreement reviewed.**
- **No paid pilot before legal / commercial pack reviewed.**
- **No real clinic data before DPA + privacy / data-boundary reviewed.**
- **No real clinic staff accounts / CPD use without solicitor-confirmed privacy / DPA position.**
- **No live Workspace generation in production.**
- **No AI-provider processing of real clinic data** unless DPA / sub-processor / privacy / pilot / AUP / onboarding terms are updated first.
- **No client / patient-identifiable data without explicit approval.**
- **No clinical decision-making positioning.**
- **No compliance / certification / RCVS / regulator-endorsement claims.**
- **No deletion promises beyond tested / runbook-backed capabilities.**
- **No destructive retention outside the approved runbook.**
- **No external use of these documents before solicitor review.**

These mirror and reinforce the operational hard stops in `docs/operations/2026-06-08_founder_status_summary.md §4`, and the hard stops in every prior commercial outline.

---

## 15. Recommended next use

- **Add this inventory to the solicitor Tier 1 or Tier 1.5 pack** (per the Solicitor Pack Dispatch Checklist §4).
- **Send it with the Solicitor Review Bundle Index** if Phase 1 scope is accepted.
- **Use it to ask the "what are we processor of, by surface?" question** — the central Phase 1 framing.
- **Update it after solicitor feedback** and before any external clinic access.
- **Cross-reference it against the DPA Outline's data-category table (§5)** when the solicitor returns the DPA draft.
- **Cross-reference it against the Privacy & Data Boundary Outline's data-zone table (§3)** to confirm no surface was overlooked.

---

## 16. Non-actions in this patch

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
- ❌ **No solicitor review completed.**
- ❌ **No legal document finalised.**
- ❌ **No founder approval granted.**
- ❌ **No clinic access authorised.**
- ❌ **No pilot authorised.**
- ❌ **No paid pilot authorised.**
- ❌ **No real clinic data authorised.**
- ❌ **No live Workspace generation authorised.**
- ❌ No sub-processor added or activated.
- ❌ No commitment, claim, or representation made to any clinic, advisor, solicitor, or regulator on the strength of this inventory.
- ❌ No commit. No push. (Per scope.)

What this inventory **did** do: mapped 26 ANCHOR product and operational surfaces against active status, data subjects, personal-data likelihood, content vs metadata, storage/transit/export posture, retention posture, sub-processor involvement, and the legal question per surface; recorded the central correction that **"metadata-only" does not mean "no personal data"** (staff accounts, CPD records, reviewer attribution, public-intake PII are all personal data under UK GDPR); recorded data-subject categories, data categories, scenario matrix, sub-processor and transit map, retention/deletion map, export/disclosure map; enumerated 12 highest-priority solicitor questions; recorded the legal-sequence correction (personal data is in scope the moment a real clinic admin signs up — not only at real clinic data); reaffirmed standing hard stops.
