# R2 Retention and Memory-Consent Note v1

> **Status:** Internal operational runbook / founder-solicitor preparation — not legal advice; not externally approved; does not authorise paid pilots or real clinic data.
>
> ANCHOR is **aligned, not compliant**. Metadata-only by default. Live Workspace generation **remains production-off**. This note documents current posture; it implements nothing and authorises nothing.

---

## 1. Purpose

This artefact reconciles the canonical **R2 Retention and Memory-Consent Note** readiness-discipline claim (cited as complete in Roadmap v2.6 §107, Decision Memo Addendum v1.3, and Readiness Map v1.1 §87/§141/§152) by placing an in-repo note that documents ANCHOR's **current retention and memory-consent posture for clinic-governance metadata surfaces**.

It exists because, until now, the only operational retention runbook in the repo was `intake_retention.md` (public intake only), while the clinic-governance evidence surfaces were covered only at outline level (DPA / privacy / data-flow inventory). This note **complements, but does not replace**, `intake_retention.md`, and it does not change product behaviour, create deletion logic, or finalise any external retention promise.

It records *current posture* by reading existing code/config/docs; it is **not** a new data-protection impact assessment, a final retention schedule, or a legal instrument.

## 2. Scope

This note covers the following clinic-governance metadata surfaces:

- governance receipts / governance metadata (`clinic_governance_events`, governance event metadata)
- Assistant metadata and Assistant receipts (`assistant_runs`, `assistant_run_receipts`)
- CPD / Learn completions (`learning_completions`)
- CPD exports (`cpd_exports`)
- staff attestations (`policy_attestations`)
- policy versions (`clinic_policy_versions`, `policy_templates`)
- self-assessments (`clinic_self_assessments`, `clinic_self_assessment_answers`)
- client transparency profiles (`clinic_client_transparency_profiles`, `client_transparency_public_versions`)
- incident / near-miss logs (`ai_incident_near_miss_records`)
- Trust Pack / Trust posture evidence (curated evidence references)
- admin audit events where relevant (`platform_admin_audit_events`)

**Out of scope by doctrine:** raw prompts, raw model outputs, transcripts, drafts, clinical records, identifiable case material, and client/patient records are **not stored** by ANCHOR by default (hashes/metadata only) and remain out of scope of this note **unless a future founder-approved, legal-reviewed exception exists**. Public-intake contact data (`demo_requests`, `start_requests`, `public_site_chat_events`) is out of scope here — it is governed by `intake_retention.md`.

## 3. Relationship to `intake_retention.md`

- **`docs/operations/intake_retention.md` remains the operational runbook for the public-intake tables only** (dry-run-first prune, 50,000-row cap, `I-UNDERSTAND` confirm, founder-approval-gated destructive runs, evidence templates).
- **This R2 note covers clinic-governance metadata and evidence records** — the surfaces in §2 — which are clinic-scoped, RLS / FORCE RLS-isolated, and governed by the metadata-only doctrine.
- **Do not merge public-intake deletion rules into governance evidence records without explicit review.** Public intake is pre-clinic marketing data with a deliberately short data-minimisation posture; governance evidence is accountability data whose retention rationale is different. The prune endpoint (`/v1/admin/intake/prune`) does **not** touch any §2 surface and must not be repurposed to do so.

## 4. Current retention posture

Conservative current posture. **No automatic deletion or pruning is authorised by this note**, and no deletion logic exists for these surfaces today.

| Surface | Data type / examples | Personal data possible? | Raw clinical content expected? | Current retention posture | Deletion / offboarding behaviour | Export behaviour | Approval required before deletion/change | Remaining legal/solicitor caveat |
|---|---|---|---|---|---|---|---|---|
| Governance receipts / governance metadata | who/when/mode/origin/review-state/risk-class/policy-version/receipt ID | Yes (staff-attributable) | No (metadata-only; hashes) | Retained for tenant lifecycle / governance accountability unless a future solicitor-approved schedule says otherwise | No automatic delete; tenant lifecycle | Metadata-only where implemented (CSV/receipt) | Founder approval + solicitor-reviewed policy | Controller/processor role + retention basis to be confirmed |
| Assistant metadata & receipts (`assistant_runs`, `assistant_run_receipts`) | run metadata, review state, hashes, receipt IDs | Yes (via attribution) | No (metadata-only) | Tenant lifecycle / accountability | No automatic delete | Metadata-only where implemented | Founder approval + solicitor review | Same caveat as governance metadata |
| CPD / Learn completions (`learning_completions`) | per-user module completion metadata | **Yes — staff training records** | No | Aligned with CPD evidence value; tenant lifecycle | No automatic delete | CPD export (metadata) | Founder approval + solicitor review | Staff-training-record retention basis to confirm |
| CPD exports (`cpd_exports`) | export records of completion metadata | Yes (staff-attributable) | No | Tenant lifecycle | No automatic delete | Role-gated export | Founder approval + solicitor review | External-sharing wording to confirm |
| Staff attestations (`policy_attestations`) | named-staff attestation + policy version + timestamp | Yes | No | Clinic record-keeping; tenant lifecycle | No automatic delete | Metadata-only where implemented | Founder approval + solicitor review | Retention basis to confirm |
| Policy versions (`clinic_policy_versions`, `policy_templates`) | policy version metadata / content hash | Indirect | No | Retained for version traceability | No automatic delete | Metadata-only | Founder approval + solicitor review | Content-hash coherence is an RC watch item |
| Self-assessments (`clinic_self_assessments`, `…_answers`) | admin-attributable responses + dated evidence | Yes | No | Clinic record-keeping; tenant lifecycle | No automatic delete | Metadata/evidence export where implemented | Founder approval + solicitor review | Retention basis to confirm |
| Client transparency profiles (`clinic_client_transparency_profiles`, `…_public_versions`) | clinic-published transparency text + version metadata | Yes (admin attribution) | No | Clinic-controlled (publish/retire) | Retire via existing flow; no row deletion runbook | Metadata + published version | Founder approval + solicitor review | Clinic editorial responsibility; deletion semantics to confirm |
| Incident / near-miss logs (`ai_incident_near_miss_records`) | category/severity/context/status + reporter/reviewer attribution | Yes | No (never-capture list applies) | Clinic record-keeping; tenant lifecycle | No automatic delete | Metadata-only | Founder approval + solicitor review | Breach-notification + retention timing to confirm |
| Trust Pack / Trust posture evidence | curated evidence references / counts | Yes if staff-attributable | No | Derived/aggregated from the above | Follows underlying records | Metadata-only | Founder approval + solicitor review | "Evidence, not guarantee" framing |
| Admin audit events (`platform_admin_audit_events`) | admin identity + action metadata | Yes | No | Retained for accountability lifetime | No automatic delete | Not routinely exported | Founder approval + solicitor review | Accountability-log retention basis to confirm |

Cross-cutting posture:

- **Exports are metadata-only where available;** there is **no promise of complete external portability** beyond implemented features.
- **Backup deletion lag** is governed by hosting/backup behaviour (Render-managed) and is **outside ANCHOR's direct control**; deletion within a backup window must **not** be overpromised.
- **Destructive deletion of governance evidence requires founder approval and a solicitor-reviewed policy before any external use.**

## 5. Memory-consent rules

ANCHOR's current position:

- ANCHOR **must not store raw chat memory, raw prompts, raw outputs, transcripts, clinical case narratives, or identifiable clinical/client material by default.**
- **"Governance memory" means metadata-only evidence** — actions, review states, policy versions, timestamps, completion records, and receipt IDs — not reusable content memory.
- **Any future feature** that stores reusable user preferences, clinic memory, AI context memory, or raw-content memory requires **explicit founder approval, legal review, and a separate consent/notice design** before it is built.
- **Staff-attributable learning, attestation, review, and audit records may be personal data even though they are metadata-only.**
- **Do not describe "metadata-only" as "no personal data."** Metadata-only narrows the privacy-risk surface; it does not remove the UK GDPR analysis where records relate to identifiable people.

## 6. Surface-by-surface rules

**Governance receipts / Assistant receipts** — *Rationale:* core accountability evidence; the product's reason to exist. *Deletion risk:* deleting receipts destroys the governance audit trail. *Safe default:* retain for tenant lifecycle; no deletion without founder + solicitor sign-off. *Must not promise publicly:* guaranteed deletion timelines, or that receipts prove clinical correctness/safety/competence.

**Learning completions / CPD exports** — *Rationale:* CPD/AI-literacy evidence value over a professional cycle. *Deletion risk:* premature deletion destroys CPD evidence; these are personal data. *Safe default:* retain aligned with CPD value; export is metadata-only. *Must not promise publicly:* RCVS-accredited/certified CPD, or proof of competence.

**Staff attestations** — *Rationale:* evidences that staff acknowledged policy. *Deletion risk:* deletion undermines attestation history; personal data. *Safe default:* retain for clinic record-keeping. *Must not promise publicly:* that attestation equals compliance or competence.

**Policy versions** — *Rationale:* version traceability for what applied when. *Deletion risk:* breaks the chain linking attestations/receipts to a policy version. *Safe default:* retain versions; treat content-hash coherence as an RC watch item. *Must not promise publicly:* regulatory approval of any policy.

**Self-assessments** — *Rationale:* internal governance readiness evidence. *Deletion risk:* loses dated readiness trail; admin-attributable personal data. *Safe default:* retain for clinic record-keeping. *Must not promise publicly:* that self-assessment is regulator-validated.

**Client transparency profiles** — *Rationale:* clinic's published statement about its AI use. *Deletion risk:* clinic-controlled content; deletion vs retire semantics differ. *Safe default:* retire via the existing publish/retire flow; no manual row deletion runbook. *Must not promise publicly:* that ANCHOR certifies the clinical accuracy of published content.

**Incident / near-miss logs** — *Rationale:* reflective governance learning. *Deletion risk:* deletion could look like concealment; reporter/reviewer attribution is personal data. *Safe default:* retain for clinic record-keeping; never-capture list applies to content. *Must not promise publicly:* that logs are a statutory report, insurer submission, or regulator notification.

**Admin audit events** — *Rationale:* operator accountability. *Deletion risk:* deletion undermines the accountability log. *Safe default:* retain for accountability lifetime. *Must not promise publicly:* external audit-grade guarantees.

## 7. Offboarding and deletion handling

Current operational posture:

- **Clinic export before closure should be preferred where implemented** (metadata/evidence export of available records).
- **Account deactivation and evidence retention are distinct:** deactivating access does not, by itself, delete governance evidence.
- **Deletion requests require founder review** (and, before any external commitment, solicitor-reviewed wording).
- **Legal / security / billing / dispute / governance evidence may survive account closure** where there is a legitimate basis to retain it.
- **Backup deletion lag must be disclosed cautiously** — Render-managed backups have their own retention window outside ANCHOR's direct control.
- **Final contractual wording requires solicitor review** (DPA exit clauses, Pilot Agreement §19, SaaS terms).

No offboarding deletion automation exists for the §2 surfaces today; this note documents posture only.

## 8. Change-control

- **Any** retention-period change, deletion automation, governance-evidence pruning, memory feature, or consent-model change **requires founder approval**.
- **Any externally facing retention promise requires solicitor review** before it is published or contracted.
- **Any backend implementation** (deletion endpoint, retention job, schema change) requires RLS / FORCE RLS, tenant-isolation, audit-trail, and metadata-only review **before coding** — and a separate authorised brief. This note does **not** authorise any such implementation.

## 9. Non-claims

This artefact is **not**:

- legal advice;
- GDPR compliance certification;
- RCVS approval;
- a compliance guarantee;
- a DPA or final privacy notice;
- authorisation for real clinic data, paid pilots, live generation, or customer onboarding.

## 10. Open items

- **Solicitor review required.**
- **Final DPA / Pilot Agreement / SaaS terms** to govern contractual retention (currently outline-only in `docs/commercial/`).
- **No automatic governance-data pruning implemented** for the §2 surfaces.
- **No deletion automation implemented** for these governance surfaces.
- **No live generation / Anthropic production processing authorised** by this note.

## 11. Gate conclusion

**R2 is now represented by an in-repo operational note, but external use, paid pilots, and real clinic data remain blocked until solicitor review and the wider hard stops are resolved.**

## 12. Cross-references

- [`intake_retention.md`](./intake_retention.md) — public-intake retention runbook (distinct scope).
- [`security_audits/2026-06-22_2a_d_1_security_audit_result.md`](./security_audits/2026-06-22_2a_d_1_security_audit_result.md) §5 — records the retention/memory-consent runbook gap this note addresses.
- [`../commercial/2026-06-08_personal_data_data_flow_inventory.md`](../commercial/2026-06-08_personal_data_data_flow_inventory.md) §10 — per-surface retention/deletion map.
- [`../commercial/2026-06-08_dpa_outline.md`](../commercial/2026-06-08_dpa_outline.md) §12, §16 — retention/deletion and exit (outline).
- [`../commercial/2026-06-08_privacy_data_boundary_outline.md`](../commercial/2026-06-08_privacy_data_boundary_outline.md) §13 — retention/deletion boundary (outline).
- [`incident_response.md`](./incident_response.md), [`backup_restore.md`](./backup_restore.md), [`env.md`](./env.md) §8 — incident, backup, export-cap references.
- Canonical: Roadmap v2.6 §107; Decision Memo Addendum v1.3; Readiness Map v1.1 §87/§141/§152 (R2 readiness discipline). For any clinic-facing wording, check Readiness Map v1.1 §2 first.
