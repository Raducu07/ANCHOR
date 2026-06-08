# ANCHOR Pilot Agreement Outline v1 — 2026-06-08

## 1. Purpose and status

- This document is an **internal founder / solicitor-preparation outline** for a future ANCHOR Pilot Agreement.
- **It is not legal advice.**
- **It is not a final Pilot Agreement.**
- **It is not a contract.**
- **It is not Terms of Service.**
- **It is not a DPA.**
- **It is not ready to send to clinics.**
- It must be reviewed and drafted by an appropriate solicitor / legal adviser before any version of it is used externally.
- **It does not authorise paid pilots.**
- **It does not authorise real clinic data.**
- It does not make ANCHOR compliant, certified, RCVS-approved, regulator-endorsed, or commercially ready by itself.

---

## 2. Relationship to existing readiness documents

References:

- [`2026-06-08_legal_commercial_pack_outline.md`](./2026-06-08_legal_commercial_pack_outline.md) — defines the **full required document set** for the legal/commercial pack.
- [`2026-06-08_privacy_data_boundary_outline.md`](./2026-06-08_privacy_data_boundary_outline.md) — defines **intended privacy and data boundaries**.
- [`2026-06-08_dpa_outline.md`](./2026-06-08_dpa_outline.md) — defines the **solicitor-preparation data-processing structure**.
- [`../operations/2026-06-08_founder_status_summary.md`](../operations/2026-06-08_founder_status_summary.md) — plain-English founder status note.
- [`../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md`](../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md) — operational evidence checkpoint.

Status:

- The legal/commercial pack outline defines the full required document set.
- The privacy/data-boundary outline defines intended data boundaries.
- The DPA outline defines the solicitor-preparation data-processing structure.
- **This Pilot Agreement outline defines the pilot relationship, permitted use, operational obligations, support expectations, boundaries, exit, and founder approval path.**
- **It must not be treated as final legal wording.**

---

## 3. Pilot posture

- ANCHOR **may later** support an assisted pilot or paid pilot, but **neither is authorised today**.
- Any future pilot must be **deliberately approved by the founder**.
- Pilot access must be **limited in scope, users, permitted use, data categories, and duration**.
- **Real clinic data remains prohibited** until the legal/commercial pack, DPA / data-boundary, operational readiness evidence, and founder approval are complete.
- **Live Workspace generation remains production-off.**
- **ANCHOR must not be positioned as clinical decision-making AI.**

---

## 4. Parties and definitions

Outline only — solicitor must confirm legal entity, trading name, address, governing law, and the binding form of every definition.

- **ANCHOR operating entity** — legal entity to be confirmed.
- **Clinic / practice / customer** — the veterinary clinic entering the pilot.
- **Authorised users** — named clinic staff with login access to the pilot tenant.
- **Founder / ANCHOR administrator** — internal ANCHOR-side accountable contact.
- **Pilot environment** — the `anchor-api-prod` deployment scoped to the clinic's tenant.
- **Pilot period** — the agreed start-and-end window.
- **ANCHOR service** — the governance / trust / learning / intelligence / accountability infrastructure as defined.
- **Governance event** — a metadata record of a governed interaction.
- **Governance receipt** — a metadata receipt identifier for a governed interaction.
- **Trust Pack / Trust posture** — the evidence packaging surface.
- **Learn / CPD evidence** — CPD-Recordable AI Literacy completion metadata.
- **Workspace** — the governed work surface (live generation production-off).
- **Live generation** — generation that hits an AI provider in production. Production-off today.
- **Clinic data** — data submitted by the clinic during pilot use (must stay inside the data boundary).
- **Personal data** — UK GDPR meaning, subject to DPA scope.
- **Prohibited data** — the list in privacy/data-boundary outline §16 and §11 of this outline.
- **Permitted use** — the list in §10.
- **Human review** — clinic-side mandatory review of any AI output touching a clinical-or-near-clinical context.
- **Incident / near-miss** — per `docs/operations/incident_response.md` definitions.
- **Exit** — pilot termination by either party or by expiry.

Legal entity, trading name, address, governing law, and definitions must be **solicitor-confirmed**.

---

## 5. Pilot scope

| Area | Included in pilot? | Boundary / notes |
|---|---|---|
| Governance receipts / governance events | Yes | Metadata-only; no raw prompts/outputs/transcripts |
| Dashboard / operational overview | Yes | Tenant-scoped via RLS / FORCE RLS |
| Policies / acknowledgements / attestations | Yes | Named-staff acknowledgement metadata only |
| Learn / CPD evidence | Yes | Completion metadata only; not proof of competence; not certified CPD |
| Trust Pack / Trust posture | Yes | Evidence references only; aligned-not-compliant wording |
| Self-assessment | Yes | RCVS self-assessment + dated evidence; internal governance readiness only |
| Client-facing transparency layer | Yes | Clinic-published surface; clinic is responsible for editorial accuracy |
| Incident / near-miss logging | Yes | Category / severity / context / status metadata; never-capture list applies |
| Exports | Yes | Role-gated; metadata-only; no raw clinical content |
| Workspace front door | Yes — surface only | Standing posture: no source content stored |
| Workspace **live generation** | **No — production-off** | Hard stop. Anthropic becomes a sub-processor the moment this is enabled in production. |
| AI provider integration | **Gated** | Not active for clinic data; sub-processor list + DPA must be updated **before** any activation |
| EHR / PMS integration | **No — not active** | Out of scope for pilot. Future change requires separate approval. |
| Ambient scribe functionality | **No — not active** | Out of scope. ANCHOR is not an ambient scribe. |
| Payment / billing automation | **No — not part of pilot** unless separately implemented and approved | Payment-card data must never enter ANCHOR's own data store |

**No real clinic data is authorised by this outline.**

---

## 6. Pilot duration and phases

Outline:

- **Pre-pilot readiness phase** — legal/commercial pack signed; DPA + privacy/data-boundary reviewed; clinic eligibility confirmed; founder approval recorded.
- **Onboarding / configuration phase** — tenant provisioned; named admin set up; user access configured; data-boundary briefing completed.
- **Limited operational trial phase** — clinic uses the in-scope modules per §5 under the permitted-use boundary per §10.
- **Review / feedback phase** — structured feedback per §21; founder decision on next step.
- **Exit / conversion / termination phase** — per §19 (retention, deletion, exit) and §24 (suspension/termination).

Placeholders (to be filled per-pilot in the order form, §26):

- Pilot start date.
- Pilot end date.
- Extension rules.
- Early termination.
- Pause / suspension.
- Conversion to paid SaaS, if later agreed.

**Duration and commercial terms must be agreed in an order form or pilot schedule** (§26).

---

## 7. Pilot fee / commercial terms

Future options (solicitor + founder to decide per-pilot):

- **Free assisted pilot** — no fee; founder-time intensive; bounded scope.
- **Discounted paid pilot** — reduced fee; clinic shares operational risk.
- **Standard paid pilot** — full fee; standard pilot terms.
- **Internal trial / no external clinic data** — no clinic onboarded; ANCHOR-side smoke only.

To be specified in the order form (§26):

- Price.
- VAT position.
- Invoicing format and timing.
- Payment method.
- Payment timing.
- Refunds / credits.
- Cancellation terms.
- Non-payment consequences.
- Upgrade / downgrade rules.
- **Stripe / payment provider only if implemented and approved** (per §16 sub-processor table; today: future / not active).

State:

- **No payment flow should be activated** until the legal / commercial pack is reviewed.
- **Payment-card details must not be entered into ANCHOR itself** — would live with a payment provider that is currently future / not active.

---

## 8. Clinic eligibility

Minimum eligibility criteria (a clinic that cannot meet any of these is not a pilot candidate):

- Clinic **understands ANCHOR is governance infrastructure, not clinical AI**.
- Clinic **accepts human review remains mandatory**.
- Clinic **agrees data-boundary rules** (privacy/data-boundary outline + DPA outline + this Pilot Agreement).
- Clinic **agrees no unnecessary personal / client / patient data upload**.
- Clinic **has a named accountable admin / user** who signs on behalf of the clinic.
- Clinic **accepts pilot limitations** (support window, feature scope, no clinical-decision-making reliance, no live Workspace generation in production).
- Clinic **agrees incident reporting route**.
- Clinic **signs the required legal / commercial pack** before access.
- **Founder approves onboarding** per §27.

---

## 9. Authorised users and access control

- **Named clinic admin** identified at onboarding; primary accountable user for the pilot tenant.
- **Authorised users only** — no shared accounts; no anonymous access; no unauthorised access.
- **Role / permission boundaries** managed by clinic admin within the tenant.
- **User removal process** — clinic admin removes departing staff promptly.
- **Responsibility for login security** — clinic-side (password hygiene, no token sharing).
- **No shared accounts.**
- **No unauthorised access.**
- **Founder / admin support access boundaries** — internal ANCHOR support access is limited to what is needed for support; auditable where the implementation supports it.
- **Auditability of user actions** where available — governance event metadata records named-user origin.

State:

- **Clinic admin is responsible for maintaining appropriate user access.**
- **ANCHOR must preserve tenant separation and access-control boundaries** (RLS / FORCE RLS).

---

## 10. Permitted use

Permitted use should include:

- AI governance review workflows.
- Policy acknowledgement and attestation.
- Governance receipt review / export.
- Trust Pack / Trust posture evidence.
- Self-assessment readiness evidence.
- Learn / CPD acknowledgement / completion evidence.
- Incident / near-miss metadata logging.
- Client-facing transparency evidence.
- Non-clinical operational governance workflows.
- Internal practice governance review.
- Founder-approved pilot feedback.

**Permitted use is limited to governance / accountability purposes.**

---

## 11. Prohibited use

Prohibited use should include:

- **Clinical diagnosis.**
- **Prescribing.**
- **Treatment recommendation.**
- **Emergency triage.**
- **Autonomous clinical decision-making.**
- **Autonomous client communication without human review.**
- **Use as EHR / PMS.**
- **Use as ambient scribe.**
- **Uploading unnecessary personal / client / patient data.**
- **Uploading real clinic records** unless explicitly authorised by signed documents.
- **Uploading raw consultation transcripts / audio.**
- **Uploading diagnostic images / lab reports** unless separately authorised later.
- **Uploading credentials, secrets, API keys, passwords, payment-card details.**
- **Using ANCHOR to replace professional judgement.**
- **Representing ANCHOR as RCVS-approved, regulator-endorsed, certified, or compliant.**

Breach of the Acceptable Use boundary should be a clear ground for suspension under §24.

---

## 12. AI governance and clinical boundary

- ANCHOR is **governance, trust, learning, intelligence, and accountability infrastructure**.
- ANCHOR is **not clinical decision-making AI**.
- ANCHOR **does not diagnose, prescribe, triage, or recommend treatment**.
- ANCHOR **does not replace veterinary professional judgement**.
- **Human review is mandatory** for any output touching a clinical-or-near-clinical context.
- Outputs / receipts / Trust surfaces are **governance evidence, not clinical correctness certificates**.
- ANCHOR may **support accountability around AI use** but **does not approve clinical outcomes**.

---

## 13. Human review obligations

- Clinic users **must review any output before use**.
- Clinic users **remain responsible** for client communication and clinical records.
- Any governed output must be checked for **accuracy, appropriateness, tone, privacy, and professional context**.
- **Review status should be visible** where the implementation supports it.
- **No autonomous release to clients** without human review.
- **Disputes / errors / incidents must be reported** via the agreed route.

---

## 14. Data boundary and DPA linkage

- **Pilot Agreement must be paired with DPA / privacy/data-boundary documents** before any real clinic data.
- **Metadata-only governance remains the default** (per `CLAUDE.md` doctrine).
- The **prohibited data list** from the privacy/data-boundary outline §16 applies.
- The **DPA outline must be converted into a solicitor-reviewed DPA** before any real clinic data.
- **Public intake / contact data remains separately bounded and retention-governed** (`intake_retention.md`; dry-run-first prune; 50 000-row hard cap; founder-approval-gated destructive runs; exact `I-UNDERSTAND` confirm literal).
- **Any change to data categories requires founder / legal approval** (per §25).

---

## 15. Privacy and confidentiality

- **Clinic confidentiality obligations** — must protect ANCHOR's non-public information shared during the pilot.
- **ANCHOR confidentiality obligations** — must protect clinic-confidential information shared during the pilot.
- **Personal data handling** linked to DPA / privacy wording per §14.
- **Prohibited data** per §11.
- **Incident reporting** per §18.
- **No secrets in user-submitted material** — passwords, tokens, API keys must not be entered.
- **No sharing access outside authorised users.**
- **No publishing screenshots / data** without permission.
- **Confidentiality survival** after termination.

**Final confidentiality wording must be solicitor-drafted.**

---

## 16. Subprocessors and third-party services

Reference: DPA outline §9.

- **Render** — active hosting infrastructure (`anchor-api-prod`, digest-pinned `python:3.11-slim@sha256:a3ab0b96…49ac0`).
- **Render Postgres** — active database infrastructure (RLS / FORCE RLS; backup/restore drill PASS 2026-06-07).
- **GitHub** — source control / CI metadata only; **not an intended clinic-data store**.
- **Anthropic** — **not active for clinic data** while live Workspace generation is production-off.
- **Payment / email providers** — **future / not active** unless implemented and approved.

**Any change to the sub-processor list requires review before any pilot data-boundary changes** (per §25 change control).

---

## 17. Support expectations / SLA posture

Modest support boundaries by intent:

- **Support channel** to be defined per order form (§26).
- **Support hours** to be defined; honest about solo-operator limits.
- **Response times** to be modest and honest (no enterprise-grade promises ANCHOR cannot back).
- **No emergency clinical support** — ANCHOR is governance infrastructure, not clinical operations.
- **No guaranteed uptime** unless later agreed and operationally supported.
- **Incident reporting route** per §18.
- **Maintenance windows** to be communicated.
- **Founder / operator limitations** — solo-operator infrastructure today.
- **Escalation process** to be defined.

**Do not overpromise enterprise-grade SLA until operationally supported.**

---

## 18. Incident / near-miss obligations

Reference: `docs/operations/incident_response.md` (severity ladder SEV-0 → SEV-3, first-15-minutes checklist, evidence capture rules with explicit never-capture list, eleven per-class containment playbooks, post-incident review template, evidence log template; first tabletop drill executed 2026-06-07 PASS).

Outline:

- **Clinic must report** suspected security / privacy / governance incidents **promptly**.
- **ANCHOR will triage** under the severity ladder.
- **Evidence capture must avoid unnecessary raw clinical / personal data** — the runbook's never-capture list (no secrets, no raw clinical content, no full bearer tokens, no `DATABASE_URL`) is operative.
- **Legal / privacy escalation** where needed.
- **Post-incident review** may be required per the runbook template.
- **Support and notification obligations** solicitor-drafted.

---

## 19. Retention, deletion, and exit

References:

- Privacy / data-boundary outline §13.
- DPA outline §12 + §16.
- `docs/operations/intake_retention.md`.
- `docs/operations/backup_restore.md`.

Outline:

- **Pilot exit process** — orderly handover; named-admin notification; final evidence capture.
- **Export of available metadata / evidence** — role-gated formats; governance event metadata, receipts, attestations, Learn/CPD completion records, Trust Pack evidence.
- **Deletion / pruning process** per the approved runbook (`intake_retention.md` shape for public-intake-style data; equivalent runbook for clinic-governance metadata must be drafted before promises are made externally).
- **Backup-retention limitations** — Render-managed backups have their own retention window; external deletion wording must be consistent with that.
- **Written confirmation** where applicable, dated.
- **No deletion promise beyond tested / runbook-backed capability.**
- **No destructive retention outside the approved runbook** (dry-run-first; founder approval; exact `I-UNDERSTAND` confirm literal; 50 000-row hard cap; evidence template).

---

## 20. Security and operational posture summary

Reference evidence **without overclaiming**:

- Dependency / CVE audit **PASS** for the locked scanned set (CI run `#5` against `de966a9`, `No known vulnerabilities found` for the 34-package set).
- Hashed runtime lockfile (per-wheel SHA256 verification at install).
- Docker base-image digest pin.
- GitHub Actions SHA pinning across the remaining `.github/workflows/*.yml`.
- Stale retention workflow removal.
- Alembic / Mako / MarkupSafe removal.
- Render deploy and smoke evidence (`cd9d966`, `7451357`).
- `/v1/version.git_sha` runtime revision observability (`RENDER_GIT_COMMIT` fallback).
- RLS / tenant-isolation posture.
- Backup / restore runbook (`backup_restore.md`).
- Retention runbook (`intake_retention.md`).
- Incident-response runbook (`incident_response.md`).

State:

- These are **operational evidence items, not guarantees** of security, compliance, certification, RCVS approval, or regulator endorsement.

---

## 21. Feedback and pilot learning

- Founder may collect pilot feedback (structured or unstructured).
- Feedback may inform product direction.
- Feedback should **not include unnecessary personal / client / patient data**.
- **Use of feedback / testimonials requires permission.**
- **No public case study without written approval.**
- **No use of clinic identity without permission.**

---

## 22. Intellectual property / ownership placeholders

Solicitor-drafted topics (this outline does **not** draft clauses):

- ANCHOR IP ownership.
- Clinic data ownership.
- Feedback use.
- Suggestions / improvements.
- Documentation / screenshots.
- Restrictions on copying / reverse engineering.
- Open-source / third-party software notices if relevant.

---

## 23. Liability / indemnity / insurance placeholders

- **Limitation of liability** must be solicitor-drafted.
- **Indemnity** must be solicitor-drafted.
- **Insurance expectations** must be reviewed.
- **ANCHOR does not accept responsibility for clinical decision-making.**
- **Clinic remains responsible for professional judgement and clinical use.**
- Pilot may require **deliberately conservative liability caps**.

This outline does **not** draft legal clauses.

---

## 24. Suspension and termination

Grounds and triggers (each to be solicitor-drafted):

- **Breach of permitted use** (per §10) or **breach of prohibited use** (per §11).
- **Prohibited data upload.**
- **Security incident.**
- **Non-payment**, if a paid pilot.
- **Legal / compliance concern.**
- **Founder safety decision.**
- **End of pilot** (expiry).
- **Clinic request.**

Effects of termination:

- **Data export / deletion** per §19.
- **Survival of confidentiality and liability terms** per §15 and §23.
- Wind-down notice and timing solicitor-drafted.

---

## 25. Change control and future features

**Separate approval required** for any of:

- Live Workspace generation.
- AI provider processing of real clinic data.
- Source material storage.
- Prompt / output content storage.
- EHR / PMS integration.
- Ambient audio / transcripts.
- Payment provider.
- Transactional email provider.
- Expanded data categories.
- Altered retention / deletion promises.
- New sub-processors.
- Production use outside pilot scope.

Each change must have its own dated decision artefact, the relevant sub-processor list / DPA update, and explicit founder authorisation.

---

## 26. Pilot schedule / order form placeholders

Per-pilot fields to be filled (solicitor + founder per pilot):

- Clinic legal name.
- Clinic address.
- Pilot start / end.
- Authorised admin (named).
- Permitted users.
- Pilot fee (and fee model).
- VAT / invoicing.
- Included modules (per §5 included list).
- Excluded modules (per §5 excluded list).
- Data boundary (referencing privacy/data-boundary + DPA).
- Support channel.
- Incident contact.
- Special terms (if any).
- Founder approval signature / date.

---

## 27. Founder pilot approval checklist

To be ticked in writing before any clinic is invited to a pilot. Each box must be supported by a dated note or evidence reference.

- [ ] Pilot Agreement solicitor-reviewed.
- [ ] DPA solicitor-reviewed.
- [ ] Privacy / data-boundary solicitor-reviewed.
- [ ] Terms / SaaS terms reviewed **or** pilot-specific terms approved.
- [ ] Pricing / VAT / invoicing reviewed.
- [ ] Support process reviewed.
- [ ] Incident process reviewed.
- [ ] Retention / deletion process reviewed.
- [ ] Backup / restore confidence reviewed.
- [ ] Clinic eligibility confirmed (per §8).
- [ ] Data boundary agreed.
- [ ] Live Workspace generation remains production-off unless separately approved (and gated on local/staging safety gate + hard-refusal harness on the live path).
- [ ] Clinic admin identified.
- [ ] Founder approves onboarding.
- [ ] Founder signs / dates approval before access.

Any unticked box is a hard stop.

---

## 28. Hard stop conditions

- **No pilot before Pilot Agreement reviewed.**
- **No paid pilot before legal / commercial pack reviewed.**
- **No real clinic data before DPA + privacy / data-boundary reviewed.**
- **No live Workspace generation in production.**
- **No AI provider processing of real clinic data** unless DPA / sub-processor / privacy / pilot terms updated first.
- **No client / patient-identifiable data without explicit approval.**
- **No clinical decision-making positioning.**
- **No compliance / certification / RCVS / regulator-endorsement claims.**
- **No deletion promises beyond tested / runbook-backed capabilities.**
- **No destructive retention outside the approved runbook.**
- **No final clinic-facing agreement without solicitor review.**

These mirror and reaffirm the hard stops in `docs/operations/2026-06-08_founder_status_summary.md §4`, the legal/commercial pack outline §12, the privacy/data-boundary outline §20, and the DPA outline §21.

---

## 29. Non-actions in this patch

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
- ❌ **No Pilot Agreement approved.**
- ❌ **No DPA approved.**
- ❌ **No pilot authorised.**
- ❌ **No paid pilot authorised.**
- ❌ **No real clinic data authorised.**
- ❌ No sub-processor added or activated.
- ❌ No commitment, claim, or representation made to any clinic, advisor, or regulator on the strength of this outline.
- ❌ No commit. No push. (Per scope.)

What this outline **did** do: defined the solicitor-preparation structure for ANCHOR's future Pilot Agreement; recorded the pilot posture (deliberate founder approval, limited scope/users/use/data/duration, real clinic data prohibited, live Workspace generation production-off, ANCHOR not positioned as clinical decision-making AI); enumerated parties + definitions, pilot scope (15-row included/excluded table), duration/phases, fee/commercial options; defined clinic eligibility, authorised users + access control, permitted use, prohibited use, AI governance + clinical boundary, human review obligations, data boundary + DPA linkage, privacy + confidentiality, sub-processors + third-party services, support / SLA posture, incident / near-miss obligations, retention/deletion/exit, security and operational posture summary (evidence not guarantee), feedback and pilot learning, IP/ownership/liability/insurance placeholders, suspension and termination grounds, change control for future features, per-pilot order-form placeholders; recorded the founder pilot approval checklist (15 unticked boxes) and the standing hard stop conditions.
