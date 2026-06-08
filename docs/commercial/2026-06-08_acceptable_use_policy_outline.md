# ANCHOR Acceptable Use Policy Outline v1 — 2026-06-08

## 1. Purpose and status

- This document is an **internal founder / solicitor-preparation outline** for a future ANCHOR Acceptable Use Policy.
- **It is not legal advice.**
- **It is not a final Acceptable Use Policy.**
- **It is not Terms of Service.**
- **It is not a Pilot Agreement.**
- **It is not a DPA.**
- **It is not ready to send to clinics.**
- It must be reviewed and drafted by an appropriate solicitor / legal adviser before any version of it is used externally.
- **It does not authorise pilots.**
- **It does not authorise paid pilots.**
- **It does not authorise real clinic data.**
- It does not make ANCHOR compliant, certified, RCVS-approved, regulator-endorsed, or commercially ready by itself.

---

## 2. Relationship to existing readiness documents

References:

- [`2026-06-08_legal_commercial_pack_outline.md`](./2026-06-08_legal_commercial_pack_outline.md) — defines the full required document set.
- [`2026-06-08_privacy_data_boundary_outline.md`](./2026-06-08_privacy_data_boundary_outline.md) — defines permitted and prohibited data boundaries.
- [`2026-06-08_dpa_outline.md`](./2026-06-08_dpa_outline.md) — defines the data-processing structure.
- [`2026-06-08_pilot_agreement_outline.md`](./2026-06-08_pilot_agreement_outline.md) — defines the pilot relationship and commercial-operational boundary.
- [`../operations/2026-06-08_founder_status_summary.md`](../operations/2026-06-08_founder_status_summary.md) — plain-English founder status note.
- [`../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md`](../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md) — operational evidence checkpoint.

Status:

- The legal/commercial pack outline defines the full required document set.
- The privacy/data-boundary outline defines permitted and prohibited data boundaries.
- The DPA outline defines the data-processing structure.
- The Pilot Agreement outline defines the pilot relationship and commercial-operational boundary.
- **This Acceptable Use Policy outline defines what users may and may not do inside ANCHOR.**
- **It must not be treated as final legal wording.**

---

## 3. ANCHOR use-positioning boundary

- ANCHOR is **governance, trust, learning, intelligence, and accountability infrastructure** for safe AI use in veterinary clinics.
- ANCHOR is **not clinical decision-making AI.**
- ANCHOR is **not an EHR / PMS.**
- ANCHOR is **not an ambient scribe.**
- ANCHOR **does not diagnose, prescribe, triage, or recommend treatment.**
- ANCHOR **does not replace veterinary professional judgement.**
- ANCHOR governance receipts, Trust surfaces, learning evidence, incident logs, and transparency surfaces are **accountability evidence, not clinical correctness certificates.**
- **Human professional review remains mandatory.**

---

## 4. Who the policy should apply to

Future scope (final role list must match the product and Pilot Agreement before external use):

- Clinic owners.
- Practice managers.
- Administrators.
- Veterinary surgeons.
- Nurses.
- Reception / admin / support users.
- Locums invited into clinic workspace, if a future account model allows.
- ANCHOR founder / admin / support users.
- Any authorised pilot user.

The final role list must match the product (named-admin and authorised-users model in the Pilot Agreement outline §9) and the binding contract before external use.

---

## 5. Permitted use

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
- Review of AI-use accountability metadata.
- Preparation for safe adoption of external AI tools, where within scope.

**Permitted use is limited to governance, accountability, transparency, learning, review, and operational assurance purposes.**

---

## 6. Prohibited clinical use

Prohibit:

- Clinical diagnosis.
- Prescribing.
- Treatment recommendation.
- Emergency triage.
- Autonomous clinical decision-making.
- Reliance on ANCHOR output as clinical advice.
- Use as a substitute for veterinary professional judgement.
- Use as a medical-record decision engine.
- Use to determine urgency of care.
- Use to override practice clinical protocols.
- Use to certify clinical correctness of an AI-generated output.

State:

- **ANCHOR may help evidence that governance / review happened; it must not be treated as deciding clinical care.**

---

## 7. Prohibited communication use

Prohibit:

- Sending client communication generated or governed through ANCHOR **without human review**.
- Autonomous release of content to clients.
- Use for **misleading, deceptive, coercive, or unfair** client communication.
- Use to **hide or obscure AI involvement** where transparency is required.
- Use to imply ANCHOR **clinically approved** an output.
- Use to create claims that are not supported by source material.

State:

- **Human review and professional accountability remain mandatory** before any external client communication.

---

## 8. Prohibited data uploads

Prohibit uploading:

- Unnecessary client-identifiable data.
- Unnecessary patient-identifying clinical histories.
- Full medical records.
- Emergency triage content.
- Raw consultation transcripts.
- Ambient audio or video.
- Diagnostic images or lab reports unless separately authorised later.
- Special-category or highly sensitive personal data unless legally reviewed and explicitly approved.
- Payment-card details.
- Passwords.
- API keys.
- Bearer tokens.
- Database URLs.
- Secrets or credentials.
- Third-party copyrighted / proprietary content without permission.
- Any data the clinic / user is not authorised to share.

State:

- **Real clinic data remains prohibited** unless and until the legal / commercial pack, DPA, privacy / data-boundary, operational gates, and founder approval are complete.

This list mirrors and reinforces the prohibited-data list in the privacy/data-boundary outline §16 and the Pilot Agreement outline §11.

---

## 9. Workspace acceptable-use boundary

- **Workspace is a governed work surface, not a clinical decision engine.**
- Workspace source material **should not include unnecessary personal / client / patient data**.
- **Workspace outputs must be reviewed by a human before any use.**
- **Live Workspace generation remains production-off.**
- Users **must not attempt to use Workspace to bypass clinical judgement, data boundaries, or policy controls.**
- If live generation is enabled later, acceptable-use wording **must be reviewed and updated before real clinic data is used**.

---

## 10. AI provider / live generation boundary

- **No real clinic data should be sent to an AI provider in production under current status.**
- Anthropic / provider integration is **gated by live-generation production-off and future approval**.
- Users **must not attempt to route real clinic data through unsupported external AI workflows using ANCHOR as cover.**
- Any future provider integration requires **DPA / sub-processor / privacy / pilot / agreement updates first**.
- **Human review remains mandatory.**

The moment live generation is enabled in production, Anthropic becomes an active sub-processor; the DPA outline §9 sub-processor list and this Acceptable Use Policy must be updated **before** that change ships.

---

## 11. Account and access responsibilities

- **Authorised users only.**
- **No shared accounts.**
- **No credential sharing.**
- **No use of another user's account.**
- **Clinic admin is responsible for removing users who leave.**
- **Clinic admin is responsible for role appropriateness.**
- Users **must keep login credentials secure**.
- **Suspected compromise must be reported promptly** through the agreed route (§17, §21).
- **Founder / admin support access** must remain bounded and auditable where applicable.

---

## 12. Tenant and confidentiality responsibilities

- Users **must not attempt to access another clinic's data**.
- Users **must not attempt to bypass tenant isolation, role checks, or access controls** (RLS / FORCE RLS posture is part of the platform; bypass attempts are out of bounds).
- Users **must not copy / export / share another clinic's data**.
- Users **must preserve confidentiality** of clinic materials.
- Users **must not publish screenshots or evidence containing clinic / client / user data without permission**.
- Users **must not use exported metadata outside the agreed pilot / commercial purpose**.

---

## 13. Security misuse

Prohibit:

- Attempting to **bypass authentication**.
- Probing or attacking ANCHOR systems.
- **Rate-limit abuse.**
- **Scraping.**
- **Credential stuffing.**
- **Uploading malware.**
- Attempting **SQL injection / prompt injection / policy bypass**.
- Attempting to **extract secrets**.
- **Reverse engineering** beyond permitted legal rights.
- **Interfering with logging, receipts, audit trails, or governance evidence.**

State:

- **Security misuse may result in suspension / termination and incident escalation** (§20).

---

## 14. Governance misuse

Prohibit:

- **Falsifying review status.**
- **Marking outputs reviewed when no review occurred.**
- **Creating misleading governance receipts.**
- **Deleting or manipulating evidence outside approved workflows.**
- **Using ANCHOR evidence to misrepresent compliance / certification.**
- **Using ANCHOR to imply RCVS approval or regulator endorsement.**
- **Using ANCHOR to obscure incidents or near-misses.**
- **Bypassing incident reporting.**
- **Bypassing retention / deletion procedures.**

These behaviours directly undermine the purpose ANCHOR exists for; they are grounds for immediate suspension under §20.

---

## 15. Learn / CPD acceptable-use boundary

- Learn / CPD evidence records **completion / acknowledgement metadata**.
- It is **not proof of competence**.
- It is **not certified CPD** unless a future approved process establishes that with the relevant body.
- Users **must not misrepresent completion as qualification, certification, or regulatory endorsement**.
- Users **must not complete learning / acknowledgement steps on behalf of another user**.

---

## 16. Trust Pack / self-assessment acceptable-use boundary

- **Trust Pack and self-assessment are readiness / evidence surfaces.**
- They **do not create** compliance, certification, RCVS approval, or regulator endorsement.
- Users **must not use Trust Pack / self-assessment output as external proof of legal compliance** without appropriate review.
- Users **must answer self-assessment honestly**.
- Users **must not submit unnecessary clinical / personal data in evidence fields**.

---

## 17. Incident / near-miss reporting obligations

- **Suspected security, privacy, governance, clinical-boundary, or AI-use incidents must be reported through the agreed route.**
- **Incident evidence should avoid unnecessary raw clinical / personal data** — the `incident_response.md` never-capture list (no secrets, no raw clinical content, no full bearer tokens, no `DATABASE_URL`) is operative.
- **Users must not conceal incidents.**
- **High-severity incidents must follow `docs/operations/incident_response.md`** (SEV-0 → SEV-3 ladder, first-15-minutes checklist, eleven per-class containment playbooks, post-incident review template).
- **ANCHOR may need to pause / suspend access** if safety, privacy, or governance risk requires it.

---

## 18. Public intake acceptable-use boundary

Public intake exists in the codebase — three tables (`demo_requests`, `start_requests`, `public_site_chat_events`) governed by `docs/operations/intake_retention.md`.

- **Public-intake routes are for bounded enquiries / contact / request handling only.**
- Public-intake users **must not submit**:
  - clinical emergencies;
  - full medical histories;
  - secrets;
  - payment-card details;
  - unnecessary personal data.
- **Public intake is governed by retention controls** (`intake_retention.md` — dry-run-first prune, 50 000-row hard cap, founder-approval-gated destructive runs, exact `I-UNDERSTAND` confirm literal).
- **Public intake is not a clinical advice or triage route.**

---

## 19. Payment / commercial misuse

- **Payment provider is future / not active** unless implemented and approved.
- **Payment-card details must not be entered into ANCHOR itself** — would live with a payment provider that is currently future / not active.
- Users **must not use ANCHOR to evade invoices, misuse trial access, or exceed agreed pilot scope**.
- **Paid-pilot terms must be handled through reviewed commercial documents** (per the legal / commercial pack outline + Pilot Agreement order form).

---

## 20. Consequences of misuse

Outline possible consequences (final enforcement wording must be solicitor-drafted):

- **Warning.**
- **Request to remove prohibited data.**
- **Access suspension.**
- **Clinic admin notification.**
- **Incident escalation** under `incident_response.md`.
- **Termination of pilot / access** per the Pilot Agreement §24.
- **Deletion / retention action under approved runbook** (`intake_retention.md`).
- **Legal escalation** where required.

State:

- **Final enforcement wording must be solicitor-drafted.**
- **Enforcement must preserve evidence** where needed for incident response.

---

## 21. Reporting misuse or concerns

Outline:

- **Report route to be defined** (per Pilot Agreement §17 support channel + §18 incident route).
- **What to report:**
  - Urgent security / privacy issues.
  - Governance boundary concerns.
  - Clinical-boundary misuse (use of ANCHOR for diagnosis / prescribing / triage / treatment recommendation).
  - Suspected account compromise.
- **Expected information to include** **without over-sharing personal / clinical data** (honour the `incident_response.md` never-capture list).

State:

- **Support route and timelines must align with Pilot Agreement / Support SLA** (Pilot Agreement outline §17).

---

## 22. Changes to acceptable use

The Acceptable Use Policy **must be updated before** any of:

- Live Workspace generation.
- AI provider processing of real clinic data.
- EHR / PMS integration.
- Ambient audio / transcripts.
- Storage of source material.
- Storage of AI prompt / output content.
- Payment provider activation.
- Transactional email provider activation.
- Expanded data categories.
- New sub-processors.
- Broader commercial launch.

Each change must update the corresponding pilot / DPA / privacy / commercial document and the relevant sub-processor list before activation.

---

## 23. Founder acceptable-use approval checklist

To be ticked in writing before the Acceptable Use Policy is shared externally:

- [ ] Permitted use reviewed.
- [ ] Prohibited clinical use reviewed.
- [ ] Prohibited communication use reviewed.
- [ ] Prohibited data upload list reviewed.
- [ ] Workspace boundary reviewed.
- [ ] AI provider / live-generation boundary reviewed.
- [ ] Account / access responsibilities reviewed.
- [ ] Security misuse section reviewed.
- [ ] Governance misuse section reviewed.
- [ ] Incident reporting route reviewed.
- [ ] Public intake wording reviewed.
- [ ] Consequences / enforcement reviewed by solicitor.
- [ ] Pilot Agreement alignment checked.
- [ ] DPA / privacy alignment checked.
- [ ] Founder explicitly approves before external use (dated signed note).

Any unticked box is a hard stop.

---

## 24. Hard stop conditions

- **No external Acceptable Use Policy before solicitor review.**
- **No pilot before Pilot Agreement reviewed.**
- **No paid pilot before legal / commercial pack reviewed.**
- **No real clinic data before DPA + privacy / data-boundary reviewed.**
- **No live Workspace generation in production.**
- **No AI provider processing of real clinic data** unless DPA / sub-processor / privacy / pilot / AUP terms are updated first.
- **No client / patient-identifiable data without explicit approval.**
- **No clinical decision-making positioning.**
- **No compliance / certification / RCVS / regulator-endorsement claims.**
- **No deletion promises beyond tested / runbook-backed capabilities.**
- **No destructive retention outside the approved runbook.**

These mirror and reinforce the operational hard stops in `docs/operations/2026-06-08_founder_status_summary.md §4`, the legal / commercial pack outline §12, the privacy / data-boundary outline §20, the DPA outline §21, and the Pilot Agreement outline §28.

---

## 25. Non-actions in this patch

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
- ❌ **No Acceptable Use Policy approved.**
- ❌ **No Pilot Agreement approved.**
- ❌ **No DPA approved.**
- ❌ **No pilot authorised.**
- ❌ **No paid pilot authorised.**
- ❌ **No real clinic data authorised.**
- ❌ No sub-processor added or activated.
- ❌ No commitment, claim, or representation made to any clinic, advisor, or regulator on the strength of this outline.
- ❌ No commit. No push. (Per scope.)

What this outline **did** do: defined the solicitor-preparation structure for ANCHOR's future Acceptable Use Policy; recorded the ANCHOR use-positioning boundary (governance infrastructure, not clinical AI; not EHR/PMS; not ambient scribe; no diagnosis/prescribing/triage/treatment recommendation; no substitute for professional judgement; human review mandatory); enumerated who the policy applies to, permitted use, prohibited clinical use, prohibited communication use, prohibited data uploads; defined zone-specific boundaries (Workspace, AI provider/live generation, account/access, tenant/confidentiality, security misuse, governance misuse, Learn/CPD, Trust Pack/self-assessment, incident/near-miss reporting, public intake, payment/commercial); outlined consequences of misuse, reporting routes, and change-control requirements; recorded the founder acceptable-use approval checklist (15 unticked boxes) and the standing hard stop conditions.
