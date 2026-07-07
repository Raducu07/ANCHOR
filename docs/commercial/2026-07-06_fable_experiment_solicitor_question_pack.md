# Fable Experiment Solicitor Question Pack — 6 July 2026

> **Status: solicitor-preparation material only. Not legal advice. Not a contract draft. Not a compliance, certification, RCVS-approval, or regulator-endorsement claim.** Prepared for the founder to send to the instructed UK solicitor alongside the existing `docs/commercial/` outlines and the 21 June 2026 external review handoff pack v2. Everything described below exists **only on unmerged experiment branches**; production is unchanged.
>
> **Standing gates, all closed:** no public launch; no paid pilots; no real clinic data; no production live generation; no live billing; no live provider switching; no OpenAI production use; no ambient transcript/audio storage; no clinical note generation; no EHR/PMS integration. ANCHOR is **aligned, not compliant**. Drafting or answering these questions authorises none of the above — paid pilots and real clinic data continue to require the completed security audit, operational resilience, and a solicitor-reviewed legal/commercial pack.

---

## 1. Purpose

The July 2026 code-completion experiment ("Fable experiment") built gated, disabled-by-default foundations for the remaining roadmap. None of it is live, but several pieces have **legal shape** — new data categories, a conditional subprocessor picture, billing structure, and workflow-adjacent metadata. This pack converts those into concrete questions so the legal/commercial pack (Terms/Pilot Agreement, Privacy Notice, DPA, AUP, Order Form, subprocessor list) can be drafted **once**, anticipating these features, instead of being amended feature-by-feature later. Questions are grouped by document, then by feature area. Section 15 lists which answers block which gate; section 16 is a plain-English founder summary.

## 2. What has changed code-wise (experiment branches only; nothing merged or deployed)

| Area | What now exists (all gated/off) |
| --- | --- |
| M6.12 provider connector | Provider interface; Anthropic adapter (behaviour-identical to before); an OpenAI adapter that is code-complete but **cannot be selected in production** (allow-list), requires an explicit non-production env selection plus an API key, and is unconfigured everywhere. Live Workspace generation itself remains production-off behind its own flag; a local/staging hard-refusal safety-gate harness exists (gate not yet passed). |
| M5.7 assisted onboarding | Read-only readiness checklist; admin-only invite lifecycle view (shows invitee **staff emails** and pending/used/expired status; never token material). |
| M4.6 Learn maturity | Self-check/scenario questions with immediate feedback; only **aggregate counts** stored (questions_total / questions_correct); role-based learning paths; renewal reminders; leadership overview keyed by user ID. Framed throughout as reinforcement — no pass/fail, grade, certificate, or competence field exists. |
| M5.8 billing foundations | Plan catalogue with deliberately **NULL prices**; per-clinic activation posture where a live Stripe mode is **impossible to store at schema level**; API refuses the gated activation states; a structure-only webhook that is disabled by default, refuses in production, verifies nothing, stores nothing. No Stripe SDK, no keys, no charge capability. |
| M6-S sustainability | Clinic-recorded operational quantities: energy kWh, waste kg, workflow CO2e estimates, with clinic-controlled supplier/workflow labels; hashed evidence reports; reporting defaults **off** per clinic. |
| M6.13 ambient governance shell | Metadata-only event records about ambient AI workflow events (tool label, event type, timestamps, optional duration, optional SHA-256 reference hash) plus a bounded human review gate. **Boundary specification adopted with amendments by founder decision on 6 July 2026** (`docs/operations/2026-07-06_m6_13_boundary_adoption_decision.md`); Rule 13 database CHECK hardening implemented and proven on a real Postgres (content-shaped inserts refused by the database itself). Every endpoint returns 503 unless a flag no environment sets is enabled. |
| Cross-cutting | Admin audit events on all new admin write-paths; real-Postgres migration validation (fresh + upgrade paths); RLS ENABLED + FORCED with USING/WITH CHECK verified on every new clinic-scoped table; frontend surfaces exist only behind a build-time internal-preview flag that is unset in every deployed environment; founder wording review applied. |

## 3. What remains off / gated

Production live generation (Anthropic-coupled path, flag off; deterministic governed generation is the current behaviour); OpenAI anywhere in production (allow-list refusal at resolution time); provider switching (no portal control exists; disabled selector only); live billing / Stripe (no SDK, no secrets, schema cannot record a live mode); ambient ingestion (flag off; no vendor adapter; no portal create UI); sustainability reporting (per-clinic default off); all frontend preview surfaces (build-time flag unset everywhere); paid pilots, real clinic data, public launch, Trust Pack exposure of any experiment surface, and all compliance/approval claims.

## 4. Questions for Terms / Pilot Agreement

1. **Customer responsibilities clause.** We need a clause mirroring product doctrine: human review before operational use of any AI-assisted output; clinical and professional accountability stays with the clinic; ANCHOR evidences governance process, not clinical correctness. What is your preferred formulation, and should it be a warranty, an acknowledgement, or both?
2. **Description of services.** Given the gated features, should the Terms describe only shipped functionality, with a mechanism (order form schedule? feature annex?) for adding gated modules later without re-papering?
3. **Review-gate records.** Where ANCHOR records that a person reviewed something (assistant runs; future ambient events), how should liability wording state that the record evidences that a decision was made and by whom — never that the decision was clinically correct?
4. **Pilot agreement.** For a future (not yet authorised) pilot: what liability caps, data-use limits, termination and evidence-export terms do you recommend for a governance-metadata product; and should pilot terms expressly restate that no clinical records are held in ANCHOR?
5. **Offboarding.** Metadata export and deletion on exit — what commitments are safe given Render-managed backup windows (we must not over-promise deletion inside the provider's backup retention window)?

## 5. Questions for Privacy Notice

6. **Staff personal data.** The platform processes staff emails (accounts, invites — invitee emails are visible to clinic admins before acceptance), roles, hashed IP/user-agent values, review attributions, learning-activity records, and admin audit events. Is our staff-data section adequate, and does invitee visibility to clinic admins need explicit mention?
7. **Public intake.** Pre-clinic marketing intake (demo/start requests, site-chat logs) stores contact details and free text, with optional webhooks (HTTPS-only enforced) that would transmit those fields if ever configured. Does the notice need a distinct section separating this UK-GDPR marketing perimeter from the clinic-governance metadata perimeter?
8. **New metadata categories.** If the gated modules later ship: learning self-check aggregate counts; sustainability operational quantities and clinic-written labels; ambient workflow-event metadata (including reviewer identity and optional duration). Which of these require notice text now versus at activation?

## 6. Questions for DPA

9. **Controller/processor mapping.** Our working assumption: the clinic is controller for clinic-governance metadata and staff data within its tenancy; ANCHOR is processor; ANCHOR is controller for the public marketing intake. Please confirm or correct, per surface — including the ambient event records, which are metadata *about* clinical workflow events without clinical content.
10. **Schedules.** What data-category schedule entries should be pre-drafted for the gated modules (ambient workflow metadata; sustainability operational data; learning-activity aggregates; billing posture states), so activation later is a schedule update, not a renegotiation?
11. **Retention.** We propose: ambient events follow the incident/near-miss retention class; sustainability evidence follows the governance-evidence class; both pending your confirmation (per the adopted M6.13 boundary rule 10). What retention language do you recommend, given no deletion automation exists and Render backups impose a floor?
12. **DPIA trigger.** Does any gated module — most plausibly ambient event records referencing clinical workflows, or duration/reviewer metadata — trigger a DPIA (or a documented DPIA-not-required decision) before real-clinic activation?

## 7. Questions for Acceptable Use Policy

13. **Content-boundary enforcement as AUP terms.** The ambient schema physically cannot store transcripts/audio/notes (database CHECK constraints), and labels are constrained to short single lines. Should the AUP nonetheless prohibit attempting to place clinical content or personal data in free-text label fields (supplier/workflow/tool labels, void reasons), so the contractual and technical boundaries match?
14. **Prohibited uses.** Please confirm AUP language prohibiting use of ANCHOR as: a clinical record system, a diagnostic/prescribing/triage aid, an ambient scribe, or a store of client/patient identifiers — matching the product's is-not list.
15. **Staff-visibility fairness.** Should the AUP (or Terms) require clinics to inform staff that governance metadata (review attributions, learning activity, audit events) is recorded — see also Q22?

## 8. Questions for Order Form / billing / Stripe

16. **Pre-Stripe drafting.** No Stripe integration, keys, or charge capability exists; plans carry no prices. Can the Order Form be drafted now with plan/term/fee placeholders so that enabling test-mode Stripe later needs no structural change? What payment-processing clauses become mandatory only at the point a Stripe account/key first exists (even test-mode)?
17. **Activation states.** The product models `internal_demo → pilot_candidate → active_limited → active_verified`, with the latter two refused by the API pending gates. Should contractual language reference these states (e.g. pilot = active_limited) or stay independent of product vocabulary?
18. **VAT/invoicing.** Anything to prepare now on VAT treatment and invoicing structure for a UK SaaS pilot, before any billing exists?

## 9. Questions for subprocessor list

19. **Anthropic conditionality.** The live generation path is built against Anthropic but remains production-off; Anthropic becomes a subprocessor **only if** live generation is enabled. How should the subprocessor list present this — a conditional entry now with the trigger stated, or addition only at enablement with a notice mechanism? Which approach better serves transparency without implying the capability is live?
20. **OpenAI adapter.** An OpenAI adapter exists in code but is unconfigured, cannot be selected in production (allow-list refusal), and reads its key only in non-production. Does mere code existence warrant any disclosure anywhere, or is disclosure correctly triggered only by configuration/enablement? We do not want the list to imply present-tense provider choice (prohibited wording: "provider choice is available today").
21. **Future provider switching.** If a second provider is ever authorised (founder decision + security + legal per the adopted posture), what contractual notice/consent mechanism for subprocessor changes should the DPA carry so switching is a notified change rather than a breach? Standing infrastructure subprocessors (Render hosting, EU-Central Postgres) should also be confirmed for the same list.

## 10. Questions for ambient governance (M6.13 — adopted boundary, experiment-only)

22. **Staff-monitoring adjacency.** Ambient events record occurred-at timestamps, optional `duration_seconds`, recorder identity, and reviewer identity. Could this constitute staff monitoring with employment-law or transparency-to-staff implications, and what clinic-side notice (and AUP/Terms language, per Q15) should accompany any activation?
23. **Controller/processor for workflow-adjacent metadata.** The records describe that ambient AI occurred around clinical consultations — metadata about clinical workflow events with **no clinical content and nowhere to put it** (no transcript/audio/note column exists; database CHECK constraints — "Rule 13" — physically refuse multi-line labels and non-SHA-256 reference values; the API additionally drops content-shaped fields). Does this metadata-only posture change your controller/processor or special-category analysis in any way?
24. **Retention.** Confirm or correct the adopted assumption that ambient events follow the incident/near-miss retention class (boundary rule 10).
25. **Review-gate liability.** The review gate stores a bounded decision category (approved for record / amended before use / rejected), reviewer, and time. Please propose wording ensuring these records evidence **process, not clinical correctness** (boundary rule 6), and that the clinical record remains in the clinic's own systems (rule 7).
26. **Reference hashes.** Events may carry a SHA-256 hash of an artefact held in the clinic's systems. Any legal characterisation issues with holding a content-free hash pointer to an external clinical document?
27. **Client transparency interplay.** If a clinic uses a third-party ambient scribe, its own client-facing AI statement may need to say so. What may ANCHOR's template *guidance* say here without giving legal advice to the clinic?

## 11. Questions for sustainability data (M6-S — experiment-only, per-clinic default off)

28. **Data classification.** Energy kWh, waste kg, and CO2e estimates are clinic **operational** data — a new category beyond governance metadata. Does it need its own DPA schedule row and data-inventory entry, and is any of it plausibly personal data in a small-practice context (e.g. a supplier label naming a sole trader)?
29. **Clinic-written labels.** Supplier and workflow labels are clinic-controlled free text (short, single-purpose). Is AUP "no personal data in labels" language (Q13) sufficient, or do you recommend contractual warranty language too?
30. **Retention.** Proposed governance-evidence retention class for readings/events/reports (reports are immutable and hashed, corrections are void-with-reason) — confirm or correct.
31. **Non-claims.** Copy states this is "governance evidence under clinic control — not an accredited carbon audit, not verified carbon accounting, and not an ESG compliance claim." Any additional disclaimer you would require before external use?

## 12. Questions for Learn maturity (M4.6 — experiment-only)

32. **Self-check counts.** Only aggregate counts per attempt are stored (e.g. "2 of 2 matched the reinforcement guidance"); no per-answer storage, no pass/fail/grade/certificate fields exist, and every response carries: *"Self-check reinforcement only. Not a competence assessment, not a pass or fail result, not certified or accredited CPD, and not regulator-approved training."* Is this framing sufficient to avoid the records being construed as competence assessment?
33. **Employment-law adjacency.** Leadership can see per-user completion/renewal status (user IDs, not free text). Does visibility of learning activity to clinic admins raise staff-monitoring or fairness issues needing Terms/AUP/notice language (with Q15/Q22)?
34. **CPD wording boundary.** We use only "CPD-recordable AI literacy activity" and never "certified CPD" or "RCVS-accredited CPD" (no accreditation exists or is claimed). Please confirm this line is safe for external copy, and whether "CPD-recordable" itself needs any qualifier in your view.

## 13. Questions for onboarding (M5.7 — experiment-only)

35. **Invitee email visibility.** Clinic admins can see invited-but-not-yet-accepted staff emails with invite status. Any notice/consent point for invitees who never accept (their email persists in the invite record), and what retention should apply to expired/unused invites?
36. **First-admin setup.** Clinic creation is operator-performed (admin-token gated bootstrap) with a time-limited invite to the first clinic admin. Any contractual account-security responsibilities to state (credential handling, admin-role hygiene) in Terms/AUP?
37. **Support obligations.** The checklist/guidance surfaces imply an onboarding journey. What minimum support and security-contact commitments (and response expectations) should the Terms state before any pilot, and where should the security contact live (Trust Centre page exists)?

## 14. Questions for public wording

38. **RCVS/VATA references.** The AI Provider Information Framework is an RCVS and Digital Practice-led **consultation** (survey closed 6 July 2026; final output awaited). Until a final framework or post-consultation output is published, may public copy reference the consultation by name in the neutral form we use internally ("an RCVS and Digital Practice-led alliance consulted the veterinary professions…"), and what constraints apply once the final output exists? We will never use "framework-compliant".
39. **Non-claims confirmation.** Our controlling list prohibits: RCVS approved/compliant, EU AI Act compliant, GDPR compliant, certified, regulator endorsed, guarantees of compliance or safety, proof of competence, certified/RCVS-accredited CPD. Please confirm this list is complete from your perspective for a product in our position, and flag anything you would add.
40. **Vendor-neutrality tense.** We only ever say "architected for vendor-neutrality" / "vendor-neutral over time," always alongside the statement that the live path is Anthropic-coupled and production-off. Is this future-tense framing acceptable in marketing and Trust Centre copy, and does it need any further qualifier?
41. **EU AI Act framing.** We frame Article 4 as an AI-literacy readiness theme, subject to legal review and amendment watch, using "from August 2026" softening and "Article 99 penalty regime may apply pending legal review," citing Regulation (EU) 2024/1689 via EUR-Lex only. Please confirm this framing or propose corrections.

## 15. Blocking decisions — which answers gate what

| Gate (all currently closed) | Blocking questions | Also required (non-legal) |
| --- | --- | --- |
| **Paid pilot** | Q1–Q5, Q16–Q18, Q37, Q39 | Security audit completion; operational resilience; founder decision |
| **Real clinic data** | Q6, Q9–Q12, Q35, Q39 | Security audit completion; backup/restore currency |
| **Live generation (Anthropic path)** | Q19, Q21, plus DPA readiness (Q9–Q11) | 2A-C.5E live safety-gate pass documented; founder decision |
| **Billing activation (even test-mode Stripe)** | Q16–Q18 | Founder decision; no live mode is schema-possible regardless |
| **Ambient activation** | Q22–Q27, Q12, Q15 | Adopted boundary spec preconditions; separate founder + security review; merge conditions |
| **OpenAI enablement (anywhere beyond local experiment)** | Q20, Q21 | Founder decision; security review; production allow-list change is a code decision, not config |

Sustainability activation with real data additionally requires Q28–Q31. Public-copy changes referencing RCVS/VATA require Q38 plus the final-output review protocol.

## 16. Plain-English summary for the founder

We built ahead, safely: everything new is switched off, fenced by the database itself where it matters most (ambient records physically cannot hold a transcript), and nothing is merged or live. Before any of it can carry real clinics or money, the solicitor needs to answer six clusters: **(1)** the standard pack — Terms/Pilot, Privacy Notice, DPA, AUP — written so the gated modules slot in later as schedule updates; **(2)** the subprocessor story — Anthropic listed as *conditional* on live generation, and whether a dormant OpenAI adapter needs mentioning at all; **(3)** ambient — confirm that metadata-about-clinical-workflows is fine as processor data, what to tell staff, and how long to keep it; **(4)** sustainability — a new "operational data" row in the data inventory; **(5)** Learn — confirm our "reinforcement, not competence" framing holds up, including for the counts we store; **(6)** wording — bless the non-claims list, the vendor-neutral-over-time tense, and how we may mention the RCVS/VATA consultation before and after its final output. None of this authorises launch, pilots, data, generation, or billing — it makes the paperwork ready so those decisions, when you take them, are signature-shaped rather than drafting projects.

---

*Prepared for solicitor review; not legal advice. All wording subject to Readiness Map v1.1 §2 controls and the operative canon (Roadmap v2.6; Addendum v1.3). Companion artefacts: `2026-06-21_solicitor_external_review_handoff_pack_v2.md`, the 5 July full-stack readiness audit, `docs/operations/2026-07-06_pre_merge_fix_validation_note.md`, and `docs/operations/2026-07-06_m6_13_boundary_adoption_decision.md`.*
