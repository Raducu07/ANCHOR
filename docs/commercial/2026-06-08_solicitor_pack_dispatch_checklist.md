# ANCHOR Solicitor Pack Dispatch Checklist v1 — 2026-06-08

> **2026-06-22 status update (founder-confirmed):** The legal/commercial pack has been **prepared and submitted to solicitor Piers for review; awaiting solicitor feedback. Not legally approved.** Paid pilots, real clinic data, customer onboarding, billing/Stripe, production live generation, and external customer use **remain blocked** until solicitor review and the wider gates are complete. This supersedes the "no solicitor engaged / no pack dispatched" wording recorded historically in §16 (as at 2026-06-08). No solicitor correspondence, legal advice, or privileged content is stored in this repo.
>
> **Changelog:** 2026-06-22 — Founder-confirmed solicitor submission status updated: pack submitted to solicitor Piers; awaiting review/feedback. No legal approval or external-use authorisation implied.

## 1. Purpose and status

- This is a **practical internal founder / operator dispatch checklist** for preparing and sending the ANCHOR solicitor review pack.
- It defines **what to send first, what to hold back unless requested, what not to send, what questions to ask, what outputs to request, how to control costs, and what hard stops remain after dispatch**.
- **It is not legal advice.**
- **It is not a final legal pack.**
- **It is not a final clinic-facing document.**
- **It is not a contract.**
- **It is not Terms of Service.**
- **It is not a Pilot Agreement.**
- **It is not a DPA.**
- **It is not an Acceptable Use Policy.**
- It must be reviewed by an appropriate solicitor / legal adviser before any external use.
- **It does not authorise pilots.**
- **It does not authorise paid pilots.**
- **It does not authorise real clinic data.**
- **It does not authorise live Workspace generation.**
- It does not make ANCHOR compliant, certified, RCVS-approved, regulator-endorsed, or commercially ready by itself.

---

## 2. Relationship to existing readiness documents

References:

- [`2026-06-08_solicitor_review_bundle_index.md`](./2026-06-08_solicitor_review_bundle_index.md) — solicitor-facing review map (what to read and in what order).
- [`2026-06-08_commercial_legal_readiness_checkpoint.md`](./2026-06-08_commercial_legal_readiness_checkpoint.md) — founder-facing checkpoint summary.
- [`2026-06-08_legal_commercial_pack_outline.md`](./2026-06-08_legal_commercial_pack_outline.md) — required document set.
- [`2026-06-08_privacy_data_boundary_outline.md`](./2026-06-08_privacy_data_boundary_outline.md) — intended data boundaries.
- [`2026-06-08_dpa_outline.md`](./2026-06-08_dpa_outline.md) — data-processing structure.
- [`2026-06-08_pilot_agreement_outline.md`](./2026-06-08_pilot_agreement_outline.md) — pilot relationship boundary.
- [`2026-06-08_acceptable_use_policy_outline.md`](./2026-06-08_acceptable_use_policy_outline.md) — per-user behaviour boundaries.
- [`2026-06-08_clinic_onboarding_checklist.md`](./2026-06-08_clinic_onboarding_checklist.md) — practical pre-access process.
- [`2026-06-08_founder_pilot_approval_checklist.md`](./2026-06-08_founder_pilot_approval_checklist.md) — internal go / no-go decision record.
- [`../operations/2026-06-08_founder_status_summary.md`](../operations/2026-06-08_founder_status_summary.md) — plain-English founder status note.
- [`../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md`](../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md) — operational evidence checkpoint.

Status:

- The Solicitor Review Bundle Index is the **solicitor-facing map**.
- This dispatch checklist is the **operator-facing send/hold/don't-send guide** that converts the index into a controlled outreach.
- **It must not be treated as final legal or external wording.**

---

## 3. Dispatch posture

- **Dispatch is deliberate, not casual.** A solicitor's time is a finite cost; sending everything at once risks paying for review of internal material the solicitor doesn't need.
- **Send the smallest coherent first bundle.** The Solicitor Review Bundle Index and the Commercial / Legal Readiness Checkpoint are the right first reads; everything else is "on request" until the solicitor asks for it.
- **Hold back internal-only artefacts unless asked.** Founder-facing summaries, internal evidence notes, and per-clinic decision records are reference material, not first-pass review material.
- **Never send secrets.** Per the `incident_response.md` never-capture list, the dispatch must not include `.env` files, raw `DATABASE_URL` values, bearer tokens, API keys, Render dashboard screenshots that include secrets, or any per-incident raw evidence.
- **No clinic identity or PII in the dispatch.** The pack is illustrative of ANCHOR's posture; it must not name a real prospective clinic, contain real clinic contact data, or contain real clinic source material.
- **Founder approval before dispatch.** A dated note from the founder authorising the dispatch belongs on the file before the pack leaves the operator's hands.

---

## 4. What to send first (Tier 1 — the smallest coherent bundle)

These are the documents that **define the spine** and let the solicitor scope the work.

| Document | Path | Why first |
|---|---|---|
| Solicitor Review Bundle Index v1 | `docs/commercial/2026-06-08_solicitor_review_bundle_index.md` | Single solicitor-facing map; orients the rest of the pack; includes suggested reading order and question banks |
| Commercial / Legal Readiness Checkpoint v1 | `docs/commercial/2026-06-08_commercial_legal_readiness_checkpoint.md` | Founder-facing state summary; explains what exists, what doesn't, and what remains gated |
| Legal & Commercial Pack Outline v1 | `docs/commercial/2026-06-08_legal_commercial_pack_outline.md` | Full required document set; defines the scope of the legal handoff |

State:

- These three give the solicitor enough to **quote on scope** without committing to drafting work.
- **Do not skip the Checkpoint** — without it the solicitor may misread the readiness state and over-quote.

---

## 5. What to send on request (Tier 2 — substance, after scope agreed)

These are the substance outlines that drive drafting. Send them **after the solicitor has read the Tier 1 documents** and confirmed scope.

| Document | Path | Why on request |
|---|---|---|
| Privacy & Data Boundary Outline v1 | `docs/commercial/2026-06-08_privacy_data_boundary_outline.md` | Drives Privacy Notice + DPA drafting |
| DPA Outline v1 | `docs/commercial/2026-06-08_dpa_outline.md` | Drives DPA drafting; binds controller/processor model |
| Pilot Agreement Outline v1 | `docs/commercial/2026-06-08_pilot_agreement_outline.md` | Drives Pilot Agreement drafting |
| Acceptable Use Policy Outline v1 | `docs/commercial/2026-06-08_acceptable_use_policy_outline.md` | Drives AUP drafting and enforcement wording |
| Operational Resilience Checkpoint | `docs/operations/security_audits/2026-06-08_operational_resilience_checkpoint.md` | Backs the security/operational posture wording with evidence |
| Founder Status Summary | `docs/operations/2026-06-08_founder_status_summary.md` | Plain-English orientation if the solicitor wants context |
| `env.md`, `backup_restore.md`, `intake_retention.md`, `incident_response.md` | `docs/operations/*.md` | Runbooks; send only the ones relevant to the question the solicitor is answering (retention, incident, support, backups) |

State:

- **Tier 2 is on request.** Sending the whole stack up-front pays for reading you don't need.

---

## 6. What to hold back unless explicitly requested (Tier 3 — internal controls)

These are **internal controls**. They inform legal drafting but are **not first-pass material** and may contain decisions / process logic that should stay internal.

| Document | Why held back |
|---|---|
| Clinic Onboarding Checklist v1 | Internal operational process; useful if the solicitor asks "what triggers contractual obligations vs internal controls", but not first-pass |
| Founder Pilot Approval Checklist v1 | Internal go / no-go decision record; per-clinic templates contain business/risk judgements |
| Internal onboarding evidence notes (per-clinic) | Internal only; redact before share |
| Per-incident evidence (from `incident_response.md` runs) | Subject to the never-capture list; redact and curate before share |
| Per-drill evidence (backup/restore, intake retention) | Internal cadence record |

State:

- **If the solicitor asks for these, send them.** Don't volunteer them in the Tier 1 / Tier 2 bundles.
- **Redact business-judgement notes** before sharing if a per-clinic record is needed for illustration.

---

## 7. What never to send

- **No `.env` files.**
- **No raw `DATABASE_URL`** values.
- **No bearer tokens, API keys, admin tokens, or other credentials.**
- **No Render dashboard screenshots** that include secrets, internal IDs, or other clinic data.
- **No per-incident raw evidence** beyond what the runbook permits (the `incident_response.md` never-capture list is operative: no secrets, no raw clinical content, no full bearer tokens, no `DATABASE_URL`).
- **No real prospective-clinic name, contact, or PII.**
- **No real clinic source material** (no medical records, no consultation transcripts, no client/patient identifiers).
- **No signed legal contracts from third parties** (NDAs with other counterparties, Render's commercial agreements, etc.) unless the solicitor explicitly needs them and a separate disclosure decision has been recorded.
- **No internal financial records** unless the solicitor asks for them for a specific commercial-terms question.
- **No third-party copyrighted material** without permission.

If any of the above must be discussed, **describe** rather than transmit; use synthetic examples; redact identifiers.

---

## 8. Questions to ask the solicitor at engagement

Before sending the pack, ask:

- **Engagement scope** — review pack and produce drafts of Pilot Agreement / DPA / Privacy Notice / AUP / Terms / Order Form, or a narrower subset?
- **Engagement form** — fixed fee, capped time, or hourly?
- **Engagement order** — which document do they want to draft first (typically Pilot Agreement + AUP first; DPA + Privacy Notice in parallel)?
- **UK jurisdiction confirmation** — confirm familiarity with UK GDPR / SaaS / professional regulation for veterinary clinics.
- **Conflicts check** — confirm no conflicts with other vet AI / vet practice clients.
- **Confidentiality** — confirm an engagement letter / NDA before any substantive material is shared.
- **Communication channel** — preferred channel (email / secure portal) and what they require to be encrypted in transit and at rest.
- **Timeline** — solicitor's realistic timeline for first draft + revisions.
- **Outputs format** — Markdown? Word? Both? (Founder preference: Markdown so the drafts can live alongside the outlines.)
- **Founder decision points** — confirm which decisions the solicitor will list back to the founder vs decide independently.

---

## 9. Outputs to request

Define explicitly what the engagement should produce. Mirrors the Solicitor Review Bundle Index §18 priority list.

**High priority (required before any pilot / paid pilot / real clinic data):**

- [ ] Pilot Agreement — signed-ready draft.
- [ ] DPA — signed-ready draft with Schedules 1–8.
- [ ] Privacy Notice / Privacy Addendum — clinic-facing draft.
- [ ] Acceptable Use Policy — clinic-facing draft.
- [ ] SaaS Terms / Terms of Service — umbrella terms.
- [ ] Commercial / Pilot Order Form — per-pilot template.
- [ ] Data Retention and Deletion Statement — clinic-facing draft.
- [ ] Incident and Support Process Statement — clinic-facing draft.

**Medium priority:**

- [ ] AI Governance Boundary Statement — linkable from every clinic-facing surface.
- [ ] Security / Operational Posture Summary — "evidence not guarantee" framing.
- [ ] Support SLA — modest by intent.
- [ ] Clinic Onboarding external wording — public-facing subset of the internal checklist.

**Later / gated (do not request now):**

- [ ] Live generation / AI provider addendum — only if and when live generation is approved.
- [ ] Sub-processor change-notice template — triggered by sub-processor addition.
- [ ] Paid subscription terms beyond pilot — only on conversion decision.

Also request:

- A **written list of recommended founder decisions** with risk implications.
- A **written list of open legal questions** the solicitor cannot resolve without further input.
- **Markup of any wording in the outlines that risks overclaiming** (compliance / certification / RCVS / regulator / clinical-AI / security overclaim).

---

## 10. Cost control

- **Fixed-fee per output** is preferred over open-ended hourly.
- **Cap the engagement** even if hourly is unavoidable.
- **Send Tier 1 first**, get scope quote, then authorise Tier 2.
- **Bundle questions** — don't ask one question at a time; group by topic (positioning, data boundary, DPA, Pilot, AUP, onboarding, retention, incident, payment, live generation, liability).
- **Do not pay for re-reading internal-only material** — keep internal controls out of the first bundle.
- **Track time on the operator side** — log each interaction and outcome.
- **Document founder decisions** as they happen so the solicitor doesn't have to re-ask.
- **Watch for scope creep** — additions to the brief mid-engagement should be priced separately.
- **Use written summaries** of phone calls; don't pay for the same conversation twice.

---

## 11. Dispatch sequence

Recommended order of operations:

1. **Founder authorises dispatch** (dated note).
2. **Confirm Tier 1 is clean** — re-read the three Tier 1 docs; redact anything that shouldn't be there.
3. **Engagement letter / NDA** signed with the solicitor.
4. **Send Tier 1** in one bundle via the agreed channel.
5. **Confirm receipt** and ask the solicitor's scope / fee proposal.
6. **Receive scope quote** — founder reviews + approves engagement form.
7. **Authorise Tier 2** — send substance outlines as the solicitor reads.
8. **Hold Tier 3** unless explicitly requested.
9. **Document every send** in an internal log with date, recipient, items sent, redactions applied.
10. **Founder review of drafts as they arrive** — track against the outlines they're based on.
11. **Founder decisions on flagged points** — record dated decisions as the engagement progresses.
12. **Final pack signed-ready** — captured per §13.

State:

- **Each step is a checkpoint, not a deadline.** Pause at any step if a hard stop activates.

---

## 12. Internal dispatch log template

Per-dispatch dated log (kept internal):

```text
Dispatch log ID:
Date:
Founder:
Solicitor / firm:
Engagement letter / NDA on file? yes/no:
Tier sent (1 / 2 / 3 / specific items):
Items sent (with paths and dates):
Redactions applied:
Channel used:
Receipt confirmed? yes/no, date:
Solicitor response received? yes/no, date:
Founder decisions captured:
Outstanding actions:
Notes:
```

State:

- Per-dispatch records are **internal only**.
- They must not contain secrets, real clinic data, or third-party confidential material.
- They should reference the dated docs and decisions that the dispatch covers, not duplicate them.

---

## 13. Acceptance criteria for the returned pack

Before any clinic-facing document is treated as "ready":

- [ ] Pilot Agreement, DPA, Privacy Notice, AUP, Terms, Order Form, Data Retention and Deletion Statement, and Incident and Support Process Statement have **all** been delivered as solicitor-drafted signed-ready versions.
- [ ] **No document overclaims** compliance / certification / RCVS / regulator / clinical-AI / security posture.
- [ ] **Hard stops** from the prior outlines are preserved (no live Workspace generation in production; no destructive retention outside the runbook; no clinical decision-making positioning).
- [ ] **Founder has read** every draft and recorded acceptance / required changes.
- [ ] **Founder decisions** flagged by the solicitor have all been recorded (dated notes).
- [ ] **Sub-processor schedule** matches the current sub-processor list (Render + Render Postgres active; GitHub not a clinic-data store; Anthropic gated; payment/email future).
- [ ] **Retention/deletion wording** does not exceed what `intake_retention.md` and `backup_restore.md` can back.
- [ ] **Incident notification wording** is consistent with `incident_response.md` (SEV ladder, never-capture list, timing).
- [ ] **Support SLA** is modest and operationally realistic.
- [ ] **Founder pilot approval checklist** (per-clinic) updated to reference the returned drafts.
- [ ] **Commercial / Legal Readiness Checkpoint** updated to reflect the new state.
- [ ] **Founder dated final acceptance** recorded.

Any unticked criterion blocks treating the pack as "ready".

---

## 14. Hard stops after dispatch

Dispatch is not authorisation. After the pack is sent (and even after drafts are returned):

- **No clinic access** without completed founder approval record.
- **No pilot** before Pilot Agreement reviewed **and signed**.
- **No paid pilot** before legal / commercial pack reviewed **and finalised**.
- **No real clinic data** before DPA + privacy / data-boundary reviewed **and finalised**.
- **No live Workspace generation in production.**
- **No AI provider processing of real clinic data** unless DPA / sub-processor / privacy / pilot / AUP / onboarding terms are updated **and re-approved**.
- **No client / patient-identifiable data** without explicit approval.
- **No clinical decision-making positioning** in any external surface.
- **No compliance / certification / RCVS / regulator-endorsement claims.**
- **No deletion promises beyond tested / runbook-backed capabilities.**
- **No destructive retention outside the approved runbook.**
- **No external use of drafts** until the founder has approved each one in writing.
- **No use of solicitor advice as cover** for a decision the founder must own.

These mirror and reinforce the operational hard stops in `docs/operations/2026-06-08_founder_status_summary.md §4`, and the hard stops in every prior commercial outline (pack §12, privacy §20, DPA §21, Pilot Agreement §28, AUP §24, Clinic Onboarding Checklist §20, Founder Pilot Approval Checklist §21, Commercial / Legal Readiness Checkpoint §6, Solicitor Review Bundle Index §21).

---

## 15. Founder dispatch approval checklist

To be ticked before the first dispatch leaves the operator:

- [ ] Founder has chosen the engagement solicitor / firm.
- [ ] Engagement letter / NDA signed.
- [ ] Tier 1 documents re-read and redactions confirmed.
- [ ] Tier 2 documents identified for "send on request" status.
- [ ] Tier 3 documents identified for "hold unless asked".
- [ ] "Never send" list confirmed.
- [ ] Communication channel confirmed (encrypted in transit; agreed at rest).
- [ ] Founder cost cap recorded.
- [ ] Dispatch log started.
- [ ] Founder accepts that dispatch does not authorise pilot / paid pilot / real clinic data.
- [ ] Founder accepts that dispatch does not enable live Workspace generation.
- [ ] Founder accepts the hard stops in §14.
- [ ] Founder explicitly authorises dispatch (dated signed note).

Any unticked box is a hard stop.

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
- ❌ **No legal document finalised.**
- ~~❌ **No solicitor engaged.**~~ — *historical, as at 2026-06-08; **superseded 2026-06-22**: pack submitted to solicitor Piers, review pending (see status update at top).*
- ~~❌ **No pack dispatched.**~~ — *historical, as at 2026-06-08; **superseded 2026-06-22**: pack submitted to solicitor Piers (see status update at top).*
- ❌ **No founder approval granted.**
- ❌ **No clinic access authorised.**
- ❌ **No Pilot Agreement approved.**
- ❌ **No DPA approved.**
- ❌ **No AUP approved.**
- ❌ **No onboarding process approved.**
- ❌ **No pilot authorised.**
- ❌ **No paid pilot authorised.**
- ❌ **No real clinic data authorised.**
- ❌ **No live Workspace generation authorised.**
- ❌ No sub-processor added or activated.
- ❌ No commitment, claim, or representation made to any clinic, advisor, solicitor, or regulator on the strength of this checklist.
- ❌ No commit. No push. (Per scope.)

What this checklist **did** do: defined the operator-facing dispatch posture for the solicitor review pack; classified every artefact as Tier 1 (send first), Tier 2 (send on request), Tier 3 (hold unless asked), or never-send; enumerated questions to ask the solicitor at engagement; defined outputs to request with explicit High / Medium / Later-gated priority; recorded cost-control discipline (fixed-fee preferred; cap engagement; bundle questions; don't pay to re-read internal-only material); defined the dispatch sequence (12 steps); recorded the internal dispatch log template; defined acceptance criteria for the returned pack (12 unticked boxes); reaffirmed the hard stops after dispatch (dispatch is not authorisation); recorded the founder dispatch approval checklist (13 unticked boxes).
