# ANCHOR Commercial / Legal Readiness Checkpoint v1 — 2026-06-08

## 1. Purpose and status

- This is an **internal founder-facing checkpoint summary** for the commercial / legal readiness track.
- It summarises the internal outlines created so far in `docs/commercial/`.
- **It is not legal advice.**
- **It is not a final legal pack.**
- **It is not a final clinic-facing document.**
- **It is not a substitute for solicitor review.**
- **It does not authorise clinic access.**
- **It does not authorise pilots.**
- **It does not authorise paid pilots.**
- **It does not authorise real clinic data.**
- **It does not authorise live Workspace generation.**
- It does not make ANCHOR compliant, certified, RCVS-approved, regulator-endorsed, or commercially ready by itself.

---

## 2. Current commercial / legal readiness state

| Area | Current state | Result |
|---|---|---|
| Commercial / legal pack outline | Internal outline created (`2026-06-08_legal_commercial_pack_outline.md`) | Pre-legal review; not final |
| Privacy / data-boundary outline | Internal outline created (`2026-06-08_privacy_data_boundary_outline.md`) | Pre-legal review; not final |
| DPA outline | Internal outline created (`2026-06-08_dpa_outline.md`) | Pre-legal review; not final |
| Pilot Agreement outline | Internal outline created (`2026-06-08_pilot_agreement_outline.md`) | Pre-legal review; not final |
| Acceptable Use Policy outline | Internal outline created (`2026-06-08_acceptable_use_policy_outline.md`) | Pre-legal review; not final |
| Clinic Onboarding Checklist | Internal outline created (`2026-06-08_clinic_onboarding_checklist.md`) | Pre-legal review; not final |
| Founder Pilot Approval Checklist | Internal outline created (`2026-06-08_founder_pilot_approval_checklist.md`) | Pre-legal review; not final |
| Commercial README index | Maintained, lists every commercial artefact with disclaimer | Internal index only |
| **Solicitor review** | Not yet performed | Required before any external use |
| **Final clinic-facing documents** | None | Not drafted; not authorised |
| **Clinic access** | None granted | **Not authorised** |
| **Pilot access** | None granted | **Not authorised** |
| **Paid pilot** | None | **Not authorised** |
| **Real clinic data** | None onboarded | **Not authorised** |
| **Live Workspace generation** | Off | **Production-off** |
| **AI provider processing of real clinic data** | Off | **Not active**; gated by live-generation production-off + future approval |

---

## 3. Completed artefacts

| Artefact | Path | Purpose | Status |
|---|---|---|---|
| Commercial README index | `docs/commercial/README.md` | Lists every artefact in the commercial / legal readiness directory with the standing disclaimer; cross-references to operations, canonical doctrine, and the founder-facing summary. | Internal index; pre-legal review; does not authorise access / pilots / real clinic data. |
| Legal & Commercial Pack Outline v1 | `docs/commercial/2026-06-08_legal_commercial_pack_outline.md` | Defines the full required document set (15 docs) and the founder approval workflow before paid pilots / real clinic data. | Internal outline; pre-legal review; does not authorise access / pilots / real clinic data. |
| Privacy & Data Boundary Outline v1 | `docs/commercial/2026-06-08_privacy_data_boundary_outline.md` | Defines intended data boundaries — what ANCHOR collects, does not collect, what metadata-only governance means, prohibited data, sub-processor posture (Render active; Anthropic gated). | Internal outline; pre-legal review; does not authorise access / pilots / real clinic data. |
| DPA Outline v1 | `docs/commercial/2026-06-08_dpa_outline.md` | Defines the solicitor-preparation data-processing structure: controller/processor model, processing purposes, data categories, sub-processors, international transfer, retention/deletion, incident notification, schedule placeholders. | Internal outline; pre-legal review; does not authorise access / pilots / real clinic data. |
| Pilot Agreement Outline v1 | `docs/commercial/2026-06-08_pilot_agreement_outline.md` | Defines the pilot relationship boundary: scope (15-row in/out table), duration/phases, fee options, eligibility, permitted/prohibited use, support/incident, retention/exit, suspension/termination, change control. | Internal outline; pre-legal review; does not authorise access / pilots / real clinic data. |
| Acceptable Use Policy Outline v1 | `docs/commercial/2026-06-08_acceptable_use_policy_outline.md` | Defines per-user behaviour boundaries: permitted use, prohibited clinical/communication/data-upload use, account/tenant/security/governance misuse, incident reporting, consequences. | Internal outline; pre-legal review; does not authorise access / pilots / real clinic data. |
| Clinic Onboarding Checklist v1 | `docs/commercial/2026-06-08_clinic_onboarding_checklist.md` | Converts the five legal/commercial outlines into a practical pre-access process: onboarding modes, hard gates, eligibility, document checklist by mode, data-boundary acknowledgement, DPA/privacy readiness, user/account setup, module enablement, support/incident/retention/exit, founder pre-access approval record, Day-0/Day-7/exit checklists. | Internal outline; pre-legal review; does not authorise access / pilots / real clinic data. |
| Founder Pilot Approval Checklist v1 | `docs/commercial/2026-06-08_founder_pilot_approval_checklist.md` | Final internal go / no-go decision record: 11 decision types, operational resilience + legal/commercial readiness checklists, clinic eligibility, onboarding mode, data-boundary go-no-go, real-clinic-data approval, paid-pilot approval, live-generation/AI-provider approval, provisioning, module enablement, support/incident/retention, external claims, decision record template, 11 approval outcomes, 17 re-approval triggers. | Internal outline; pre-legal review; does not authorise access / pilots / real clinic data. |

---

## 4. What the stack now gives ANCHOR

In plain language — what these outlines deliver, without overclaiming:

- **A first internal legal / commercial map.** The full required document set is enumerated and traceable; nothing important is unnamed.
- **A privacy / data-boundary posture.** Metadata-only governance is the default; prohibited data is listed; public intake is bounded; sub-processor posture is honest (Render active; Anthropic gated by live-generation production-off; GitHub not a clinic-data store).
- **A DPA-preparation structure.** Solicitor can see the working controller/processor assumption, data categories, schedules, and what needs binding wording — without the legal language being drafted prematurely.
- **A Pilot Agreement structure.** Pilot relationship, scope (15-row in/out table), duration, fee options, eligibility, permitted/prohibited use, support, incident, retention/exit, change control are all sketched.
- **An Acceptable Use boundary.** Per-user behaviour expectations are explicit; misuse categories and consequences are defined; user acknowledgements are traceable to AUP sections.
- **An onboarding pre-access checklist.** A clinic cannot be provisioned without an approved record; modes are bounded; modules are gated; live Workspace generation is explicitly off by default.
- **A founder go / no-go checklist.** Operational resilience and legal/commercial readiness must both be reviewed; default answers for real clinic data, paid pilot, and live generation are "not approved"; approval is per-clinic and does not generalise.
- **Consistent hard stops across the commercial / legal track.** Every outline repeats the same hard stops — paid pilot, real clinic data, live generation, compliance / certification / RCVS / regulator claims — so the boundary is not weakened by drift between documents.
- **A clearer path for solicitor review.** A solicitor walking into the stack has a coherent, internally consistent set of outlines to work from instead of scattered notes.
- **A way to avoid accidental pilot / sales drift before the gates are complete.** The hard-stop language is in every artefact; founder approval is the single chokepoint.

What the stack **does not** do: it is not legally approved; it is not "ready for pilots"; it is not commercially ready; it does not authorise any of the gated outcomes.

---

## 5. What this does not mean

- **It does not mean ANCHOR is compliant.**
- **It does not mean ANCHOR is certified.**
- **It does not mean ANCHOR is RCVS-approved.**
- **It does not mean ANCHOR is regulator-endorsed.**
- **It does not mean security risk is gone.**
- **It does not mean solicitor review has happened.**
- **It does not mean final legal documents exist.**
- **It does not mean clinic access is approved.**
- **It does not mean paid pilots are approved.**
- **It does not mean real clinic data is approved.**
- **It does not mean live Workspace generation can be enabled.**
- **It does not mean AI provider processing of real clinic data is approved.**

---

## 6. Standing hard stops

- **No clinic access without completed founder approval record.**
- **No pilot before Pilot Agreement reviewed.**
- **No paid pilot before legal / commercial pack reviewed.**
- **No real clinic data before DPA + privacy / data-boundary reviewed.**
- **No live Workspace generation in production.**
- **No AI provider processing of real clinic data** unless DPA / sub-processor / privacy / pilot / AUP / onboarding terms are updated first.
- **No client / patient-identifiable data without explicit approval.**
- **No clinical decision-making positioning.**
- **No compliance / certification / RCVS / regulator-endorsement claims.**
- **No deletion promises beyond tested / runbook-backed capabilities.**
- **No destructive retention outside the approved runbook.**
- **No external use of these documents before solicitor review.**

These mirror and reinforce the operational hard stops in `docs/operations/2026-06-08_founder_status_summary.md §4` and the hard stops in every commercial outline (`legal_commercial_pack §12`, `privacy_data_boundary §20`, `dpa §21`, `pilot_agreement §28`, `acceptable_use_policy §24`, `clinic_onboarding §20`, `founder_pilot_approval §21`).

---

## 7. Relationship to operational resilience

References:

- [`../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md`](../operations/security_audits/2026-06-08_operational_resilience_checkpoint.md)
- [`../operations/2026-06-08_founder_status_summary.md`](../operations/2026-06-08_founder_status_summary.md)

State:

- **Operational resilience evidence is materially stronger now** — dependency / CVE PASS for the locked 34-package set; hashed runtime lockfile; Docker base digest pin; GitHub Actions SHA pin; stale retention workflow removed; alembic / mako / markupsafe removed; two Render deploy smokes PASS (`cd9d966`, `7451357`); `/v1/version.git_sha` populated in production via `RENDER_GIT_COMMIT` fallback; RLS / FORCE RLS tenant isolation preserved; backup/restore runbook (first PASS drill 2026-06-07); intake-retention runbook (first PASS dry-run 2026-06-07); incident-response runbook (first tabletop 2026-06-07 PASS).
- **The commercial / legal checkpoint sits on top of that operational evidence.** Both tracks are visible and traceable.
- **Operational evidence does not replace legal / commercial readiness.** A clean `pip-audit` PASS is not a DPA. A digest-pinned image is not a Pilot Agreement. A passing tabletop drill is not solicitor approval.
- **Legal / commercial outlines do not replace operational evidence.** A solicitor-reviewed DPA does not eliminate the need for working backups, working incident-response, or honest deploy smokes.
- **Both tracks are required before any real pilot or real clinic data decision.**
- Dependency / CVE PASS, lockfile, Docker digest, Actions SHA, deploy smoke, RLS posture, runbooks, and version metadata are **evidence items, not guarantees**.

---

## 8. Remaining work before any pilot

| Workstream | Still needed | Blocks |
|---|---|---|
| Solicitor review | Not yet performed | **External use of any document**; paid pilot; real clinic data |
| Pilot Agreement finalisation | Outline → solicitor-reviewed draft → signed-ready | Pilot; paid pilot; real clinic data |
| DPA finalisation | Outline → solicitor-reviewed draft → signed-ready | Real clinic data; AI provider processing of real clinic data |
| Privacy Notice / Privacy Addendum finalisation | Outline → solicitor-reviewed draft → published version | Pilot; paid pilot; real clinic data |
| Terms / SaaS Terms | Required — not finalised | Paid pilot; full commercial onboarding |
| Acceptable Use Policy finalisation | Outline → solicitor-reviewed draft → signed-ready | Pilot; paid pilot; real clinic data |
| AI Governance Boundary Statement | Required — not finalised | Demo; pilot; paid pilot |
| Data Retention and Deletion Statement | Required — not finalised | Pilot; paid pilot; real clinic data |
| Incident and Support Process Statement | Required — not finalised | Pilot; paid pilot; real clinic data |
| Security / Operational Posture Summary | Required — not finalised | Pilot; paid pilot; real clinic data |
| Commercial / Pilot Order Form | Required — not finalised | Pilot; paid pilot |
| Pricing / VAT / invoicing | Required — not finalised (paid only) | Paid pilot; full commercial onboarding |
| Cancellation / exit process | Required — not finalised | Pilot; paid pilot |
| Support SLA / support expectations | Required — not finalised | Pilot; paid pilot; real clinic data |
| Clinic onboarding process | Outline → solicitor-reviewed → operational | Clinic access; pilot; real clinic data |
| Founder approval record | Template exists; per-clinic record blank | Clinic access; pilot; paid pilot; real clinic data |
| Operational evidence refresh, if pilot delayed | Second backup/restore drill, second intake-retention dry-run, additional incident-response tabletops | Recommended cadence; not strictly blocking |
| Payment provider / Stripe, if paid pilot | Not implemented today | Paid pilot only; not required for free / internal demo |
| Live generation safety gate, if ever considered | Local/staging gate + hard-refusal harness on live path | Live Workspace generation in production; AI provider processing of real clinic data |

Conservative summary: **many workstreams block paid pilot and real clinic data**; **solicitor review is required before any external use of any of these documents**; **payment provider is not required for a free / internal demo but is required before any paid flow**; **live generation is not required for a governance-only pilot and remains off**.

---

## 9. Recommended next decisions

| Option | Description | Recommended now? | Why |
|---|---|:---:|---|
| Pause and review internally | Founder rereads the spine; no new doc | ✅ **Yes** | The stack is now large enough that an internal pass before solicitor handoff is worth doing |
| Send outline pack to solicitor | Hand the eight commercial artefacts + operational checkpoint to legal counsel | ✅ **Yes — soon** | Solicitor review is the single biggest unblock; nothing meaningful moves without it |
| Create final solicitor-ready bundle / index | Single index document the solicitor can read first | ✅ **Yes** | Saves solicitor time; provides the questions and decision points up front |
| Convert outlines into draft clinic-facing docs | Promote outline → draft for each document | ⏳ Only after solicitor review | Premature promotion locks wording before legal input |
| Do optional engineering hygiene | `httpx<2` cleanup, Dockerfile `--require-hashes`, base-image digest refresh cadence, Dependabot | ⚠ Optional | Small wins; do not block legal track |
| Run another operational evidence drill | Second backup/restore, second intake-retention dry-run, additional incident-response tabletop | ⚠ Optional | Builds standing evidence record; cadence-driven |
| Prepare synthetic-demo walkthrough | Founder-driven demo on synthetic content for advisor / solicitor / interested party | ✅ **Possible** | **Only if no clinic access is provisioned and no real clinic data is involved**; founder approval still required |
| Approach clinics | Initiate pilot conversations with real clinics | ❌ **Not yet** | No solicitor-reviewed pack; no signed Pilot Agreement; no DPA |
| Enable real clinic data | Real clinic-data permission for any clinic | ❌ **No** | Hard stop until DPA + privacy + AUP + Pilot Agreement reviewed and signed |
| Enable paid pilot | Charge a clinic for a pilot | ❌ **No** | Hard stop until legal / commercial pack reviewed |
| Enable live Workspace generation | Workspace hitting Anthropic in production | ❌ **No** | Hard stop until local/staging safety gate + hard-refusal harness PASS on live path and DPA / sub-processor / privacy / pilot / AUP / onboarding all updated |

---

## 10. Suggested next artefact

**Recommended next artefact:**

`docs/commercial/2026-06-08_solicitor_review_bundle_index.md`

It should:

- List all commercial / legal outlines (with paths, status, and a one-line summary per document).
- List operational evidence references (checkpoint, dependency audit, deploy smokes, version metadata, runbooks).
- List the questions for solicitor review (controller/processor confirmation, transfer basis, SCC/UK IDTA scope, liability framing, indemnity / insurance, governing law, DPA Schedule 4 technical-and-organisational-measures wording boundary, retention promises, exit deletion, breach notification timing, Acceptable Use enforcement, Pilot Agreement scope language, etc.).
- Identify which documents need to become **actual legal drafts** (Pilot Agreement, DPA, Privacy Notice, ToS, AUP) versus which remain **founder-decision documents** (Onboarding Checklist, Founder Pilot Approval Checklist, Commercial Order Form template, Pricing/VAT note, Cancellation/exit process, Support SLA).
- Identify what is founder decision vs solicitor drafting per document.
- Remain **internal only** with the same disclaimer block carried by every other commercial artefact.

Alternative next artefacts (lower priority):

- `commercial_order_form_outline.md`
- `security_operational_posture_summary.md`
- `data_retention_deletion_statement_outline.md`
- `incident_support_process_statement_outline.md`

The solicitor-review bundle index is recommended **first** because the outline stack is now large enough that a clean solicitor-facing index is more useful than another outline.

---

## 11. Founder-readable summary

ANCHOR now has a coherent internal commercial / legal readiness spine: the document map, privacy / data boundary, DPA outline, Pilot Agreement outline, Acceptable Use outline, clinic onboarding checklist, and founder approval checklist are all in place as internal preparation documents. This is meaningful progress, but it is not legal approval and does not authorise clinic access, paid pilots, real clinic data, or live generation. The next best move is to package these outlines into a solicitor-review bundle and decide which documents need formal legal drafting before any clinic is onboarded.

---

## 12. Non-actions in this patch

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
- ❌ No commitment, claim, or representation made to any clinic, advisor, or regulator on the strength of this checkpoint.
- ❌ No commit. No push. (Per scope.)

What this checkpoint **did** do: summarised the current commercial / legal readiness state across eight artefacts; captured the completed artefact table with one-line purpose statements; recorded what the stack now gives ANCHOR (without overclaiming); restated what this checkpoint does not mean; reaffirmed the standing hard stops; cross-referenced the operational resilience evidence track and explicitly noted that neither track replaces the other; enumerated remaining work before any pilot with per-row "blocks" column; recorded the recommended next decisions (pause/review internally, solicitor-ready bundle/index, solicitor review soon, optional engineering hygiene, optional operational drill, synthetic-demo possible without clinic access, no clinic approach yet, no real clinic data, no paid pilot, no live generation); recommended the solicitor-review bundle index as the next artefact; provided a calm founder-readable paragraph.
