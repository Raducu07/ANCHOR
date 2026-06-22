# Controlled Founder Demo Script — 2026-06-22

> **Documentation-only controlled founder demo artefact. Demo / test-data only.**
> **Not** commercial release. **Not** paid pilot approval. **Not** customer onboarding. **Not** real clinic data approval. **Not** live generation approval. **Not** billing / Stripe approval. **Not** connector approval. **Not** solicitor-approved legal status. **Not** compliance / certification / regulator approval.
>
> ANCHOR is **aligned, not compliant** — not RCVS-approved, not regulator-endorsed, not certified. Metadata-only by default. Live Workspace generation **remains production-off**. This script changes no product behaviour and unlocks no gated functionality.

---

## 1. Title

**Controlled Founder Demo Script — 2026-06-22**

A route-by-route founder walkthrough for demonstrating the current ANCHOR frontend (`anchor-portal`, branch `anchor-portal-main-clean`) **using demo / test data only**.

## 2. Status

- Documentation-only controlled founder demo artefact.
- Demo / test-data only.
- **Not** commercial release.
- **Not** paid pilot approval.
- **Not** customer onboarding.
- **Not** real clinic data approval.
- **Not** live generation approval.
- **Not** billing / Stripe approval.
- **Not** connector approval.
- **Not** solicitor-approved legal status.
- **Not** compliance / certification / regulator approval.

This script is a talk-track, not an authorisation. The founder remains the decision-maker; nothing here crosses a hard stop.

## 3. Purpose

This script gives the founder a **safe, repeatable route-by-route walkthrough** of ANCHOR using demo / test data only. It is intended for:

- founder-led product walkthroughs;
- solicitor / security orientation;
- early market-feedback conversations.

It does **not** change product behaviour, public copy, routes, screenshots, legal wording, or production settings, and it **does not unlock** any gated functionality (paid pilot, real clinic data, customer onboarding, live generation, billing, connectors).

## 4. Demo rules / hard stops

During any demo:

- **Use demo / test data only.**
- **Do not enter real client data.**
- **Do not enter real patient data.**
- **Do not enter real clinical notes.**
- **Do not enter real staff personal data** unless it is the founder's own demo account.
- **Do not present this as a paid pilot.**
- **Do not present this as customer onboarding.**
- **Do not enable live generation.**
- **Do not activate Stripe / billing.**
- **Do not connect external systems.**
- **Do not claim** compliance / certification / RCVS approval / regulator endorsement.
- **Do not claim** receipts prove clinical correctness, patient safety, staff competence, or clinical safety.

If a viewer pushes toward any of the above, the correct answer is: *"That's a gated step — it requires completed legal/commercial review and isn't part of this demo."*

## 5. Setup assumptions

- The demo uses the **current frontend app** with an **authenticated founder / demo account** (the app surfaces fetch live tenant data behind auth; an unauthenticated `/dashboard` returns 401).
- The **backend may need seeded demo / test data** for best effect. Surfaces populate from governed workflow events and receipts.
- **If a surface is empty**, the founder should explain what *would* appear there once demo governed workflows have generated events / receipts (see §11 fallback).
- **Public-site screenshots are current** after the screenshot refresh (`5cc03f1`, checkpoint `bbeff48`).
- **`/workspace-live` and `/workspace-stitch` redirect to `/workspace`** and must **not** be demoed as separate products. They are legacy route names pointing at the single governed Workspace.
- **Live Workspace generation remains production-off.** The governed Workspace runs deterministic governed generation today; external model routing is production-gated and not part of the demo.

## 6. Recommended route order

1. Public homepage — `/`
2. Trust Centre — `/trust-center`
3. Dashboard — `/dashboard`
4. Workspace — `/workspace`
5. Assistant — `/assistant`
6. Receipts — `/receipts`
7. Trust Profile — `/trust/profile`
8. Trust Posture — `/trust/posture`
9. Trust Pack — `/trust/pack`
10. Learn — `/learn` and `/learn/cpd`
11. Intelligence — `/intelligence`
12. Governance Events — `/governance-events`
13. Demo / Start boundary — `/demo` and `/start`
14. Request Access boundary — `/trust-center/request-access`

## 7. One-line positioning for the demo

> *"ANCHOR is governance, trust, learning, intelligence, and readiness infrastructure for responsible AI use in veterinary clinics. It is not diagnostic, prescribing, treatment-planning, or autonomous clinical decision-making AI."*

Open with this line, and return to it whenever a viewer drifts toward treating ANCHOR as a clinical tool.

## 8. Route-by-route script

For each route: **What to show · What to say · What this surface proves / evidences · What it does not prove · If empty · Watch-outs.**

### A. Public homepage — `/`

- **Show:** current public positioning and the refreshed product screenshots; the non-clinical-AI boundary statement.
- **Say:** "ANCHOR is not clinical AI; it helps clinics evidence responsible AI-use governance."
- **Proves / evidences:** the public framing and product boundary are consistent and conservative.
- **Does not prove:** compliance, certification, regulator approval, or clinical safety.
- **If empty:** n/a (static public page).
- **Watch-outs:** do not embellish beyond the page; do not say "approved", "compliant", or "safe".

### B. Trust Centre — `/trust-center`

- **Show:** public trust / procurement / privacy / security orientation pages (`/trust-center/ai-governance`, `/privacy`, `/security`, `/procurement`).
- **Say:** "This is informational and boundary-setting — it explains our posture and what we are and aren't."
- **Proves / evidences:** ANCHOR can articulate its governance, privacy, and security posture in plain, conservative language.
- **Does not prove:** solicitor-approved legal status or compliance.
- **If empty:** n/a (static).
- **Watch-outs:** these pages are informational, not contractual; do not present them as finalised customer terms.

### C. Dashboard — `/dashboard`

- **Show:** the command centre — Dashboard-first navigation, **Open Workspace** / **Open Assistant** actions, the **Governance & readiness** card (Trust posture, Self-Assessment [admin-gated], Incidents), recent governance receipts, trust posture letter, recommended learning, and intelligence context if populated.
- **Say:** "This is the leadership-facing overview: governance activity, trust posture, receipts, learning signals, and intelligence in one calm surface."
- **Proves / evidences:** ANCHOR centralises governance visibility and routes to the evidence surfaces.
- **Does not prove:** clinic readiness or compliance.
- **If empty:** "This is a fresh demo / test tenant. The 24-hour telemetry, recent receipts, and intelligence fill in as governed workflows are run."
- **Watch-outs:** the trust letter (A/B/C) is a posture indicator, not a compliance grade — say so if asked.

### D. Workspace — `/workspace`

- **Show:** the governed source/review flow — source bundle, governed run, human-review guidance, the review confirmation gate, and the receipt preview / traceability.
- **Say:** "Workspace structures governed review and receipt-backed accountability. Outputs are reviewed by a human before any use."
- **Proves / evidences:** a governed workflow → human review → receipt path with metadata-only storage.
- **Does not prove:** clinical correctness or patient safety.
- **If empty:** "No source items are in the bundle yet — in a real session the clinician adds text/files, runs a governed review, and a receipt is produced."
- **Watch-outs:** **do not enter real clinical data.** State that **live generation remains production-off** (deterministic governed generation today) unless and until it is explicitly gated on. Do not imply the output is clinically validated.

### E. Assistant — `/assistant`

- **Show:** the **governed Assistant** surface as an **existing product surface** — the client-communication governed mode under human review, the active contract, policy-version display, run history, and receipt creation.
- **Say:** "Assistant supports the governed client-communication workflow / evidence loop, always under human review."
- **Proves / evidences:** governed assistance produces reviewable, receipt-backed evidence.
- **Does not provide:** diagnosis, prescribing, treatment planning, or autonomous clinical decision-making.
- **If empty:** "No Assistant runs are recorded yet for this clinic — runs and receipts appear here once a governed workflow is used."
- **Watch-outs:** **do not redefine Assistant as a generic navigation / chat bot.** It is the governed evidence-loop surface, not a new helper. (Any future explainer helper would be a separate "Guidance" / "In-product Help" concept, not this.)

### F. Receipts — `/receipts`

- **Show:** receipt metadata, the no-raw-content-stored posture, mode, review state, and hashes / metadata where present.
- **Say:** "Receipts evidence governance metadata and review state — who, when, what mode, what review status — without storing raw clinical content."
- **Proves / evidences:** receipt-backed accountability and the metadata-only doctrine in practice.
- **Does not prove:** clinical correctness, patient safety, staff competence, or compliance.
- **If empty:** "No receipts yet in this demo tenant — each governed Workspace or Assistant run produces one here."
- **Watch-outs:** do not say a receipt "proves" anything clinical; it evidences governance posture at a stated strength, nothing more.

### G. Trust Profile / Trust Posture / Trust Pack — `/trust/profile`, `/trust/posture`, `/trust/pack`

- **Show:** the trust posture and evidence-aggregation surfaces.
- **Say:** "Trust surfaces aggregate governance evidence into a legible posture and a shareable pack."
- **Proves / evidences:** governance evidence can be aggregated and surfaced as trust posture.
- **Does not prove:** regulator approval, compliance, certification, or legal sign-off.
- **If empty:** "These aggregate from underlying governance activity — they read as sparse until receipts and events exist."
- **Watch-outs:** "Trust" is a posture surface, not a compliance certificate; keep aligned-not-compliant framing.

### H. Learn / CPD — `/learn`, `/learn/cpd`

- **Show:** learning modules, cards, explainers, and CPD evidence.
- **Say:** "Learn supports AI literacy and internal governance awareness, with CPD-recordable activity."
- **Proves / evidences:** structured AI-literacy learning and completion metadata.
- **Does not prove:** staff competence or compliance.
- **If empty:** "Completion evidence appears here as staff work through modules."
- **Watch-outs:** **avoid claiming RCVS-accredited CPD or formal certification** unless a formal accreditation has actually been achieved and is documented. Use "CPD-recordable AI literacy activity."

### I. Intelligence — `/intelligence`

- **Show:** recommendations and hotspots if populated (`/intelligence/recommendations`, `/intelligence/hotspots`).
- **Say:** "Intelligence surfaces governance signals and learning opportunities from the activity in the clinic."
- **Proves / evidences:** governance signals can be summarised into actionable next steps.
- **Does not prove:** clinical risk scoring, clinical safety, or compliance.
- **If empty:** "No prominent hotspot is surfaced in this window — it populates from real governed activity."
- **Watch-outs:** do not present hotspots/recommendations as clinical risk assessment.

### J. Governance Events — `/governance-events`

- **Show:** the metadata event trail.
- **Say:** "Events help trace governance activity over time — a metadata audit trail."
- **Proves / evidences:** a traceable, metadata-only record of governance activity.
- **Does not replace:** statutory reporting, insurer notification, regulator notification, or clinical incident reporting.
- **If empty:** "Events accrue as governed workflows run; this is empty in a fresh demo tenant."
- **Watch-outs:** do not imply the event trail is a regulatory submission or a substitute for any statutory process.

### K. Demo / Start / Request Access — `/demo`, `/start`, `/trust-center/request-access`

- **Show:** the public intake boundary pages.
- **Say:**
  - **`/demo`** = a walkthrough request.
  - **`/start`** = structured interest / assisted-onboarding discussion — **not** access approval (the page states there is no live self-serve checkout).
  - **`/trust-center/request-access`** = a conservative request-access boundary ("requesting materials is not authorisation … those steps require a completed security audit, operational-resilience evidence, and a solicitor-reviewed legal and commercial pack").
- **Proves / evidences:** intake is bounded and honest about what it does and doesn't authorise.
- **Does not authorise:** paid pilot, clinic onboarding, or real clinic data.
- **If empty:** n/a (static forms).
- **Watch-outs:** never imply that submitting a form grants access, a pilot, or onboarding.

## 9. Demo fallback if the app is empty

> *"This is a demo / test environment. Some surfaces are intentionally empty until governed workflows generate receipts and events. The important point is the evidence path: **governed workflow → human review → receipt → Receipts → Intelligence → Trust.** What you're seeing is the structure that captures accountability, not a populated production clinic."*

Use this whenever a surface is sparse — it reframes empty states as the architecture rather than a gap.

## 10. Questions to ask the viewer

- Are staff already using AI informally in the practice?
- Who is responsible for AI-use policy in the practice?
- What would worry you most: data leakage, client communication, staff supervision, professional accountability, or evidence after an incident?
- What evidence would you want before allowing AI tools in clinic workflows?
- Who would own this internally: practice owner, clinical director, practice manager, or operations?
- Would a readiness review or governance setup be more useful than software access at this stage?
- What would stop you using something like ANCHOR?
- What would you pay for first: review, setup, training, policy support, or software?

## 11. What not to say

Never use any of these (they are false or unsafe today):

- "ANCHOR is compliant."
- "ANCHOR is certified."
- "ANCHOR is RCVS-approved."
- "ANCHOR is regulator-approved."
- "ANCHOR makes AI safe."
- "ANCHOR proves clinical safety."
- "ANCHOR proves clinical correctness."
- "ANCHOR replaces veterinary judgement."
- "ANCHOR is ready for real clinic data."
- "ANCHOR is ready for paid pilots."
- "ANCHOR is live-generation ready."
- "ANCHOR is vendor-neutral in production."
- "ANCHOR gives legal / GDPR assurance."

## 12. Better phrases to use

- "designed to support responsible AI-use governance"
- "evidence-oriented"
- "metadata-only by default"
- "human-review visible"
- "demo / test-data only at this stage"
- "internally signed off for controlled founder / internal review"
- "not a clinical decision-making system"
- "not solicitor-approved customer terms"
- "legal / commercial review is ongoing"
- "hard stops remain in place"

## 13. Post-demo notes (record after each demo)

- Viewer role.
- Clinic type.
- Main pain point.
- Current AI use.
- Strongest reaction.
- Biggest objection.
- Buying trigger.
- Likely budget owner.
- Requested feature / evidence.
- Whether they would pay for readiness review / setup / software.
- Follow-up action.

## 14. Exit / follow-up options (safe)

- Send the public site link.
- Offer another demo with synthetic / test data.
- Offer a paid **AI governance readiness review** only if the founder chooses (a services conversation, not product access).
- Add to a waitlist / record request-access interest.
- **Do not** offer real clinic access or real-data use unless and until future legal / commercial gates close.

## 15. Current known caveats

- Legal / solicitor first-stage review is **pending / not complete**.
- **No paid pilot** authorised.
- **No real clinic data** authorised.
- **No customer onboarding** authorised.
- Production **live generation remains off**.
- **Billing / Stripe off.**
- **Connectors off.**
- Demo quality depends on **seeded demo / test data**.
- Some **empty states are sparse** and can be improved later.

## 16. Next optional product improvements

- Richer empty states explaining how each surface is populated.
- A seeded demo / test-tenant procedure.
- Static in-product help / route signposting.
- A demo-data checklist.
- **No conversational help surface** unless separately designed and safety-reviewed (and, if built, framed as "Guidance" / "In-product Help" — **not** "Assistant MVP" and **not** a redefinition of the governed Assistant).

## 17. Final conclusion

This script supports **controlled founder demonstration** while preserving all hard stops and product boundaries. It does **not** change ANCHOR's product, legal, commercial, or deployment status. ANCHOR remains internally signed off only for controlled founder / internal review and demo / test-data demonstration; the commercial, legal, real-data, billing, connector, and live-generation gates remain closed.

## 18. Cross-references

- [`../frontend_rc_polish/2026-06-20_frontend_rc_polish_checkpoint.md`](../frontend_rc_polish/2026-06-20_frontend_rc_polish_checkpoint.md) — frontend RC polish checkpoint (final UI / nav state).
- [`../frontend_rc_polish/2026-06-21_public_screenshot_refresh_checkpoint.md`](../frontend_rc_polish/2026-06-21_public_screenshot_refresh_checkpoint.md) — public screenshot refresh checkpoint.
- [`../frontend_rc_polish/2026-06-21_demo_walkthrough_qa_audit_checkpoint.md`](../frontend_rc_polish/2026-06-21_demo_walkthrough_qa_audit_checkpoint.md) — demo / walkthrough QA audit checkpoint.
