# Demo / Walkthrough QA Audit Checkpoint — 2026-06-21

## 1. Status

Documentation-only evidence checkpoint. Read-only QA audit of demo, walkthrough,
start, and request-access materials.

- Not a final RC sign-off.
- Not a commercial release.
- Does **not** authorise paid pilots, real clinic data, live generation,
  Stripe/billing, connectors, customer onboarding, compliance claims, RCVS
  approval, or regulator endorsement.

## 2. Reason for checkpoint

After the public screenshot refresh (see
[2026-06-21_public_screenshot_refresh_checkpoint.md](2026-06-21_public_screenshot_refresh_checkpoint.md)),
the demo / walkthrough / request-access lane was audited to confirm it remained
coherent with current app reality and did not reopen stale visual, route, or
claim-risk issues.

## 3. Scope

Read-only source audit of:

- `/demo`
- `/demo/thanks`
- `/start`
- `/start/thanks`
- `/trust-center/request-access`
- homepage and marketing links into demo/start
- public proof / static material sweep (no PDFs, GIFs, or videos in repo; only
  `public/anchor-public/*.png`, already refreshed in `5cc03f1`)
- frontend RC polish checkpoint
- public screenshot refresh checkpoint

## 4. Audit method

Manual read-only QA fallback, because `/qa-only` was not separately callable in
this environment. No files were edited, created, staged, committed, pushed, or
deployed during the audit (git inspection, Glob, Read only; no live/production
browsing or authentication).

## 5. Findings

- **Critical:** none.
- **High:** none.
- **Medium:** none.
- **Low:**
  - `/demo/thanks` "one working day" aim could optionally be hedged like
    `/start/thanks` ("response times may vary while ANCHOR is founder-operated").
  - Orphaned `public/marketing/dashboard.png`, `intelligence.png`,
    `receipt.png` remain (unreferenced) as future housekeeping.
  - Demo "what we'll show" copy (`demoWhatWeWillShow`) does not explicitly
    mention Assistant — optional future completeness improvement.

## 6. Coherence verdict

The demo / walkthrough / request-access materials are **coherent** with current
product reality, remain demo / founder-review safe, and do not contain stale
screenshots or material route mismatch. These pages describe the current product
(governed workflow, receipts, trust / learning / intelligence surfaces,
onboarding) and embed no product screenshots, so the screenshot refresh does not
affect them.

## 7. Claim-risk verdict

No material claim-risk was found for: commercial release, paid pilot
availability, real clinic data use, live generation, Stripe/billing, connectors,
RCVS approval, regulator endorsement, certification, compliance, clinical safety,
diagnosis, prescribing, treatment planning, or autonomous clinical
decision-making.

## 8. Demo / start / request-access boundary

- `/demo` remains a **walkthrough request**.
- `/start` remains **assisted onboarding interest / structured intake** (the
  form explicitly states there is no live self-serve checkout behind the page).
- `/trust-center/request-access` remains **conservative** and does not authorise
  access, paid pilot, onboarding, or real data ("requesting materials is not
  authorisation … those steps require a completed security audit,
  operational-resilience evidence, and a solicitor-reviewed legal and commercial
  pack").
- Request-access expectations are clear enough for current RC review.

## 9. Stale material result

No stale demo / walkthrough material was identified. Repo-wide stale material is
limited to the orphaned legacy `public/marketing/*.png` files, which are
unreferenced and non-blocking.

## 10. Final Internal RC Sign-Off implication

Nothing in the demo / walkthrough lane blocks a later Final Internal RC Sign-Off
Note, assuming the founder accepts the wider evidence pack. This checkpoint is
itself **not** that sign-off.

## 11. Hard stops preserved

This checkpoint does **not** unlock:

- paid pilots
- real clinic data
- live Workspace generation
- billing / Stripe
- connectors
- ambient integrations
- customer onboarding
- compliance / certification / regulator-approval claims

## 12. Remaining optional follow-ups

- Optional orphaned `public/marketing/*.png` asset housekeeping.
- Optional `/demo/thanks` response-time hedge wording alignment with
  `/start/thanks`.
- Optional Assistant mention in `demoWhatWeWillShow`.
- Later Final Internal RC Sign-Off Note.
