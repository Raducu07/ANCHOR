# ANCHOR 2A-D Wording / Copy Scan Closure Note

> **Internal release-candidate hardening artefact.** This note records closure of the 2A-D wording / copy scan lane across **backend-held** documentation and **frontend public Legal + Trust / public-site** copy. It is **not legal advice**, **not solicitor review**, **not final RC sign-off**, and **not authorisation** for paid pilots, real clinic data, billing, Stripe activation, live Workspace generation, or connectors.
>
> ANCHOR is **governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics** — **not** clinical decision-making AI. ANCHOR is **aligned, not compliant**. Live Workspace generation **remains production-off**.

---

## 1. Status and purpose

This is an internal release-candidate hardening artefact recording that the 2A-D wording / copy scan lane is closed for current internal RC purposes. It consolidates the backend-held and frontend public-copy scans into one closure record.

It is explicitly:

- **Not legal advice.**
- **Not solicitor review.**
- **Not final RC sign-off.**
- **Not authorisation** for paid pilots, real clinic data, billing, Stripe activation, live Workspace generation, or connectors.

## 2. Inputs reviewed

- **Backend-held wording / copy scan:** [`2026-06-15_final_rc_wording_copy_scan.md`](./2026-06-15_final_rc_wording_copy_scan.md) (this repo).
- **Frontend public Legal + Trust / public-site wording scan:** `C:\Users\rggal\anchor-portal\docs\audits\2026-06-15_frontend_public_legal_trust_wording_scan.md` (confirmed present).
- **Frontend correction commit/PR:** commit `133acda` ("Soften legal review status labels") on branch `anchor-portal-main-clean`; merged to production via **PR #45** as merge commit `624ba82` ("Merge pull request #45 from Raducu07/anchor-portal-main-clean") on `anchor-portal-master`. Both confirmed from the `anchor-portal` git log. The frontend scan itself was committed as `5290530` ("Add frontend public wording scan").
- **Backend supporting commit:** `eaab52e` ("Add final RC wording copy scan"), plus the recent commercial / strategy support commits (commercial order form outline + README index correction; receipt schema strategy and gap analysis).

## 3. Backend scan outcome

- **Result:** PASS WITH WATCH ITEMS.
- **Issues:** 0.
- **Blockers:** 0.
- **Disposition:** Safe for internal founder / solicitor preparation; **not** cleared for binding external legal reliance.
- **Method note:** the backend scan did **not** use a dedicated legal skill at the time, because none was installed in the backend repo. It used `CLAUDE.md`, the operative canon (Roadmap v2.6, Readiness Map v1.1 §2, Addendum v1.3), and the `anchor-doctrine-check` skill's hard-rejection list as its rubric. (That gap is now closed — see §8.)
- Every prohibited term in the backend-held set appeared only in negated, conditional, avoid-list, or future-required-state contexts.

## 4. Frontend scan outcome

- **Result:** PASS WITH WATCH ITEMS.
- **Issues:** 0.
- **Blockers:** 0.
- **Legal skill used:** the frontend `.claude/skills/anchor-legal-prep/SKILL.md` was found and invoked (its §4 prohibited-claims list, §5 safer wording, §6 legal-gate rules, §7 Article 4 rule, §8 Anthropic/provider rule), cross-checked against `CLAUDE.md`, `CODEX_GUARDRAILS.md`, and the operative canon.
- **Main WATCH item:** Slice 2 status labels asserting **"solicitor reviewed"** / **"Founder-approved public summary"** — recorded founder framing that could not be verified from the repo and should be confirmed or softened before binding external reliance.

## 5. WATCH item closure

- The frontend WATCH item was corrected in **PR #45** (commit `133acda`).
- **"solicitor reviewed"** labels were softened to **"prepared for solicitor review"**.
- **"Founder-approved public summary"** was softened to **"Founder-prepared public summary — solicitor review pending"**.
- Production-preview verification (per the frontend record) showed **no remaining `solicitor reviewed` or `Founder-approved` strings** in `app/`, `components/`, or `lib/`.
- The safer labels are present in `app/legal/versions/page.tsx` and `lib/legal/legalContent.ts`.
- The corrected branch was merged to production (`anchor-portal-master`) as merge commit `624ba82`.

## 6. Current wording posture

Backend-held docs and frontend public copy now consistently preserve:

- aligned, not compliant;
- governance / readiness infrastructure;
- metadata-only by default;
- human review required;
- not clinical AI;
- not diagnostic / prescribing / treatment planning / autonomous triage;
- not ambient scribe / EHR / PMS;
- not GPAI provider;
- not RCVS-approved / regulator-endorsed / certified;
- no compliance guarantee;
- live Workspace generation production-off;
- Stripe future-candidate / not active;
- billing reserved / not active;
- no paid pilot or real clinic data authorised;
- vendor-neutral over time / architected for vendor-neutrality — **not** present-tense multi-provider capability.

## 7. Remaining watch items

These are not blockers; they remain open and watched:

- Solicitor review still not complete.
- Accountant / VAT / payment treatment still not complete.
- Paid pilots and real clinic data remain blocked.
- Live Workspace safety gate (2A-C.5E + hard-refusal harness on the live path) remains blocked.
- Stripe / payment activation remains future / gated.
- Anthropic / live AI provider subprocessor posture remains gated by live-generation activation.
- Connector / runtime ingestion remains future / gated.
- Final external-use decision still requires founder + solicitor / commercial review.

## 8. Backend legal skill installation note

- The backend repo now includes the **`anchor-legal-prep`** skill at `.claude/skills/anchor-legal-prep/SKILL.md`, installed from the frontend source verbatim (its canonical-path references — `docs/canonical/`, `CLAUDE.md`, `docs/commercial/` — map cleanly to the backend repo, and it self-handles any absent directory, so no backend-path edit was required).
- The skill is for **future audit consistency only** — so backend and frontend wording scans use the same prohibited-claims list, safer-wording set, legal-gate rules, and provider/Article 4 discipline.
- The skill **does not** replace solicitor review and **does not** authorise legal conclusions. It prepares and reviews text for human and solicitor review only; it performs no autonomous action and adds no connectors, MCP, scripts, or agents.
- No existing backend skill was overwritten (`anchor-legal-prep` did not previously exist; `anchor-backend-safety-review`, `anchor-doctrine-check`, and `anchor-security-audit` are unchanged).

## 9. Conclusion

- The **2A-D wording / copy scan lane is closed** for current internal RC hardening purposes: backend-held docs PASS WITH WATCH ITEMS (0 issues / 0 blockers), frontend public copy PASS WITH WATCH ITEMS (0 issues / 0 blockers) with its one WATCH item corrected and merged to production.
- The current posture is **suitable for founder / solicitor review and conservative public informational copy**.
- It is **not** final legal sign-off and **not** authorisation for paid pilots, real clinic data, billing, Stripe activation, live Workspace generation, or connectors.
- **Next decision:** whether to proceed to operational cadence evidence (second backup/restore drill, second intake-retention dry-run, further incident-response tabletops), solicitor pack handoff (per the solicitor review bundle index / dispatch checklist), or RC coherence fixes. This is a founder choice; none is forced by a failing gate.
