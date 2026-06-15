# ANCHOR Legal + Trust Centre Implementation Brief v1.1

**Status:** Founder / solicitor-preparation and engineering-planning draft
**Date:** 15 June 2026
**Owner:** Founder / Product Owner

**Purpose:** Convert ANCHOR's legal/trust-centre strategy into a safe static-frontend implementation plan, aligned with Roadmap v2.6, Readiness Map v1.1, Addendum v1.3, and the local `anchor-legal-prep` skill. This brief plans a build; it does not authorise one, and it is not legal advice.

> **Solicitor-review caveat (applies to the whole document):** Every page specification, skeleton, and wording suggestion in this brief is a *drafting aid prepared for solicitor review*. It is not legal advice, not final legal copy, and not a legal conclusion. No page described here may be relied on externally until it has passed solicitor review and a final wording scan against Readiness Map v1.1 §2.

---

## 1. Document control

| Field | Value |
| --- | --- |
| Version | v1.1 |
| Owner | Founder / Product Owner |
| Status | Solicitor-preparation and engineering-planning draft |
| Date | 15 June 2026 |

This document is explicitly:

- **not legal advice**
- **not final Terms of Service**
- **not a final DPA** (Data Processing Agreement)
- **not a DPIA** (Data Protection Impact Assessment)
- **not a security certification**
- **not authorisation** to onboard clinics, run paid pilots, process real clinic data, or enable live generation

It is a planning and solicitor-preparation artefact only. Content boundaries follow the `anchor-legal-prep` skill: it prepares material for human and solicitor decision; it does not decide.

---

## 2. Operative source set

Operative canonical sources for this brief (defer to these, in this order):

1. `docs/canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md` — Roadmap v2.6 (as-built reconciliation; §1 doctrine; active phase 2A-D release-candidate hardening).
2. `docs/canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md` — Readiness Map v1.1 (§2 wording controls operative for all clinic-facing copy; §3 RCVS principles; §4 EU AI Act articles).
3. `docs/canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md` — Addendum v1.3 (OPERATIVE decision; gates; live-generation safety gate; Article 4 amendment watch).
4. `docs/canonical/Official_EU_AI_Act_Source_Note_v1_1.md` — EU AI Act source discipline (EUR-Lex only; Article 113 for applicability dates). *(Present in repo.)*
5. Current frontend `CLAUDE.md` (and `AGENTS.md`) at repo root.
6. `.claude/skills/anchor-legal-prep/SKILL.md` — local legal-prep skill governing wording, prohibited claims, gates, and stop conditions.

**Historical only** (consult for provenance, do not treat as operative unless explicitly requested): Roadmap v2.5, Readiness Map v1, Decision Memo v1.1, Addendum v1.2, the Phase 2A-1 Engineering Brief, and Official EU AI Act Source Note v1. Where these differ from the operative set, the operative set wins.

---

## 3. Executive decision

**Build ANCHOR's public legal surface as a Legal + Trust + Procurement Centre — not merely a footer with Terms and Privacy pages.**

A footer with two links treats legal posture as an afterthought. ANCHOR's positioning ("governance and readiness infrastructure") requires the legal surface itself to be legible, structured, and procurement-ready, because the legal/trust surface is part of the product's trust narrative.

The centre must make five boundaries clear and easy to find:

- **Legal boundary** — what the service is, what the terms cover, what is excluded.
- **Data boundary** — what data is processed, in what role, with what retention and classification.
- **Procurement boundary** — what a buyer's procurement/security team needs (Trust Centre, security posture, document versions, access path).
- **AI governance boundary** — what ANCHOR is and is not; that governance receipts are governance evidence only.
- **Customer responsibility boundary** — what the clinic remains responsible for (clinical judgement, professional standards, lawful processing, safe use of AI tools).

---

## 4. Gate position

**Static legal/trust pages may be drafted and built.** That is the only authorisation this brief carries.

Drafting and building these pages **does not** authorise:

- selling
- paid pilots
- live clinic onboarding
- processing real clinic data
- enabling live generation

**Paid pilots or real clinic data require, first:**

- a completed **security audit** (2A-D.1)
- **operational resilience** evidence (backups, tested restore, breach runbook)
- a **legal/commercial pack with solicitor review** (2A-D.2), naming Anthropic as a subprocessor where live generation is in scope

**Live Workspace generation remains production-off** until the local/staging safety gate (2A-C.5E) passes and the hard-refusal boundary (diagnosis, treatment, prescribing) is demonstrated on the live path. Until then, ANCHOR is presented as **deterministic governed generation** only.

Publishing legal pages that *describe* a future capability must not imply the gate has been crossed. Every page that touches data, pilots, or live generation must carry the relevant gate caveat.

---

## 5. Doctrine controls

**ANCHOR is:**

- governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics
- metadata-only by default
- human-review based
- receipt-backed
- trust-surface oriented
- multi-tenant and privacy-aware
- standalone now, integrable later
- architected for vendor-neutrality / vendor-neutral over time (future-tense framing only)

**ANCHOR is not:**

- diagnostic AI
- prescribing AI
- treatment-planning AI
- autonomous triage
- ambient scribe
- EHR / PMS
- clinical decision-support product
- GPAI model provider
- RCVS-approved product
- regulator-endorsed product
- compliance guarantee
- replacement for veterinary judgement

---

## 6. Prohibited claims

Hard list. None of these may appear (in any tense or paraphrase) on any page built from this brief. A single occurrence blocks publication until reworded.

- RCVS approved
- RCVS compliant
- EU AI Act compliant
- GDPR compliant
- certified
- regulator endorsed
- guarantees compliance
- guarantees safety
- clinical decision support
- clinical record
- patient record
- diagnostic evidence
- proves clinical correctness
- RCVS-accredited CPD (unless formally achieved and documented)
- Article 4 compliant
- fine-proof
- vendor-neutral as a current-state capability
- provider-agnostic as a current-state capability
- live AI generation is active
- Anthropic/OpenAI provider choice is available today

---

## 7. Safe wording bank

Prefer these formulations (drawn from Readiness Map v1.1 §2):

- aligned with emerging professional expectations
- governance and readiness infrastructure
- helps clinics evidence responsible AI governance practices
- metadata-only governance evidence
- human review required
- governance receipt
- CPD-recordable AI literacy activity
- Article 4 readiness theme, subject to legal review and amendment watch
- Article 99 penalty regime may apply pending legal review
- architected for vendor-neutrality / vendor-neutral over time
- deterministic governed generation today
- live Workspace generation remains production-off pending local/staging safety gate

---

## 8. Recommended route architecture

Three slices. Only **Slice 1** is in scope for the first implementation. Slice 2 and Slice 3 are deferred and listed for planning continuity only.

### Slice 1 — static, frontend-only (in scope when authorised)

- `/legal`
- `/legal/terms`
- `/legal/privacy`
- `/legal/acceptable-use`
- `/legal/ai-governance-boundary`
- `/legal/security`
- `/legal/data-retention`
- `/legal/data-roles`
- `/legal/data-classification`
- `/legal/ai-data-use`
- `/legal/customer-responsibilities`
- `/legal/offboarding`
- `/legal/versions`
- `/security/vulnerability-disclosure`
- `/trust-center`

### Slice 2 — deferred (not in scope; plan only)

- `/legal/data-processing`
- `/legal/security/toms`
- `/legal/subprocessors`
- `/legal/ai-providers`
- `/legal/pilot-terms`
- `/legal/cookies`
- `/trust-center/security`
- `/trust-center/privacy`
- `/trust-center/ai-governance`
- `/trust-center/procurement`
- `/trust-center/request-access`

### Slice 3 — backend legal evidence controls (future only)

- legal document versions
- legal acceptance events
- trust-centre access requests
- subprocessor change notices
- security contact messages

> **Slice 3 must not be implemented without a separate backend-authorised brief.** It requires its own RLS / FORCE RLS / retention / audit design and sits behind the security and legal gates in §4. Nothing in this brief authorises any backend table, migration, endpoint, or stored event.

---

## 9. Page-level content specifications

Each Slice 1 page is content-only (static). For every page, the implementation must populate:

- **title** — page H1.
- **subtitle** — one-line framing under the title.
- **version** — document version (e.g. `v0.1 draft`).
- **effective date or draft status** — either an effective date or an explicit "Draft — not in force" label.
- **last updated** — date string.
- **status label** — one of: `Internal draft`, `Prepared for solicitor review`, `Published`. Default to the most conservative applicable label.
- **plain-English summary** — short, non-legalese overview of the page's purpose.
- **main sections** — the substantive content blocks (page-specific; see §10).
- **non-claim notice** — the standard non-claim block (no compliance/certification/approval claims; not legal advice; aligned, not compliant).
- **link back to `/legal`** — every page returns to the Legal Centre index.

A shared **non-claim notice** string (re-used across pages):

> *ANCHOR is governance and readiness infrastructure that helps clinics evidence responsible AI governance practices, aligned with emerging professional expectations. It is not a compliance, certification, or regulator-approved product, and it does not replace veterinary judgement. This page is information, not legal advice.*

---

## 10. Required page skeletons

Skeletons below are **drafting scaffolds for solicitor review**, not final legal copy. Each carries the standard meta block (title / subtitle / version / effective-or-draft / last-updated / status label), a plain-English summary, the listed main sections, the non-claim notice, and a link back to `/legal`.

### `/legal` — Legal Centre index
- **Title:** ANCHOR Legal Centre · **Subtitle:** Legal, data, and AI-governance information for ANCHOR.
- **Status:** Internal draft.
- **Summary:** Entry point to ANCHOR's legal, data, and governance pages, and to the Trust Centre.
- **Main sections:** card grid linking every Slice 1 page; short "what this centre covers" note; pointer to `/trust-center`; pointer to `/legal/versions`.

### `/legal/terms` — Terms of Service (draft)
- **Title:** Terms of Service · **Subtitle:** The terms that govern use of ANCHOR.
- **Status:** Prepared for solicitor review · **Draft — not in force.**
- **Summary:** Plain-English overview of what the terms cover and that they are a draft pending solicitor review.
- **Main sections:** scope of service (governance/readiness infrastructure, not clinical AI); acceptable use pointer; no-warranty / no-guarantee framing (no compliance/safety guarantee); limitation framing placeholder for solicitor; customer responsibilities pointer; changes/versioning pointer.
- **Note:** Do not state the terms are "in force" or "binding" while in draft.

### `/legal/privacy` — Privacy Notice (draft)
- **Title:** Privacy Notice · **Subtitle:** How ANCHOR handles personal data.
- **Status:** Prepared for solicitor review · **Draft — not in force.**
- **Summary:** What personal data ANCHOR processes and the roles involved; metadata-only by default but personal data may still be present.
- **Main sections:** what data is processed (metadata-only governance evidence; account/staff identifiers); data roles pointer (`/legal/data-roles`); retention pointer (`/legal/data-retention`); data-subject rights placeholder for solicitor; contact placeholder.

### `/legal/acceptable-use` — Acceptable Use Policy (draft)
- **Title:** Acceptable Use Policy · **Subtitle:** Safe and permitted use of ANCHOR.
- **Status:** Prepared for solicitor review.
- **Summary:** What ANCHOR may and may not be used for, consistent with product doctrine.
- **Main sections:** permitted use (governed, metadata-only, human-review-based workflows); prohibited use (no diagnosis, prescribing, treatment planning, autonomous triage; no attempt to make ANCHOR a clinical decision engine); no uploading of raw clinical records expectation; human-review-required reminder.

### `/legal/ai-governance-boundary` — AI Governance Boundary
- **Title:** AI Governance Boundary · **Subtitle:** What ANCHOR is, what it is not, and what receipts mean.
- **Status:** Prepared for solicitor review.
- **Summary:** The clinical and governance boundary of the product, in plain English.
- **Main sections (required):**
  - **what ANCHOR is** — governance, trust, learning, intelligence, and readiness infrastructure; metadata-only; human-review based; receipt-backed; architected for vendor-neutrality / vendor-neutral over time.
  - **what ANCHOR is not** — not diagnostic / prescribing / treatment-planning AI, not autonomous triage, not an ambient scribe, not an EHR/PMS, not a clinical decision-support product, not a GPAI model provider, not RCVS-approved or regulator-endorsed, not a compliance guarantee, not a replacement for veterinary judgement.
  - **governance receipts are governance evidence only.**
  - **receipts do not prove clinical correctness, patient safety, professional competence, or regulatory compliance.**

### `/legal/security` — Security Overview (draft)
- **Title:** Security Overview · **Subtitle:** ANCHOR's security posture in plain English.
- **Status:** Internal draft.
- **Summary:** High-level, non-certifying description of security posture; no certification claims.
- **Main sections:** multi-tenant isolation (RLS / FORCE RLS as architecture description, not a guarantee); access control; metadata-only storage posture; pointer to `/security/vulnerability-disclosure`; explicit note that this is a description, not a security certification, and that the formal security audit (2A-D.1) is a separate gate.

### `/legal/data-retention` — Data Retention (draft)
- **Title:** Data Retention · **Subtitle:** How long ANCHOR keeps governance metadata.
- **Status:** Internal draft.
- **Summary:** Retention approach for metadata-only governance evidence.
- **Main sections:** what is retained (metadata, receipts, audit events); retention-period placeholders for solicitor/operational confirmation; deletion-on-offboarding pointer (`/legal/offboarding`); no raw clinical content retained by default.

### `/legal/data-roles` — Data Roles
- **Title:** Data Roles · **Subtitle:** Who is the controller and who is the processor.
- **Status:** Prepared for solicitor review.
- **Summary:** Plain-English description of data-protection roles, with the explicit caveat that final role determination is for solicitor confirmation.
- **Main sections (required):**
  - **metadata-only does not mean no personal data.**
  - **the following may still be personal data:** staff identifiers, reviewer attribution, learning records, audit events, public intake submissions, and governance metadata.
  - controller/processor framing placeholder for solicitor (clinic likely controller for clinic data; ANCHOR's role to be confirmed by solicitor).

### `/legal/data-classification` — Data Classification (draft)
- **Title:** Data Classification · **Subtitle:** Categories of data ANCHOR handles.
- **Status:** Internal draft.
- **Summary:** Categories of data and their handling posture.
- **Main sections:** account/identity data; governance metadata; learning/CPD records; audit events; public intake submissions; explicit "no raw clinical content by default" statement; note that classification interacts with data-roles (`/legal/data-roles`).

### `/legal/ai-data-use` — AI Data Use
- **Title:** AI Data Use · **Subtitle:** How AI is used, and how data is and is not used.
- **Status:** Prepared for solicitor review.
- **Summary:** Plain-English statement of AI data-use posture.
- **Main sections (required):**
  - **ANCHOR does not use customer governance records, learning records, Trust Pack materials, clinic metadata, or account data to train public general-purpose AI models.**
  - **live Workspace generation is production-off.**
  - **Anthropic becomes a subprocessor only when live generation is enabled** (and the legal/subprocessor pack must name Anthropic before any paid pilot or real clinic data).
  - **do not claim that no AI provider ever sees data unless that is both technically and contractually true.** State the current posture (deterministic governed generation today; live generation off), not an absolute guarantee.

### `/legal/customer-responsibilities` — Customer Responsibilities
- **Title:** Customer Responsibilities · **Subtitle:** What your clinic remains responsible for.
- **Status:** Prepared for solicitor review.
- **Summary:** The responsibilities that remain with the clinic when using ANCHOR.
- **Main sections (required):** clinics remain responsible for **clinical judgement, professional standards, staff supervision, client communication, lawful processing, and safe use of AI tools.** ANCHOR is governance/readiness infrastructure, not a replacement for any of these.

### `/legal/offboarding` — Offboarding & Data Export (draft)
- **Title:** Offboarding & Data Export · **Subtitle:** What happens to your data when you leave.
- **Status:** Internal draft.
- **Summary:** Export and deletion approach on exit.
- **Main sections:** export of governance metadata/receipts; deletion approach and timing placeholders for solicitor/operational confirmation; relationship to retention (`/legal/data-retention`); no raw clinical content held by default.

### `/legal/versions` — Document Versions
- **Title:** Legal Document Versions · **Subtitle:** Version and effective-date register.
- **Status:** Internal draft.
- **Summary:** A static, human-maintained register of legal-page versions and dates.
- **Main sections:** table of page · version · status · last updated. **Static only** in Slice 1 — no backend version store (that is Slice 3).

### `/security/vulnerability-disclosure` — Vulnerability Disclosure
- **Title:** Vulnerability Disclosure · **Subtitle:** How to report a security issue responsibly.
- **Status:** Internal draft.
- **Summary:** A responsible-disclosure path and rules of engagement.
- **Main sections (required):**
  - **safe reporting path** — how to report (channel/contact).
  - **prohibited testing** — no testing against production, no accessing other tenants' data, no denial-of-service, no social engineering, no automated scanning that degrades service.
  - **security contact placeholder** — **warn:** do not publish a contact address externally until the mailbox actually exists and is monitored; until then keep this page in `Internal draft` and use a placeholder.

### `/trust-center` — Trust Centre (overview)
- **Title:** ANCHOR Trust Centre · **Subtitle:** Governance, security, and procurement information in one place.
- **Status:** Internal draft.
- **Summary:** Procurement-facing overview that gathers the trust narrative and links the legal pages.
- **Main sections:** what ANCHOR is (governance and readiness infrastructure); links to AI Governance Boundary, Security Overview, Data Roles, AI Data Use, Customer Responsibilities; pointer to `/legal`; note that deeper Trust Centre sub-pages and a request-access flow are deferred (Slice 2/3).

---

## 11. Frontend implementation design

Recommended approach: a **static, data-driven content registry** so legal copy lives in one typed place and pages render from it. Example shape:

- `app/legal/page.tsx` — Legal Centre index.
- `app/legal/[slug]/page.tsx` — renders each legal page from the registry by slug.
- `app/trust-center/page.tsx` — Trust Centre overview.
- `app/security/vulnerability-disclosure/page.tsx` — vulnerability disclosure.
- `components/legal/LegalPageShell.tsx` — shared page shell (title, meta block, sections, non-claim notice, back-link).
- `components/legal/LegalCardGrid.tsx` — index card grid.
- `components/legal/LegalStatusBadge.tsx` — `Internal draft` / `Prepared for solicitor review` / `Published` badge.
- `components/legal/LegalDocumentMeta.tsx` — version / effective-or-draft / last-updated block.
- `lib/legal/legalContent.ts` — typed content registry (one entry per page; no `any`).

**Explicit route files are acceptable if clearer** — a `[slug]` registry is the recommendation, but per-page `app/legal/<page>/page.tsx` files are a valid alternative where they read more clearly. Either way: no new colour system, no new typography, reuse existing shell/card/spacing primitives, and keep the content typed (no `any`, no `@ts-nocheck`).

---

## 12. Visual direction

- Use the **existing ANCHOR card / shell / spacing / typography** primitives.
- Tone: **calm, official, procurement-ready.**
- **No** dramatic gradients.
- **No** AI-revolution styling.
- **No** sales-led copy.
- **Readable legal page width** (constrained measure for long-form text).
- **No new colour system** and no new layout pattern.

This is consistent with CLAUDE.md's "preserve approved visual direction" rule and does not touch `components/shell/AppShell.tsx`.

---

## 13. Backend implications

- **Slice 1 is frontend/static only.**
- **No backend migrations.**
- **No legal acceptance events.**
- **No subprocessor change workflow.**
- **No trust-centre request form yet** (the request-access flow is Slice 2/3).
- Backend legal-evidence controls (Slice 3) require a **separate authorised backend brief** with RLS / FORCE RLS / retention / audit design.

If implementation appears to need a backend change, **stop and report** — do not edit backend, add endpoints, or create migrations under this brief.

---

## 14. Acceptance criteria for Slice 1

When Slice 1 is implemented (only after explicit founder authorisation), it is acceptable when:

- all Slice 1 routes render
- footer links include **Legal Centre, Terms, Privacy, Acceptable Use, AI Governance Boundary, Trust Centre, Security, Vulnerability Disclosure**
- no backend files changed
- no auth / RLS / migration changes
- no new compliance / certification / approval claims
- no present-tense vendor-neutrality claim
- no live-generation-active claim
- no Article 4 hard-sales claim
- solicitor-review caveat present where appropriate
- a **final wording scan against Readiness Map v1.1 §2 is completed before any external reliance**
- `npm run build` and `npm run lint` pass **when implementation touches frontend app code** — not required for this documentation-only task (no app code is changed by this brief)

---

## 15. Claude Code implementation prompt (Slice 1)

> **Do not run until founder explicitly authorises implementation.**

This prompt is recorded here for future use. It implements **Slice 1 only**.

```
You are working in the ANCHOR frontend repo. Implement Slice 1 of the ANCHOR Legal + Trust Centre.

Read first, before writing any code:
- docs/legal/ANCHOR_Legal_Trust_Centre_Implementation_Brief_v1_1.md (this brief — the binding plan)
- CLAUDE.md (and AGENTS.md)
- docs/canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md (Roadmap v2.6)
- docs/canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md (Readiness Map v1.1, esp. §2 wording controls)
- docs/canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md (Addendum v1.3)
- .claude/skills/anchor-legal-prep/SKILL.md (run this skill over all copy before declaring done)

Scope — Slice 1 only (static, frontend-only):
- Build the routes in §8 Slice 1 of the brief, using the content specs (§9) and skeletons (§10).
- Use the static content-registry design in §11 (or explicit route files if clearer); no `any`, no `@ts-nocheck`.
- Apply the visual direction in §12: reuse existing card/shell/spacing/typography; no new colour system; do not touch components/shell/AppShell.tsx.
- Add the footer links listed in §14.

Hard constraints:
- Frontend/static only. No backend, no migrations, no acceptance events, no request form (Slice 3 is out of scope).
- Do not build Slice 2 or Slice 3 routes.
- No prohibited claims (brief §6). No present-tense vendor-neutrality. No live-generation-active claim. No Article 4 hard-sales claim.
- Keep solicitor-review caveats and gate caveats where the brief requires them.
- Do not commit or push unless explicitly asked.

Before declaring done:
- Run the anchor-legal-prep skill over every page's copy and report the result.
- Run `npm run build` and `npm run lint`; report exact results (0 errors; only the known AppShell font warning).
- Report against the §14 acceptance criteria, and flag any item that needs solicitor review or a backend brief.
```

---

*ANCHOR Legal + Trust Centre Implementation Brief v1.1 — 15 June 2026 — solicitor-preparation and engineering-planning draft. Not legal advice. Aligned with Roadmap v2.6, Readiness Map v1.1, Addendum v1.3, and the anchor-legal-prep skill. Slice 1 is static frontend only and is not authorised for implementation, selling, pilots, real clinic data, or live generation by this document.*
